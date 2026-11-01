//go:build with_utls

package tls

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	mRand "math/rand"
	"net"
	"net/http"
	"reflect"
	"strings"
	"time"
	"unsafe"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/debug"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/ntp"
	aTLS "github.com/sagernet/sing/common/tls"

	utls "github.com/metacubex/utls"
	utlsmlkem "github.com/metacubex/utls/mlkem"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/net/http2"
)

var _ ConfigCompat = (*RealityClientConfig)(nil)

type RealityClientConfig struct {
	ctx       context.Context
	uClient   *UTLSClientConfig
	publicKey []byte
	shortID   [8]byte
}

func NewRealityClient(ctx context.Context, serverAddress string, options option.OutboundTLSOptions) (*RealityClientConfig, error) {
	if options.UTLS == nil || !options.UTLS.Enabled {
		return nil, E.New("uTLS is required by reality client")
	}

	uClient, err := NewUTLSClient(ctx, serverAddress, options)
	if err != nil {
		return nil, err
	}

	publicKey, err := base64.RawURLEncoding.DecodeString(options.Reality.PublicKey)
	if err != nil {
		return nil, E.Cause(err, "decode public_key")
	}
	if len(publicKey) != 32 {
		return nil, E.New("invalid public_key")
	}
	var shortID [8]byte
	decodedLen, err := hex.Decode(shortID[:], []byte(options.Reality.ShortID))
	if err != nil {
		return nil, E.Cause(err, "decode short_id")
	}
	if decodedLen > 8 {
		return nil, E.New("invalid short_id")
	}
	return &RealityClientConfig{ctx, uClient.(*UTLSClientConfig), publicKey, shortID}, nil
}

func (e *RealityClientConfig) ServerName() string {
	return e.uClient.ServerName()
}

func (e *RealityClientConfig) SetServerName(serverName string) {
	e.uClient.SetServerName(serverName)
}

func (e *RealityClientConfig) NextProtos() []string {
	return e.uClient.NextProtos()
}

func (e *RealityClientConfig) SetNextProtos(nextProto []string) {
	e.uClient.SetNextProtos(nextProto)
}

func (e *RealityClientConfig) Config() (*STDConfig, error) {
	return nil, E.New("unsupported usage for reality")
}

func (e *RealityClientConfig) Client(conn net.Conn) (Conn, error) {
	return ClientHandshake(context.Background(), conn, e)
}

func (e *RealityClientConfig) ClientHandshake(ctx context.Context, conn net.Conn) (aTLS.Conn, error) {
	verifier := &realityVerifier{
		serverName: e.uClient.ServerName(),
	}
	uConfig := e.uClient.config.Clone()
	uConfig.InsecureSkipVerify = true
	uConfig.SessionTicketsDisabled = true
	uConfig.VerifyPeerCertificate = verifier.VerifyPeerCertificate
	if pool := realityKeyPoolFor(uConfig); pool != nil {
		defer pool.refill()
	}
	var uConn *utls.UConn
	var err error
	if realityIsRandomized(e.uClient.id) {
		// Normal uTLS randomization, then a per-connection edit. The shared
		// Weights value is only read.
		uConn, err = buildRandomizedRealityConn(conn, uConfig, e.uClient.id)
	} else {
		uConn = utls.UClient(conn, uConfig, e.uClient.id)
		err = ensureRealityX25519MLKEM(uConn, realityKeyPoolFor(uConfig))
	}
	if err != nil {
		return nil, err
	}
	verifier.UConn = uConn

	if len(uConfig.NextProtos) > 0 {
		for _, extension := range uConn.Extensions {
			if alpnExtension, isALPN := extension.(*utls.ALPNExtension); isALPN {
				alpnExtension.AlpnProtocols = uConfig.NextProtos
				break
			}
		}
	}

	hello := uConn.HandshakeState.Hello
	hello.SessionId = make([]byte, 32)
	copy(hello.Raw[39:], hello.SessionId)

	var nowTime time.Time
	if uConfig.Time != nil {
		nowTime = uConfig.Time()
	} else {
		nowTime = time.Now()
	}
	binary.BigEndian.PutUint64(hello.SessionId, uint64(nowTime.Unix()))

	// Xray-core since v26.7.11 defaults minClientVer to 26.3.27 when the
	// field is unset (af7eb680). Xray's own client writes core.Version_*
	// here; advertise 26.10.31, matching the latest Xray release, so
	// servers with that default, or with minClientVer up to 26.10.31,
	// accept the handshake.
	// SessionId[3] is reserved and stays 0.
	hello.SessionId[0] = 26
	hello.SessionId[1] = 10
	hello.SessionId[2] = 31
	hello.SessionId[3] = 0
	binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(time.Now().Unix()))
	copy(hello.SessionId[8:], e.shortID[:])
	if debug.Enabled {
		fmt.Printf("REALITY hello.sessionId[:16]: %v\n", hello.SessionId[:16])
	}
	publicKey, err := ecdh.X25519().NewPublicKey(e.publicKey)
	if err != nil {
		return nil, err
	}
	keyShareKeys := uConn.HandshakeState.State13.KeyShareKeys
	if keyShareKeys == nil {
		return nil, E.New("nil KeyShareKeys")
	}
	ecdheKey := keyShareKeys.Ecdhe
	if ecdheKey == nil {
		return nil, E.New("nil ecdheKey")
	}
	authKey, err := ecdheKey.ECDH(publicKey)
	if err != nil {
		return nil, err
	}
	if authKey == nil {
		return nil, E.New("nil auth_key")
	}
	verifier.authKey = authKey
	_, err = hkdf.New(sha256.New, authKey, hello.Random[:20], []byte("REALITY")).Read(authKey)
	if err != nil {
		return nil, err
	}
	aesBlock, _ := aes.NewCipher(authKey)
	aesGcmCipher, _ := cipher.NewGCM(aesBlock)
	aesGcmCipher.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
	copy(hello.Raw[39:], hello.SessionId)
	if debug.Enabled {
		fmt.Printf("REALITY hello.sessionId: %v\n", hello.SessionId)
		fmt.Printf("REALITY uConn.AuthKey: %v\n", authKey)
	}

	err = uConn.HandshakeContext(ctx)
	if err != nil {
		return nil, err
	}

	if debug.Enabled {
		fmt.Printf("REALITY Conn.Verified: %v\n", verifier.verified)
	}

	if !verifier.verified {
		go realityClientFallback(e.ctx, uConn, e.uClient.ServerName(), e.uClient.id)
		return nil, E.New("reality verification failed")
	}

	return &realityClientConnWrapper{uConn}, nil
}

// ensureRealityX25519MLKEM makes a ClientHello acceptable to Xray-core
// v26.9.8+, which rejects a hello that does not list an X25519MLKEM768 key
// share before X25519.
//
// Fingerprints that already send both (chrome) are built unchanged. Fingerprints
// that send an X25519 key share but no hybrid share (firefox, safari, ios,
// edge, qq) get the group and an empty key share inserted immediately before
// X25519, then uTLS ApplyPreset fills the private keys. GREASE stays where the
// template put it. A secp256r1 key share is kept when the template sends one
// (Firefox 120). randomized is handled separately and does not keep that share.
//
// android and 360 have no X25519 key share. Inserting a hybrid share there
// would not give the server an X25519 peer key that matches KeyShareKeys.Ecdhe,
// and those fingerprints already fail against older Xray. They are left as-is,
// aside from dropping an incomplete hybrid pair if one ever appears.
//
// When pool is not nil, the X25519MLKEM768 and X25519 keys come from it
// instead of being generated inside ApplyPreset.
func ensureRealityX25519MLKEM(uConn *utls.UConn, pool *realityKeyPool) error {
	spec, err := utls.UTLSIdToSpec(uConn.ClientHelloID)
	if err != nil || !specHasX25519Anchor(&spec) {
		if err := uConn.BuildHandshakeState(); err != nil {
			return err
		}
		return stripUnpairedX25519MLKEM(uConn)
	}
	insertMLKEMIntoSpec(&spec)
	// HelloCustom + ApplyPreset is the supported way to send a modified spec.
	// ApplyPreset generates the X25519 and X25519MLKEM768 private keys. It is
	// also used when the spec is unchanged (chrome): BuildHandshakeState on
	// the original ID would build and shuffle the same spec a second time.
	uConn.ClientHelloID = utls.HelloCustom
	if err := applyRealitySpec(uConn, &spec, pool); err != nil {
		return err
	}
	return uConn.BuildHandshakeState()
}

// realityKeyPoolFor returns the shared key pool, or nil when the config
// supplies its own randomness source, which ApplyPreset must keep using.
func realityKeyPoolFor(config *utls.Config) *realityKeyPool {
	if config.Rand != nil {
		return nil
	}
	return realityKeys
}

// applyRealitySpec is ApplyPreset with the X25519MLKEM768 and X25519 keys
// taken from pool when the spec's key shares allow it.
func applyRealitySpec(uConn *utls.UConn, spec *utls.ClientHelloSpec, pool *realityKeyPool) error {
	var shares *utls.KeyShareExtension
	for _, extension := range spec.Extensions {
		if ext, ok := extension.(*utls.KeyShareExtension); ok {
			shares = ext
		}
	}
	var keys *realityHelloKeys
	if pool != nil && shares != nil && canFillRealityKeyShares(shares.KeyShares) {
		var err error
		keys, err = pool.take()
		if err != nil {
			return err
		}
		fillRealityKeyShares(shares.KeyShares, keys)
	}
	if err := uConn.ApplyPreset(spec); err != nil {
		return err
	}
	if keys != nil {
		installRealityKeys(uConn, keys)
	}
	return nil
}

func realityIsRandomized(id utls.ClientHelloID) bool {
	switch id.Client {
	case "Randomized", "Randomized-ALPN", "Randomized-NoALPN":
		return true
	default:
		return false
	}
}

// buildRandomizedRealityConn lets uTLS randomize with the caller's weights,
// then rewrites only this connection's hello. supported_groups keeps every
// group the randomizer chose, including P256. key_share is X25519MLKEM768
// immediately before X25519, plus any GREASE share. A secp256r1 key share is
// removed; that group stays in supported_groups only.
func buildRandomizedRealityConn(conn net.Conn, config *utls.Config, id utls.ClientHelloID) (*utls.UConn, error) {
	uConn := utls.UClient(conn, config, id)
	if err := uConn.BuildHandshakeState(); err != nil {
		return nil, err
	}
	needKey, err := normalizeBuiltRandomizedHello(uConn)
	if err != nil {
		return nil, err
	}
	if !needKey {
		if err := uConn.BuildHandshakeState(); err != nil {
			return nil, err
		}
		return uConn, nil
	}
	clearNonGREASEKeyShareData(uConn)
	spec := &utls.ClientHelloSpec{
		CipherSuites:       append([]uint16(nil), uConn.HandshakeState.Hello.CipherSuites...),
		CompressionMethods: append([]byte(nil), uConn.HandshakeState.Hello.CompressionMethods...),
		Extensions:         uConn.Extensions,
	}
	fresh := utls.UClient(conn, config, utls.HelloCustom)
	if err := applyRealitySpec(fresh, spec, realityKeyPoolFor(config)); err != nil {
		return nil, err
	}
	if err := fresh.BuildHandshakeState(); err != nil {
		return nil, err
	}
	return fresh, nil
}

// normalizeBuiltRandomizedHello returns true when the MLKEM share has no
// private key yet and ApplyPreset must generate one.
func normalizeBuiltRandomizedHello(uConn *utls.UConn) (bool, error) {
	var curves *utls.SupportedCurvesExtension
	var shares *utls.KeyShareExtension
	for _, extension := range uConn.Extensions {
		switch ext := extension.(type) {
		case *utls.SupportedCurvesExtension:
			curves = ext
		case *utls.KeyShareExtension:
			shares = ext
		}
	}
	if curves == nil || shares == nil || !common.Contains(curves.Curves, utls.X25519) {
		return false, E.New("randomized REALITY hello has no X25519 group")
	}
	nextCurves, _ := placeCurveBefore(curves.Curves, utls.X25519MLKEM768, utls.X25519)
	curves.Curves = nextCurves
	kept := make([]utls.KeyShare, 0, 3)
	var x25519 *utls.KeyShare
	var mlkem *utls.KeyShare
	for _, share := range shares.KeyShares {
		switch {
		case realityIsGREASE(uint16(share.Group)):
			kept = append(kept, share)
		case share.Group == utls.X25519:
			cp := share
			x25519 = &cp
		case share.Group == utls.X25519MLKEM768:
			cp := share
			mlkem = &cp
		}
	}
	if x25519 == nil {
		return false, E.New("randomized REALITY hello has no X25519 key share")
	}
	needKey := mlkem == nil || len(mlkem.Data) != utlsmlkem.EncapsulationKeySize768+32
	if mlkem != nil && !needKey {
		kept = append(kept, *mlkem)
	} else {
		kept = append(kept, utls.KeyShare{Group: utls.X25519MLKEM768})
	}
	kept = append(kept, *x25519)
	shares.KeyShares = kept
	return needKey, nil
}

func clearNonGREASEKeyShareData(uConn *utls.UConn) {
	for _, extension := range uConn.Extensions {
		shares, ok := extension.(*utls.KeyShareExtension)
		if !ok {
			continue
		}
		for i := range shares.KeyShares {
			if realityIsGREASE(uint16(shares.KeyShares[i].Group)) {
				continue
			}
			shares.KeyShares[i].Data = nil
		}
	}
}

func realityIsGREASE(v uint16) bool {
	return v>>8 == v&0xff && v&0xf == 0xa
}

func specHasX25519Anchor(spec *utls.ClientHelloSpec) bool {
	var curves *utls.SupportedCurvesExtension
	var shares *utls.KeyShareExtension
	for _, extension := range spec.Extensions {
		switch ext := extension.(type) {
		case *utls.SupportedCurvesExtension:
			curves = ext
		case *utls.KeyShareExtension:
			shares = ext
		}
	}
	return curves != nil && shares != nil &&
		common.Contains(curves.Curves, utls.X25519) &&
		common.Any(shares.KeyShares, func(share utls.KeyShare) bool {
			return share.Group == utls.X25519
		})
}

func insertMLKEMIntoSpec(spec *utls.ClientHelloSpec) bool {
	var curves *utls.SupportedCurvesExtension
	var shares *utls.KeyShareExtension
	for _, extension := range spec.Extensions {
		switch ext := extension.(type) {
		case *utls.SupportedCurvesExtension:
			curves = ext
		case *utls.KeyShareExtension:
			shares = ext
		}
	}
	if curves == nil || shares == nil {
		return false
	}
	nextCurves, curvesChanged := placeCurveBefore(curves.Curves, utls.X25519MLKEM768, utls.X25519)
	nextShares, sharesChanged := placeShareBefore(shares.KeyShares, utls.X25519MLKEM768, utls.X25519)
	if curvesChanged {
		curves.Curves = nextCurves
	}
	if sharesChanged {
		shares.KeyShares = nextShares
	}
	return curvesChanged || sharesChanged
}

func stripUnpairedX25519MLKEM(uConn *utls.UConn) error {
	var mlkemCurve, mlkemKeyShare bool
	for _, extension := range uConn.Extensions {
		switch ext := extension.(type) {
		case *utls.SupportedCurvesExtension:
			mlkemCurve = common.Contains(ext.Curves, utls.X25519MLKEM768)
		case *utls.KeyShareExtension:
			mlkemKeyShare = common.Any(ext.KeyShares, func(share utls.KeyShare) bool {
				return share.Group == utls.X25519MLKEM768
			})
		}
	}
	if mlkemCurve == mlkemKeyShare {
		return nil
	}
	for _, extension := range uConn.Extensions {
		if ce, ok := extension.(*utls.SupportedCurvesExtension); ok {
			ce.Curves = common.Filter(ce.Curves, func(curveID utls.CurveID) bool {
				return curveID != utls.X25519MLKEM768
			})
		}
		if ks, ok := extension.(*utls.KeyShareExtension); ok {
			ks.KeyShares = common.Filter(ks.KeyShares, func(share utls.KeyShare) bool {
				return share.Group != utls.X25519MLKEM768
			})
		}
	}
	return uConn.BuildHandshakeState()
}

func placeCurveBefore(curves []utls.CurveID, curve, anchor utls.CurveID) ([]utls.CurveID, bool) {
	if realityIDBefore(curves, curve, anchor) {
		return curves, false
	}
	filtered := make([]utls.CurveID, 0, len(curves))
	for _, id := range curves {
		if id != curve {
			filtered = append(filtered, id)
		}
	}
	anchorAt := -1
	for i, id := range filtered {
		if id == anchor {
			anchorAt = i
			break
		}
	}
	if anchorAt < 0 {
		return curves, false
	}
	out := make([]utls.CurveID, 0, len(filtered)+1)
	out = append(out, filtered[:anchorAt]...)
	out = append(out, curve)
	out = append(out, filtered[anchorAt:]...)
	return out, true
}

func placeShareBefore(shares []utls.KeyShare, group, anchor utls.CurveID) ([]utls.KeyShare, bool) {
	groups := make([]utls.CurveID, len(shares))
	for i, share := range shares {
		groups[i] = share.Group
	}
	if realityIDBefore(groups, group, anchor) {
		return shares, false
	}
	filtered := make([]utls.KeyShare, 0, len(shares))
	for _, share := range shares {
		if share.Group != group {
			filtered = append(filtered, share)
		}
	}
	anchorAt := -1
	for i, share := range filtered {
		if share.Group == anchor {
			anchorAt = i
			break
		}
	}
	if anchorAt < 0 {
		return shares, false
	}
	out := make([]utls.KeyShare, 0, len(filtered)+1)
	out = append(out, filtered[:anchorAt]...)
	out = append(out, utls.KeyShare{Group: group})
	out = append(out, filtered[anchorAt:]...)
	return out, true
}

func realityIDBefore(ids []utls.CurveID, id, anchor utls.CurveID) bool {
	idAt, anchorAt := -1, -1
	for i, item := range ids {
		if item == id && idAt < 0 {
			idAt = i
		}
		if item == anchor && anchorAt < 0 {
			anchorAt = i
		}
	}
	return idAt >= 0 && anchorAt >= 0 && idAt < anchorAt
}

// realityFallbackUserAgent is the User-Agent of the fallback request to the
// dest site. Every randomized preset sends "Randomized", the label stock
// sing-box sends, so switching the preset to HelloRandomizedALPN does not
// show up in the dest's request logs.
func realityFallbackUserAgent(fingerprint utls.ClientHelloID) string {
	if realityIsRandomized(fingerprint) {
		return "Randomized"
	}
	return fingerprint.Client
}

func realityClientFallback(ctx context.Context, uConn net.Conn, serverName string, fingerprint utls.ClientHelloID) {
	defer uConn.Close()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if deadline, ok := ctx.Deadline(); ok {
		_ = uConn.SetDeadline(deadline)
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, config *tls.Config) (net.Conn, error) {
				return uConn, nil
			},
			TLSClientConfig: &tls.Config{
				Time:    ntp.TimeFuncFromContext(ctx),
				RootCAs: adapter.RootPoolFromContext(ctx),
			},
		},
	}
	request, err := http.NewRequestWithContext(ctx, "GET", "https://"+serverName, nil)
	if err != nil {
		return
	}
	request.Header.Set("User-Agent", realityFallbackUserAgent(fingerprint))
	request.AddCookie(&http.Cookie{Name: "padding", Value: strings.Repeat("0", mRand.Intn(32)+30)})
	response, err := client.Do(request)
	if err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
}

func (e *RealityClientConfig) Clone() Config {
	return &RealityClientConfig{
		e.ctx,
		e.uClient.Clone().(*UTLSClientConfig),
		e.publicKey,
		e.shortID,
	}
}

type realityVerifier struct {
	*utls.UConn
	serverName string
	authKey    []byte
	verified   bool
}

func (c *realityVerifier) VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	p, _ := reflect.TypeOf(c.Conn).Elem().FieldByName("peerCertificates")
	certs := *(*([]*x509.Certificate))(unsafe.Pointer(uintptr(unsafe.Pointer(c.Conn)) + p.Offset))
	if pub, ok := certs[0].PublicKey.(ed25519.PublicKey); ok {
		h := hmac.New(sha512.New, c.authKey)
		h.Write(pub)
		if bytes.Equal(h.Sum(nil), certs[0].Signature) {
			c.verified = true
			return nil
		}
	}
	opts := x509.VerifyOptions{
		DNSName:       c.serverName,
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return err
	}
	return nil
}

type realityClientConnWrapper struct {
	*utls.UConn
}

func (c *realityClientConnWrapper) ConnectionState() tls.ConnectionState {
	state := c.Conn.ConnectionState()
	//nolint:staticcheck
	return tls.ConnectionState{
		Version:                     state.Version,
		HandshakeComplete:           state.HandshakeComplete,
		DidResume:                   state.DidResume,
		CipherSuite:                 state.CipherSuite,
		NegotiatedProtocol:          state.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  state.NegotiatedProtocolIsMutual,
		ServerName:                  state.ServerName,
		PeerCertificates:            state.PeerCertificates,
		VerifiedChains:              state.VerifiedChains,
		SignedCertificateTimestamps: state.SignedCertificateTimestamps,
		OCSPResponse:                state.OCSPResponse,
		TLSUnique:                   state.TLSUnique,
	}
}

func (c *realityClientConnWrapper) Upstream() any {
	return c.UConn
}

// Due to low implementation quality, the reality server intercepted half close and caused memory leaks.
// We fixed it by calling Close() directly.
func (c *realityClientConnWrapper) CloseWrite() error {
	return c.Close()
}

func (c *realityClientConnWrapper) ReaderReplaceable() bool {
	return true
}

func (c *realityClientConnWrapper) WriterReplaceable() bool {
	return true
}
