//go:build with_utls

package tls

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"slices"
	"testing"

	"github.com/sagernet/sing-box/option"

	utls "github.com/metacubex/utls"
	"github.com/metacubex/utls/mlkem"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/hkdf"
)

func newRealityHelloClient(t *testing.T, fingerprint string) (*RealityClientConfig, *ecdh.PrivateKey) {
	t.Helper()
	serverKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	config, err := NewRealityClient(context.Background(), "example.com", option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: "example.com",
		UTLS:       &option.OutboundUTLSOptions{Enabled: true, Fingerprint: fingerprint},
		Reality: &option.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: base64.RawURLEncoding.EncodeToString(serverKey.PublicKey().Bytes()),
			ShortID:   "0123456789abcdef",
		},
	})
	require.NoError(t, err)
	return config, serverKey
}

func readRealityClientHello(t *testing.T, config *RealityClientConfig) ([]byte, *utls.PubClientHelloMsg) {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })
	go func() {
		defer client.Close()
		_, _ = config.ClientHandshake(context.Background(), client)
	}()
	var header [5]byte
	_, err := io.ReadFull(server, header[:])
	require.NoError(t, err)
	require.Equal(t, byte(22), header[0])
	message := make([]byte, binary.BigEndian.Uint16(header[3:]))
	_, err = io.ReadFull(server, message)
	require.NoError(t, err)
	hello := utls.UnmarshalClientHello(message)
	require.NotNil(t, hello)
	return message, hello
}

func realityKeyShareIndex(hello *utls.PubClientHelloMsg, group utls.CurveID) int {
	return slices.IndexFunc(hello.KeyShares, func(share utls.KeyShare) bool {
		return share.Group == group
	})
}

// Xray-core since v26.9.8 rejects a chrome ClientHello that lacks an
// X25519MLKEM768 key share ahead of X25519. The session id stays sealed
// with the standalone X25519 share.
func TestRealityClientHelloChromeKeepsX25519MLKEM768(t *testing.T) {
	t.Parallel()
	config, serverKey := newRealityHelloClient(t, "chrome")
	message, hello := readRealityClientHello(t, config)

	assertRealitySession(t, serverKey, message, hello)
}

// Fixed fingerprints are the named uTLS templates sing-box ships, as opposed
// to random/randomized. readRealityClientHello unmarshals the ClientHello
// record ClientHandshake writes, not the raw uTLS spec. Xray-core v26.9.8+
// rejects that hello unless X25519MLKEM768 is present and listed before
// X25519, so a utls template that drops the share, or a revert of the
// insertion, fails this test.
func TestRealityClientHelloFixedFingerprintsOfferMLKEMBeforeX25519(t *testing.T) {
	t.Parallel()
	for _, fingerprint := range []string{"chrome", "firefox", "safari", "ios", "edge", "qq"} {
		t.Run(fingerprint, func(t *testing.T) {
			t.Parallel()
			config, serverKey := newRealityHelloClient(t, fingerprint)
			message, hello := readRealityClientHello(t, config)
			assertRealitySession(t, serverKey, message, hello)
		})
	}
}

func TestRealityClientHelloRandomOffersMLKEM(t *testing.T) {
	t.Parallel()
	config, serverKey := newRealityHelloClient(t, "random")
	message, hello := readRealityClientHello(t, config)
	assertRealitySession(t, serverKey, message, hello)
}

// randomized draws the hybrid group and its key share independently.
// Every seed must still offer both, with the share ahead of X25519.
func TestRealityClientHelloRandomizedAlwaysOffersMLKEM(t *testing.T) {
	t.Parallel()
	config, serverKey := newRealityHelloClient(t, "randomized")
	for range 20 {
		seed, err := utls.NewPRNGSeed()
		require.NoError(t, err)
		config.uClient.id.Seed = seed
		message, hello := readRealityClientHello(t, config)
		assertRealitySession(t, serverKey, message, hello)
	}
}

// android and 360 have no X25519 key share and already fail on old Xray.
// The hybrid share is not invented for them.
func TestRealityClientHelloLegacyFingerprintsStayUntouched(t *testing.T) {
	t.Parallel()
	for _, fingerprint := range []string{"android", "360"} {
		t.Run(fingerprint, func(t *testing.T) {
			t.Parallel()
			config, _ := newRealityHelloClient(t, fingerprint)
			spec, err := utls.UTLSIdToSpec(config.uClient.id)
			require.NoError(t, err)
			beforeCurves := append([]utls.CurveID(nil), specCurves(&spec)...)
			beforeShares := append([]utls.CurveID(nil), specShareGroups(&spec)...)
			client, server := net.Pipe()
			t.Cleanup(func() {
				_ = client.Close()
				_ = server.Close()
			})
			uConn := utls.UClient(client, config.uClient.config.Clone(), config.uClient.id)
			require.NoError(t, ensureRealityX25519MLKEM(uConn))
			require.Equal(t, beforeCurves, realityCurves(uConn))
			require.Equal(t, beforeShares, realityShareGroups(uConn))
			require.NotContains(t, realityCurves(uConn), utls.X25519MLKEM768)
			require.NotContains(t, realityShareGroups(uConn), utls.X25519MLKEM768)
			require.NotContains(t, realityShareGroups(uConn), utls.X25519)
		})
	}
}

func assertRealitySession(t *testing.T, serverKey *ecdh.PrivateKey, message []byte, hello *utls.PubClientHelloMsg) {
	t.Helper()
	curveIndex := slices.Index(hello.SupportedCurves, utls.X25519MLKEM768)
	x25519Curve := slices.Index(hello.SupportedCurves, utls.X25519)
	require.GreaterOrEqual(t, curveIndex, 0, "built ClientHello lacks X25519MLKEM768 group")
	require.GreaterOrEqual(t, x25519Curve, 0, "built ClientHello lacks X25519 group")
	require.Less(t, curveIndex, x25519Curve, "built ClientHello lists X25519MLKEM768 after X25519")
	mlkemIndex := realityKeyShareIndex(hello, utls.X25519MLKEM768)
	x25519Index := realityKeyShareIndex(hello, utls.X25519)
	require.GreaterOrEqual(t, mlkemIndex, 0, "built ClientHello lacks X25519MLKEM768 key share")
	require.GreaterOrEqual(t, x25519Index, 0, "built ClientHello lacks X25519 key share")
	require.Less(t, mlkemIndex, x25519Index, "built ClientHello lists X25519MLKEM768 key share after X25519")
	require.Len(t, hello.KeyShares[mlkemIndex].Data, mlkem.EncapsulationKeySize768+32)
	require.Len(t, hello.KeyShares[x25519Index].Data, 32)

	peerKey, err := ecdh.X25519().NewPublicKey(hello.KeyShares[x25519Index].Data)
	require.NoError(t, err)
	authKey, err := serverKey.ECDH(peerKey)
	require.NoError(t, err)
	_, err = hkdf.New(sha256.New, authKey, hello.Random[:20], []byte("REALITY")).Read(authKey)
	require.NoError(t, err)
	block, err := aes.NewCipher(authKey)
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)
	additional := slices.Clone(message)
	clear(additional[39:71])
	plaintext, err := aead.Open(nil, hello.Random[20:], hello.SessionId, additional)
	require.NoError(t, err)
	require.Equal(t, []byte{26, 3, 27, 0}, plaintext[:4])
	require.Equal(t, []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}, plaintext[8:16])
}

func TestRealityFingerprintKeepsMLKEMPrivateKey(t *testing.T) {
	t.Parallel()
	for _, fingerprint := range []string{"firefox", "qq", "randomized"} {
		t.Run(fingerprint, func(t *testing.T) {
			t.Parallel()
			config, _ := newRealityHelloClient(t, fingerprint)
			client, server := net.Pipe()
			t.Cleanup(func() {
				_ = client.Close()
				_ = server.Close()
			})
			uConn := utls.UClient(client, config.uClient.config.Clone(), config.uClient.id)
			require.NoError(t, ensureRealityX25519MLKEM(uConn))
			keys := uConn.HandshakeState.State13.KeyShareKeys
			require.NotNil(t, keys)
			require.NotNil(t, keys.Ecdhe)
			require.NotNil(t, keys.Mlkem)
			require.NotNil(t, keys.MlkemEcdhe)
			require.Len(t, keys.Ecdhe.PublicKey().Bytes(), 32)
		})
	}
}

func specCurves(spec *utls.ClientHelloSpec) []utls.CurveID {
	for _, extension := range spec.Extensions {
		if curves, ok := extension.(*utls.SupportedCurvesExtension); ok {
			return curves.Curves
		}
	}
	return nil
}

func specShareGroups(spec *utls.ClientHelloSpec) []utls.CurveID {
	for _, extension := range spec.Extensions {
		if shares, ok := extension.(*utls.KeyShareExtension); ok {
			groups := make([]utls.CurveID, len(shares.KeyShares))
			for i, share := range shares.KeyShares {
				groups[i] = share.Group
			}
			return groups
		}
	}
	return nil
}

func realityCurves(uConn *utls.UConn) []utls.CurveID {
	for _, extension := range uConn.Extensions {
		if curves, ok := extension.(*utls.SupportedCurvesExtension); ok {
			return curves.Curves
		}
	}
	return nil
}

func realityShareGroups(uConn *utls.UConn) []utls.CurveID {
	for _, extension := range uConn.Extensions {
		if shares, ok := extension.(*utls.KeyShareExtension); ok {
			groups := make([]utls.CurveID, len(shares.KeyShares))
			for i, share := range shares.KeyShares {
				groups[i] = share.Group
			}
			return groups
		}
	}
	return nil
}
