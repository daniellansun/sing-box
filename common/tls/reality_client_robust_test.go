//go:build with_utls

package tls

import (
	"bytes"
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
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"

	utls "github.com/metacubex/utls"
	"github.com/metacubex/utls/mlkem"
	"golang.org/x/crypto/hkdf"
)

func TestRealityCancelledContextReturns(t *testing.T) {
	config, _ := newRealityHelloClient(t, "firefox")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- conn
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = config.ClientHandshake(ctx, conn)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("handshake succeeded against a peer that never reads")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("cancelled handshake took %s", elapsed)
	}
	select {
	case peer := <-accepted:
		peer.Close()
	default:
	}
	time.Sleep(50 * time.Millisecond)
}

func TestRealityParallelDials(t *testing.T) {
	fingerprints := []string{
		"chrome", "firefox", "safari", "ios", "edge", "qq",
		"random", "randomized", "android", "360",
	}
	configs := make(map[string]*RealityClientConfig, len(fingerprints))
	for _, fingerprint := range fingerprints {
		config, err := NewRealityClient(context.Background(), "example.com", option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: "example.com",
			UTLS:       &option.OutboundUTLSOptions{Enabled: true, Fingerprint: fingerprint},
			Reality: &option.OutboundRealityOptions{
				Enabled:   true,
				PublicKey: base64.RawURLEncoding.EncodeToString(mustX25519Public(t)),
				ShortID:   "0123456789abcdef",
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		configs[fingerprint] = config
	}

	const dials = 300
	runtime.GC()
	before := runtime.NumGoroutine()
	var wg sync.WaitGroup
	wg.Add(dials)
	for i := 0; i < dials; i++ {
		config := configs[fingerprints[i%len(fingerprints)]]
		go func() {
			defer wg.Done()
			client, server := net.Pipe()
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer server.Close()
				var header [5]byte
				_, err := io.ReadFull(server, header[:])
				if err != nil {
					return
				}
				_, _ = io.CopyN(io.Discard, server, int64(binary.BigEndian.Uint16(header[3:])))
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_, _ = config.ClientHandshake(ctx, client)
			cancel()
			_ = client.Close()
			<-done
		}()
	}
	wg.Wait()
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before+15 && time.Now().Before(deadline) {
		runtime.GC()
		time.Sleep(20 * time.Millisecond)
	}
	after := runtime.NumGoroutine()
	if after > before+15 {
		t.Fatalf("goroutines leaked: before %d after %d", before, after)
	}
}

func TestRealityParallelDialsDistinctHellos(t *testing.T) {
	config, serverKey := newRealityHelloClient(t, "firefox")
	const dials = 32
	var wg sync.WaitGroup
	errCh := make(chan error, dials)
	wg.Add(dials)
	for range dials {
		go func() {
			defer wg.Done()
			client, server := net.Pipe()
			defer client.Close()
			go func() {
				defer server.Close()
				header := make([]byte, 5)
				if _, err := io.ReadFull(server, header); err != nil {
					errCh <- err
					return
				}
				payload := make([]byte, binary.BigEndian.Uint16(header[3:]))
				if _, err := io.ReadFull(server, payload); err != nil {
					errCh <- err
					return
				}
				hello := utls.UnmarshalClientHello(payload)
				if hello == nil {
					errCh <- io.ErrUnexpectedEOF
					return
				}
				if err := checkMLKEMBeforeX25519(hello); err != nil {
					errCh <- err
					return
				}
				if err := decryptRealityShortID(serverKey, payload, hello); err != nil {
					errCh <- err
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, _ = config.ClientHandshake(ctx, client)
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func FuzzRealityRandomizedHello(f *testing.F) {
	f.Add(make([]byte, 32))
	f.Add([]byte("reality-mlkem-seed-padding-0123456789abcdef"))
	f.Fuzz(func(t *testing.T, seed []byte) {
		var prng utls.PRNGSeed
		if len(seed) > 0 {
			for i := range prng {
				prng[i] = seed[i%len(seed)]
			}
		}
		config, _ := newRealityHelloClient(t, "randomized")
		config.uClient.id.Seed = &prng
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		uConn := utls.UClient(client, config.uClient.config.Clone(), config.uClient.id)
		if err := ensureRealityX25519MLKEM(uConn, realityKeys); err != nil {
			t.Fatal(err)
		}
		hello := uConn.HandshakeState.Hello
		if hello == nil {
			t.Fatal(errBadHello)
		}
		if err := checkMLKEMBeforeX25519(hello); err != nil {
			t.Fatal(err)
		}
		keys := uConn.HandshakeState.State13.KeyShareKeys
		if keys == nil || keys.Ecdhe == nil || keys.Mlkem == nil || keys.MlkemEcdhe == nil {
			t.Fatal(errBadHello)
		}
		if len(hello.Raw) < 71 || len(hello.Random) < 32 {
			t.Fatal(errBadHello)
		}
	})
}

func mustX25519Public(t *testing.T) []byte {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key.PublicKey().Bytes()
}

func checkMLKEMBeforeX25519(hello *utls.PubClientHelloMsg) error {
	curveAt, anchorAt := -1, -1
	mlkemCount := 0
	for i, curve := range hello.SupportedCurves {
		switch curve {
		case utls.X25519MLKEM768:
			mlkemCount++
			if curveAt < 0 {
				curveAt = i
			}
		case utls.X25519:
			if anchorAt < 0 {
				anchorAt = i
			}
		}
	}
	if mlkemCount != 1 || curveAt < 0 || anchorAt < 0 || curveAt > anchorAt {
		return errBadHello
	}
	shareAt, xAt := -1, -1
	shareCount := 0
	for i, share := range hello.KeyShares {
		switch share.Group {
		case utls.X25519MLKEM768:
			shareCount++
			if shareAt < 0 {
				shareAt = i
			}
			if len(share.Data) != mlkem.EncapsulationKeySize768+32 {
				return errBadHello
			}
		case utls.X25519:
			if xAt < 0 {
				xAt = i
			}
			if len(share.Data) != 32 {
				return errBadHello
			}
		}
	}
	if shareCount != 1 || shareAt < 0 || xAt < 0 || shareAt > xAt {
		return errBadHello
	}
	return nil
}

func decryptRealityShortID(serverKey *ecdh.PrivateKey, message []byte, hello *utls.PubClientHelloMsg) error {
	xAt := -1
	for i, share := range hello.KeyShares {
		if share.Group == utls.X25519 {
			xAt = i
			break
		}
	}
	if xAt < 0 || len(hello.Random) < 32 || len(hello.SessionId) != 32 || len(message) < 71 {
		return errBadHello
	}
	peer, err := ecdh.X25519().NewPublicKey(hello.KeyShares[xAt].Data)
	if err != nil {
		return err
	}
	authKey, err := serverKey.ECDH(peer)
	if err != nil {
		return err
	}
	if _, err = hkdf.New(sha256.New, authKey, hello.Random[:20], []byte("REALITY")).Read(authKey); err != nil {
		return err
	}
	block, err := aes.NewCipher(authKey)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	additional := slices.Clone(message)
	clear(additional[39:71])
	plaintext, err := aead.Open(nil, hello.Random[20:], hello.SessionId, additional)
	if err != nil {
		return err
	}
	if !bytes.Equal(plaintext[8:16], []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}) {
		return errBadHello
	}
	return nil
}

var errBadHello = errString("reality client hello invariant failed")

type errString string

func (e errString) Error() string { return string(e) }
