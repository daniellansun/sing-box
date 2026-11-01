//go:build with_utls

package tls

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func BenchmarkRealityClientHello(b *testing.B) {
	for _, fingerprint := range []string{"chrome", "firefox", "safari", "ios", "edge", "qq", "randomized"} {
		b.Run(fingerprint, func(b *testing.B) {
			config, err := benchRealityConfig(fingerprint)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := benchOneHello(config); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func benchRealityConfig(fingerprint string) (*RealityClientConfig, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return NewRealityClient(context.Background(), "example.com", option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: "example.com",
		UTLS:       &option.OutboundUTLSOptions{Enabled: true, Fingerprint: fingerprint},
		Reality: &option.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()),
			ShortID:   "0123456789abcdef",
		},
	})
}

func benchOneHello(config *RealityClientConfig) error {
	client, server := net.Pipe()
	defer client.Close()
	errCh := make(chan error, 1)
	go func() {
		defer server.Close()
		var header [5]byte
		if _, err := io.ReadFull(server, header[:]); err != nil {
			errCh <- err
			return
		}
		_, err := io.CopyN(io.Discard, server, int64(binary.BigEndian.Uint16(header[3:])))
		errCh <- err
	}()
	_, _ = config.ClientHandshake(context.Background(), client)
	return <-errCh
}
