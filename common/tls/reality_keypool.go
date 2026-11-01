//go:build with_utls

package tls

import (
	"sync/atomic"
	"time"

	E "github.com/sagernet/sing/common/exceptions"

	utls "github.com/metacubex/utls"
	utlsmlkem "github.com/metacubex/utls/mlkem"
)

// realityKeyPoolSize bounds the pregenerated REALITY key material. One entry
// holds an expanded ML-KEM-768 decapsulation key (~8 KiB) and two X25519 keys.
const realityKeyPoolSize = 4

// realityKeyMaxAge bounds how long an unused entry may wait in the pool. take
// drops older entries, so keys are never held for long ahead of the hello
// that carries them.
const realityKeyMaxAge = 30 * time.Second

// realityHelloKeys is the ephemeral key material for a single ClientHello: the
// standalone X25519 share and the X25519MLKEM768 share. The hybrid share uses
// its own X25519 key, as Chrome (BoringSSL) and uTLS ApplyPreset do, so the
// last 32 bytes of the hybrid share never equal the X25519 share.
//
// An entry is handed to exactly one connection and never returned to the pool.
type realityHelloKeys struct {
	created     time.Time
	private     *utls.KeySharePrivateKeys // Ecdhe, Mlkem, MlkemEcdhe
	x25519Share []byte
	hybridShare []byte // ML-KEM-768 encapsulation key || X25519 public key
}

// newRealityHelloKeys lets uTLS ApplyPreset generate the keys, on a
// connectionless UConn, so they come from the same code and randomness
// (crypto/rand) as keys generated inline during a handshake.
func newRealityHelloKeys() (*realityHelloKeys, error) {
	shares := &utls.KeyShareExtension{KeyShares: []utls.KeyShare{
		{Group: utls.X25519MLKEM768},
		{Group: utls.X25519},
	}}
	uConn := utls.UClient(nil, &utls.Config{InsecureSkipVerify: true}, utls.HelloCustom)
	err := uConn.ApplyPreset(&utls.ClientHelloSpec{
		TLSVersMin: utls.VersionTLS13,
		TLSVersMax: utls.VersionTLS13,
		Extensions: []utls.TLSExtension{
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{utls.X25519MLKEM768, utls.X25519}},
			shares,
			&utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13}},
		},
	})
	if err != nil {
		return nil, err
	}
	private := uConn.HandshakeState.State13.KeyShareKeys
	hybridShare, x25519Share := shares.KeyShares[0].Data, shares.KeyShares[1].Data
	if private == nil || private.Ecdhe == nil || private.Mlkem == nil || private.MlkemEcdhe == nil ||
		len(hybridShare) != utlsmlkem.EncapsulationKeySize768+32 || len(x25519Share) != 32 {
		return nil, E.New("uTLS did not generate REALITY key shares")
	}
	return &realityHelloKeys{
		created: time.Now(),
		private: &utls.KeySharePrivateKeys{
			Ecdhe:      private.Ecdhe,
			Mlkem:      private.Mlkem,
			MlkemEcdhe: private.MlkemEcdhe,
		},
		x25519Share: x25519Share,
		hybridShare: hybridShare,
	}, nil
}

// realityKeyPool moves key generation off the handshake path. take never
// blocks: when the pool is empty it generates inline, exactly as uTLS would.
// refill is called once a handshake has finished, so generation overlaps the
// idle time between connections rather than the handshake that used the keys.
// It runs in at most one goroutine, which exits once the pool is full, so an
// idle process holds no goroutine and at most realityKeyPoolSize entries.
type realityKeyPool struct {
	keys      chan *realityHelloKeys
	refilling atomic.Bool
	generate  func() (*realityHelloKeys, error)
}

var realityKeys = newRealityKeyPool(realityKeyPoolSize, newRealityHelloKeys)

func newRealityKeyPool(size int, generate func() (*realityHelloKeys, error)) *realityKeyPool {
	return &realityKeyPool{keys: make(chan *realityHelloKeys, size), generate: generate}
}

func (p *realityKeyPool) take() (*realityHelloKeys, error) {
	for {
		select {
		case keys := <-p.keys:
			if keys.fresh(time.Now()) {
				return keys, nil
			}
		default:
			return p.generate()
		}
	}
}

// fresh checks the age on both clocks. The monotonic clock does not advance
// while Android or Linux is suspended; the wall clock does, so an entry made
// before a long sleep is dropped too.
func (k *realityHelloKeys) fresh(now time.Time) bool {
	monotonic := now.Sub(k.created)
	wall := now.Round(0).Sub(k.created.Round(0))
	return monotonic >= 0 && monotonic < realityKeyMaxAge && wall > -realityKeyMaxAge && wall < realityKeyMaxAge
}

func (p *realityKeyPool) refill() {
	if p.refilling.CompareAndSwap(false, true) {
		go p.fill()
	}
}

func (p *realityKeyPool) fill() {
	for {
		for len(p.keys) < cap(p.keys) {
			keys, err := p.generate()
			if err != nil {
				p.refilling.Store(false)
				return
			}
			select {
			case p.keys <- keys:
			default:
			}
		}
		p.refilling.Store(false)
		// A take that ran after the loop's last check saw refilling set and
		// did not start a fill; pick that slot up here.
		if len(p.keys) == cap(p.keys) || !p.refilling.CompareAndSwap(false, true) {
			return
		}
	}
}

// canFillRealityKeyShares reports whether shares has exactly one empty
// X25519MLKEM768 share and one empty X25519 share, with X25519 the first
// non-GREASE classic share. That X25519 key is the one uTLS itself stores as
// KeyShareKeys.Ecdhe, so installRealityKeys leaves the hello's semantics
// unchanged. Any other layout is left to ApplyPreset.
func canFillRealityKeyShares(shares []utls.KeyShare) bool {
	hybridAt, x25519At := -1, -1
	for i, share := range shares {
		switch {
		case realityIsGREASE(uint16(share.Group)):
		case share.Group == utls.X25519MLKEM768:
			if hybridAt >= 0 || len(share.Data) > 1 {
				return false
			}
			hybridAt = i
		case share.Group == utls.X25519:
			if x25519At >= 0 || len(share.Data) > 1 {
				return false
			}
			x25519At = i
		case x25519At < 0:
			return false
		}
	}
	return hybridAt >= 0 && x25519At >= 0
}

// fillRealityKeyShares writes the public keys into shares that passed
// canFillRealityKeyShares, so ApplyPreset does not generate them.
func fillRealityKeyShares(shares []utls.KeyShare, keys *realityHelloKeys) {
	for i := range shares {
		switch shares[i].Group {
		case utls.X25519MLKEM768:
			shares[i].Data = keys.hybridShare
		case utls.X25519:
			shares[i].Data = keys.x25519Share
		}
	}
}

// installRealityKeys stores the private keys behind shares filled by
// fillRealityKeyShares. Call it after ApplyPreset.
func installRealityKeys(uConn *utls.UConn, keys *realityHelloKeys) {
	keyShareKeys := uConn.HandshakeState.State13.KeyShareKeys
	keyShareKeys.Ecdhe = keys.private.Ecdhe
	keyShareKeys.Mlkem = keys.private.Mlkem
	keyShareKeys.MlkemEcdhe = keys.private.MlkemEcdhe
}
