//go:build with_utls

package tls

import (
	"bytes"
	"errors"
	"net"
	"runtime/pprof"
	"strings"
	"sync"
	"testing"
	"time"

	utls "github.com/metacubex/utls"
	utlsmlkem "github.com/metacubex/utls/mlkem"
	"github.com/stretchr/testify/require"
)

func waitRealityPoolIdle(t *testing.T, pool *realityKeyPool) {
	t.Helper()
	require.Eventually(t, func() bool { return !pool.refilling.Load() }, 5*time.Second, time.Millisecond)
}

func TestRealityKeyPoolBoundedAndSingleUse(t *testing.T) {
	pool := newRealityKeyPool(3, newRealityHelloKeys)
	seen := make(map[string]bool)
	for i := 0; i < 20; i++ {
		keys, err := pool.take()
		require.NoError(t, err)
		pool.refill()
		for _, share := range [][]byte{keys.x25519Share, keys.hybridShare} {
			require.False(t, seen[string(share)], "key material handed out twice")
			seen[string(share)] = true
		}
		require.LessOrEqual(t, len(pool.keys), 3)
	}
	waitRealityPoolIdle(t, pool)
	require.Len(t, pool.keys, 3)
}

func TestRealityKeyPoolGeneratesInlineWhenEmpty(t *testing.T) {
	block := make(chan struct{})
	var calls int
	var mu sync.Mutex
	pool := newRealityKeyPool(2, func() (*realityHelloKeys, error) {
		mu.Lock()
		calls++
		first := calls == 1
		mu.Unlock()
		if !first {
			<-block // stall the background refill
		}
		return newRealityHelloKeys()
	})
	keys, err := pool.take()
	require.NoError(t, err)
	require.NotNil(t, keys)
	pool.refill()
	close(block)
	waitRealityPoolIdle(t, pool)
}

func TestRealityKeyPoolGenerateError(t *testing.T) {
	errGenerate := errors.New("no entropy")
	pool := newRealityKeyPool(2, func() (*realityHelloKeys, error) { return nil, errGenerate })
	_, err := pool.take()
	require.ErrorIs(t, err, errGenerate)
	pool.refill()
	waitRealityPoolIdle(t, pool)
	require.Empty(t, pool.keys)
}

func realityFillGoroutines() int {
	var buf bytes.Buffer
	_ = pprof.Lookup("goroutine").WriteTo(&buf, 2)
	return strings.Count(buf.String(), "(*realityKeyPool).fill(")
}

func TestRealityKeyPoolNoGoroutineLeak(t *testing.T) {
	pool := newRealityKeyPool(4, newRealityHelloKeys)
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := pool.take()
			require.NoError(t, err)
			pool.refill()
		}()
	}
	wg.Wait()
	waitRealityPoolIdle(t, pool)
	waitRealityPoolIdle(t, realityKeys)
	require.Eventually(t, func() bool { return realityFillGoroutines() == 0 }, 5*time.Second, 5*time.Millisecond)
	require.Len(t, pool.keys, 4)
}

func TestRealityKeyPoolDropsStaleKeys(t *testing.T) {
	pool := newRealityKeyPool(2, newRealityHelloKeys)
	stale, err := newRealityHelloKeys()
	require.NoError(t, err)
	stale.created = stale.created.Add(-2 * realityKeyMaxAge)
	pool.keys <- stale
	keys, err := pool.take()
	require.NoError(t, err)
	require.NotSame(t, stale, keys)
	require.Empty(t, pool.keys)

	fresh, err := newRealityHelloKeys()
	require.NoError(t, err)
	now := fresh.created
	require.True(t, fresh.fresh(now))
	require.False(t, fresh.fresh(now.Add(realityKeyMaxAge)))
	// Wall clock moved on (device suspended) while the monotonic clock did not.
	require.False(t, fresh.fresh(now.Round(0).Add(realityKeyMaxAge)))
}

func TestRealityKeyAgeFreshClockRollback(t *testing.T) {
	ok := time.Second
	cases := []struct {
		name            string
		monotonic, wall time.Duration
		want            bool
	}{
		{"both clocks forward", ok, ok, true},
		{"same instant", 0, 0, true},
		{"wall rollback under max age", ok, -time.Second, false},
		{"wall rollback of 1ns", ok, -time.Nanosecond, false},
		{"wall rollback over max age", ok, -2 * realityKeyMaxAge, false},
		{"wall jump past max age (suspend)", ok, realityKeyMaxAge, false},
		{"monotonic past max age", realityKeyMaxAge, ok, false},
		{"monotonic backwards", -time.Second, ok, false},
	}
	for _, c := range cases {
		require.Equal(t, c.want, realityKeyAgeFresh(c.monotonic, c.wall), c.name)
	}
	// Through fresh(): a wall-only "now" earlier than creation is expired.
	keys, err := newRealityHelloKeys()
	require.NoError(t, err)
	require.False(t, keys.fresh(keys.created.Round(0).Add(-time.Second)))
	require.False(t, keys.fresh(keys.created.Round(0).Add(-2*realityKeyMaxAge)))
}

// The private keys uTLS will use must belong to the shares on the wire, and
// the hybrid share must carry its own X25519 key, like Chrome.
func TestRealityPooledKeysMatchHello(t *testing.T) {
	for _, fingerprint := range []string{"chrome", "firefox", "safari", "ios", "edge", "qq", "randomized"} {
		t.Run(fingerprint, func(t *testing.T) {
			for i := 0; i < 8; i++ {
				config, _ := newRealityHelloClient(t, fingerprint)
				client, server := net.Pipe()
				uConfig := config.uClient.config.Clone()
				var uConn *utls.UConn
				var err error
				if realityIsRandomized(config.uClient.id) {
					uConn, err = buildRandomizedRealityConn(client, uConfig, config.uClient.id)
				} else {
					uConn = utls.UClient(client, uConfig, config.uClient.id)
					err = ensureRealityX25519MLKEM(uConn, realityKeys)
				}
				require.NoError(t, err)
				hello := utls.UnmarshalClientHello(uConn.HandshakeState.Hello.Raw)
				require.NotNil(t, hello)
				keys := uConn.HandshakeState.State13.KeyShareKeys
				x25519 := hello.KeyShares[realityKeyShareIndex(hello, utls.X25519)].Data
				hybrid := hello.KeyShares[realityKeyShareIndex(hello, utls.X25519MLKEM768)].Data
				require.Equal(t, x25519, keys.Ecdhe.PublicKey().Bytes())
				require.Equal(t, hybrid[utlsmlkem.EncapsulationKeySize768:], keys.MlkemEcdhe.PublicKey().Bytes())
				require.Equal(t, hybrid[:utlsmlkem.EncapsulationKeySize768], keys.Mlkem.EncapsulationKey().Bytes())
				require.False(t, bytes.Equal(x25519, hybrid[utlsmlkem.EncapsulationKeySize768:]), "X25519 key reused in hybrid share")
				_ = client.Close()
				_ = server.Close()
			}
		})
	}
}

func TestRealityCanFillKeyShares(t *testing.T) {
	grease := utls.CurveID(utls.GREASE_PLACEHOLDER)
	cases := []struct {
		shares []utls.KeyShare
		want   bool
	}{
		{[]utls.KeyShare{{Group: grease, Data: []byte{0}}, {Group: utls.X25519MLKEM768}, {Group: utls.X25519}}, true},
		{[]utls.KeyShare{{Group: utls.X25519MLKEM768}, {Group: utls.X25519}, {Group: utls.CurveP256}}, true},
		{[]utls.KeyShare{{Group: utls.CurveP256}, {Group: utls.X25519MLKEM768}, {Group: utls.X25519}}, false},
		{[]utls.KeyShare{{Group: utls.X25519}}, false},
		{[]utls.KeyShare{{Group: utls.X25519MLKEM768}}, false},
		{[]utls.KeyShare{{Group: utls.X25519MLKEM768}, {Group: utls.X25519, Data: make([]byte, 32)}}, false},
		{[]utls.KeyShare{{Group: utls.X25519MLKEM768}, {Group: utls.X25519}, {Group: utls.X25519}}, false},
	}
	for i, c := range cases {
		require.Equal(t, c.want, canFillRealityKeyShares(c.shares), "case %d", i)
	}
}
