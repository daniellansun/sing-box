package v2rayhttpupgrade

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type trackConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *trackConn) Close() error {
	c.closed.Store(true)
	if c.Conn != nil {
		return c.Conn.Close()
	}
	return nil
}

type stubDialer struct{ conn net.Conn }

func (d *stubDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return d.conn, nil
}
func (d *stubDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

func TestDialClosesConnWhenUpgradeWriteFails(t *testing.T) {
	left, right := net.Pipe()
	right.Close()
	tracked := &trackConn{Conn: left}
	client := &Client{
		dialer:     &stubDialer{conn: tracked},
		serverAddr: M.ParseSocksaddr("127.0.0.1:1"),
		requestURL: url.URL{Scheme: "http", Host: "example.com", Path: "/"},
		headers:    make(http.Header),
		host:       "example.com",
	}
	_, err := client.DialContext(context.Background())
	if err == nil {
		t.Fatal("expected write error")
	}
	if !tracked.closed.Load() {
		t.Fatal("connection was not closed")
	}
}

var _ N.Dialer = (*stubDialer)(nil)
