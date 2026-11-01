package vless

import (
	"context"
	"net"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/log"
	singvless "github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type trackConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *trackConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

type stubDialer struct {
	conn net.Conn
}

func (d *stubDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return d.conn, nil
}

func (d *stubDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

func TestVisionWithoutTLSClosesConn(t *testing.T) {
	left, right := net.Pipe()
	right.Close()
	tracked := &trackConn{Conn: left}
	h := &Outbound{
		logger: logger.NOP().(log.ContextLogger),
		dialer: &stubDialer{conn: tracked},
		vision: true,
	}
	_, err := (*vlessDialer)(h).DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("1.1.1.1:80"))
	if err == nil {
		t.Fatal("expected vision error")
	}
	if !tracked.closed.Load() {
		t.Fatal("dial connection was not closed")
	}
}

func TestPacketAddrDomainClosesConn(t *testing.T) {
	left, right := net.Pipe()
	right.Close()
	tracked := &trackConn{Conn: left}
	client, err := singvless.NewClient("b3b8e2c4-8f0a-4d3e-9c1a-6e5d4c3b2a19", "", logger.NOP())
	if err != nil {
		t.Fatal(err)
	}
	h := &Outbound{
		logger:     logger.NOP().(log.ContextLogger),
		dialer:     &stubDialer{conn: tracked},
		client:     client,
		packetAddr: true,
	}
	_, err = (*vlessDialer)(h).ListenPacket(context.Background(), M.ParseSocksaddr("example.com:53"))
	if err == nil {
		t.Fatal("expected packetaddr error")
	}
	if !tracked.closed.Load() {
		t.Fatal("dial connection was not closed")
	}
}
