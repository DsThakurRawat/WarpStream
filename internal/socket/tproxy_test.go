package socket

import (
	"net"
	"testing"
)

type mockConn struct {
	net.Conn
	localAddr net.Addr
}

func (m *mockConn) LocalAddr() net.Addr { return m.localAddr }

func TestGetOriginalDst_FallbackToLocalAddr(t *testing.T) {
	addr, err := net.ResolveTCPAddr("tcp", "192.168.1.10:8080")
	if err != nil {
		t.Fatal(err)
	}
	conn := &mockConn{localAddr: addr}

	host, port, err := GetOriginalDst(conn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if host != "192.168.1.10" || port != 8080 {
		t.Errorf("got %s:%d, want 192.168.1.10:8080", host, port)
	}
}
