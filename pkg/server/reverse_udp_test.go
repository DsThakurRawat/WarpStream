package server

import (
	"net"
	"sync/atomic"
	"testing"
)

func TestUdpSessionConn_PushAndRead(t *testing.T) {
	peerAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
	var closedCount int32
	sess := newUdpSessionConn(nil, peerAddr, func() {
		atomic.AddInt32(&closedCount, 1)
	})

	sess.push([]byte("hello udp"))

	buf := make([]byte, 100)
	n, err := sess.Read(buf)
	if err != nil {
		t.Fatalf("unexpected read error: %v", err)
	}
	if string(buf[:n]) != "hello udp" {
		t.Errorf("got %q, want 'hello udp'", string(buf[:n]))
	}

	_ = sess.Close()
	if atomic.LoadInt32(&closedCount) != 1 {
		t.Errorf("expected onClose callback to be called once, got %d", closedCount)
	}
}
