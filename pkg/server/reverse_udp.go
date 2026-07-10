package server

import (
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/DsThakurRawat/WarpStream/pkg/tunnel"
)

type udpSessionConn struct {
	udpConn *net.UDPConn
	peer    *net.UDPAddr
	ch      chan []byte
	closed  bool
	mu      sync.Mutex
	onClose func()
}

func newUdpSessionConn(udpConn *net.UDPConn, peer *net.UDPAddr, onClose func()) *udpSessionConn {
	return &udpSessionConn{
		udpConn: udpConn,
		peer:    peer,
		ch:      make(chan []byte, 128),
		onClose: onClose,
	}
}

func (u *udpSessionConn) push(data []byte) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	select {
	case u.ch <- cp:
	default:
		// drop packet if session buffer full
	}
}

func (u *udpSessionConn) Read(b []byte) (int, error) {
	data, ok := <-u.ch
	if !ok {
		return 0, io.EOF
	}
	n := copy(b, data)
	return n, nil
}

func (u *udpSessionConn) Write(b []byte) (int, error) {
	return u.udpConn.WriteToUDP(b, u.peer)
}

func (u *udpSessionConn) Close() error {
	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		return nil
	}
	u.closed = true
	close(u.ch)
	onClose := u.onClose
	u.mu.Unlock()
	if onClose != nil {
		onClose()
	}
	return nil
}

func (u *udpSessionConn) LocalAddr() net.Addr                { return u.udpConn.LocalAddr() }
func (u *udpSessionConn) RemoteAddr() net.Addr               { return u.peer }
func (u *udpSessionConn) SetDeadline(t time.Time) error      { return nil }
func (u *udpSessionConn) SetReadDeadline(t time.Time) error  { return nil }
func (u *udpSessionConn) SetWriteDeadline(t time.Time) error { return nil }

func (m *ReverseTunnelManager) runUdpListener(tl *tunnelListener, udpConn *net.UDPConn) {
	defer func() { _ = udpConn.Close() }()
	slog.Info("Reverse UDP tunnel listener started", "addr", tl.addr)

	sessions := make(map[string]*udpSessionConn)
	var mu sync.Mutex

	timeoutDuration := 30 * time.Second
	if tl.protocol.ReverseUdp != nil && tl.protocol.ReverseUdp.Timeout != nil && tl.protocol.ReverseUdp.Timeout.Secs > 0 {
		timeoutDuration = time.Duration(tl.protocol.ReverseUdp.Timeout.Secs) * time.Second
	}

	buf := make([]byte, 64*1024)
	for {
		n, peerAddr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			slog.Warn("Reverse UDP listener error", "addr", tl.addr, "err", err)
			m.closeTunnelListener(tl, false)
			m.mu.Lock()
			if current, ok := m.listeners[tl.addr]; ok && current == tl {
				delete(m.listeners, tl.addr)
			}
			m.mu.Unlock()
			return
		}

		mu.Lock()
		session, ok := sessions[peerAddr.String()]
		if !ok {
			peerKey := peerAddr.String()
			sess := newUdpSessionConn(udpConn, peerAddr, func() {
				mu.Lock()
				delete(sessions, peerKey)
				mu.Unlock()
			})
			sessions[peerKey] = sess
			session = sess

			wrapped := tunnel.NewIdleTimeoutNetConn(sess, timeoutDuration)
			m.beginIncoming(tl)
			go m.handleIncoming(tl, wrapped)
		}
		mu.Unlock()

		session.push(buf[:n])
	}
}
