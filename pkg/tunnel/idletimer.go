package tunnel

import (
	"io"
	"net"
	"sync"
	"time"
)

// IdleTimeoutConn wraps an io.ReadWriteCloser and closes it after
// a specified period of inactivity on either Read or Write.
type IdleTimeoutConn struct {
	io.ReadWriteCloser
	timeout time.Duration
	timer   *time.Timer
	mu      sync.Mutex
	closed  bool
}

// NewIdleTimeoutConn creates a new IdleTimeoutConn around rwc.
func NewIdleTimeoutConn(rwc io.ReadWriteCloser, timeout time.Duration) *IdleTimeoutConn {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	c := &IdleTimeoutConn{
		ReadWriteCloser: rwc,
		timeout:         timeout,
	}
	c.mu.Lock()
	c.timer = time.AfterFunc(timeout, func() {
		_ = c.Close()
	})
	c.mu.Unlock()
	return c
}

func (c *IdleTimeoutConn) touch() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed && c.timer != nil {
		c.timer.Reset(c.timeout)
	}
}

func (c *IdleTimeoutConn) Read(p []byte) (int, error) {
	n, err := c.ReadWriteCloser.Read(p)
	if n > 0 {
		c.touch()
	}
	return n, err
}

func (c *IdleTimeoutConn) Write(p []byte) (int, error) {
	n, err := c.ReadWriteCloser.Write(p)
	if n > 0 {
		c.touch()
	}
	return n, err
}

func (c *IdleTimeoutConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	if c.timer != nil {
		c.timer.Stop()
	}
	c.mu.Unlock()
	return c.ReadWriteCloser.Close()
}

type IdleTimeoutNetConn struct {
	net.Conn
	it *IdleTimeoutConn
}

// NewIdleTimeoutNetConn wraps a net.Conn with inactivity timeout while preserving net.Conn interface.
func NewIdleTimeoutNetConn(conn net.Conn, timeout time.Duration) net.Conn {
	return &IdleTimeoutNetConn{
		Conn: conn,
		it:   NewIdleTimeoutConn(conn, timeout),
	}
}

func (c *IdleTimeoutNetConn) Read(p []byte) (int, error) {
	return c.it.Read(p)
}

func (c *IdleTimeoutNetConn) Write(p []byte) (int, error) {
	return c.it.Write(p)
}

func (c *IdleTimeoutNetConn) Close() error {
	return c.it.Close()
}
