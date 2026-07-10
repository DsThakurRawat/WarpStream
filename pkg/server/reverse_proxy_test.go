package server

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

type dummyConn struct {
	io.Reader
	io.Writer
}

func (d *dummyConn) Close() error                       { return nil }
func (d *dummyConn) LocalAddr() net.Addr                { return nil }
func (d *dummyConn) RemoteAddr() net.Addr               { return nil }
func (d *dummyConn) SetDeadline(t time.Time) error      { return nil }
func (d *dummyConn) SetReadDeadline(t time.Time) error  { return nil }
func (d *dummyConn) SetWriteDeadline(t time.Time) error { return nil }

func TestReverseHttpProxyHandshake_Connect(t *testing.T) {
	reqData := "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\nhello world"
	outBuf := new(bytes.Buffer)
	dc := &dummyConn{
		Reader: bytes.NewReader([]byte(reqData)),
		Writer: outBuf,
	}

	mgr := NewReverseTunnelManager(0, 0)
	wrapped, host, port, err := mgr.handleHttpProxyHandshake(dc)
	if err != nil {
		t.Fatalf("handleHttpProxyHandshake unexpected err: %v", err)
	}

	if host != "example.com" || port != 443 {
		t.Errorf("got target %s:%d, want example.com:443", host, port)
	}

	// Verify response written to client
	if !bytes.Contains(outBuf.Bytes(), []byte("200 Connection Established")) {
		t.Errorf("expected 200 Connection Established response, got %q", outBuf.String())
	}

	// Verify leftover data is readable from wrapped connection
	leftover, err := io.ReadAll(wrapped)
	if err != nil && err != io.EOF {
		t.Fatalf("unexpected read error: %v", err)
	}
	if string(leftover) != "hello world" {
		t.Errorf("got leftover %q, want 'hello world'", string(leftover))
	}
}
