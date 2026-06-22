// Package client provides the client implementation for WarpStream.
// This test file provides extended test coverage for the client's authentication
// and proxy handlers, specifically testing constant time comparisons, HTTP proxy
// authentication edge cases, and robust SOCKS5 protocol handling and rejections.
package client

import (
	"encoding/base64"
	"io"
	"net"
	"testing"

	"github.com/divyansh-rawat/warpstream/pkg/protocol"
)

// TestConstantTimeEqualBytes tests the timing-safe byte comparison used for auth.
func TestConstantTimeEqualBytes(t *testing.T) {
	cases := []struct {
		name   string
		a, b   []byte
		expect bool
	}{
		{"equal", []byte("secret"), []byte("secret"), true},
		{"empty both", []byte{}, []byte{}, true},
		{"empty vs non-empty", []byte{}, []byte("x"), false},
		{"non-empty vs empty", []byte("x"), []byte{}, false},
		{"same length different", []byte("abcdef"), []byte("abcdeg"), false},
		{"prefix match shorter", []byte("sec"), []byte("secret"), false},
		{"prefix match longer", []byte("secret"), []byte("sec"), false},
		{"single byte match", []byte{0x42}, []byte{0x42}, true},
		{"single byte mismatch", []byte{0x42}, []byte{0x43}, false},
		{"binary data equal", []byte{0x00, 0xFF, 0xAB}, []byte{0x00, 0xFF, 0xAB}, true},
		{"binary data different", []byte{0x00, 0xFF, 0xAB}, []byte{0x00, 0xFF, 0xAC}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := constantTimeEqualBytes(tc.a, tc.b)
			if got != tc.expect {
				t.Errorf("constantTimeEqualBytes(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.expect)
			}
		})
	}
}

// TestAuthenticateHTTPProxyEdgeCases tests edge cases not covered by existing tests.
func TestAuthenticateHTTPProxyEdgeCases(t *testing.T) {
	creds := &protocol.Credentials{Username: "user", Password: "pass"}
	validHeader := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass"))

	t.Run("nil credentials always pass", func(t *testing.T) {
		if !authenticateHTTPProxy("anything", nil) {
			t.Error("expected nil credentials to allow any header")
		}
		if !authenticateHTTPProxy("", nil) {
			t.Error("expected nil credentials to allow empty header")
		}
	})

	t.Run("leading/trailing whitespace on header is trimmed", func(t *testing.T) {
		if !authenticateHTTPProxy("  "+validHeader+"  ", creds) {
			t.Error("expected trimmed header to be accepted")
		}
	})

	t.Run("colon in password", func(t *testing.T) {
		colonCreds := &protocol.Credentials{Username: "user", Password: "p:a:s:s"}
		h := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:p:a:s:s"))
		if !authenticateHTTPProxy(h, colonCreds) {
			t.Error("expected password with colons to be accepted")
		}
	})

	t.Run("empty password", func(t *testing.T) {
		emptyCreds := &protocol.Credentials{Username: "user", Password: ""}
		h := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:"))
		if !authenticateHTTPProxy(h, emptyCreds) {
			t.Error("expected empty password to be accepted")
		}
	})

	t.Run("malformed base64 rejected", func(t *testing.T) {
		if authenticateHTTPProxy("Basic not!!valid==base64", creds) {
			t.Error("expected malformed base64 to be rejected")
		}
	})

	t.Run("Digest scheme rejected", func(t *testing.T) {
		if authenticateHTTPProxy("Digest realm=\"test\"", creds) {
			t.Error("expected Digest scheme to be rejected")
		}
	})

	t.Run("only whitespace rejected", func(t *testing.T) {
		if authenticateHTTPProxy("   ", creds) {
			t.Error("expected whitespace-only header to be rejected")
		}
	})
}

// TestHandleSocks5NoAuthRequired tests SOCKS5 when no authentication is configured.
func TestHandleSocks5NoAuthRequired(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	c := &Client{}
	type result struct {
		host string
		port uint16
		err  error
	}
	resultCh := make(chan result, 1)
	go func() {
		host, port, err := c.handleSocks5(serverConn, nil) // no auth
		resultCh <- result{host, port, err}
	}()

	// Client sends: version=5, 1 method: no-auth (0x00)
	_, _ = clientConn.Write([]byte{0x05, 0x01, 0x00})

	// Server replies: chosen method = no-auth (0x00)
	reply := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, reply); err != nil {
		t.Fatalf("read method selection: %v", err)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("method selection = %v, want [5 0] (no auth)", reply)
	}

	// Send CONNECT request: target = 93.184.216.34:80 (IPv4)
	_, _ = clientConn.Write([]byte{
		0x05, 0x01, 0x00, 0x01, // VER CMD RSV ATYP=IPv4
		93, 184, 216, 34, // 93.184.216.34
		0x00, 0x50, // port 80
	})

	// Read success response (10 bytes)
	resp := make([]byte, 10)
	if _, err := io.ReadFull(clientConn, resp); err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp[1] != 0x00 {
		t.Fatalf("socks5 reply = %d, want 0 (success)", resp[1])
	}

	got := <-resultCh
	if got.err != nil {
		t.Fatalf("handleSocks5() error = %v", got.err)
	}
	if got.host != "93.184.216.34" {
		t.Errorf("host = %q, want 93.184.216.34", got.host)
	}
	if got.port != 80 {
		t.Errorf("port = %d, want 80", got.port)
	}
}

// TestHandleSocks5IPv6AddressType tests SOCKS5 with an IPv6 target address.
func TestHandleSocks5IPv6AddressType(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	c := &Client{}
	type result struct {
		host string
		port uint16
		err  error
	}
	resultCh := make(chan result, 1)
	go func() {
		host, port, err := c.handleSocks5(serverConn, nil)
		resultCh <- result{host, port, err}
	}()

	// Negotiate: no auth
	_, _ = clientConn.Write([]byte{0x05, 0x01, 0x00})
	reply := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, reply); err != nil {
		t.Fatalf("read method: %v", err)
	}

	// CONNECT to ::1 port 443 using ATYP=0x04 (IPv6)
	ipv6 := net.ParseIP("::1").To16()
	req := []byte{0x05, 0x01, 0x00, 0x04}
	req = append(req, ipv6...)
	req = append(req, 0x01, 0xBB) // port 443
	_, _ = clientConn.Write(req)

	resp := make([]byte, 10)
	if _, err := io.ReadFull(clientConn, resp); err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp[1] != 0x00 {
		t.Fatalf("socks5 reply = %d, want 0", resp[1])
	}

	got := <-resultCh
	if got.err != nil {
		t.Fatalf("handleSocks5() error = %v", got.err)
	}
	if got.host != "::1" {
		t.Errorf("host = %q, want ::1", got.host)
	}
	if got.port != 443 {
		t.Errorf("port = %d, want 443", got.port)
	}
}

// TestHandleSocks5RejectsUnsupportedCommand tests that non-CONNECT commands are rejected.
func TestHandleSocks5RejectsUnsupportedCommand(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()

	c := &Client{}
	errCh := make(chan error, 1)
	go func() {
		_, _, err := c.handleSocks5(serverConn, nil)
		errCh <- err
	}()

	// Negotiate: no auth
	_, _ = clientConn.Write([]byte{0x05, 0x01, 0x00})
	reply := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, reply); err != nil {
		_ = clientConn.Close()
		t.Fatalf("read method: %v", err)
	}

	// Send BIND command (0x02) instead of CONNECT (0x01).
	// Only send the 4-byte header; handleSocks5 returns an error as soon as it
	// sees cmd != 0x01, before reading the address bytes, so no extra data needed.
	_, _ = clientConn.Write([]byte{0x05, 0x02, 0x00, 0x01})

	// Drain any bytes the server tries to write back, then close.
	go func() {
		buf := make([]byte, 64)
		for {
			_, err := clientConn.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	if err := <-errCh; err == nil {
		_ = clientConn.Close()
		t.Fatal("handleSocks5() should have rejected BIND command")
	}
	_ = clientConn.Close()
}

// drainAndClose concurrently reads from conn until EOF, then closes it.
// This prevents net.Pipe writes from blocking when the other side isn't reading.
func drainAndClose(conn net.Conn) {
	go func() {
		buf := make([]byte, 64)
		for {
			_, err := conn.Read(buf)
			if err != nil {
				return
			}
		}
	}()
}

// TestHandleSocks5RejectsUnsupportedAddressType tests unknown ATYP bytes.
func TestHandleSocks5RejectsUnsupportedAddressType(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()
	defer func() { _ = clientConn.Close() }()

	c := &Client{}
	errCh := make(chan error, 1)
	go func() {
		_, _, err := c.handleSocks5(serverConn, nil)
		errCh <- err
	}()

	// Negotiate: no auth
	_, _ = clientConn.Write([]byte{0x05, 0x01, 0x00})
	reply := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, reply); err != nil {
		t.Fatalf("read method: %v", err)
	}

	// ATYP = 0x05 (unsupported)
	_, _ = clientConn.Write([]byte{0x05, 0x01, 0x00, 0x05})

	// Drain so the server goroutine isn't blocked writing an error response.
	drainAndClose(clientConn)

	if err := <-errCh; err == nil {
		t.Fatal("handleSocks5() should have rejected unsupported address type")
	}
}

// TestHandleSocks5RejectsInvalidVersion tests a non-SOCKS5 version byte.
func TestHandleSocks5RejectsInvalidVersion(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()
	defer func() { _ = clientConn.Close() }()

	c := &Client{}
	errCh := make(chan error, 1)
	go func() {
		_, _, err := c.handleSocks5(serverConn, nil)
		errCh <- err
	}()

	// Send SOCKS4 version byte — handleSocks5 reads 2 bytes, sees invalid version, and returns error.
	_, _ = clientConn.Write([]byte{0x04, 0x01})

	// Drain so the server goroutine isn't blocked on its error write.
	drainAndClose(clientConn)

	if err := <-errCh; err == nil {
		t.Fatal("handleSocks5() should have rejected SOCKS4 version")
	}
}

// TestHandleSocks5RejectsNoAcceptableMethod tests when client offers only methods the server won't accept.
func TestHandleSocks5RejectsNoAcceptableMethod(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	c := &Client{}
	errCh := make(chan error, 1)
	go func() {
		// Server requires auth (credentials != nil), but client only offers no-auth
		_, _, err := c.handleSocks5(serverConn, &protocol.Credentials{Username: "u", Password: "p"})
		errCh <- err
	}()

	// Client offers only no-auth (0x00), but server needs username/password (0x02)
	_, _ = clientConn.Write([]byte{0x05, 0x01, 0x00})

	// Server should respond with 0xFF (no acceptable methods)
	reply := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply[1] != 0xFF {
		t.Fatalf("method reply = 0x%02X, want 0xFF", reply[1])
	}

	if err := <-errCh; err == nil {
		t.Fatal("handleSocks5() should have returned error for no acceptable method")
	}
}
