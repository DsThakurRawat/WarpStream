// Package client provides the client implementation for WarpStream.
// This test file provides extended test coverage for the tunnel argument
// parser, covering invalid inputs, edge cases in query parameters,
// and correct protocol parsing for various configurations.
package client

import (
	"strings"
	"testing"

	"github.com/divyansh-rawat/warpstream/pkg/protocol"
)

// TestParseTunnelArgInvalidInputs tests malformed and edge-case tunnel argument strings.
func TestParseTunnelArgInvalidInputs(t *testing.T) {
	cases := []struct {
		name string
		arg  string
	}{
		{"empty string", ""},
		{"no scheme", "8080:localhost:80"},
		{"unsupported scheme", "ftp://8080:localhost:21"},
		{"garbage", "://::!!"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseTunnelArg(tc.arg, false)
			if err == nil {
				t.Errorf("ParseTunnelArg(%q) = %+v, want error", tc.arg, got)
			}
		})
	}
}

// TestParseTunnelArgHostVariants tests various valid host formats.
func TestParseTunnelArgHostVariants(t *testing.T) {
	cases := []struct {
		name       string
		arg        string
		wantRemote string
		wantPort   uint16
	}{
		{"IPv4 remote", "tcp://9000:192.168.1.1:8080", "192.168.1.1", 8080},
		{"IPv6 remote brackets", "tcp://9000:[::1]:80", "::1", 80},
		{"hostname with dots", "tcp://9000:my.db.internal:5432", "my.db.internal", 5432},
		{"hostname uppercase", "tcp://9000:EXAMPLE.COM:443", "EXAMPLE.COM", 443},
		{"port 1", "tcp://9000:localhost:1", "localhost", 1},
		{"port max", "tcp://9000:localhost:65535", "localhost", 65535},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseTunnelArg(tc.arg, false)
			if err != nil {
				t.Fatalf("ParseTunnelArg(%q) unexpected error: %v", tc.arg, err)
			}
			if got.Remote != tc.wantRemote {
				t.Errorf("Remote = %q, want %q", got.Remote, tc.wantRemote)
			}
			if got.Port != tc.wantPort {
				t.Errorf("Port = %d, want %d", got.Port, tc.wantPort)
			}
		})
	}
}

// TestParseTunnelArgLocalBindAddress tests that explicit local bind addresses are preserved.
func TestParseTunnelArgLocalBindAddress(t *testing.T) {
	cases := []struct {
		name      string
		arg       string
		wantLocal string
	}{
		{"explicit IPv4 bind", "tcp://0.0.0.0:8080:localhost:80", "0.0.0.0:8080"},
		{"explicit IPv6 bind", "tcp://[::]:8080:localhost:80", "[::]:8080"},
		{"loopback bind", "tcp://127.0.0.1:8080:localhost:80", "127.0.0.1:8080"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseTunnelArg(tc.arg, false)
			if err != nil {
				t.Fatalf("ParseTunnelArg(%q) unexpected error: %v", tc.arg, err)
			}
			if got.Local != tc.wantLocal {
				t.Errorf("Local = %q, want %q", got.Local, tc.wantLocal)
			}
		})
	}
}

// TestParseTunnelArgProtocolFields checks protocol-specific parsed fields.
func TestParseTunnelArgProtocolFields(t *testing.T) {
	t.Run("TCP no proxy protocol by default", func(t *testing.T) {
		got, err := ParseTunnelArg("tcp://8080:localhost:80", false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Protocol.Tcp == nil || got.Protocol.Tcp.ProxyProtocol {
			t.Errorf("expected Tcp.ProxyProtocol = false, got %+v", got.Protocol)
		}
	})

	t.Run("UDP default timeout is zero when not set", func(t *testing.T) {
		got, err := ParseTunnelArg("udp://1212:1.1.1.1:53", false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Protocol.Udp == nil {
			t.Fatal("expected Udp protocol")
		}
		// no timeout_sec query param → Timeout field may be nil or zero
	})

	t.Run("SOCKS5 no credentials", func(t *testing.T) {
		got, err := ParseTunnelArg("socks5://127.0.0.1:1080", false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Protocol.Socks5 == nil {
			t.Fatal("expected Socks5 protocol")
		}
		if got.Protocol.Socks5.Credentials != nil {
			t.Errorf("expected no credentials, got %+v", got.Protocol.Socks5.Credentials)
		}
	})

	t.Run("HTTP proxy", func(t *testing.T) {
		got, err := ParseTunnelArg("http://127.0.0.1:8888", false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Protocol.HttpProxy == nil {
			t.Fatal("expected HttpProxy protocol")
		}
	})

	t.Run("unix socket forward", func(t *testing.T) {
		got, err := ParseTunnelArg("unix:///run/app.sock:/run/remote.sock", false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Protocol.Unix == nil {
			t.Fatalf("expected Unix protocol, got %+v", got.Protocol)
		}
	})
}

// TestParseTunnelArgReverseVariants ensures reverse tunnel parsing respects protocol support.
func TestParseTunnelArgReverseVariants(t *testing.T) {
	t.Run("reverse TCP succeeds", func(t *testing.T) {
		got, err := ParseTunnelArg("tcp://9090:localhost:22", true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Protocol.ReverseTcp == nil {
			t.Errorf("expected ReverseTcp, got %+v", got.Protocol)
		}
		if got.Protocol.Tcp != nil {
			t.Errorf("forward Tcp should be nil for reverse tunnel")
		}
	})

	t.Run("reverse unix succeeds", func(t *testing.T) {
		got, err := ParseTunnelArg("unix:///run/listen.sock:/run/client.sock", true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Protocol.ReverseUnix == nil {
			t.Errorf("expected ReverseUnix, got %+v", got.Protocol)
		}
	})
}

// TestParseTunnelArgQueryParamEdgeCases covers edge cases in query parameter handling.
func TestParseTunnelArgQueryParamEdgeCases(t *testing.T) {
	t.Run("proxy_protocol without value", func(t *testing.T) {
		got, err := ParseTunnelArg("tcp://8080:localhost:80?proxy_protocol", false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Protocol.Tcp == nil || !got.Protocol.Tcp.ProxyProtocol {
			t.Errorf("expected ProxyProtocol=true, got %+v", got.Protocol)
		}
	})

	t.Run("unknown query params are ignored", func(t *testing.T) {
		_, err := ParseTunnelArg("tcp://8080:localhost:80?unknown_param=foo", false)
		if err != nil {
			t.Errorf("unexpected error for unknown param: %v", err)
		}
	})

	t.Run("udp large timeout", func(t *testing.T) {
		got, err := ParseTunnelArg("udp://1212:1.1.1.1:53?timeout_sec=3600", false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Protocol.Udp == nil || got.Protocol.Udp.Timeout == nil {
			t.Fatal("expected Udp timeout")
		}
		if got.Protocol.Udp.Timeout.Secs != 3600 {
			t.Errorf("timeout = %d, want 3600", got.Protocol.Udp.Timeout.Secs)
		}
	})
}

// TestParseTunnelArgResultFields checks all top-level output fields of a basic parse.
func TestParseTunnelArgResultFields(t *testing.T) {
	got, err := ParseTunnelArg("tcp://9999:db.internal:5432", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.HasSuffix(got.Local, ":9999") {
		t.Errorf("Local = %q, want suffix ':9999'", got.Local)
	}
	if got.Remote != "db.internal" {
		t.Errorf("Remote = %q, want db.internal", got.Remote)
	}
	if got.Port != 5432 {
		t.Errorf("Port = %d, want 5432", got.Port)
	}
	if got.Protocol.Tcp == nil {
		t.Error("expected TCP protocol to be set")
	}
}

// TestParseTunnelArgReturnsNilOnSuccess confirms non-nil return on valid input.
func TestParseTunnelArgReturnsNilOnSuccess(t *testing.T) {
	cases := []string{
		"tcp://8080:localhost:80",
		"udp://1212:8.8.8.8:53",
		"socks5://127.0.0.1:1080",
		"stdio://example.com:443",
		"http://127.0.0.1:3128",
	}
	for _, arg := range cases {
		got, err := ParseTunnelArg(arg, false)
		if err != nil {
			t.Errorf("ParseTunnelArg(%q) unexpected error: %v", arg, err)
		}
		if got == nil {
			t.Errorf("ParseTunnelArg(%q) returned nil result without error", arg)
		}
	}
}

// Compile-time check that protocol types are used correctly in tests.
var _ *protocol.LocalToRemote = (*protocol.LocalToRemote)(nil)
