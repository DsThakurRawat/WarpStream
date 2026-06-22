// Package server provides the server implementation for WarpStream.
// This test file provides extended test coverage for the server's HTTP handler,
// JWT authentication extraction and parsing, YAML configuration precedence,
// and tunnel restriction rules.
package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/divyansh-rawat/warpstream/pkg/protocol"
	"github.com/golang-jwt/jwt/v5"
	"gopkg.in/yaml.v3"
)

// buildWSUpgradeRequest creates a fake WebSocket upgrade request with an optional JWT.
func buildWSUpgradeRequest(path, jwtToken string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	if jwtToken != "" {
		req.Header.Set("Sec-WebSocket-Protocol", fmt.Sprintf("v1, bearer.%s", jwtToken))
	}
	return req
}

// --- ServeHTTP path prefix tests ---

func TestServeHTTPRejectsMissingToken(t *testing.T) {
	srv := NewServer(Config{PathPrefix: "v1", WebsocketProtocol: "legacy"})
	w := httptest.NewRecorder()
	req := buildWSUpgradeRequest("/v1/events", "") // no JWT
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestServeHTTPRejectsWrongPathPrefix(t *testing.T) {
	srv := NewServer(Config{PathPrefix: "v1", WebsocketProtocol: "legacy"})
	token := signedToken(t, "secret")
	w := httptest.NewRecorder()
	req := buildWSUpgradeRequest("/wrong/events", token)
	req.Header.Set("Sec-WebSocket-Protocol", fmt.Sprintf("v1, bearer.%s", token))
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d (wrong path prefix)", w.Code, http.StatusNotFound)
	}
}

func TestServeHTTPRejectsUnsignedTokenInWSMode(t *testing.T) {
	srv := NewServer(Config{
		PathPrefix:        "v1",
		WebsocketProtocol: "ws",
		JWTSecret:         "shared-secret",
	})
	// Token signed with wrong key
	badToken := signedToken(t, "different-secret")
	w := httptest.NewRecorder()
	req := buildWSUpgradeRequest("/v1/events", badToken)
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d (bad token)", w.Code, http.StatusUnauthorized)
	}
}

func TestServeHTTPNoPrefixAcceptsAnyPath(t *testing.T) {
	// When PathPrefix is empty, the server should not reject based on path
	srv := NewServer(Config{WebsocketProtocol: "legacy"})
	// No token → should reach token check, not path check
	w := httptest.NewRecorder()
	req := buildWSUpgradeRequest("/any/path/here", "")
	srv.ServeHTTP(w, req)
	// Should get 401 (missing token), not 404 (wrong path)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d; server without prefix should not reject by path", w.Code, http.StatusUnauthorized)
	}
}

// --- JWT parsing edge cases ---

func TestParseJWTClaimsEmptyStringReturnsError(t *testing.T) {
	srv := NewServer(Config{WebsocketProtocol: "legacy"})
	if _, err := srv.parseJWTClaims(""); err == nil {
		t.Fatal("parseJWTClaims() should return error for empty token")
	}
}

func TestParseJWTClaimsGarbageStringReturnsError(t *testing.T) {
	cases := []string{
		"notavalidjwt",
		"a.b",
		"a.b.c.d",
		"Bearer token",
		"   ",
	}
	srv := NewServer(Config{WebsocketProtocol: "legacy"})
	for _, tc := range cases {
		if _, err := srv.parseJWTClaims(tc); err == nil {
			t.Errorf("parseJWTClaims(%q) should return error", tc)
		}
	}
}

func TestParseJWTClaimsWSModeNoSecretAcceptsAnyHS256(t *testing.T) {
	// ws mode + no secret + insecure = accepts any HS256 shape
	srv := NewServer(Config{
		WebsocketProtocol:       "ws",
		InsecureNoJWTValidation: true,
	})
	token := signedToken(t, "totally-random-key")
	claims, err := srv.parseJWTClaims(token)
	if err != nil {
		t.Fatalf("parseJWTClaims() error = %v", err)
	}
	if claims.Remote != "example.com" {
		t.Errorf("Remote = %q, want example.com", claims.Remote)
	}
}

func TestParseJWTClaimsPreservesAllFields(t *testing.T) {
	srv := NewServer(Config{WebsocketProtocol: "legacy"})

	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, protocol.JwtTunnelConfig{
		ID:     "my-unique-id",
		Remote: "db.internal",
		Port:   5432,
		Protocol: protocol.LocalProtocol{
			Tcp: &protocol.TcpProtocol{ProxyProtocol: true},
		},
	}).SignedString([]byte("any"))
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}

	claims, err := srv.parseJWTClaims(token)
	if err != nil {
		t.Fatalf("parseJWTClaims() error = %v", err)
	}
	if claims.ID != "my-unique-id" {
		t.Errorf("ID = %q, want my-unique-id", claims.ID)
	}
	if claims.Remote != "db.internal" {
		t.Errorf("Remote = %q, want db.internal", claims.Remote)
	}
	if claims.Port != 5432 {
		t.Errorf("Port = %d, want 5432", claims.Port)
	}
	if claims.Protocol.Tcp == nil || !claims.Protocol.Tcp.ProxyProtocol {
		t.Errorf("Protocol.Tcp.ProxyProtocol = false, want true")
	}
}

// --- Config YAML edge cases ---

func TestConfigYAMLPrefersPrimaryOverLegacyPrefix(t *testing.T) {
	// When both keys exist, http_upgrade_path_prefix should take precedence.
	raw := "http_upgrade_path_prefix: primary\nrestrict_http_upgrade_path_prefix: legacy\n"
	var cfg Config
	if err := yaml.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatalf("yaml.Unmarshal() error = %v", err)
	}
	if cfg.PathPrefix != "primary" {
		t.Errorf("PathPrefix = %q, want \"primary\" (explicit key should win over legacy key)", cfg.PathPrefix)
	}
}

// --- Restriction rule tests ---

func TestNewServerWithRestrictToBuildsRules(t *testing.T) {
	srv := NewServer(Config{
		WebsocketProtocol: "legacy",
		RestrictTo:        []string{"db.internal:5432"},
	})
	if srv.rules == nil {
		t.Fatal("expected rules to be built from RestrictTo")
	}
}

func TestNewServerWithEmptyRestrictToNoRules(t *testing.T) {
	srv := NewServer(Config{WebsocketProtocol: "legacy"})
	if srv.rules != nil {
		t.Errorf("expected no rules when no restrictions configured")
	}
}

func TestServerSetAndGetRules(t *testing.T) {
	srv := NewServer(Config{WebsocketProtocol: "legacy"})
	rules := &RestrictionsRules{}
	srv.SetRules(rules)
	if srv.GetRules() != rules {
		t.Error("GetRules() did not return the rule set passed to SetRules()")
	}
}

func TestServerClearRules(t *testing.T) {
	srv := NewServer(Config{
		WebsocketProtocol: "legacy",
		RestrictTo:        []string{"db.internal:5432"},
	})
	srv.SetRules(nil)
	if srv.GetRules() != nil {
		t.Error("expected GetRules() to return nil after SetRules(nil)")
	}
}

// --- HTTP/2 token extraction via Cookie header ---

func TestServeHTTPExtractsTokenFromCookieHeader(t *testing.T) {
	// When there's no Sec-WebSocket-Protocol header, the server should try Cookie
	srv := NewServer(Config{WebsocketProtocol: "legacy"})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/events", nil)

	// Provide a valid (parseable) token in the Cookie header
	token := signedToken(t, "secret")
	req.Header.Set("Cookie", token)
	req.Proto = "HTTP/2.0"
	req.ProtoMajor = 2
	req.ProtoMinor = 0

	// With a valid token but no actual H2 body the server will attempt to forward,
	// which will fail at network dial — but we should NOT get 401.
	// We can't easily test full H2 handling here without a real listener,
	// so we just verify the token is extracted by checking not-401.
	srv.ServeHTTP(w, req)
	if w.Code == http.StatusUnauthorized {
		t.Errorf("status = 401 Unauthorized; server should have extracted token from Cookie header")
	}
}
