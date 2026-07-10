package server

import (
	"crypto/x509"
	"testing"
)

func TestGenerateSelfSignedCert(t *testing.T) {
	cert, err := generateSelfSignedCert([]string{"example.com", "10.0.0.1"})
	if err != nil {
		t.Fatalf("unexpected error generating cert: %v", err)
	}

	if len(cert.Certificate) == 0 {
		t.Fatalf("expected non-empty certificate chain")
	}

	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("failed to parse generated X.509 cert: %v", err)
	}

	foundExample := false
	for _, dns := range parsed.DNSNames {
		if dns == "example.com" {
			foundExample = true
		}
	}
	if !foundExample {
		t.Errorf("expected DNSName example.com in SANs, got %v", parsed.DNSNames)
	}

	foundIP := false
	for _, ip := range parsed.IPAddresses {
		if ip.String() == "10.0.0.1" {
			foundIP = true
		}
	}
	if !foundIP {
		t.Errorf("expected IP 10.0.0.1 in SANs, got %v", parsed.IPAddresses)
	}
}
