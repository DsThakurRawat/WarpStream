package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func generateTestCertFiles(t *testing.T, dir, cn string) (string, string) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}

	certPath := filepath.Join(dir, cn+".crt")
	keyPath := filepath.Join(dir, cn+".key")

	certOut, err := os.Create(certPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	_ = certOut.Close()

	keyOut, err := os.Create(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	_ = keyOut.Close()

	return certPath, keyPath
}

func TestCertReloader_ReloadAndGetCertificate(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := generateTestCertFiles(t, dir, "test1.example.com")

	reloader, err := NewCertReloader(certFile, keyFile)
	if err != nil {
		t.Fatalf("NewCertReloader failed: %v", err)
	}

	cert1, err := reloader.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}
	if cert1 == nil || len(cert1.Certificate) == 0 {
		t.Fatalf("expected non-empty certificate")
	}

	// Overwrite files with new cert
	generateTestCertFiles(t, dir, "test1.example.com")
	if err := reloader.Reload(); err != nil {
		t.Fatalf("Reload failed: %v", err)
	}

	cert2, err := reloader.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate after reload failed: %v", err)
	}
	if cert2 == nil || len(cert2.Certificate) == 0 {
		t.Fatalf("expected non-empty certificate after reload")
	}
}

func TestCertReloader_InvalidFiles(t *testing.T) {
	dir := t.TempDir()
	_, err := NewCertReloader(filepath.Join(dir, "nonexistent.crt"), filepath.Join(dir, "nonexistent.key"))
	if err == nil {
		t.Fatalf("expected error for nonexistent files, got nil")
	}
}

func TestCertReloader_WatchFiles(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := generateTestCertFiles(t, dir, "watch.example.com")

	reloader, err := NewCertReloader(certFile, keyFile)
	if err != nil {
		t.Fatalf("NewCertReloader failed: %v", err)
	}

	cert1, err := reloader.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}
	original := cert1.Certificate[0]

	// Start polling with a very short interval
	reloader.WatchFiles(20 * time.Millisecond)

	// Overwrite cert files with a new cert (small sleep to ensure mtime advances)
	time.Sleep(50 * time.Millisecond)
	generateTestCertFiles(t, dir, "watch.example.com")

	// Wait for WatchFiles to pick up the change
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(30 * time.Millisecond)
		cert2, err := reloader.GetCertificate(nil)
		if err != nil {
			continue
		}
		if len(cert2.Certificate) > 0 && string(cert2.Certificate[0]) != string(original) {
			return // successfully detected hot-reload
		}
	}
	t.Fatal("WatchFiles did not reload the certificate within 2 seconds")
}
