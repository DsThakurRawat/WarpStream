package server

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

type CertReloader struct {
	certFile string
	keyFile  string

	mu   sync.RWMutex
	cert *tls.Certificate
}

func NewCertReloader(certFile, keyFile string) (*CertReloader, error) {
	r := &CertReloader{
		certFile: certFile,
		keyFile:  keyFile,
	}
	if err := r.Reload(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *CertReloader) Reload() error {
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return fmt.Errorf("failed to reload certificate %s / key %s: %w", r.certFile, r.keyFile, err)
	}
	r.mu.Lock()
	r.cert = &cert
	r.mu.Unlock()
	slog.Info("Successfully reloaded TLS certificate", "cert", r.certFile, "key", r.keyFile)
	return nil
}

func (r *CertReloader) GetCertificate(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.cert == nil {
		return nil, fmt.Errorf("no TLS certificate loaded")
	}
	return r.cert, nil
}

func (r *CertReloader) WatchFiles(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		var lastCertMod, lastKeyMod time.Time
		for range ticker.C {
			certFi, err1 := os.Stat(r.certFile)
			keyFi, err2 := os.Stat(r.keyFile)
			if err1 != nil || err2 != nil {
				continue
			}
			if lastCertMod.IsZero() {
				lastCertMod = certFi.ModTime()
				lastKeyMod = keyFi.ModTime()
				continue
			}
			if certFi.ModTime().After(lastCertMod) || keyFi.ModTime().After(lastKeyMod) {
				slog.Info("Detected certificate file change, reloading TLS certificate...", "cert", r.certFile, "key", r.keyFile)
				if err := r.Reload(); err != nil {
					slog.Error("Failed to reload TLS certificate on file change", "err", err)
				} else {
					lastCertMod = certFi.ModTime()
					lastKeyMod = keyFi.ModTime()
				}
			}
		}
	}()
}

func (r *CertReloader) WatchSignals() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP)
	go func() {
		for range sigChan {
			slog.Info("Received SIGHUP, reloading TLS certificate...")
			if err := r.Reload(); err != nil {
				slog.Error("Failed to reload TLS certificate on SIGHUP", "err", err)
			}
		}
	}()
}
