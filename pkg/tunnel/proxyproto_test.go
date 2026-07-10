package tunnel

import (
	"bytes"
	"net"
	"testing"
)

func TestWriteProxyHeaderV1_IPv4(t *testing.T) {
	src := &net.TCPAddr{IP: net.ParseIP("192.168.1.10"), Port: 12345}
	dst := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 80}

	var buf bytes.Buffer
	err := WriteProxyHeaderV1(&buf, src, dst)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := "PROXY TCP4 192.168.1.10 10.0.0.1 12345 80\r\n"
	if buf.String() != expected {
		t.Errorf("expected %q, got %q", expected, buf.String())
	}
}

func TestWriteProxyHeaderV2_IPv4(t *testing.T) {
	src := &net.TCPAddr{IP: net.ParseIP("192.168.1.10"), Port: 12345}
	dst := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 80}

	var buf bytes.Buffer
	err := WriteProxyHeaderV2(&buf, src, dst)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data := buf.Bytes()
	if len(data) != 16+12 {
		t.Fatalf("expected 28 bytes, got %d", len(data))
	}

	// Verify v2 signature
	if !bytes.Equal(data[:12], v2Signature) {
		t.Errorf("invalid v2 signature")
	}

	if data[12] != 0x21 || data[13] != 0x11 {
		t.Errorf("invalid command or address family byte: %x %x", data[12], data[13])
	}
}

func TestWriteProxyHeaderV2_IPv6(t *testing.T) {
	src := &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443}
	dst := &net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 8080}

	var buf bytes.Buffer
	err := WriteProxyHeaderV2(&buf, src, dst)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data := buf.Bytes()
	if len(data) != 16+36 {
		t.Fatalf("expected 52 bytes, got %d", len(data))
	}
}
