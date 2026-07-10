package socket

import (
	"encoding/binary"
	"testing"
)

func TestParseOrigDstAddr_IPv4(t *testing.T) {
	// Construct a 64-bit cmsg header + sockaddr_in
	// Total cmsgLen = 16 (hdr) + 16 (sockaddr_in) = 32
	buf := make([]byte, 32)
	binary.LittleEndian.PutUint64(buf[0:8], 32)
	binary.LittleEndian.PutUint32(buf[8:12], protoIP)
	binary.LittleEndian.PutUint32(buf[12:16], cmsgIpOrigDstAddr)

	// sockaddr_in data starts at index 16
	// port at data[2:4] = 8080 (0x1F90)
	binary.BigEndian.PutUint16(buf[18:20], 8080)
	// IP at data[4:8] = 198.51.100.42
	buf[20] = 198
	buf[21] = 51
	buf[22] = 100
	buf[23] = 42

	ip, port, err := ParseOrigDstAddr(buf)
	if err != nil {
		t.Fatalf("ParseOrigDstAddr returned error: %v", err)
	}
	if ip != "198.51.100.42" {
		t.Errorf("expected IP 198.51.100.42, got %s", ip)
	}
	if port != 8080 {
		t.Errorf("expected port 8080, got %d", port)
	}
}

func TestParseOrigDstAddr_IPv6(t *testing.T) {
	// Construct a 64-bit cmsg header + sockaddr_in6
	// Total cmsgLen = 16 (hdr) + 28 (sockaddr_in6) = 44
	buf := make([]byte, 48) // padded to 8 bytes
	binary.LittleEndian.PutUint64(buf[0:8], 44)
	binary.LittleEndian.PutUint32(buf[8:12], protoIPv6)
	binary.LittleEndian.PutUint32(buf[12:16], cmsgIpv6OrigDstAddr)

	// sockaddr_in6 data starts at index 16
	// port at data[2:4] = 9090
	binary.BigEndian.PutUint16(buf[18:20], 9090)
	// IPv6 address at data[8:24] = 2001:db8::1
	copy(buf[24:40], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})

	ip, port, err := ParseOrigDstAddr(buf)
	if err != nil {
		t.Fatalf("ParseOrigDstAddr returned error: %v", err)
	}
	if ip != "2001:db8::1" {
		t.Errorf("expected IP 2001:db8::1, got %s", ip)
	}
	if port != 9090 {
		t.Errorf("expected port 9090, got %d", port)
	}
}
