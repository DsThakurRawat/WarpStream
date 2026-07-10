package tunnel

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
)

var v2Signature = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

// parseIPPort extracts an IP and port from a net.Addr or string representation.
func parseIPPort(addr net.Addr) (net.IP, uint16, bool) {
	if addr == nil {
		return nil, 0, false
	}
	switch v := addr.(type) {
	case *net.TCPAddr:
		if v == nil || v.IP == nil {
			return nil, 0, false
		}
		return v.IP, uint16(v.Port), true
	case *net.UDPAddr:
		if v == nil || v.IP == nil {
			return nil, 0, false
		}
		return v.IP, uint16(v.Port), true
	}

	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil, 0, false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, 0, false
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, 0, false
	}
	return ip, uint16(port), true
}

// WriteProxyHeaderV1 writes an HAProxy PROXY Protocol v1 text header to w.
func WriteProxyHeaderV1(w io.Writer, src, dst net.Addr) error {
	srcIP, srcPort, srcOK := parseIPPort(src)
	dstIP, dstPort, dstOK := parseIPPort(dst)

	if !srcOK || !dstOK {
		_, err := w.Write([]byte("PROXY UNKNOWN\r\n"))
		return err
	}

	src4 := srcIP.To4()
	dst4 := dstIP.To4()

	var line string
	if src4 != nil && dst4 != nil {
		line = fmt.Sprintf("PROXY TCP4 %s %s %d %d\r\n", src4.String(), dst4.String(), srcPort, dstPort)
	} else if src4 == nil && dst4 == nil {
		line = fmt.Sprintf("PROXY TCP6 %s %s %d %d\r\n", srcIP.String(), dstIP.String(), srcPort, dstPort)
	} else {
		line = "PROXY UNKNOWN\r\n"
	}

	_, err := w.Write([]byte(line))
	return err
}

// WriteProxyHeaderV2 writes an HAProxy PROXY Protocol v2 binary header to w.
func WriteProxyHeaderV2(w io.Writer, src, dst net.Addr) error {
	srcIP, srcPort, srcOK := parseIPPort(src)
	dstIP, dstPort, dstOK := parseIPPort(dst)

	if !srcOK || !dstOK {
		// UNKNOWN address family/protocol
		buf := make([]byte, 16)
		copy(buf[0:12], v2Signature)
		buf[12] = 0x20 // Version 2 | LOCAL command
		buf[13] = 0x00 // AF_UNSPEC | UNSPEC
		binary.BigEndian.PutUint16(buf[14:16], 0)
		_, err := w.Write(buf)
		return err
	}

	src4 := srcIP.To4()
	dst4 := dstIP.To4()

	if src4 != nil && dst4 != nil {
		// IPv4 TCP
		buf := make([]byte, 16+12)
		copy(buf[0:12], v2Signature)
		buf[12] = 0x21 // Version 2 | PROXY command
		buf[13] = 0x11 // AF_INET | STREAM (TCP)
		binary.BigEndian.PutUint16(buf[14:16], 12)
		copy(buf[16:20], src4)
		copy(buf[20:24], dst4)
		binary.BigEndian.PutUint16(buf[24:26], srcPort)
		binary.BigEndian.PutUint16(buf[26:28], dstPort)
		_, err := w.Write(buf)
		return err
	}

	// Ensure 16-byte IPv6 format
	src6 := srcIP.To16()
	dst6 := dstIP.To16()
	if src6 == nil || dst6 == nil {
		// Fallback to UNKNOWN
		buf := make([]byte, 16)
		copy(buf[0:12], v2Signature)
		buf[12] = 0x20 // Version 2 | LOCAL command
		buf[13] = 0x00
		binary.BigEndian.PutUint16(buf[14:16], 0)
		_, err := w.Write(buf)
		return err
	}

	buf := make([]byte, 16+36)
	copy(buf[0:12], v2Signature)
	buf[12] = 0x21 // Version 2 | PROXY command
	buf[13] = 0x21 // AF_INET6 | STREAM (TCP)
	binary.BigEndian.PutUint16(buf[14:16], 36)
	copy(buf[16:32], src6)
	copy(buf[32:48], dst6)
	binary.BigEndian.PutUint16(buf[48:50], srcPort)
	binary.BigEndian.PutUint16(buf[50:52], dstPort)
	_, err := w.Write(buf)
	return err
}
