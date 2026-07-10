//go:build linux

package socket

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

const soOriginalDst = 80
const ip6tSoOriginalDst = 80

func GetOriginalDst(conn net.Conn) (string, uint16, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return addrToHostPort(conn.LocalAddr())
	}

	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return addrToHostPort(conn.LocalAddr())
	}

	var origIP net.IP
	var origPort uint16
	var found bool

	err = rawConn.Control(func(fd uintptr) {
		// Try IPv4 SO_ORIGINAL_DST (struct sockaddr_in is 16 bytes)
		var addr [16]byte
		addrLen := uint32(len(addr))
		_, _, errno := syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			uintptr(syscall.IPPROTO_IP),
			uintptr(soOriginalDst),
			uintptr(unsafe.Pointer(&addr[0])),
			uintptr(unsafe.Pointer(&addrLen)),
			0,
		)
		if errno == 0 && addrLen >= 8 {
			origPort = binary.BigEndian.Uint16(addr[2:4])
			origIP = net.IPv4(addr[4], addr[5], addr[6], addr[7])
			found = true
			return
		}

		// Try IPv6 IP6T_SO_ORIGINAL_DST (struct sockaddr_in6 is 28 bytes)
		var addr6 [28]byte
		addrLen6 := uint32(len(addr6))
		_, _, errno6 := syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			uintptr(syscall.IPPROTO_IPV6),
			uintptr(ip6tSoOriginalDst),
			uintptr(unsafe.Pointer(&addr6[0])),
			uintptr(unsafe.Pointer(&addrLen6)),
			0,
		)
		if errno6 == 0 && addrLen6 >= 24 {
			origPort = binary.BigEndian.Uint16(addr6[2:4])
			origIP = make(net.IP, 16)
			copy(origIP, addr6[8:24])
			found = true
			return
		}
	})

	if err == nil && found && origPort != 0 {
		return origIP.String(), origPort, nil
	}

	return addrToHostPort(conn.LocalAddr())
}

func addrToHostPort(addr net.Addr) (string, uint16, error) {
	if addr == nil {
		return "", 0, fmt.Errorf("nil address")
	}
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return "", 0, err
	}
	var port uint16
	_, _ = fmt.Sscanf(portStr, "%d", &port)
	return host, port, nil
}
