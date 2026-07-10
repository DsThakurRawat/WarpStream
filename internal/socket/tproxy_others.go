//go:build !linux

package socket

import (
	"fmt"
	"net"
)

func GetOriginalDst(conn net.Conn) (string, uint16, error) {
	if conn == nil {
		return "", 0, fmt.Errorf("nil conn")
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
