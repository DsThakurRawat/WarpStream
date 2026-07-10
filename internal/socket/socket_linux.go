//go:build linux

package socket

import "syscall"

func SetSoMark(fd uintptr, mark uint32) error {
	return syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(mark))
}

func SetIpTransparent(fd uintptr) error {
	return syscall.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
}

const (
	ipRecvOrigDstAddr   = 20
	ipv6RecvOrigDstAddr = 74
)

func SetIpRecvOrigDstAddr(fd uintptr) error {
	err1 := syscall.SetsockoptInt(int(fd), syscall.SOL_IP, ipRecvOrigDstAddr, 1)
	err2 := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, ipv6RecvOrigDstAddr, 1)
	if err1 != nil && err2 != nil {
		return err1
	}
	return nil
}
