//go:build !linux

package socket

func SetSoMark(fd uintptr, mark uint32) error {
	return nil
}

func SetIpTransparent(fd uintptr) error {
	return nil
}

func SetIpRecvOrigDstAddr(fd uintptr) error {
	return nil
}
