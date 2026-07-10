package socket

import (
	"encoding/binary"
	"fmt"
	"net"
)

const (
	cmsgIpOrigDstAddr   = 20
	cmsgIpv6OrigDstAddr = 80
	protoIP             = 0
	protoIPv6           = 41
)

// ParseOrigDstAddr extracts the destination IP and port from UDP OOB control messages
// returned by IP_RECVORIGDSTADDR / IPV6_RECVORIGDSTADDR.
func ParseOrigDstAddr(oob []byte) (string, uint16, error) {
	for len(oob) >= 16 {
		cmsgLen := binary.LittleEndian.Uint64(oob[0:8])
		if cmsgLen < 16 || uint64(len(oob)) < cmsgLen {
			break
		}
		level := int32(binary.LittleEndian.Uint32(oob[8:12]))
		typ := int32(binary.LittleEndian.Uint32(oob[12:16]))
		data := oob[16:cmsgLen]

		if level == protoIP && typ == cmsgIpOrigDstAddr {
			if len(data) >= 8 {
				port := binary.BigEndian.Uint16(data[2:4])
				ip := net.IPv4(data[4], data[5], data[6], data[7])
				return ip.String(), port, nil
			}
		}

		if level == protoIPv6 && typ == cmsgIpv6OrigDstAddr {
			if len(data) >= 24 {
				port := binary.BigEndian.Uint16(data[2:4])
				ip := make(net.IP, 16)
				copy(ip, data[8:24])
				return ip.String(), port, nil
			}
		}

		// Advance to next cmsg aligned to 8 bytes
		next := (cmsgLen + 7) &^ 7
		if uint64(len(oob)) < next {
			break
		}
		oob = oob[next:]
	}

	return "", 0, fmt.Errorf("original destination address control message not found")
}
