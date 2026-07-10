package server

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/DsThakurRawat/WarpStream/pkg/client"
	"github.com/DsThakurRawat/WarpStream/pkg/protocol"
)

func TestReverseSocks5_DynamicTargetE2E(t *testing.T) {
	// 1. Start target echo server (only reachable when client dials targetHost:targetPort)
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen target echo server: %v", err)
	}
	defer targetLn.Close()

	targetPort := uint16(targetLn.Addr().(*net.TCPAddr).Port)

	go func() {
		for {
			c, err := targetLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	// 2. Start WarpStream server
	srvLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen WarpStream server: %v", err)
	}
	srvPort := srvLn.Addr().(*net.TCPAddr).Port
	srvLn.Close()
	srvAddr := fmt.Sprintf("ws://127.0.0.1:%d", srvPort)

	srv := NewServer(Config{ListenAddr: srvAddr})
	go func() {
		_ = srv.Start()
	}()

	// 3. Find free port for reverse SOCKS5 listener on the server
	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to reserve SOCKS5 port: %v", err)
	}
	socksPort := socksLn.Addr().(*net.TCPAddr).Port
	socksLn.Close()

	// 4. Start WarpStream client requesting reverse SOCKS5 tunnel
	wstClient := client.NewClient(client.Config{
		ServerURL:                              srvAddr,
		ReverseTunnelConnectionRetryMaxBackoff: 1 * time.Second,
	})

	ltr := &protocol.LocalToRemote{
		Local:  fmt.Sprintf("127.0.0.1:%d", socksPort),
		Remote: "127.0.0.1",
		Port:   uint16(socksPort),
		Protocol: protocol.LocalProtocol{
			ReverseSocks5: &protocol.ReverseSocks5Protocol{},
		},
	}

	go wstClient.StartReverseTunnel(ltr)

	// Wait for reverse SOCKS5 listener to open on server
	var proxyConn net.Conn
	for i := 0; i < 40; i++ {
		time.Sleep(50 * time.Millisecond)
		c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort))
		if err == nil {
			proxyConn = c
			break
		}
	}
	if proxyConn == nil {
		t.Fatalf("Timeout waiting for server reverse SOCKS5 listener")
	}
	defer proxyConn.Close()

	// 5. SOCKS5 Handshake with proxyConn requesting targetHost:targetPort
	// Send version 5, 1 auth method (0 = no auth)
	if _, err := proxyConn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("Failed to write SOCKS5 greeting: %v", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(proxyConn, resp); err != nil {
		t.Fatalf("Failed to read SOCKS5 greeting response: %v", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		t.Fatalf("Unexpected SOCKS5 greeting response: %v", resp)
	}

	// Send CONNECT request to 127.0.0.1:targetPort
	req := []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 0}
	binary.BigEndian.PutUint16(req[8:10], targetPort)
	if _, err := proxyConn.Write(req); err != nil {
		t.Fatalf("Failed to write SOCKS5 connect request: %v", err)
	}

	connectResp := make([]byte, 10)
	if _, err := io.ReadFull(proxyConn, connectResp); err != nil {
		t.Fatalf("Failed to read SOCKS5 connect response: %v", err)
	}
	if connectResp[1] != 0x00 {
		t.Fatalf("SOCKS5 connect request failed with reply code %d", connectResp[1])
	}

	// 6. Round-trip data test
	msg := []byte("hello dynamic target")
	if _, err := proxyConn.Write(msg); err != nil {
		t.Fatalf("Failed to write payload: %v", err)
	}

	echoBuf := make([]byte, len(msg))
	if _, err := io.ReadFull(proxyConn, echoBuf); err != nil {
		t.Fatalf("Failed to read echo payload: %v", err)
	}
	if string(echoBuf) != string(msg) {
		t.Fatalf("Expected %q, got %q", string(msg), string(echoBuf))
	}
}

func TestReverseHttpProxy_DynamicTargetE2E(t *testing.T) {
	// 1. Start target echo server
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen target echo server: %v", err)
	}
	defer targetLn.Close()

	targetPort := uint16(targetLn.Addr().(*net.TCPAddr).Port)

	go func() {
		for {
			c, err := targetLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	// 2. Start WarpStream server
	srvLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen WarpStream server: %v", err)
	}
	srvPort := srvLn.Addr().(*net.TCPAddr).Port
	srvLn.Close()
	srvAddr := fmt.Sprintf("ws://127.0.0.1:%d", srvPort)

	srv := NewServer(Config{ListenAddr: srvAddr})
	go func() {
		_ = srv.Start()
	}()

	// 3. Reserve HTTP Proxy listen port
	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to reserve HTTP proxy port: %v", err)
	}
	httpPort := httpLn.Addr().(*net.TCPAddr).Port
	httpLn.Close()

	// 4. Start WarpStream client requesting reverse HTTP proxy tunnel
	wstClient := client.NewClient(client.Config{
		ServerURL:                              srvAddr,
		ReverseTunnelConnectionRetryMaxBackoff: 1 * time.Second,
	})

	ltr := &protocol.LocalToRemote{
		Local:  fmt.Sprintf("127.0.0.1:%d", httpPort),
		Remote: "127.0.0.1",
		Port:   uint16(httpPort),
		Protocol: protocol.LocalProtocol{
			ReverseHttpProxy: &protocol.ReverseHttpProxyProtocol{},
		},
	}

	go wstClient.StartReverseTunnel(ltr)

	var proxyConn net.Conn
	for i := 0; i < 40; i++ {
		time.Sleep(50 * time.Millisecond)
		c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", httpPort))
		if err == nil {
			proxyConn = c
			break
		}
	}
	if proxyConn == nil {
		t.Fatalf("Timeout waiting for server reverse HTTP proxy listener")
	}
	defer proxyConn.Close()

	// 5. HTTP CONNECT Handshake
	connectReq := fmt.Sprintf("CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n", targetPort, targetPort)
	if _, err := proxyConn.Write([]byte(connectReq)); err != nil {
		t.Fatalf("Failed to write CONNECT request: %v", err)
	}

	respBuf := make([]byte, 1024)
	n, err := proxyConn.Read(respBuf)
	if err != nil {
		t.Fatalf("Failed to read CONNECT response: %v", err)
	}
	respStr := string(respBuf[:n])
	if !strings.Contains(respStr, "200") {
		t.Fatalf("Expected 200 response from HTTP CONNECT, got: %s", respStr)
	}

	// 6. Round-trip data test
	msg := []byte("hello http proxy dynamic target")
	if _, err := proxyConn.Write(msg); err != nil {
		t.Fatalf("Failed to write payload: %v", err)
	}

	echoBuf := make([]byte, len(msg))
	if _, err := io.ReadFull(proxyConn, echoBuf); err != nil {
		t.Fatalf("Failed to read echo payload: %v", err)
	}
	if string(echoBuf) != string(msg) {
		t.Fatalf("Expected %q, got %q", string(msg), string(echoBuf))
	}
}
