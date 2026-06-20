# WarpStream — Architecture Deep Dive

**Author:** Divyansh Rawat ([@DsThakurRawat](https://github.com/DsThakurRawat))  
**Module:** `github.com/divyansh-rawat/warpstream`  
**Language:** Go 1.25+

---

## Overview

WarpStream is a high-performance network tunneling tool written in Go. It allows arbitrary TCP, UDP, SOCKS5, HTTP, Unix Socket, and Stdio traffic to be tunneled over WebSocket or HTTP/2 connections, making it effective at bypassing restrictive firewalls and proxies that only permit standard HTTPS traffic.

---

## High-Level Architecture

WarpStream operates as two cooperating processes:

```
+---------------------------+              +-----------------------------+
|   Restricted Machine      |              |   Unrestricted Machine      |
|                           |              |                             |
|  +---------+   +--------+ | WSS/HTTPS   | +--------+   +----------+  |
|  | App     |-->| Client |=|=============|=| Server |-->| Target   |  |
|  | (SSH,   |   | (warp- | | Port 443    | | (warp- |   | (TCP/UDP |  |
|  |  curl,  |<--| stream)| |             | | stream)|<--| service) |  |
|  |  etc.)  |   +--------+ |             | +--------+   +----------+  |
|  +---------+              |             |                             |
+---------------------------+             +-----------------------------+
```

The **Client** listens locally (TCP, UDP, SOCKS5, HTTP proxy, or Unix socket), accepts connections from local applications, and forwards each connection as a new **tunnel stream** to the **Server** over a persistent WebSocket or HTTP/2 connection. The **Server** decapsulates the stream and opens a raw connection to the true destination, then pipes data bidirectionally.

---

## Package Structure

```
warpstream/
├── cmd/warpstream/          # CLI entrypoint (main.go, main_test.go)
├── pkg/
│   ├── client/             # Client logic: connect, tunnel, auth, pool
│   │   ├── client.go       # Core client: JWT generation, dialing, piping
│   │   ├── config.go       # Config struct + tunnel arg parser
│   │   ├── pool.go         # TCP connection pool
│   │   └── transport.go    # TLS, proxy, SO_MARK, DNS dialers
│   ├── server/             # Server logic: HTTP handler, JWT, restriction rules
│   │   ├── server.go       # Core server: WebSocket upgrade, HTTP/2 handler
│   │   ├── manager.go      # Reverse tunnel session manager
│   │   └── restrictions.go # YAML restriction rule engine
│   ├── protocol/           # Shared data types: JWT claims, tunnel types
│   ├── tunnel/             # Bidirectional IO piping utilities
│   │   ├── pipe.go         # Pipe, PipeGorilla, PipeRW, PipeBiDir
│   │   └── benchmark_test.go
│   ├── wst/                # Custom WebSocket transport (non-strict RFC 6455)
│   └── caddy/              # Caddy HTTP server integration module
├── internal/
│   ├── rlimit/             # Raises file descriptor limits on startup
│   └── socket/             # SO_MARK support for Linux
├── packaging/
│   ├── systemd/            # systemd unit templates
│   ├── windows/            # PowerShell install/uninstall/control scripts
│   └── caddy/              # Example Caddyfile
└── docs/                   # Documentation
```

---

## Core Subsystems

### 1. Transport Layer (`pkg/wst`, `pkg/client/transport.go`)

WarpStream supports three distinct transport modes:

| Mode | URL Scheme | Description |
|---|---|---|
| Legacy WebSocket | `ws://`, `wss://` | Custom WebSocket with intentional RFC 6455 deviations for broad compatibility. JWT passed in `Sec-WebSocket-Protocol` header. |
| RFC 6455 WebSocket | `ws://`, `wss://` (with `--mode ws`) | Strict RFC-compliant WebSocket via `gorilla/websocket`. JWT also in `Sec-WebSocket-Protocol`. |
| HTTP/2 | `http://`, `https://` | Full-duplex POST request streams. JWT passed in `Cookie` header. Uses `golang.org/x/net/http2`. |

The client selects the transport automatically based on the URL scheme of the server:
- `http://` or `https://` → HTTP/2
- `ws://` or `wss://` with `--mode ws` → Gorilla WebSocket
- `ws://` or `wss://` (default) → Custom `wst` WebSocket

---

### 2. Authentication (`pkg/protocol`, JWT)

Every tunnel connection is authenticated via a **HS256 JWT** token. The token encodes:

```go
type JwtTunnelConfig struct {
    ID       string        // Unique UUID for the tunnel request
    Protocol LocalProtocol // The protocol being tunneled (tcp, udp, socks5, ...)
    Remote   string        // Destination hostname
    Port     uint16        // Destination port
}
```

**Client-side:** The client calls `generateJWT()` to sign a token using the configured `jwt_secret`. If no secret is configured, a built-in default is used (with a warning logged).

**Server-side:** The server calls `parseJWTClaims()`, with behaviour determined by the `--mode` flag:
- In `legacy` mode: The JWT is parsed but **not cryptographically verified** (only the HS256 shape is checked).
- In `ws` mode: The JWT is **verified** using the configured `jwt_secret`. If `--insecure-no-jwt-validation` is set, it falls back to unverified parsing.

---

### 3. Client Tunnel Types (`pkg/client/client.go`)

After a tunnel stream is established, the client's `StartTunnel()` method dispatches to a type-specific handler:

```
StartTunnel(ltr)
├── ltr.Protocol.Stdio   → runStdioTunnel()   — pipes stdin/stdout
├── ltr.Protocol.Udp     → runUdpTunnel()     — UDP datagram forwarding
├── ltr.Protocol.Socks5  → runSocks5Tunnel()  — SOCKS5 proxy negotiation
├── ltr.Protocol.HttpProxy→ runHttpProxyTunnel()— HTTP CONNECT proxy
├── ltr.Protocol.Unix    → runUnixTunnel()    — Unix domain socket listener
└── (default)            → runTcpTunnel()     — TCP port forwarding
```

For **reverse tunnels**, `StartReverseTunnel()` connects to the server and waits for the server to initiate a connection. The server's `ReverseTunnelManager` tracks these sessions.

---

### 4. Server Request Handling (`pkg/server/server.go`)

The server runs a single `http.ServeMux` that handles all incoming requests in `ServeHTTP()`. Every request goes through the following pipeline:

```
HTTP Request
    │
    ├─ 1. Path Prefix Check  (if configured)
    │
    ├─ 2. Extract JWT        (from Sec-WebSocket-Protocol or Cookie header)
    │
    ├─ 3. Parse & Validate JWT
    │
    ├─ 4. Apply Restriction Rules  (if configured)
    │
    └─ 5. Dispatch
           ├─ HTTP/2 request (ProtoAtLeast 2.0, no Upgrade header) → handleHttp2Connection()
           ├─ WebSocket (--mode ws) → handleGorillaConnection()
           └─ WebSocket (--mode legacy) → handleConnection()
```

The server automatically handles both WebSocket and HTTP/2 on the same port using `h2c.NewHandler` (HTTP/2 cleartext).

---

### 5. Connection Pool (`pkg/client/pool.go`)

When `--connection-min-idle N` is set, the client pre-establishes and caches `N` raw TCP connections to the server. This reduces the per-tunnel handshake latency, as new tunnel streams can reuse an already-established TCP connection without a fresh DNS lookup and TCP three-way handshake.

---

### 6. Bidirectional Pipe (`pkg/tunnel/pipe.go`)

The `tunnel` package provides low-level goroutine-based piping utilities:

| Function | Description |
|---|---|
| `Pipe(net.Conn, *wst.Conn)` | Pipes between a TCP conn and the custom wst WebSocket |
| `PipeGorilla(net.Conn, *websocket.Conn)` | Pipes between a TCP conn and a Gorilla WebSocket |
| `PipeRW(io.ReadWriteCloser, *wst.Conn)` | Pipes between any `ReadWriteCloser` and wst WebSocket |
| `PipeGorillaRW(io.ReadWriteCloser, *websocket.Conn)` | Pipes between any `ReadWriteCloser` and Gorilla WebSocket |
| `PipeBiDir(rwc1, rwc2 io.ReadWriteCloser)` | Generic bidirectional pipe between two `ReadWriteCloser`s |

Each function spawns two goroutines — one for each direction — and uses a `sync.WaitGroup` to block until both directions close.

---

### 7. Restriction Rules (`pkg/server/restrictions.go`)

The server supports a YAML-based restriction file (`--restrict-config rules.yaml`). Rules define:
- **`match`**: which incoming requests to apply the rule to (by path prefix or `any: true`)
- **`allow`**: which tunnel destinations are permitted (by host regex and port range)

Example `rules.yaml`:
```yaml
restrictions:
  - name: "Allow only internal services"
    match:
      - path_prefix: "/v1"
    allow:
      - tunnel:
          host: "^db\\.internal$"
          port: [{ min: 5432, max: 5432 }]
```

---

### 8. Reverse Tunnel Manager (`pkg/server/manager.go`)

Reverse tunnels work differently from forward tunnels. When the client requests a reverse tunnel:

1. The **client** connects to the server's WebSocket/HTTP2 endpoint with a `ReverseTcp` protocol claim.
2. The **server's** `ReverseTunnelManager` registers this session.
3. The **server** listens on a local port and when a connection arrives, it signals the client through the existing WebSocket to open a new tunnel connection back.

The `ReverseTunnelManager` tracks sessions per tunnel ID and handles idle timeouts (`--remote-to-local-server-idle-timeout`, default 3 min).

---

## Data Flow Example: SSH over WarpStream

```
Local Machine (Restricted)         Remote Server (Unrestricted)
─────────────────────────          ────────────────────────────
ssh → 127.0.0.1:2222               Target: 192.168.1.10:22
           │
     warpstream client
     -L tcp://2222:192.168.1.10:22
     wss://my-server.com
           │
           │ 1. Accept TCP conn from SSH
           │ 2. Generate JWT: {proto: tcp, remote: 192.168.1.10, port: 22}
           │ 3. Dial wss://my-server.com/v1/events
           │    Header: Sec-WebSocket-Protocol: v1, bearer.<jwt>
           │────────── WebSocket Upgrade ──────────▶
           │                                        │
           │                              4. Parse JWT
           │                              5. Dial 192.168.1.10:22
           │                              6. Pipe WebSocket ↔ TCP(22)
           │
           │◀───────── Bidirectional Data ─────────▶
           │
     7. Pipe local TCP(2222) ↔ WebSocket
           │
    SSH Client receives data
```

---

## Security Considerations

- **JWT tokens** are scoped to a single tunnel destination (host + port + protocol). They cannot be reused for other destinations.
- **mTLS** (`--tls-client-ca-certs`) enables mutual certificate authentication between client and server.
- **ECH** (Encrypted Client Hello) can be enabled with `--tls-ech-enable` to hide the SNI from network observers.
- **Restriction rules** enforce allowlists on the server side, preventing the tunnel from being abused to reach unauthorized destinations.
- **Constant-time comparison** is used for SOCKS5 and HTTP proxy credential checks to prevent timing attacks.

---

## Key Dependencies

| Package | Purpose |
|---|---|
| `github.com/golang-jwt/jwt/v5` | JWT signing and parsing |
| `github.com/gorilla/websocket` | RFC 6455 compliant WebSocket (used in `--mode ws`) |
| `golang.org/x/net/http2` | HTTP/2 transport and h2c (cleartext HTTP/2) |
| `github.com/google/uuid` | Unique tunnel request IDs |
| `github.com/urfave/cli/v2` | CLI argument parsing |
| `gopkg.in/yaml.v3` | YAML configuration file parsing |
| `log/slog` | Structured logging (standard library, Go 1.21+) |
