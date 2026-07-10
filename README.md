# warpstream

A feature-complete Go implementation of [warpstream](https://github.com/erebe/warpstream), designed for high performance, ease of use, and library integration.

`warpstream` allows you to tunnel any traffic through a WebSocket or HTTP/2 connection, effectively bypassing restrictive firewalls and proxies that only allow HTTP/HTTPS traffic.

## Features

-   **Protocol Support**:
    -   **TCP**: Reliable stream tunneling.
    -   **UDP**: Datagram tunneling with state tracking.
    -   **SOCKS5**: Local SOCKS5 proxy (with optional authentication).
    -   **HTTP Proxy**: Local HTTP CONNECT proxy (with optional authentication).
    -   **Unix Domain Sockets**: Tunneling to/from local unix sockets.
    -   **Stdio**: Tunneling via standard input/output.
-   **TProxy Support**: Transparent proxying for TCP and UDP on Linux (requires root/`CAP_NET_ADMIN`). TCP works with both `-j TPROXY` (via `LocalAddr()`) and `-j REDIRECT` (via `SO_ORIGINAL_DST`); UDP recovers the per-datagram original destination via `IP_RECVORIGDSTADDR`.
-   **Reverse Tunneling**: Server-to-client tunnels.
    -   **Rust-compatible**: static reverse **TCP** and reverse **Unix** sockets.
    -   **Go-to-Go only**: dynamic reverse **UDP**, **SOCKS5**, and **HTTP CONNECT** proxies. These use an in-band target frame (like `--mode ws`, they interoperate between Go client and Go server only, not with the Rust implementation).
-   **Transports**:
    -   **WebSocket-like transport**: Secure WebSocket-style transport (default) with intentional RFC 6455 deviations for compatibility with the original Rust implementation.
    -   **RFC 6455 compliant WebSocket**: Enable strict RFC 6455 compliance with `--mode ws` (compatible with standard Go clients).
    -   **HTTP/2**: Full-duplex streaming over HTTP/2.
-   **Deployment**:
    -   **Systemd**: Ready-to-use systemd unit templates for Linux.
    -   **Windows Task Scheduler**: PowerShell scripts for easy deployment as a background task on Windows.
    -   **Docker**: (Coming soon) Ready-to-use Docker images.
-   **Security**:
    -   **TLS (wss://, https://)**: Full TLS support with certificate verification.
    -   **mTLS**: Support for client certificates and private keys.
    -   **Ephemeral self-signed certificate**: Start a TLS server with `--tls` and no cert/key to auto-generate an in-memory self-signed certificate (clients must trust it or disable verification).
    -   **Certificate hot-reload**: Reload server and client TLS certificates without a restart — automatically via file-change polling, or on demand by sending `SIGHUP`. A failed reload keeps the last-good certificate.
    -   **ECH (Encrypted Client Hello)**: Enable ECH for enhanced privacy.
    -   **SNI Control**: Override or disable Server Name Indication.
    -   **JWT Authentication**: Fully compatible with the original Rust implementation's JWT-based auth.
    -   **Restriction Rules**: Server-side YAML configuration to restrict allowed tunnel destinations and path prefixes.
-   **Advanced Networking**:
    -   **SO_MARK**: (Linux only) Support for marking outgoing packets.
    -   **DNS Control**: Custom DNS resolvers and IPv4/IPv6 preference.
    -   **Proxy Support**: Connect through HTTP/HTTPS proxies (with authentication).
    -   **PROXY Protocol**: Server-side injection of a HAProxy PROXY v2 header to the target (via `?proxy_protocol`) so backends see the originating client address.
    -   **UDP session timeout**: Idle UDP sessions are reclaimed after `?timeout_sec` (default 30s) on both client and server.
-   **Modern Architecture**:
    -   **Highly Concurrent**: Leverages Go's goroutines for efficient handling of many simultaneous tunnels.
    -   **Structured Logging**: Uses `log/slog` for modern, structured logging.
    -   **Library First**: Designed as a library for easy integration into other Go projects.
-   **Interoperability**: Maintains protocol compatibility and CLI parity with the original Rust implementation for all forward tunnels and static reverse (TCP/Unix) tunnels. Dynamic reverse tunnels (UDP/SOCKS5/HTTP) are a Go-to-Go extension and do not interoperate with the Rust implementation.

## Installation

### Prerequisites

-   **Go version 1.25** or above.
-   `make` (optional, for convenient building).

### Build from Source

```bash
git clone https://github.com/DsThakurRawat/WarpStream.git
cd warpstream
make build
# Binary will be available in ./bin/warpstream
```

Alternatively, using standard Go commands:

```bash
go build -o warpstream ./cmd/warpstream
```

### Download Pre-built Binaries and Packages

Binaries for various platforms (Linux, macOS, Windows) and distribution packages (`.deb`, `.rpm`, `.apk`) are available on the [Releases](https://github.com/DsThakurRawat/WarpStream/releases) page.

### Installation via Package Manager (Linux)

For Debian/Ubuntu-based systems:
```bash
sudo dpkg -i warpstream_amd64.deb
```

### Systemd Integration (Linux)

`warpstream` provides systemd template units for easy management of client and server instances.

1.  Place your configuration YAML file in `/etc/warpstream/client-myserver.yaml`.
2.  Enable and start the service:
    ```bash
    sudo systemctl enable --now warpstream-client@myserver
    ```

For the server:
1.  Place your configuration YAML file in `/etc/warpstream/server-main.yaml`.
2.  Enable and start the service:
    ```bash
    sudo systemctl enable --now warpstream-server@main
    ```

### Windows Task Scheduler Integration

Use the provided PowerShell scripts in the `packaging/windows` directory to register `warpstream` as a background task.

```powershell
# In an elevated PowerShell session:
.\packaging\windows\install.ps1 -ConfigPath "C:\path\to\your\client.yaml" -BinaryPath "C:\path\to\warpstream.exe"

# Control the task:
.\packaging\windows\control.ps1 -Action start
```

### Caddy Integration (Server)

`warpstream` can be built into Caddy server as an HTTP handler.

1.  Build Caddy with `warpstream` module:
    ```bash
    xcaddy build --with github.com/DsThakurRawat/WarpStream/pkg/caddy
    ```

2.  Configure in `Caddyfile`:
    ```caddyfile
    {
        order warpstream before reverse_proxy
    }

    example.com {
        route /warpstream/* {
            warpstream {
                prefix /warpstream
                mode rust
                # restrict_config /etc/warpstream/rules.yaml
            }
        }
    }
    ```

`warpstream` in Caddy automatically leverages Caddy's TLS termination, including mTLS.

## Usage

### Client Mode

`warpstream` provides a CLI that mirrors the original tool's arguments.

```bash
# Forward local SOCKS5 to remote server
warpstream client -L socks5://127.0.0.1:1080 wss://my-server.com

# Forward local port to remote destination
warpstream client -L tcp://8080:google.com:443 wss://my-server.com

# Reverse tunnel: remote server port 8080 forwards to local 127.0.0.1:80
warpstream client -R tcp://8080:127.0.0.1:80 wss://my-server.com

# Reverse SOCKS5 proxy (Go-to-Go only): server exposes a SOCKS5 listener on :1080,
# dynamic destinations are dialed from the client's network
warpstream client -R socks5://0.0.0.0:1080 wss://my-server.com

# Reverse HTTP CONNECT proxy (Go-to-Go only)
warpstream client -R http://0.0.0.0:3128 wss://my-server.com

# Preserve the client IP to the backend via a PROXY v2 header
warpstream client -L "tcp://8080:backend.internal:80?proxy_protocol" wss://my-server.com

# UDP tunnel with a 15s idle-session timeout
warpstream client -L "udp://5353:1.1.1.1:53?timeout_sec=15" wss://my-server.com

# Transparent proxy (Linux, needs CAP_NET_ADMIN + an iptables rule — see below)
warpstream client -L tproxy+tcp://0.0.0.0:1234 wss://my-server.com

# Use HTTP/2 transport
warpstream client -L tcp://8080:google.com:443 https://my-server.com

# Use custom DNS resolver and prefer IPv4
warpstream client --dns-resolver 8.8.8.8 --dns-resolver-prefer-ipv4 -L tcp://8080:google.com:443 wss://my-server.com
```

#### Tunnel address syntax

Tunnels are `scheme://[bind_or_listen:]host:port[?options]`. Supported schemes: `tcp`,
`udp`, `socks5`, `http`, `unix`, `stdio`, `tproxy+tcp`, `tproxy+udp` (forward, via `-L`);
`tcp`, `udp`, `unix`, `socks5`, `http` (reverse, via `-R`). Query options:

-   `?proxy_protocol` — prepend a HAProxy PROXY v2 header to the target connection (TCP forward tunnels).
-   `?timeout_sec=N` — idle timeout in seconds for UDP sessions (default 30).
-   `?login=USER&password=PASS` — credentials for `socks5`/`http` proxy listeners.

#### Transparent proxy (TPROXY) setup

`tproxy+tcp` / `tproxy+udp` require Linux, `CAP_NET_ADMIN` (or root), and an iptables
rule to redirect traffic to the listener. Example for true TPROXY on port `1234`:

```bash
iptables -t mangle -A PREROUTING -p tcp --dport 80 \
  -j TPROXY --on-port 1234 --tproxy-mark 0x1/0x1
ip rule add fwmark 0x1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100
```

`-j REDIRECT` (DNAT) setups are also supported — the client falls back to
`SO_ORIGINAL_DST` when the original destination is not in `LocalAddr()`.

### Server Mode

```bash
# Start a basic server listening on port 8080
warpstream server ws://0.0.0.0:8080

# Start a TLS server with an auto-generated ephemeral self-signed certificate
warpstream server --tls wss://0.0.0.0:8443

# Start server with mTLS and restriction rules
warpstream server --tls-certificate cert.pem --tls-private-key key.pem --tls-client-ca-certs ca.pem --restrict-config rules.yaml

# Reload the server's TLS certificate in place after replacing the files on disk
kill -HUP "$(pidof warpstream)"   # also reloads automatically within a few seconds
```

## Configuration

`warpstream` can be configured via command-line flags, environment variables, or a YAML configuration file.

### CLI Flags

#### Global Flags
-   `--config`: Path to YAML configuration file.
-   `--log-lvl`: Log verbosity (TRACE, DEBUG, INFO, WARN, ERROR, OFF). Default: INFO.
-   `--no-color`: Disable color output.
-   `--nb-worker-threads`: Number of worker threads (environment variable: `TOKIO_WORKER_THREADS`).

#### Client Flags
-   `-L, --local-to-remote`: Define a local-to-remote tunnel.
-   `-R, --remote-to-local`: Define a remote-to-local (reverse) tunnel.
-   `--mode`: Transport mode, `rust` (default, Rust-compatible) or `ws` (strict RFC 6455).
-   `--http-upgrade-path-prefix`: HTTP upgrade path prefix (default: "v1").
-   `--jwt-secret`: Shared secret used to sign tunnel JWTs.
-   `--http-upgrade-credentials`: Basic auth credentials for upgrade request.
-   `-H, --header`: Custom HTTP headers for upgrade request.
-   `--http-headers-file`: File containing custom HTTP headers.
-   `--tls-verify-certificate`: Enable/disable TLS cert verification.
-   `--tls-certificate`, `--tls-private-key`: Client certificate/key for mTLS (hot-reloaded on change).
-   `--tls-sni-override`: Override SNI domain.
-   `--tls-sni-disable`: Disable sending SNI.
-   `--tls-ech-enable`: Enable ECH.
-   `--http-proxy`, `--http-proxy-login`, `--http-proxy-password`: Route the connection through an HTTP proxy.
-   `--connection-min-idle`: Maintain a pool of idle connections.
-   `--connection-retry-max-backoff`: Maximum retry backoff for server connection.
-   `--reverse-tunnel-connection-retry-max-backoff`: Maximum retry backoff for reverse tunnels.
-   `--socket-so-mark`: (Linux) Set `SO_MARK` on outgoing sockets.
-   `--dns-resolver`: Custom DNS resolver(s).
-   `--dns-resolver-prefer-ipv4`: Prioritize IPv4 for DNS lookup.
-   `--websocket-ping-frequency`: Frequency of WebSocket pings.
-   `--websocket-mask-frame`: Enable masking of WebSocket frames.

#### Server Flags
-   `--mode`: Transport mode, `rust` (default) or `ws` (strict RFC 6455).
-   `--restrict-to`: Restrict tunnels to specific destinations.
-   `-r, --restrict-http-upgrade-path-prefix`: Restrict tunnels to specific path prefixes.
-   `--jwt-secret`: Shared secret used to verify tunnel JWT signatures when running with `--mode ws`. In `--mode rust`, tunnel JWTs are parsed in Rust-compatible mode and are not cryptographically verified.
-   `--insecure-no-jwt-validation`: Allow Rust-compatible parsing of HS256 tunnel JWTs without signature verification in situations where `--mode ws` would otherwise reject them.
-   `--restrict-config`: Path to a YAML file with restriction rules.
-   `--tls`: Serve TLS; if no cert/key is provided, generate an ephemeral self-signed certificate.
-   `--tls-certificate`, `--tls-private-key`: Paths to TLS cert/key for the server (hot-reloaded on change or `SIGHUP`).
-   `--tls-client-ca-certs`: Enable mTLS by providing CA certificates to verify clients.
-   `--socket-so-mark`: (Linux) Set `SO_MARK` on outgoing sockets.
-   `--dns-resolver`, `--dns-resolver-prefer-ipv4`: Custom DNS resolver settings.
-   `--websocket-ping-frequency`, `--websocket-mask-frame`: WebSocket keep-alive / frame masking.
-   `--http-proxy`, `--http-proxy-login`, `--http-proxy-password`: Route server-side dials through an HTTP proxy.
-   `--remote-to-local-server-idle-timeout`: Idle timeout for reverse tunnel server.

### YAML Configuration Example

```yaml
mode: client # or server
log_lvl: INFO
no_color: false
client:
  remote_addr: wss://my-server.com
  local_to_remote:
    - "tcp://8080:google.com:443"
    - "socks5://127.0.0.1:1080"
server:
  listen_addr: ws://0.0.0.0:8080
  restrict_config: /etc/warpstream/rules.yaml
```

## API Reference (Library Usage)

`warpstream` is built with a modular design, making it easy to use as a library.

```go
import (
    "github.com/DsThakurRawat/WarpStream/pkg/client"
    "github.com/DsThakurRawat/WarpStream/pkg/protocol"
)

func main() {
    config := client.Config{
        ServerURL: "wss://my-server.com",
        PathPrefix: "v1",
        // ... other config
    }
    c := client.NewClient(config)

    ltr, _ := client.ParseTunnelArg("tcp://8080:google.com:443", false)
    go c.StartTunnel(ltr)

    select {}
}
```

## Status & Interoperability

`warpstream` aims for 100% parity with the [Rust version](https://github.com/erebe/warpstream).

| Feature | Status | Interop (Rust) |
| :--- | :---: | :---: |
| TCP Forward/Reverse | ✅ | ✅ |
| UDP Forward | ✅ | ✅ |
| UDP Reverse | ✅ | ⚠️ Go-to-Go only |
| SOCKS5 Forward | ✅ | ✅ |
| SOCKS5 Reverse | ✅ | ⚠️ Go-to-Go only |
| HTTP Proxy (CONNECT) | ✅ | ✅ |
| Reverse HTTP Proxy | ✅ | ⚠️ Go-to-Go only |
| Unix Sockets | ✅ | ✅ |
| Stdio Tunneling | ✅ | ✅ |
| YAML Restrictions | ✅ | ✅ |
| mTLS | ✅ | ✅ |
| Ephemeral self-signed TLS (`--tls`) | ✅ | N/A |
| TLS cert hot-reload (poll + SIGHUP) | ✅ | N/A |
| PROXY protocol injection (`?proxy_protocol`) | ✅ | ✅ |
| UDP idle timeout (`?timeout_sec`) | ✅ | ✅ |
| HTTP/2 Transport | ✅ | ✅ |
| TProxy TCP/UDP (Linux) | ✅ | ✅ |
| ECH (Encrypted Client Hello) | ✅ | ✅ |
| JWT Authentication | ✅ | ✅ |

### Performance Metrics

| Metric | warpstream (Rust) | warpstream |
| :--- | :---: | :---: |
| Throughput (TCP) | ~ Gbps | ~ Gbps |
| Latency Overhead | < 1ms | < 1ms |
| Memory Usage (Idle) | ~ 10MB | ~ 20MB |

*Note: Benchmarks are environment-dependent. Go version typically shows slightly higher memory usage due to GC and goroutine stacks, but comparable throughput.*

### Compatibility Versions

-   **Rust warpstream**: v9.0.0+
-   **Go**: 1.25+

## Contributing

Contributions are welcome! Please ensure you follow the project's coding standards:
1.  Run `make fmt` to format code.
2.  Run `make lint` and `make vet` for static analysis.
3.  Ensure all tests pass with `make test`.
4.  Run `make test-interop` if you change protocol-related code.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
