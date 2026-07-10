# WarpStream

**Move any traffic through a single WebSocket.**

WarpStream is a high-performance tunneling engine written in Go. It hides arbitrary TCP, UDP, SOCKS5, and HTTP-proxy traffic inside ordinary WebSocket or HTTP/2 streams — the kind of traffic every firewall, corporate proxy, and DPI box already lets through. If a network permits HTTPS, it permits WarpStream.

It ships as a single static binary, runs as either end of a tunnel, and drops in as a Go library when you want to build tunneling into your own software.

---

## Why WarpStream

- **Goes where plain sockets can't.** Restrictive gateways see nothing but a long-lived WebSocket or an HTTP/2 POST. Your SSH session, database connection, game traffic, or WireGuard handshake rides inside it.
- **Speaks a lot of protocols.** TCP, UDP, SOCKS5, HTTP CONNECT, Unix sockets, stdio, and Linux transparent proxying — forward or reverse.
- **Built for scale.** Every tunnel is a handful of goroutines. Thousands of concurrent connections stay cheap.
- **Secure by construction.** TLS and mTLS, ECH, JWT-authenticated tunnels, and server-side rules that decide exactly what a client is allowed to reach.
- **Operator-friendly.** Structured `slog` logging, hot-reloadable certificates, self-signed bootstrap, systemd and Windows service tooling, and a Caddy module.
- **Embeddable.** Clean package layout so `pkg/client`, `pkg/server`, and `pkg/protocol` compose into your own binaries.

---

## Quickstart

Grab a binary from [Releases](https://github.com/DsThakurRawat/WarpStream/releases), or build it yourself:

```bash
git clone https://github.com/DsThakurRawat/WarpStream.git
cd WarpStream
make build          # -> ./bin/warpstream
# or: go build -o warpstream ./cmd/warpstream   (needs Go 1.25+)
```

Stand up a server, then reach a service through it:

```bash
# On the far side of the firewall:
warpstream server --tls wss://0.0.0.0:8443

# On your machine — expose the remote's Postgres on a local port:
warpstream client -L tcp://5432:db.internal:5432 wss://gateway.example.com:8443
```

`psql -h 127.0.0.1 -p 5432` now talks to `db.internal:5432`, tunneled over TLS-wrapped WebSocket.

---

## What you can tunnel

A tunnel is written as `scheme://[listen:]host:port[?options]`.

### Forward tunnels (`-L`) — listen locally, exit at the server

```bash
# Local SOCKS5 proxy, everything routed out through the server
warpstream client -L socks5://127.0.0.1:1080 wss://gateway.example.com

# Local HTTP CONNECT proxy
warpstream client -L http://127.0.0.1:3128 wss://gateway.example.com

# Point a single local port at one remote destination
warpstream client -L tcp://8080:example.com:443 wss://gateway.example.com

# UDP, e.g. DNS — reclaim idle sessions after 15s
warpstream client -L "udp://5353:1.1.1.1:53?timeout_sec=15" wss://gateway.example.com

# Hand the real client IP to the backend with a PROXY v2 header
warpstream client -L "tcp://8080:backend.internal:80?proxy_protocol" wss://gateway.example.com

# Unix socket -> remote unix socket; and stdio (great as an SSH ProxyCommand)
warpstream client -L unix:///tmp/local.sock:/var/run/app.sock wss://gateway.example.com
warpstream client -L stdio://remote-host:22 wss://gateway.example.com
```

**Schemes:** `tcp`, `udp`, `socks5`, `http`, `unix`, `stdio`, `tproxy+tcp`, `tproxy+udp`.

**Query options:**

| Option | Effect |
| :--- | :--- |
| `?proxy_protocol` | Prepend a HAProxy PROXY v2 header to the target (TCP forward tunnels), so backends log the originating client. |
| `?timeout_sec=N` | Idle timeout for UDP sessions, seconds. Default `30`; `0` disables. |
| `?login=U&password=P` | Credentials required by a `socks5` / `http` proxy listener. |

### Reverse tunnels (`-R`) — listen on the server, exit at the client

```bash
# Expose the client's local web server on the server's port 8080
warpstream client -R tcp://8080:127.0.0.1:80 wss://gateway.example.com

# Turn the client into an exit node: a SOCKS5 proxy on the server,
# dynamic destinations dialed from the client's network
warpstream client -R socks5://0.0.0.0:1080 wss://gateway.example.com

# Same idea over HTTP CONNECT
warpstream client -R http://0.0.0.0:3128 wss://gateway.example.com
```

**Reverse schemes:** `tcp`, `udp`, `unix`, `socks5`, `http`.

> **Heads-up on dynamic reverse tunnels.** Reverse `udp`, `socks5`, and `http` carry the per-connection target in an in-band frame between WarpStream's own client and server. They work **Go-to-Go only** — the same way `--mode ws` does — and are not wire-compatible with other implementations. Static reverse `tcp`/`unix` are fully interoperable.

### Transparent proxy (Linux)

`tproxy+tcp` and `tproxy+udp` intercept traffic without the application knowing. They need Linux, `CAP_NET_ADMIN` (or root), and an iptables rule pointing at the listener:

```bash
warpstream client -L tproxy+tcp://0.0.0.0:1234 wss://gateway.example.com
```

```bash
# True TPROXY (mark-based) on port 1234:
iptables -t mangle -A PREROUTING -p tcp --dport 80 \
  -j TPROXY --on-port 1234 --tproxy-mark 0x1/0x1
ip rule add fwmark 0x1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100
```

`-j REDIRECT` (DNAT) setups work too — WarpStream reads the original destination from the socket and falls back to `SO_ORIGINAL_DST` when needed. UDP recovers each datagram's original destination via `IP_RECVORIGDSTADDR`.

---

## TLS and security

```bash
# Bootstrap TLS instantly with an in-memory self-signed certificate
warpstream server --tls wss://0.0.0.0:8443

# Bring your own certificate and require client certs (mTLS)
warpstream server \
  --tls-certificate cert.pem --tls-private-key key.pem \
  --tls-client-ca-certs ca.pem \
  --restrict-config rules.yaml wss://0.0.0.0:8443

# Rotate certificates without downtime — replace the files, then:
kill -HUP "$(pidof warpstream)"     # also picks up changes automatically within a few seconds
```

- **TLS / mTLS** — full verification, client certificates, both ends.
- **Self-signed bootstrap** — `--tls` with no cert/key generates an ephemeral certificate in memory; clients trust it or disable verification.
- **Hot-reload** — server and client certificates reload on file change (polling) or on `SIGHUP`. A bad reload is ignored and the last-good certificate stays live.
- **ECH & SNI control** — Encrypted Client Hello, plus SNI override or suppression.
- **JWT-authenticated tunnels** — every tunnel request is a signed token describing exactly what it may open.
- **Server-side rules** — a YAML policy restricts which destinations, ports, and path prefixes a client can use.

---

## Transports

WarpStream negotiates one of three carriers:

| Transport | Select with | Notes |
| :--- | :--- | :--- |
| WebSocket (default) | `ws://` / `wss://` | Battle-tested framing with deliberate deviations for broad compatibility. |
| Strict RFC 6455 | `--mode ws` | Standards-clean WebSocket; interoperates with generic Go WebSocket clients. |
| HTTP/2 | `http://` / `https://` | Full-duplex streaming over an HTTP/2 POST. |

---

## Deployment

**systemd** — template units manage client and server from config files:

```bash
# /etc/warpstream/client-myserver.yaml
sudo systemctl enable --now warpstream-client@myserver
# /etc/warpstream/server-main.yaml
sudo systemctl enable --now warpstream-server@main
```

**Windows** — register a background task with the bundled PowerShell scripts:

```powershell
.\packaging\windows\install.ps1 -ConfigPath "C:\path\client.yaml" -BinaryPath "C:\path\warpstream.exe"
.\packaging\windows\control.ps1 -Action start
```

**Caddy** — build WarpStream into Caddy and let it terminate TLS (including mTLS):

```bash
xcaddy build --with github.com/DsThakurRawat/WarpStream/pkg/caddy
```

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

**Packages** — `.deb`, `.rpm`, and `.apk` are attached to each release. **Docker** images are on the roadmap.

---

## Configuration

Configure by flags, environment, or a YAML file (`--config`).

<details>
<summary><b>Global flags</b></summary>

- `--config` — path to a YAML config file.
- `--log-lvl` — `TRACE` … `ERROR` / `OFF` (default `INFO`).
- `--no-color` — plain log output.
- `--nb-worker-threads` — accepted for compatibility (`TOKIO_WORKER_THREADS`); a no-op in Go.

</details>

<details>
<summary><b>Client flags</b></summary>

- `-L, --local-to-remote`, `-R, --remote-to-local` — define tunnels.
- `--mode` — `rust` (default) or `ws` (strict RFC 6455).
- `--http-upgrade-path-prefix` — upgrade path prefix (default `v1`).
- `--jwt-secret` — secret used to sign tunnel JWTs.
- `--http-upgrade-credentials`, `-H, --header`, `--http-headers-file` — customize the upgrade request.
- `--tls-verify-certificate`, `--tls-certificate`, `--tls-private-key` — verification and client mTLS (hot-reloaded).
- `--tls-sni-override`, `--tls-sni-disable`, `--tls-ech-enable` — SNI and ECH control.
- `--http-proxy`, `--http-proxy-login`, `--http-proxy-password` — dial through an HTTP proxy.
- `--connection-min-idle`, `--connection-retry-max-backoff`, `--reverse-tunnel-connection-retry-max-backoff` — pooling and retry.
- `--socket-so-mark` — (Linux) `SO_MARK` on outgoing sockets.
- `--dns-resolver`, `--dns-resolver-prefer-ipv4` — resolver control.
- `--websocket-ping-frequency`, `--websocket-mask-frame` — keep-alive and frame masking.

</details>

<details>
<summary><b>Server flags</b></summary>

- `--mode` — `rust` (default) or `ws`.
- `--restrict-to`, `-r, --restrict-http-upgrade-path-prefix`, `--restrict-config` — access policy.
- `--jwt-secret` — verifies tunnel JWT signatures under `--mode ws`. Under `--mode rust`, tokens are parsed Rust-style and not cryptographically verified.
- `--insecure-no-jwt-validation` — accept unverified HS256 tokens even in `--mode ws`.
- `--tls` — serve TLS; generate an ephemeral self-signed cert if none is supplied.
- `--tls-certificate`, `--tls-private-key` — server cert/key (hot-reloaded on change or `SIGHUP`).
- `--tls-client-ca-certs` — enable mTLS.
- `--socket-so-mark`, `--dns-resolver`, `--dns-resolver-prefer-ipv4` — networking.
- `--websocket-ping-frequency`, `--websocket-mask-frame` — WebSocket behavior.
- `--http-proxy`, `--http-proxy-login`, `--http-proxy-password` — route server-side dials through a proxy.
- `--remote-to-local-server-idle-timeout` — reap idle reverse-tunnel listeners.

</details>

```yaml
# config.yaml  ->  warpstream --config config.yaml
mode: client            # or: server
log_lvl: INFO
client:
  remote_addr: wss://gateway.example.com
  local_to_remote:
    - "tcp://8080:example.com:443"
    - "socks5://127.0.0.1:1080"
server:
  listen_addr: ws://0.0.0.0:8080
  restrict_config: /etc/warpstream/rules.yaml
```

---

## As a library

```go
import (
    "github.com/DsThakurRawat/WarpStream/pkg/client"
    "github.com/DsThakurRawat/WarpStream/pkg/protocol"
)

func main() {
    c := client.NewClient(client.Config{
        ServerURL:  "wss://gateway.example.com",
        PathPrefix: "v1",
    })

    ltr, _ := client.ParseTunnelArg("tcp://8080:example.com:443", false)
    go c.StartTunnel(ltr)

    select {}
}
```

---

## Compatibility and status

WarpStream implements the wstunnel wire protocol, so it interoperates with existing wstunnel deployments for all forward tunnels and static reverse (TCP/Unix) tunnels. Dynamic reverse tunnels are a Go-native extension and stay within the WarpStream client/server pair.

| Capability | Status | Cross-implementation |
| :--- | :---: | :---: |
| TCP forward / reverse | ✅ | ✅ |
| UDP forward | ✅ | ✅ |
| UDP reverse | ✅ | ⚠️ WarpStream ↔ WarpStream |
| SOCKS5 forward | ✅ | ✅ |
| SOCKS5 reverse | ✅ | ⚠️ WarpStream ↔ WarpStream |
| HTTP CONNECT forward | ✅ | ✅ |
| HTTP CONNECT reverse | ✅ | ⚠️ WarpStream ↔ WarpStream |
| Unix sockets / stdio | ✅ | ✅ |
| Transparent proxy (Linux TCP/UDP) | ✅ | ✅ |
| PROXY protocol injection (`?proxy_protocol`) | ✅ | ✅ |
| UDP idle timeout (`?timeout_sec`) | ✅ | ✅ |
| mTLS | ✅ | ✅ |
| Ephemeral self-signed TLS (`--tls`) | ✅ | N/A |
| Certificate hot-reload (poll + SIGHUP) | ✅ | N/A |
| ECH (Encrypted Client Hello) | ✅ | ✅ |
| HTTP/2 transport | ✅ | ✅ |
| JWT authentication | ✅ | ✅ |
| YAML restriction rules | ✅ | ✅ |

**Performance.** Expect throughput on par with native connections and sub-millisecond added latency; idle memory sits around ~20 MB (Go runtime and goroutine stacks). Numbers are workload- and environment-dependent — measure on your own path.

---

## Contributing

1. `make fmt` — format.
2. `make lint && make vet` — static analysis.
3. `make test` — unit and integration tests.
4. `make test-interop` — run this whenever you touch protocol code.

Pull requests welcome.

## License

MIT — see [LICENSE](LICENSE).
