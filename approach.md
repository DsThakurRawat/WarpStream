# Implementation Approach — Closing the Feature Gap

This document is the work order for finishing feature parity across tunnel protocols. It covers the six remaining
`[ ]` items in `TODO.md` plus an examples/tests pass. **Every task below is an
implementation task — write working code and prove it with tests, not prose.**
Each task is self-contained: goal, exact files/line anchors, step-by-step plan,
edge cases, tests, and acceptance criteria.

Do the tasks in section order (§1 → §7), which is already sorted lowest-risk /
highest-value first: **§1 PROXY protocol → §2 ephemeral cert → §3 UDP idle
timeout → §4 cert hot-reload → §5 TProxy → §6 reverse SOCKS5/HTTP → §7 examples +
CLI help + e2e coverage.** Ship each as its own commit with its own tests; do not
batch.

---

## 0. Shared conventions (read first)

These facts about the codebase constrain every task below.

1. **Three server data-path handlers must stay in sync.** The server forwards
   traffic in three near-identical functions in `pkg/server/server.go`:
   - `handleConnection`      (custom `wst` websocket)  — `:376`
   - `handleGorillaConnection` (RFC-6455 gorilla)       — `:423`
   - `handleHttp2Connection`  (HTTP/2)                  — `:469`

   Any change to server-side target dialing, PROXY-header emission, or UDP
   timeout logic **must be applied to all three**, or extracted into one shared
   helper that all three call. Prefer extracting a helper
   (e.g. `dialTarget(claims) (net.Conn, error)`) to eliminate the triplication
   as part of task #2.

2. **The client dispatches tunnels** in `StartTunnel`
   (`pkg/client/client.go:437`) and `StartReverseTunnel` (`:779`). Forward
   protocols each get a `run*Tunnel` method; the default fall-through is
   `runTcpTunnel`.

3. **Tunnel arg parsing** lives in `ParseTunnelArg`
   (`pkg/client/config.go:30`). Helpers `getTimeout`, `getCredentials`,
   `getProxyProtocol` already exist (`:51`–`:70`). The protocol structs are in
   `pkg/protocol/types.go`; the parsed `LocalProtocol` is serialized into the
   JWT (`JwtTunnelConfig`, `types.go:114`) and is what the server sees in
   `claims.Protocol`.

4. **Platform-specific syscalls** go in `internal/socket/` behind build tags:
   `socket_linux.go` (real) and `socket_others.go` (stubs returning an error).
   Follow the existing `SetSoMark` pattern. Never call `syscall.*` platform
   constants from cross-platform files.

5. **CLI flags** are registered in `cmd/warpstream/main.go` (client flags start
   `:234`, server flags `:362`) and mapped into the config structs in
   `runClient`/`runServer` and `main_test.go` (the test harness re-declares every
   flag — update it too or `TestParseFlags` breaks). Config-file keys are the
   `yaml:"..."` tags on `client.Config` / `server.Config`.

6. **Piping primitives** are in `pkg/tunnel/pipe.go`: `Pipe` (wst),
   `PipeGorilla`, `PipeBiDir` (h2/generic), plus `*RW` variants. New wrappers
   (idle-timeout conn, PROXY-header writer) should compose with these, not
   reimplement them.

7. **Rust interop is the default and must not regress.** Features that cannot be
   made wire-compatible with the Rust implementation (reverse SOCKS5/HTTP, see
   task #3) must be gated and documented as **Go-to-Go only**, exactly as
   `--mode ws` already is. Never change the default forward-tunnel wire format.

Run `make build && make test` (or `go build ./... && go test ./...`) green after
every task.

---

## 1. Task: PROXY protocol header injection (`?proxy_protocol`)

**Status today:** parsed only. `getProxyProtocol` (`config.go:68`) sets
`Tcp.ProxyProtocol` / `HttpProxy.ProxyProtocol` / `Stdio.ProxyProtocol` /
`Unix.ProxyProtocol`, these travel in the JWT claims, but **nothing writes a
PROXY header**. `grep -r ProxyProtocol pkg/server` is empty.

**Goal:** When a forward tunnel carries `proxy_protocol`, the **server** prepends
a HAProxy PROXY protocol header to the target connection *before* any tunneled
bytes, so the backend (SSH/nginx/HAProxy) sees the real source.

### Design
- The header is written **server-side**, because the server is what dials the
  target (`net.DialTimeout`, `server.go:399/445/501`).
- **Source address** to advertise: the remote address of the tunnel connection
  (the warpstream *client*), obtained from the underlying websocket/h2 request.
  - For `wst`/gorilla: use `wsConn.RemoteAddr()`.
  - For h2: capture `r.RemoteAddr` in `handleHttp2Connection` (it has the
    `*http.Request`).
  - **Fidelity note:** upstream advertises the address of the app that connected
    to the client's *local* listener. That address is not currently carried in
    the JWT. Implement the client-IP-of-tunnel approximation now; leave a
    `// TODO(proxy-protocol-fidelity)` and see "Optional fidelity upgrade" below.
- **Destination address:** the resolved target (`claims.Remote:claims.Port`).
- Default to **PROXY protocol v2** (binary; nginx/HAProxy both accept it).
  Support v1 too. Upstream uses `?proxy_protocol` as a boolean; keep that (v2
  default). If you want a knob, accept `?proxy_protocol=v1`, else v2.

### Steps
1. Add `pkg/tunnel/proxyproto.go` with:
   - `func WriteProxyHeaderV2(w io.Writer, src, dst net.Addr) error`
   - `func WriteProxyHeaderV1(w io.Writer, src, dst net.Addr) error`
   Implement the byte layout per the
   [PROXY protocol spec](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt)
   (v2 signature `\r\n\r\n\x00\r\nQUIT\n`, `0x21`, family/proto `0x11` TCP4 /
   `0x21` TCP6, addr block). Handle IPv4 and IPv6; skip (write nothing, return
   nil) for non-TCP addrs. No third-party dep required, but
   `github.com/pires/go-proxyproto` is acceptable if you prefer a vetted encoder.
2. Extract the triplicated forward-dial block from the three handlers into a
   single helper in `server.go`:
   ```go
   func (s *Server) dialAndMaybeProxyHeader(claims *protocol.JwtTunnelConfig, srcAddr net.Addr) (net.Conn, error)
   ```
   It dials the target, and if `claims.Protocol.Tcp.ProxyProtocol` (or the
   `HttpProxy`/`Unix`/`Stdio` equivalents) is true, writes the PROXY header to
   the freshly dialed conn before returning it. Only meaningful for TCP targets;
   skip for `udp`/`unix` unless src/dst are TCP.
3. Call the helper from all three handlers, passing the correct `srcAddr`.

### Edge cases
- UDP target + proxy_protocol: no-op (spec is TCP-oriented); log a debug line.
- Unix target: no-op.
- Ensure the header is written **once**, before `tunnel.Pipe*`, and counts as the
  first bytes on the wire.

### Tests
- Unit test `WriteProxyHeaderV2`/`V1` against known-good byte vectors for a v4
  and a v6 pair.
- Integration test (extend `tests/`): start a server + client `tcp://` tunnel
  with `?proxy_protocol`, back it with a tiny TCP listener that parses the PROXY
  v2 header, assert the parsed src/dst.

### Acceptance
- Backend receives a valid PROXY v2 (or v1) header; a tunnel **without**
  `?proxy_protocol` is byte-identical to today (no header). Rust-mode forward
  tunnels unaffected.

### Optional fidelity upgrade (do only if cheap)
Carry the client's local-listener peer address to the server. The cleanest
non-breaking route: the client sets a custom header
(`X-WarpStream-Src: ip:port`) in `connectToWarpStream`/`connectToHttp2`/
`connectToGorilla` when `ProxyProtocol` is set, and the server prefers it over
`RemoteAddr()`. Gate behind the same flag so default tunnels are untouched.

---

## 2. Task: Ephemeral self-signed TLS certificate on startup

**Status today:** server enables TLS **only** when both `--tls-certificate` and
`--tls-private-key` are provided (`server.go:246`). No auto-generation.

**Goal:** Allow starting a TLS server without supplying a cert/key by generating
an in-memory self-signed certificate at startup.

### Design
The current server has no explicit "I want TLS" signal other than cert presence.
Add one:
- New bool flag `--tls` (config key `tls: true`) meaning "serve TLS". Also treat
  "`--tls-client-ca-certs` set but no server cert" as implying TLS (mTLS still
  needs a server cert to present).
- Resolution order in `server.Run` (around `:246`):
  1. If `TlsCertificate` **and** `TlsPrivateKey` set → load from disk (today's
     path).
  2. Else if TLS is requested (`--tls`, or CA certs present) → generate ephemeral
     cert.
  3. Else → plaintext (today's default).

### Steps
1. Add `func generateSelfSignedCert(hosts []string) (tls.Certificate, error)` in
   a new `pkg/server/selfsigned.go`. Use `crypto/ecdsa` P-256 (or RSA-2048),
   `x509.CreateCertificate` with `KeyUsageDigitalSignature |
   KeyUsageKeyEncipherment`, `ExtKeyUsageServerAuth`, SANs for `localhost`,
   `127.0.0.1`, `::1`, plus the host part of `ListenAddr` if it's a hostname/IP.
   Validity ~1 year (avoid `Date.now`-style nondeterminism only matters for
   tests, real code uses `time.Now()` which is fine here). Reference the test
   helper at `pkg/client/client_auth_test.go:287` for the shape.
2. In `server.Run`, build `tlsConfig.Certificates = []tls.Certificate{cert}` from
   the generated cert and call `srv.ServeTLS(ln, "", "")` (empty file args are
   allowed when `Certificates` is populated), or set `GetCertificate`.
3. Add `Tls bool` to `server.Config` (`yaml:"tls"`), register `--tls` flag in
   `main.go` server flags + `main_test.go`, map it in `runServer`.
4. Log a clear `WARN` that an ephemeral self-signed cert is in use (clients must
   disable verification or trust it).

### Edge cases
- mTLS (`TlsClientCaCerts`) with generated server cert must still work
  (`ClientAuth = RequireAndVerifyClientCert` unchanged).
- Do not persist the key to disk.

### Tests
- Unit: `generateSelfSignedCert` returns a parseable cert whose SANs include
  `localhost`/`127.0.0.1`.
- Integration: start server with `--tls` and no cert; connect a client with
  `wss://` and cert verification disabled; assert a tunnel round-trips.

### Acceptance
- `warpstream server --tls` (no cert/key) serves working TLS; explicit cert/key
  still takes precedence; plaintext default unchanged.

---

## 3. Task: UDP tunnel inactivity timeout (`?timeout_sec=30`)

**Status today:** `timeout_sec` is parsed into `Udp.Timeout` /
`TProxyUdp.Timeout` (`config.go:51`, default 30s) and travels in claims, but the
value is **never enforced on forward UDP**. Server does
`net.DialTimeout("udp", ...)` then `tunnel.Pipe` — a UDP conn never returns a
read error on idle, so the tunnel and target socket live forever. The
client-side `runUdpTunnel` (`client.go:876`) only evicts a source on write error.
(The `idleTimeout` in `ReverseTunnelManager` is unrelated — it's for reverse
listeners.)

**Goal:** Expire idle UDP sessions after `timeout_sec` on both ends.

### Design
Introduce a small idle-deadline wrapper so existing pipes get free timeouts:
```go
// pkg/tunnel/idleconn.go
type idleConn struct { net.Conn; d time.Duration }
func (c idleConn) Read(b []byte) (int, error)  { c.SetReadDeadline(time.Now().Add(c.d)); return c.Conn.Read(b) }
func (c idleConn) Write(b []byte) (int, error) { c.SetWriteDeadline(time.Now().Add(c.d)); return c.Conn.Write(b) }
func IdleConn(c net.Conn, d time.Duration) net.Conn
```
A read timeout surfaces as an error → the existing pipe goroutines return and
close the session. Exactly the desired eviction.

### Steps — server (all three handlers / the shared dial helper from task #1)
1. When the target `network == "udp"` and `claims.Protocol.Udp.Timeout` (or
   `TProxyUdp.Timeout`) is set, wrap the dialed conn: `conn = tunnel.IdleConn(conn, d)`.
   Since `tunnel.Pipe` reads from `conn` in a loop, the deadline auto-resets each
   read; genuine idleness (> d) closes it.

### Steps — client (`runUdpTunnel`, `client.go:876`)
2. Track `lastActivity` per source in the `clients` map (make the map value a
   small struct `{ts *tunnelStream; last time.Time}` or a parallel map).
3. Start one janitor goroutine per listener: every `d/2`, sweep the map and for
   any entry idle > `d`, `delete` + `ts.Close()`. Read `d` from
   `ltr.Protocol.Udp.Timeout` (fallback 30s). Update `last` on each inbound
   packet (main loop) and on each outbound packet (the per-source read goroutine).
4. Guard all map access with the existing `mu`.

### Edge cases
- `timeout_sec=0` → treat as "no timeout" (don't wrap / don't sweep), matching
  the parser producing `Secs:0`. Decide and document: recommend 0 = disabled.
- Ensure closing a session from the janitor races cleanly with the per-source
  read goroutine's own `defer delete/Close` (both hold `mu`; `Close` is
  idempotent on `tunnelStream`).

### Tests
- Client-side: table test that a session absent from traffic for > timeout is
  removed from the map (inject a short timeout, assert map shrinks).
- Integration: UDP echo through the tunnel, stop sending, assert the server’s
  target-side socket is closed after ~timeout (observe via connection count or a
  closed-callback).

### Acceptance
- Idle UDP sessions are reclaimed within ~`timeout_sec` on both ends; active
  sessions are never dropped; `timeout_sec=0` disables expiry.

---

## 4. Task: TLS certificate hot-reload (fsnotify)

**Status today:** none. `srv.ServeTLS(ln, certFile, keyFile)` (`server.go:263`)
loads the cert once. Client mTLS cert is loaded once in `tlsClientConfig`.
`fsnotify` appears only in the Caddy submodule's `go.sum`.

**Goal:** Reload `--tls-certificate`, `--tls-private-key`, and
`--tls-client-ca-certs` (server) and client cert/key without restart.

### Design
Back the cert with an `atomic.Pointer[tls.Certificate]` and serve it via
`tls.Config.GetCertificate` (server) / `GetClientCertificate` (client). A
watcher reloads on file change and swaps the pointer atomically.

### Steps
1. `go get github.com/fsnotify/fsnotify` (add to root `go.mod`).
2. New `internal/tlsreload/reloader.go`:
   ```go
   type Reloader struct { certFile, keyFile string; cert atomic.Pointer[tls.Certificate] }
   func New(certFile, keyFile string) (*Reloader, error)   // initial load
   func (r *Reloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
   func (r *Reloader) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error)
   func (r *Reloader) Watch(ctx context.Context) error     // fsnotify loop, debounce ~200ms
   ```
   On a write/create/rename event, `LoadX509KeyPair` again; on success
   `cert.Store(&c)` and log; on failure log and keep the old cert.
3. Server (`server.go:246`): when cert+key files are set, build the reloader,
   set `tlsConfig.GetCertificate = r.GetCertificate`, drop the file args
   (`srv.ServeTLS(ln, "", "")`), and start `r.Watch` in a goroutine.
   Also watch `TlsClientCaCerts` and rebuild `tlsConfig.ClientCAs` on change
   (a small second watcher or fold into the same one).
4. Client (`tlsClientConfig`, in `pkg/client/transport.go`): when a client cert
   is configured, wire `GetClientCertificate` to a reloader and start its watch.
   (Search `tlsClientConfig` / `TlsClientCert` for the exact spot.)

### Edge cases
- Editors write via rename/replace → also handle `Create`/`Rename`, and re-add
  the watch on the file's directory (fsnotify loses the watch on the inode).
  Watching the parent dir and filtering by basename is the robust pattern.
- Debounce rapid multi-event saves.
- A bad reload must not crash or blank the cert — keep serving the last good one.

### Tests
- Unit: create temp cert A, start reloader, overwrite with cert B, assert
  `GetCertificate` returns B's serial within a short poll window.
- Skip on platforms where fsnotify is flaky in CI if needed (guard with build
  tag or `testing.Short`).

### Acceptance
- Overwriting the cert/key on disk swaps the served cert with no restart and no
  dropped listener; malformed input is ignored with a logged error.

---

## 5. Task: Linux transparent proxy (`tproxy+tcp://`, `tproxy+udp://`)

**Status today:** `config.go:200-203` parses the two schemes into
`TProxyTcp`/`TProxyUdp`, but `StartTunnel` has **no case** for them → silently
falls through to `runTcpTunnel`, which listens on a normal socket and cannot
recover the original destination. So it's a no-op masquerading as TCP.

**Goal:** Real Linux TPROXY listeners that recover the original destination and
tunnel to it. Original dst becomes a normal `Tcp`/`Udp` claim to the server — **no
server change needed.**

### Design (Linux-only; other platforms return a clear error)
- **TCP:** With an iptables `TPROXY` rule + `IP_TRANSPARENT` on the listener,
  `conn.LocalAddr()` of an accepted connection **is** the original destination.
  So: create a transparent TCP listener, accept, read `LocalAddr()` as
  `remote:port`, then reuse the existing forward path
  (`connectToTransport` with `protocol.LocalProtocol{Tcp: {}}`, target =
  original dst) and `startPipe`.
- **UDP:** Harder. Bind a transparent UDP socket with `IP_TRANSPARENT` and
  `IP_RECVORIGDSTADDR`; use `recvmsg` to read both payload and the original
  destination from the ancillary `IP_ORIGDSTADDR` cmsg. Maintain a per-flow
  (src→origdst) map like `runUdpTunnel`, one tunnel per flow, target = origdst.
  Return packets must be sent from a transparent socket bound to the origdst
  (spoofed source) — set `IP_TRANSPARENT` and bind to the original dst.

### Steps
1. Extend `internal/socket/socket_linux.go`:
   ```go
   func SetIPTransparent(fd uintptr) error            // IPPROTO_IP, IP_TRANSPARENT=1
   func SetIPRecvOrigDstAddr(fd uintptr) error         // IP_RECVORIGDSTADDR=1
   ```
   Add matching stubs in `socket_others.go` returning
   `errors.New("tproxy not supported on this platform")`.
2. New `pkg/client/tproxy_linux.go` (build tag `//go:build linux`) with:
   - `func (c *Client) runTProxyTcpTunnel(ltr *protocol.LocalToRemote)` — build
     the listener via `net.ListenConfig{Control:}` calling `SetIPTransparent`
     (and `SO_REUSEADDR`); accept loop; per-conn: `dst := conn.LocalAddr()`;
     `ts := c.connectToTransport(protocol.LocalProtocol{Tcp:&protocol.TcpProtocol{}}, host, port)`;
     `c.startPipe(conn, ts)`.
   - `func (c *Client) runTProxyUdpTunnel(ltr *protocol.LocalToRemote)` — the
     `recvmsg`/`IP_ORIGDSTADDR` flow above; reuse the timeout logic from task #3.
3. New `pkg/client/tproxy_others.go` (build tag `//go:build !linux`) with the
   same method names logging/erroring "TProxy is only supported on Linux".
4. Wire into `StartTunnel` (`client.go:437`), **before** the `runTcpTunnel`
   fallthrough:
   ```go
   if ltr.Protocol.TProxyTcp != nil { c.runTProxyTcpTunnel(ltr); return }
   if ltr.Protocol.TProxyUdp != nil { c.runTProxyUdpTunnel(ltr); return }
   ```
5. Document required setup (needs `CAP_NET_ADMIN`/root and iptables rules) in the
   README usage section; link the standard TPROXY iptables recipe.

### Edge cases
- Missing capability/rule → surface a clear error, don't silently degrade.
- IPv6 TPROXY (`IPV6_TRANSPARENT`, `IPV6_RECVORIGDSTADDR`) — implement v4 first;
  add v6 or explicitly log "IPv6 TPROXY not yet supported".

### Tests
- Pure-unit test the original-dst parsing of the `IP_ORIGDSTADDR` cmsg from a
  crafted `[]byte` (no root needed).
- Mark full end-to-end TPROXY tests as manual/root-only (they need iptables);
  document the manual verification steps rather than gating CI on them.

### Acceptance
- On Linux with the TPROXY iptables rule, `tproxy+tcp://` transparently tunnels
  intercepted TCP to its original destination; non-Linux builds compile and emit
  a clear unsupported error. The silent `runTcpTunnel` fallthrough is gone.

---

## 6. Task: Reverse SOCKS5 / reverse HTTP proxy (`-R socks5://…`, `-R http://…`)

**Status today:** client `ParseTunnelArg` **rejects** both
(`config.go:190`, `:196`), `StartReverseTunnel` rejects them (`client.go:780`),
and all three server handlers route only `ReverseTcp`/`ReverseUnix` to the
reverse manager while explicitly rejecting `ReverseSocks5`/`ReverseHttpProxy`
(`server.go:415/461/518`). The manager already has a partial
`handleSocks5Handshake` (`manager.go:545`) and `handleIncoming` calls it for
`ReverseSocks5` (`:517`) — but the resolved target is never delivered to the
client, so it can't work end-to-end.

**The core problem:** for reverse **dynamic** proxies, the target is chosen at the
*server* (by the SOCKS5/CONNECT handshake from the remote user) but the actual
outbound dial must happen at the *client*. The existing static reverse path
(`ReverseTcp`) has a fixed target known at connect time (via `Set-Cookie`,
`client.go:809`), which cannot express a per-connection dynamic target because
one pooled client conn serves whichever incoming arrives.

**Implement it, don't punt.** Build reverse SOCKS5 **and** reverse HTTP CONNECT so
both work end-to-end. Use a tiny in-band target header on the reverse data stream
(spec below) to carry the per-connection dynamic target from server to client. It
runs **Go client ↔ Go server** (same class as `--mode ws`); that's an engineering
consequence of the framing, not a reason to skip work — ship fully working code
for both protocols. Do not change the existing forward/rust wire format.

### Wire extension (reverse dynamic only)
When the server accepts an incoming connection on a `ReverseSocks5`/
`ReverseHttpProxy` listener and pairs it with a waiting client conn, the server
writes **one framing message first**, then pipes raw bytes:
```
[1 byte version=0x01][1 byte addr_len][addr_len bytes host][2 bytes port BE]
```
The client reads this header off the tunnel stream, dials `host:port` on its own
network, then pipes tunnel⇄local. This frame only ever appears on reverse
socks5/http tunnels, so no other path is affected.

### Steps — protocol / parsing
1. `config.go`: replace the two "not implemented" returns with real construction:
   ```go
   case "socks5": if isReverse { ltr.Protocol = protocol.LocalProtocol{ReverseSocks5: &protocol.ReverseSocks5Protocol{Timeout:getTimeout(), Credentials:getCredentials()}} }
   case "http":   if isReverse { ltr.Protocol = protocol.LocalProtocol{ReverseHttpProxy: &protocol.ReverseHttpProxyProtocol{Timeout:getTimeout(), Credentials:getCredentials()}} }
   ```

### Steps — server
2. In `handleSocks5Handshake` (`manager.go:545`): it currently only replies
   "no auth"; add optional username/password auth when
   `tl.protocol.ReverseSocks5.Credentials != nil` (mirror the client-side
   `handleSocks5` auth block, `client.go:584`). It already parses the target;
   ensure it returns host/port (it does).
3. Add `handleHttpProxyHandshake(conn, creds) (host string, port uint16, err error)`
   in `manager.go`: read the HTTP `CONNECT` request (reuse
   `http.ReadRequest`), enforce `Proxy-Authorization` if creds set (mirror
   `authenticateHTTPProxy`, `client.go:505`), reply `200 Connection Established`,
   return the target from `req.Host`.
4. In `handleIncoming` (`manager.go:509`): after resolving `targetHost/targetPort`
   for `ReverseSocks5` (and now `ReverseHttpProxy`), **write the target framing
   header** (above) to the acquired client conn (`wait.wsConn` /
   `wait.gorillaConn` / `wait.h2Conn`) before the `tunnel.Pipe*` call. Use a
   `WriteMessage(BinaryMessage, frame)` for ws/gorilla and a raw `Write` for h2.
5. In the three server dispatchers (`server.go:415/461/518`): route
   `ReverseSocks5`/`ReverseHttpProxy` to `s.rvMgr.HandleClient*` instead of
   rejecting. `getOrCreateListener` already binds a plain TCP listener for
   non-unix protocols (`manager.go:377`), which is correct for both.

### Steps — client
6. In `StartReverseTunnel` (`client.go:779`): remove the rejection for
   `ReverseSocks5`/`ReverseHttpProxy`. For these protocols, after obtaining the
   tunnel stream `ts`, **read the target framing header first** (from `ts.ws` /
   `ts.gorilla` / `ts.h2`), then `net.Dial("tcp", host:port)` and `startPipe`.
   The existing loop already reconnects on failure — keep that. Factor the
   header-read so it works across all three transports.

### Edge cases
- Auth failures on the server handshake must close the incoming conn cleanly
  without consuming a pooled client conn.
- Malformed framing on the client → drop that stream, reconnect.
- Keep static `ReverseTcp`/`ReverseUnix` on their existing header-less path
  (do not send the frame for them).

### Tests
- Server unit: `handleHttpProxyHandshake` parses `CONNECT host:port` and enforces
  auth; `handleSocks5Handshake` auth path accepts/rejects correctly.
- Integration (Go client + Go server): `-R socks5://` — run a SOCKS5 client
  against the server's reverse listener, target a local echo server reachable
  only from the *client* side, assert round-trip. Repeat for `-R http://`.

### Acceptance
- `-R socks5://…` and `-R http://…` both work end-to-end Go-to-Go with optional
  auth, verified by passing integration tests; static reverse tunnels and all
  forward/rust paths are unchanged. This is an implementation task — "done" means
  a real user can proxy through the client's network, not that a limitation is
  written down.

---

## 7. Task: Working examples, CLI help, and end-to-end coverage

This is an **implementation** task, not a prose task. Ship runnable artifacts
that exercise every feature from #1–#6, so the new capabilities are usable and
provably working — not merely described.

**Goal:** For each new feature, deliver a working example config, real CLI
`--help`/usage strings, and an end-to-end test that actually drives it.

### Steps
1. **Example config files** (build these, don't just mention them). Add ready-to-run
   YAML under `packaging/` (follow the existing systemd config layout the README
   references, e.g. `client-*.yaml` / `server-*.yaml`) plus a `docs/examples/`
   set covering: `proxy_protocol`, `tproxy+tcp`/`tproxy+udp`, reverse
   `socks5`/`http`, `--tls` self-signed, cert hot-reload, and `timeout_sec`. Each
   file must be valid and load cleanly through the existing config parser.
2. **CLI usage strings** — implement real `Usage:` text for every new flag added
   in tasks #2 and #6 (`--tls`, and any `?query` options surfaced in help) in
   `cmd/warpstream/main.go`, and make sure `warpstream client --help` /
   `warpstream server --help` render them. Add a one-line example to each flag's
   usage where a scheme/query is involved (e.g. `tproxy+tcp://`, `-R socks5://`).
3. **End-to-end tests** in `tests/` — one per feature, wired into `go test`:
   - `proxy_protocol`: backend parses a valid PROXY v2 header (shared with #1).
   - reverse `socks5`/`http`: Go client ↔ Go server round-trip (shared with #6).
   - UDP `timeout_sec`: idle session reclaimed (shared with #3).
   - `--tls` self-signed: `wss://` handshake succeeds (shared with #2).
   - cert hot-reload: served cert swaps after on-disk overwrite (shared with #4).
   - TProxy: cmsg-parse unit test in CI; full path documented as root/iptables
     manual run (it genuinely cannot run in unprivileged CI).
   These may reuse the per-task tests; the deliverable here is that the suite
   exists, is green, and covers each feature.
4. **TODO.md** — flip each `[ ]` to `[x]` as its task merges, with a one-line note
   on any deliberate scoping (e.g. "UDP IPv6 TPROXY deferred").
5. **README** — this is the only doc-edit sub-step, and it is secondary: once the
   above works, make the Features list match reality and add the platform notes
   (TProxy Linux-only + iptables; reverse SOCKS5/HTTP Go-to-Go; self-signed needs
   `--tls`). Keep it brief — the working configs and `--help` are the primary
   documentation. Also reconcile stale strings:
   `grep -rn "not implemented\|Coming soon\|not supported" README.md pkg`.

### Acceptance
- Every new feature has a valid, loadable example config and a green end-to-end
  (or unit, for TProxy) test in the repo; `--help` documents each new flag with an
  example; `TODO.md` reflects true state. Success is measured by artifacts that
  run, not by paragraphs written.

---

## Cross-cutting definition of done

- `go build ./...` and `go test ./...` green on Linux; cross-compile check for
  `GOOS=darwin`/`GOOS=windows` still builds (the `!linux` stubs matter).
- No regression to default (Rust-compatible) forward tunnels — verify with an
  existing interop e2e test in `tests/`.
- Each feature has: unit tests for pure logic, an integration/e2e test where
  feasible, and a working, loadable example config (see §7).
- New third-party deps limited to `github.com/fsnotify/fsnotify` (task #4) and
  optionally a PROXY-protocol encoder (task #1); everything else uses stdlib.
