# Local VPN Policy Gateway — Architecture

**Status:** Phase 1 investigation complete  
**Scope:** macOS-first local policy-controlled VPN on top of existing SSC transport  
**Principle:** Web UI manages a local service; it is not the VPN mechanism itself. UI binds to `127.0.0.1` only (e.g. `http://127.0.0.1:8765`).

---

## 1. Current architecture (as of investigation)

SSC is a **thin orchestration layer over [sing-box](https://github.com/SagerNet/sing-box) TUN**. Rust owns URI parsing, profile storage, config generation, privilege elevation, and process lifecycle. **sing-box owns the tunnel interface, packet path, DNS hijack, and routing.**

```
ssc CLI
  │
  ├── ssc-core          URI parse, profiles.json, sing-box JSON builder
  ├── ssc-runtime       sing-box download, elevate, spawn/stop tunnel
  └── sing-box (1.13.x) utun + VLESS/VMess/Trojan + route/DNS
```

### Crates

| Crate | Path | Role |
|-------|------|------|
| `ssc-core` | `crates/ssc-core/` | Share URI parse, profiles, sing-box JSON |
| `ssc-runtime` | `crates/ssc-runtime/` | Setup, tunnel lifecycle, race/failover |
| `ssc-cli` | `crates/ssc-cli/` | `ssc` binary |

There is **no** Web UI, REST API, Policy Engine, or custom utun/packet loop in Rust today.

### Connect flow

```
ssc connect [--id] | ssc connect --best
        │
        ▼
ensure_singbox() → write_singbox_config(uri)
        │
        ▼
ssc_runtime::connect(config, profile_id)
  → sing-box check
  → elevate (sudo) → __tunnel-worker
  → sing-box run -c singbox-run.json
  → tunnel.pid + tunnel.status.json
```

### Authentication / keys / protocol

- **Not WireGuard.** Credentials live in share URIs:
  - VLESS / VMess: UUID
  - Trojan: password
  - TLS / Reality: SNI, uTLS fingerprint, Reality `pbk` / `sid`
- Secrets today are **plaintext** in `profiles.json` and again in `singbox-run.json`.
- Transport protocols: TCP / WS / gRPC / HTTP(H2) via sing-box native outbounds.

### Tunnel & packets

- TUN inbound generated in `ssc-core::singbox::build_singbox_config_from_parsed`:
  - `type: tun`, `address: 172.19.0.1/30`, `auto_route: true`, `strict_route: true`, `stack: system`
- On macOS, sing-box creates **utunN** and installs routes.
- Packet I/O, crypto, and outbound framing are **entirely inside sing-box**.
- SSC only spawns/stops the process and tracks PID/status.

### Existing routing / DNS (hardcoded)

| Concern | Current behavior |
|---------|------------------|
| Default | `route.final = "proxy"` (full tunnel) |
| Private IPs | → `direct` |
| VPN server literal IP | `/32` → `direct` (anti-hairpin) |
| DNS | UDP `1.1.1.1` + `local`; `hijack-dns` |
| Domain split | **None** |

### CLI (existing)

`add`, `list`, `use`, `remove`, `race`, `ping`, `connect`, `disconnect`, `status`, `setup`, `install`, `uninstall`, hidden `__tunnel-worker`.

### Config layout

Default macOS: `~/Library/Application Support/ssc/`

| File | Purpose |
|------|---------|
| `profiles.json` | Profiles + active id (URI = secret) |
| `singbox-run.json` | Generated TUN config |
| `bin/sing-box` | Bundled runtime |
| `tunnel.pid` / `tunnel.status.json` / `tunnel.log` | Lifecycle |

### OS-specific (macOS)

- Elevation via `sudo -n` + `__tunnel-worker` after PKG installs `/etc/sudoers.d/ssc` (NOPASSWD).
- Without privileges, Connect falls back to a one-time macOS admin dialog.
- Entire sing-box still runs elevated; no separate Network Extension helper yet.
- Installer: DMG + PKG (`Makefile.build`, `packaging/macos/`).

---

## 2. Design decision: reuse sing-box as transport

**Do not rewrite** TUN creation, packet I/O, or VLESS/VMess/Trojan crypto.

Policy-controlled routing is implemented by **compiling Policy Engine state into sing-box JSON** and reconnecting / hot-reloading the tunnel when policy changes.

```
Browser (127.0.0.1)
        │
        ▼
Local API + WebSocket          (new: ssc-api)
        │
VpnManager / PolicyService     (new: ssc-service)
        │
PolicyEngine → sing-box rules  (new: ssc-policy)
        │
EXISTING TRANSPORT
  ssc-core (URI + profiles + JSON builder)
  ssc-runtime (elevate + sing-box lifecycle)
  sing-box (utun + packets + DNS hijack)
```

### Why not a custom userspace DNS + route table?

sing-box already provides:

1. **Domain-aware routing** via `route.rules` (`domain`, `domain_suffix`, `ip_cidr`) + sniff
2. **DNS hijack** (`protocol: dns` → `hijack-dns`) — domain rules apply without DNS spoofing
3. **VPN server exclusion** via `ip_cidr` / domain direct rules
4. **Clash API** (experimental) for live connection metadata (Traffic page)

A parallel custom DNS on `127.0.0.1` would fight with TUN DNS hijack.  
**DNS policy layer** = PolicyEngine → sing-box `dns` + `route` rules; association of resolved IPs to policy is done inside sing-box (sniff + domain match). We do **not** spoof or rewrite DNS answers.

Optional later: expose a diagnostic DNS view by reading sing-box Clash API / logs — not a second resolver.

---

## 3. Target components

### 3.1 VpnManager

Wraps `ssc_runtime::{connect, disconnect, is_connected, read_status}` with explicit states:

| State | Meaning |
|-------|---------|
| `Disconnected` | No tunnel |
| `Connecting` | Config write / elevate / spawn in progress |
| `Connected` | sing-box alive |
| `Disconnecting` | Stop in progress |
| `Error` | Last operation failed (`last_error` set) |

API surface:

- `connect()` / `disconnect()` / `reconnect()` / `status()`
- Auto-reconnect with exponential backoff: 1s → 2s → 4s → 8s → 16s → 30s
- Status JSON (no secrets): state, server host, interface hint, connected_at, bytes, latency

### 3.2 PolicyEngine

Input: destination (domain / IP / CIDR / optional protocol+port)  
Output: `DIRECT` | `VPN` | `BLOCK` (BLOCK prepared; MVP enables DIRECT/VPN)

**Match types:** exact domain, `*.domain` wildcard (= `domain_suffix`), exact IP, CIDR.

**Precedence (deterministic, first match wins after sort):**

1. Exact domain  
2. Domain wildcard (longest suffix wins among wildcards)  
3. Exact IP  
4. CIDR (most specific prefix length wins)  
5. Protocol/port (architected; deferred if unused in MVP)  
6. Default policy (`Selective` → DIRECT, `Full` → VPN)

Disabled rules are skipped.

### 3.3 Policy modes

| Mode | Default | Exceptions |
|------|---------|------------|
| **Selective VPN** (MVP default) | DIRECT | Listed → VPN |
| **Full VPN** | VPN | Listed → DIRECT |

Compiled to sing-box:

- Selective: `route.final = "direct"` + VPN match rules → `proxy`
- Full: `route.final = "proxy"` + DIRECT match rules → `direct`
- Always: private → direct; VPN server → direct; localhost preserved by sing-box/system

### 3.4 Routing manager (macOS)

Primary path: **sing-box `auto_route` / `strict_route`**.  
SSC does not shell out from HTTP handlers to `route`/`ifconfig`.

On disconnect / crash / `ssc reset-network`:

1. Stop sing-box (TUN teardown removes its routes)
2. Clear SSC pid/status/stop flags
3. Do **not** delete unrelated system routes

VPN server exclusion is always emitted as a `direct` rule (IP `/32` or domain) to prevent routing loops.

### 3.5 Kill switch (architectural)

| Mode | On disconnect |
|------|----------------|
| OFF | Normal OS routing |
| ON | VPN-destined destinations blocked; localhost / Web UI remain reachable |

MVP: setting persisted; enforcement via sing-box `block` outbound + reconnect. Full offline firewall deferred if it requires a privileged helper beyond TUN.

### 3.6 Local API + WebSocket

- Bind: **`127.0.0.1` only** (default port `8765`)
- REST under `/api/v1/...`
- WebSocket `/ws` for `vpn_status`, `connection`, `traffic` events
- CSRF: Origin check for mutating requests (localhost only)
- No secrets in responses or WS payloads

### 3.7 Web UI

Static SPA served by the local API. Pages: Dashboard, Rules, Traffic, Profiles, Diagnostics / Advanced.

UI → HTTP only. **Never** executes shell or touches routes directly.

### 3.8 CLI

Extend `ssc` (alias conceptually `myvpn` in docs; binary remains `ssc`):

```
ssc start | stop          # local API + optional auto-connect
ssc connect | disconnect | status | reconnect
ssc mode selective | full
ssc rules list | add | remove
ssc reset-network
```

CLI and Web UI share `ssc-service` — no duplicated business logic.

### 3.9 Persistence

| Store | Contents |
|-------|----------|
| `policy.json` / SQLite | rules, mode, kill-switch, UI settings |
| `profiles.json` | profile metadata (existing) |
| Keychain (macOS) | URI / password / UUID (Phase 9) |

MVP may keep URI in profiles with `0600` file mode; Keychain migration is Phase 9.

### 3.10 Privileged operations

```
User process (API, UI, Policy, VpnManager)
        │
        ▼
ssc-runtime elevate → __tunnel-worker → sing-box (root)
```

Do not run the Web UI as root. Minimize privileged surface to tunnel start/stop.

### 3.11 Startup / recovery

- Optional LaunchAgent: start API at login
- Graceful shutdown: disconnect → cleanup status
- Crash: sing-box exit clears routes via TUN destroy; API marks Disconnected; auto-reconnect if enabled
- `ssc reset-network`: disconnect + clear SSC-managed state only

---

## 4. Proposed crate layout

```
crates/
  ssc-core/       # EXISTING + parameterized build_singbox_config(…, PolicySnapshot)
  ssc-runtime/    # EXISTING tunnel lifecycle (mostly unchanged)
  ssc-policy/     # NEW: rules, precedence, compile → sing-box rule fragments
  ssc-service/    # NEW: VpnManager, PolicyService, TrafficMonitor, persistence, diagnostics
  ssc-api/        # NEW: axum HTTP + WS + static UI
  ssc-cli/        # EXISTING + start/mode/rules/reset-network
web/              # NEW: dashboard SPA (built assets embedded or served from disk)
```

### Extension point in `ssc-core`

Refactor:

```rust
build_singbox_config_from_parsed(parsed, &PolicySnapshot) -> Value
```

`PolicySnapshot` supplies: mode, rules, kill_switch, DNS overrides.  
Outbound crypto builders stay untouched.

---

## 5. API sketch

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/v1/status` | Aggregate status |
| GET/POST | `/api/v1/vpn/status\|connect\|disconnect\|reconnect` | VpnManager |
| GET/PUT | `/api/v1/policy` | Mode + defaults |
| CRUD | `/api/v1/rules` | Policy rules |
| GET | `/api/v1/traffic` | Ring buffer (last 1000) |
| CRUD | `/api/v1/profiles` | Connection profiles (no secrets in GET) |
| GET | `/api/v1/diagnostics` | Diagnostics + run |
| WS | `/ws` | Live events |

---

## 6. Security constraints

- Bind `127.0.0.1` only unless user explicitly enables remote management
- Never log or return private keys / passwords / full URIs
- Validate all API inputs; no shell interpolation from HTTP
- Routing changes only via PolicyService → config rebuild → tunnel

---

## 7. Implementation phases

| Phase | Deliverable | Behavior change |
|-------|-------------|-----------------|
| **1** | This document | None |
| **2** | VpnManager states + reconnect API | Wrap existing connect |
| **3** | Policy-aware sing-box builder + server exclusion tests | Config shape |
| **4** | PolicyEngine + precedence tests | — |
| **5** | DNS via sing-box rules (no spoof) | Domain routing works |
| **6** | Local API + WebSocket | Service process |
| **7** | Web UI | Local dashboard |
| **8** | Persistence (rules/profiles/settings) | Survives restart |
| **9** | Keychain, CSRF, LaunchAgent | Hardening |
| **10** | Unit + integration tests | Acceptance |

---

## 8. Acceptance criteria (real macOS)

1. `ssc start` → open `http://127.0.0.1:8765`
2. Connect VPN; add `google.com → VPN` → real apps use VPN for Google
3. Add `github.com → DIRECT` → GitHub bypasses VPN
4. `ssc disconnect` → routes/DNS restored; no leftover SSC routes
5. Restart → rules persist
6. VPN server, LAN, localhost remain DIRECT; default follows selected mode

---

## 9. Non-goals (MVP)

- LAN gateway / NAT / sharing VPN to other devices
- Rewriting sing-box packet path in Rust
- Network Extension entitlement packaging (future alternative transport)
- Full protocol/port classification unless needed for correctness

---

## 10. Related docs

- `docs/macos-networking.md` — TUN, routes, cleanup, VPN server exclusion
- `docs/policy-rules.md` — match types, precedence, modes
- `docs/web-api.md` — REST + WebSocket contract
