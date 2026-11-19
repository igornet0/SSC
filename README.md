# SSC — Security System Connection

Standalone Rust **local VPN policy gateway** for macOS (also Linux/Windows). Import standard share links, connect via **sing-box TUN** or **independent local proxies**, and steer traffic with domain/IP/CIDR rules from a **localhost Web UI** or CLI.

> Principle: the Web UI manages the local service — it is not the VPN mechanism. Open `http://ssc.lan:8765` (or `http://127.0.0.1:8765`).

## Protocols (v1)

- `vless://` (TLS / Reality / WS / gRPC)
- `vmess://` (base64 JSON)
- `trojan://`

## Quick start

### Installer (recommended)

**macOS (DMG + PKG)**

```bash
make -f Makefile.build installer-macos-arm64
# → dist/installers/ssc-macos-arm64-0.1.0.dmg
```

### Dev build

```bash
cargo build -p ssc-cli --release
./target/release/ssc install   # PATH + sing-box
./target/release/ssc setup
```

### Local policy gateway

```bash
ssc add 'vless://uuid@host:443?security=reality&…#node'
ssc mode selective
ssc rules add domain google.com vpn
ssc rules add domain github.com direct
ssc connect
ssc start          # http://ssc.lan:8765
ssc status
ssc disconnect
ssc reset-network  # safe cleanup
```

**Selective VPN (default):** everything DIRECT except listed VPN rules.  
**Full VPN:** everything VPN except listed DIRECT exceptions.  
VPN server, LAN, and localhost stay DIRECT.

### Multiple VPNs at once

System TUN and Local Proxy instances can run side by side. Local Proxy mode needs
no root and gives each app its own loopback endpoint:

```bash
ssc instance add --id work --profile work --mode proxy --port 19101 --start
ssc instance add --id personal --profile home --mode proxy --port 19102 --start
ssc instance list
# work      connected  proxy  mixed  http://127.0.0.1:19101
# personal  connected  proxy  mixed  http://127.0.0.1:19102
ssc instance stop work        # personal keeps running
```

Only one system TUN instance may run per host (`tun_in_use`); any number of
Local Proxy instances may run concurrently. See
[docs/vpn-instances.md](docs/vpn-instances.md).

## Commands

| Command | Action |
|---------|--------|
| `ssc add '<uri>'` | Parse + save profile |
| `ssc list` / `use` / `remove` | Profiles |
| `ssc connect` / `disconnect` / `reconnect` / `status` | Default instance (TUN) |
| `ssc connect --mode proxy [--proxy-port P]` | Default instance as local proxy |
| `ssc connect --best` | Latency race + failover |
| `ssc instance add\|list\|show\|start\|stop\|restart\|remove\|logs\|policy` | Independent VPN instances |
| `ssc start [--port 8765]` | Local Web UI + API (`127.0.0.1`, `http://ssc.lan:8765`) |
| `ssc mode selective\|full` | Routing mode |
| `ssc rules list\|add\|remove` | Policy rules |
| `ssc diagnostics` | Health checks |
| `ssc privileges status\|install\|remove` | Passwordless TUN (`/etc/sudoers.d/ssc`) + `ssc.lan` in `/etc/hosts` |
| `ssc reset-network` | Disconnect + clear SSC tunnel state |
| `ssc setup` / `install` / `uninstall` | Runtime / PATH |

## Architecture

See [docs/local-policy-gateway.md](docs/local-policy-gateway.md). Related:

- [docs/macos-networking.md](docs/macos-networking.md)
- [docs/policy-rules.md](docs/policy-rules.md)
- [docs/web-api.md](docs/web-api.md)
- [docs/vpn-instances.md](docs/vpn-instances.md)

```
Web UI (127.0.0.1) → Local API → VpnInstanceManager / PolicyEngine
                                      ├── default  → sing-box TUN (utun)
                                      └── instance → sing-box local proxy
                                                     (HTTP/SOCKS, no root)
```

`VpnManager` remains as a compatibility façade over the reserved `default`
instance, so existing commands and scripts keep working.

## Config layout

Override with `SSC_CONFIG_DIR`. Defaults:

- macOS: `~/Library/Application Support/ssc/`
- Linux: `~/.config/ssc/`

| File | Purpose |
|------|---------|
| `profiles.json` | Connection profiles (URI secrets) |
| `policy.json` | Mode + rules + settings |
| `singbox-run.json` | Generated TUN config |
| `bin/sing-box` | Bundled runtime |
| `tunnel.*` | Default-instance PID / status / log |
| `instances.json` | Named-instance registry (no credentials) |
| `instances/<id>/` | Isolated config, policy, ports, pid, status, log |

## Crates

| Crate | Role |
|-------|------|
| `ssc-core` | URI parse, profiles, policy-aware sing-box JSON |
| `ssc-policy` | Policy engine + persistence |
| `ssc-runtime` | sing-box install + isolated instance lifecycle |
| `ssc-service` | VpnInstanceManager, VpnManager façade, traffic, diagnostics |
| `ssc-api` | REST + WebSocket + static UI |
| `ssc-cli` | `ssc` binary |
