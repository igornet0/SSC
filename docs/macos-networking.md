# macOS Networking — SSC Local Policy Gateway

## How traffic is steered

SSC does **not** implement a custom utun driver. On connect it elevates and runs **sing-box** with a TUN inbound:

```json
{
  "type": "tun",
  "tag": "tun-in",
  "address": ["172.19.0.1/30"],
  "mtu": 1500,
  "auto_route": true,
  "strict_route": true,
  "stack": "system",
  "route_exclude_address": ["127.0.0.0/8", "::1/128", "…LAN…"]
}
```

sing-box creates a `utunN` interface and installs routes. Packets matching policy leave via the `proxy` outbound (VLESS/VMess/Trojan); everything else uses `direct` on the physical interface (`auto_detect_interface`).

`route_exclude_address` keeps loopback and LAN **off the TUN stack** (not merely routed DIRECT). Capturing `127.0.0.0/8` breaks Electron apps such as Cursor (localhost IPC / extension host). DNS uses `strategy: ipv4_only` so AAAA answers do not send clients onto a half-configured IPv6 path.

## Policy → routes

| Mode | `route.final` | User rules |
|------|---------------|------------|
| Selective VPN (default) | `direct` | matched → `proxy` |
| Full VPN | `proxy` | matched → `direct` |

Always inserted **before** user rules:

1. sniff  
2. hijack-dns  
3. private IPs → direct  
4. **VPN server exclusion** → direct (IP `/32` or hostname domain)

## VPN server exclusion

If the VPN endpoint were routed into the tunnel, the client would hairpin:

`app → tun → proxy dial → tun → …`

SSC always emits a DIRECT rule for the configured server host/IP. Unit test: `vpn_server_ip_exclusion_when_default_vpn`.

## DNS

Domain rules rely on sing-box DNS hijack + sniff — **not** a second local stub resolver and **not** DNS spoofing. Answers are resolved normally; routing uses domain match / sniffed name.

## Cleanup

On `ssc disconnect` / `ssc reset-network`:

1. SIGTERM sing-box (TUN destroy removes its routes)  
2. Clear `tunnel.pid`, `tunnel.stop`, `tunnel.status.json`  
3. Do **not** delete unrelated system routes or DNS settings outside sing-box

After crash, OS reclaim of the TUN process also drops auto_route state.

## Privileges

- Web UI / API run as the user on `127.0.0.1`
- Tunnel start/stop uses `sudo -n` → `/usr/local/bin/ssc __tunnel-worker` (no password after install)
- The macOS PKG (and `sudo ssc privileges install`) writes `/etc/sudoers.d/ssc` with NOPASSWD for:
  - `ssc __tunnel-worker …`
  - `pfctl -a ssc.killswitch …` (kill switch)
  - `kill -TERM/-KILL` (disconnect)
- If privileges are missing, Connect falls back to a one-time macOS admin password dialog
- HTTP handlers never execute shell with user-controlled strings for routing

Check: `ssc privileges status` / Diagnostics → "Passwordless TUN privileges"

## Diagnostics

`ssc diagnostics` / UI Diagnostics checks: sing-box binary, process, interface hint, server TCP reachability, DNS markers in config, policy engine, direct-rule presence.
