# Policy Rules

## Actions

| Action | Meaning |
|--------|---------|
| `vpn` | Send via proxy outbound (tunnel) |
| `direct` | Bypass tunnel |
| `block` | Reject (architected; uses sing-box `action: reject`) |

## Match types

| Kind | Examples | sing-box mapping |
|------|----------|------------------|
| `domain` | `google.com` | `domain` |
| `domain` wildcard | `*.google.com` | `domain_suffix` |
| `ip` | `8.8.8.8` | `ip_cidr` `/32` or `/128` |
| `cidr` | `192.168.0.0/16` | `ip_cidr` |
| `port` | `tcp:443` | `network` + `port` (optional MVP) |

## Precedence

First applicable class wins, in order:

1. Exact domain  
2. Domain wildcard (longest suffix among wildcards)  
3. Exact IP  
4. CIDR (largest prefix length)  
5. Protocol/port  
6. Default from mode  

Example:

```
*.google.com     → VPN
mail.google.com  → DIRECT
```

→ `mail.google.com` is DIRECT; `youtube.google.com` is VPN.

Disabled rules are ignored.

## Modes

| Mode | Default | Typical use |
|------|---------|-------------|
| **selective** | DIRECT | Only listed destinations use VPN (MVP recommended) |
| **full** | VPN | Full tunnel with DIRECT exceptions |

## Persistence

Stored in `policy.json` under the SSC config directory (`~/Library/Application Support/ssc/` on macOS). Rules survive restart. Secrets are **not** stored in this file.

## CLI

```bash
ssc mode selective
ssc mode full
ssc rules list
ssc rules add domain '*.youtube.com' vpn
ssc rules add domain '*.googlevideo.com' vpn
ssc rules add domain google.com vpn
ssc rules add domain github.com direct
ssc rules add cidr 192.168.0.0/16 direct
ssc rules remove google.com
```

### Groups

Rules live in the global `policy.json` (not per VPN profile). Optional **groups**
can be enabled/disabled together from the Rules UI (`+ Group`, toggle on each pack).

A rule applies only when both the rule and its group (if any) are enabled.

Video playback hits dozens of rotating hosts (`rr5---sn-….googlevideo.com`, `i1.ytimg.com`, `*.c.youtube.com`).
Exact IP `/32` rules and `www.youtube.com` alone will miss them.

Use **suffix wildcards** (Web UI: **+ YouTube pack** on Rules):

| Rule | Covers |
|------|--------|
| `*.youtube.com` | www, m, accounts, `*.c.youtube.com` |
| `*.googlevideo.com` | video CDN shards |
| `*.ytimg.com` | thumbnails |
| `*.ggpht.com` | images |
| `*.gvt1.com` | static / video |
| `*.clients6.google.com` | signaler / realtime APIs |

Changing mode/rules while connected rebuilds sing-box config and reconnects via `VpnManager::apply_policy`.
