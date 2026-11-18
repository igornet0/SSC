# Kill Switch — guarantees and limitations

## What is guaranteed

With **Kill Switch = ON** and an **unexpected** sing-box death:

| Policy | Mechanism | Guarantee |
|--------|-----------|-----------|
| **Full VPN** | macOS `pf` anchor `ssc.killswitch` blocks outbound except lo0, private LAN, VPN server | Strong — clear-path leak of general internet is blocked |
| **Selective + IP/CIDR VPN rules** | `pf` blocks only those VPN destination CIDRs | Strong for listed IPs/CIDRs |
| **Selective + domain-only VPN rules** | `pf` cannot match DNS names | **Weaker** — see below |

Intentional `ssc disconnect` deactivates the kill switch (normal clear routing restored).

## Domain-only limitation

Domain rules (`google.com`, `*.youtube.com`) are enforced by **sing-box** while the tunnel is up (sniff + route).

After an unexpected tunnel crash, pf only knows **IP/CIDR** tables. If:

1. the only VPN rules are domain matches, and  
2. resolved IPs change after the crash,

then kill switch **cannot** promise “block that domain’s new IPs”.

**Do not claim 100% domain-level kill switch.**

Mitigations:

- Prefer IP/CIDR VPN rules for destinations that must never leak.
- Keep kill switch ON in Full mode for blanket block-on-drop.
- Reconnect quickly (`auto_reconnect`) after unexpected drop.

## Stress test

```bash
# With live profile + Kill Switch ON:
# force-kill sing-box PID (not `ssc disconnect`)
# verify VPN-only destination does not return the home DIRECT egress IP
./scripts/p8-e2e.sh
```
