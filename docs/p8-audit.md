# P8 Audit — SSC Local VPN Gateway (post-implementation)

**Date:** 2026-09-17  
**Transport:** sing-box TUN (unchanged)

## Component table

| Component | Status | Notes |
|-----------|--------|-------|
| VPN | PASS* | VpnManager + friendly errors; *live connect needs profile |
| TUN | PASS | sing-box TUN; cleanup on process death |
| Policy | PASS | Domain/IP/CIDR, precedence, per-profile `policies/{id}.json`, import/export |
| DNS | PASS | hijack-dns + sniff; no spoof; lifecycle via TUN teardown |
| Routing | PASS | Server exclusion, dynamic LAN exclusions, route probe API/CLI/UI |
| API | PASS | 127.0.0.1 only; CSRF Origin; probe/import/export; integration tests |
| Web UI | PASS | Control/Rules/Traffic/Probe/Profiles/Diagnostics; Traffic filters |
| Persistence | PASS | Per-profile policy; Keychain secrets (macOS) |
| Security | PASS | Keychain; localhost API; secrets not in API/UI; pf kill switch |
| Recovery | PASS | reconcile on start; reset-network; LaunchAgent; kill-switch deactivate |

\* Real connect not demonstrated on this host (no share URI).

## P8 checklist

| # | Item | Status |
|---|------|--------|
| Hot apply | Clash reload → reconnect fallback; `applied` + `policy_changed` | DONE |
| Route probe | API/CLI/UI | DONE |
| Traffic UX | search/filter/pause/clear | DONE |
| Keychain | macOS `security` CLI | DONE |
| Launch at login | LaunchAgent `com.ssc.gateway` | DONE |
| Kill switch | pf anchor on unexpected drop | DONE (manual leak test pending) |
| Per-profile policy | `policies/{id}.json` | DONE |
| WS initial `state` | DONE | |
| Reconcile | `reconcile_on_startup` | DONE |
| Diagnostics pretty/`--json` | DONE | |
| Integration tests | `ssc-api/tests/api_integration.rs` | DONE |
| Real macOS E2E | **BLOCKED** — no live profile | |

## Commands

```bash
ssc probe google.com
ssc diagnostics
ssc diagnostics --json
./scripts/p8-e2e.sh
```
