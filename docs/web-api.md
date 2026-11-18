# Web API

Local control plane for SSC. **Bind: `127.0.0.1` only** (default port `8765`).

```bash
ssc start --port 8765
# → http://ssc.lan:8765  (or http://127.0.0.1:8765)
```

`ssc.lan` is a `127.0.0.1` line in `/etc/hosts`, tagged `# ssc (managed)`. It is added by
`sudo ssc privileges install` (run by the macOS PKG) and removed by `sudo ssc privileges remove`
/ `ssc-uninstall`. The server still binds `127.0.0.1` only. `http://ssc.lan` is an allowed `Origin`.

Mutating requests with a non-local `Origin` header are rejected (CSRF soft guard).

Secrets (share URIs, passwords, UUIDs) are **never** returned in JSON or WebSocket payloads.

## REST

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/status` | Aggregate VPN + mode + rule count |
| GET | `/api/v1/vpn/status` | VpnManager status |
| POST | `/api/v1/vpn/connect` | Connect |
| POST | `/api/v1/vpn/disconnect` | Disconnect |
| POST | `/api/v1/vpn/reconnect` | Reconnect |
| GET | `/api/v1/policy` | Full policy snapshot |
| PUT | `/api/v1/policy` | Update mode / settings |
| GET | `/api/v1/rules` | List rules |
| POST | `/api/v1/rules` | Create rule `{kind,value,action}` |
| PUT | `/api/v1/rules/:id` | Patch rule |
| DELETE | `/api/v1/rules/:id` | Delete rule |
| GET | `/api/v1/traffic` | Ring buffer + counters |
| GET | `/api/v1/profiles` | Profiles **without** URIs |
| POST | `/api/v1/profiles` | Import `{uri, name?}` |
| PUT | `/api/v1/profiles/:id` | Rename / activate |
| DELETE | `/api/v1/profiles/:id` | Remove |
| GET/POST | `/api/v1/diagnostics` | Run diagnostics |

### VPN status example

```json
{
  "state": "connected",
  "server": "ingress.example.com",
  "interface": "utun5",
  "connected_at": "2026-09-17T13:00:00+00:00",
  "bytes_sent": 12345,
  "bytes_received": 67890,
  "latency_ms": 42,
  "mode": "selective"
}
```

## WebSocket `/ws`

Server pushes JSON events (no polling required for live UI):

```json
{ "type": "vpn_status", "state": "connected", "mode": "selective", ... }
{ "type": "traffic", "bytes_sent": 12345, "bytes_received": 67890 }
{ "type": "connection", "domain": "google.com", "route": "vpn" }
```

## Static UI

Files under `web/` (`index.html`, `styles.css`, `app.js`) are served as the dashboard (Control, Rules, Traffic, Profiles, Diagnostics).

Override directory with `SSC_UI_DIR`.
