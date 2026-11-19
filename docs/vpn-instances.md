# Independent VPN instances

SSC can run many independent VPN connections at the same time. Each instance has
its own profile, policy snapshot, sing-box config, runtime directory, ports,
process, state, and traffic counters. Stopping or crashing one instance never
touches another.

Two modes are supported:

| Mode | Transport | Root | Concurrency |
|------|-----------|------|-------------|
| `tun` | System TUN interface (sing-box `tun` inbound) | Required (passwordless sudo after `ssc privileges install`) | One per host (`tun_in_use`) |
| `proxy` | Local `mixed` / `http` / `socks` inbound on loopback | **No** | Many, one per instance |

Local Proxy mode lets different apps or sessions use different VPNs at the same
time:

```bash
ssc instance add --id work --name "Work" --profile work --mode proxy --port 19101
ssc instance add --id personal --name "Personal" --profile home --mode proxy --port 19102
ssc instance start work
ssc instance start personal

# point each app at its own instance
#   work     → http://127.0.0.1:19101 (mixed HTTP/SOCKS)
#   personal → http://127.0.0.1:19102
```

## CLI

```bash
ssc instance add --id <id> [--name N] [--profile ID|NAME]
                 [--mode proxy|tun] [--proxy-kind mixed|http|socks]
                 [--port P] [--clash-port P] [--start]

ssc instance list
ssc instance show <id>
ssc instance start <id>
ssc instance stop <id>
ssc instance restart <id>
ssc instance remove <id>
ssc instance logs <id> [--max-bytes N]
ssc instance policy <id> [--mode selective|full]
```

The legacy commands keep working and operate on the reserved `default`
instance:

```bash
ssc connect                 # default instance, TUN
ssc connect --mode proxy    # default instance, local proxy
ssc connect --instance work # start an already-configured instance
ssc disconnect / reconnect / status
```

## REST API

All endpoints are localhost-only and never return credentials.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/instances` | List instances |
| POST | `/api/v1/instances` | Create `{id?, name?, profile_id?, mode?, proxy_kind?, listen_port?, clash_api_port?, policy?}` |
| GET | `/api/v1/instances/:id` | One instance status |
| PUT | `/api/v1/instances/:id` | Patch definition (restarts if running) |
| DELETE | `/api/v1/instances/:id` | Stop + remove (default is protected) |
| POST | `/api/v1/instances/:id/start` | Start only this instance |
| POST | `/api/v1/instances/:id/stop` | Stop only this instance |
| POST | `/api/v1/instances/:id/restart` | Restart only this instance |
| GET | `/api/v1/instances/:id/policy` | Isolated policy snapshot |
| PUT | `/api/v1/instances/:id/policy` | Replace policy + hot-reload |
| GET | `/api/v1/instances/:id/traffic` | Per-instance bytes/connections |
| GET | `/api/v1/instances/:id/logs?max_bytes=N` | Redacted log tail |

`GET /api/v1/status` and `GET /api/v1/vpn/status` remain compatible and report
the `default` instance.

## Architecture

```
ssc-api / ssc-cli
        │
        ▼
VpnInstanceManager (ssc-service)
  ├── default  → InstanceEntry (tun)
  ├── work     → InstanceEntry (proxy)
  └── personal → InstanceEntry (proxy)
        │
        ▼
ssc-runtime::instance
  ├── InstancePaths (validated id → isolated directory)
  ├── InstanceProcessBackend (SingBoxBackend / injected fakes)
  ├── per-instance file lock (flock)
  └── spawn / stop / identity / health
```

Each `InstanceEntry` owns:

- `RwLock<InstanceConfig>` — definition (never credentials)
- `RwLock<PolicySnapshot>` — isolated policy
- `Mutex<LiveState>` — state, process handle, ports, errors, health
- `TrafficMonitor` — per-instance counters
- `AsyncMutex<()>` — serializes start/stop/restart/reload for that instance
- supervisor task — health checks and reconnect with exponential backoff

No global mutable instance state is used. No lock is held across `.await`.

`VpnManager` is a thin compatibility façade over the reserved `default`
instance. New code should use `VpnInstanceManager` directly:

```rust
use ssc_service::{VpnInstanceManager, CreateInstanceRequest};

let manager = VpnInstanceManager::new();
manager.create(CreateInstanceRequest {
    id: Some("work".into()),
    name: Some("Work".into()),
    profile_id: Some("p1".into()),
    mode: Some("proxy".into()),
    ..Default::default()
}).await?;
manager.start("work").await?;

let status = manager.status("work").await?;
println!("{}", status.endpoint.unwrap()); // http://127.0.0.1:19101
```

Embedders and tests can inject a `ProfileResolver` and an
`InstanceProcessBackend` with
`VpnInstanceManager::with_backend_and_resolver(...)`.

## Files and isolation

`SSC_CONFIG_DIR` remains the root. `default` keeps the legacy layout for
upgrades. Named instances live under `instances/<id>/`:

```
<SSC_CONFIG_DIR>/
├── policy.json                 # global policy (default instance)
├── profiles.json               # profile metadata
├── instances.json              # registry (no credentials)
├── runtime/singbox-ephemeral.json
├── tunnel.pid                  # default instance
├── tunnel.status.json
└── instances/
    └── work/
        ├── singbox.json        # secret-bearing config (0600, deleted on stop)
        ├── singbox.meta.json   # redacted config snapshot
        ├── policy.json         # isolated policy snapshot
        ├── tunnel.pid
        ├── tunnel.status.json  # credentials-free
        ├── tunnel.log          # redacted tail endpoint
        ├── tunnel.stop
        └── instance.lock       # flock, 0700 runtime dir
```

Instance ids are validated (`[A-Za-z0-9._-]`, max 64) and may not contain path
separators, `..`, or a leading dot, preventing path traversal.

## Ports

- Explicit `listen_port` / `clash_api_port` are validated and reserved.
- Otherwise ports are allocated from the policy ranges:
  - proxy inbound: `proxy_port_start`–`proxy_port_end` (default `19000`–`19999`)
  - Clash/admin API: `clash_port_start`–`clash_port_end` (default `9091`–`9199`)
  - `default` prefers Clash `9090` for backward compatibility.
- Allocation checks both an in-process reservation table and an OS bind probe,
  so two SSC instances cannot claim the same port.
- A proxy port and its Clash port must differ.

## Fail-closed and reconnect

- If an instance process exits unexpectedly, its state becomes `error`; SSC
  never silently falls back to a direct connection.
- For TUN instances with `fail_closed` + `kill_switch`, the policy kill switch
  is engaged on an unexpected drop.
- Automatic reconnect uses exponential backoff
  (`reconnect_delay_ms` → `reconnect_max_delay_ms`, capped at 16 doublings).
- Reconnect, stop, and restart are scoped to one instance only.

## Diagnostics and startup reconciliation

- `run_diagnostics()` now returns an `instances` array — one snapshot per
  instance (id, name, mode, state, ports, last error) — in addition to the
  legacy `default`-instance fields, so dashboards can show every connection at
  once.
- `reconcile_on_startup()` clears stale `pid` / `status` / `stop` files for the
  `default` instance **and** every named instance found in `instances.json` or
  `instances/`, while leaving live sing-box processes intact and preserving the
  last error so crash evidence stays visible after a restart.

## Security properties

- Credentials live in the profile store / OS keychain and only transiently in a
  `0600` per-instance config, which is overwritten and deleted on stop.
- Status, registry, and WebSocket payloads contain no share URIs or secrets.
- Process identity is verified by exact per-instance config path in the command
  line before a pid is killed or adopted. This prevents cross-instance kills and
  PID-reuse attacks.
- A per-instance `flock` prevents two SSC processes from controlling the same
  instance.
- Instance logs are returned through a redacting, bounded tail.

## Tests

`cargo test --workspace` covers:

- 10 concurrent Local Proxy instances with unique ports and processes
- stopping one instance leaving the other nine connected
- unexpected exit producing `error` (fail-closed) with no direct fallback
- TUN exclusivity while proxies continue to run
- per-instance policy isolation and removal
- API instance CRUD, 404/409 handling, and default protection
