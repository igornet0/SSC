# P8.1 E2E Validation

**Date:** 2026-09-18T05:25Z
**Status:** `LIVE_PROFILE_REQUIRED`

## Gate

No live VPN share URI is present in SSC profiles / Keychain.

```
LIVE_PROFILE_REQUIRED
```

Import a real working profile, then re-run:

```bash
./target/release/ssc add 'vless://…'
./scripts/p8-e2e.sh
```

Do **not** use a fake URI. Networking checks remain **BLOCKED**.

## Security checks (code — no live VPN needed)

| Test | Expected | Observed | Result |
|------|----------|----------|--------|
| Persistent credentials removed | no raw secrets in singbox-run.json | see unit test `ephemeral_config_keeps_secrets_out_of_persistent_path` | PASS (unit) |
| Keychain source of secret | secrets not in profiles.json plaintext | Keychain / secrets/ fallback | PASS (code) |

## Final

**P8.1 CODE COMPLETE / LIVE E2E BLOCKED**
