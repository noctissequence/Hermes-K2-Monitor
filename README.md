# Hermes K2 Monitor

Real-time agent + system monitoring dashboard. Pure Python / asyncio, no LLM, self-contained.

Watches agent task state, discussion log, and system health over WebSocket, served as a cyberpunk terminal dashboard.

## Architecture

```
Agent agents ──write──→ ~/hermes-shared/tasks/{pending,processing,done}
                              │  ~/hermes-shared/log/live.jsonl
                    File Watcher (poll 2s)
                              │
                    WebSocket Server (:8765)
                              │
                    HTTP Server (:8766, serves frontend)
                              │
                    Browser ←→ WebSocket (real-time)
```

| Component | Tech | Port |
|-----------|------|------|
| WebSocket server | Python `websockets` | **8765** (primary, frontend connects here) |
| HTTP + `/api/state` + `/ws` | Python `aiohttp` | **8766** (serves frontend) |
| File watcher | Python polling (2s) | — |
| System health | `psutil` every 2s | — |
| Frontend | Vanilla HTML/CSS/JS, zero external deps | — |

## Dependencies

```bash
pip install websockets aiohttp psutil cryptography
```

Tested on Python 3.11+, websockets 17+, aiohttp 3.14+, cryptography 50+.

## Collab Mesh backend core

The additive backend core lives under `collab/` and keeps collaboration data separate from `~/hermes-shared`. `collab/vault.py` owns the append-only ledger, state snapshot, isolated task folders, mirror directory, whitelist-only file operations, and a tamper-evident audit hash-chain. `collab/auth.py` encrypts join-code, token, and revoked-node stores using the mesh key, enforces single-use TTL join codes, issues revocable bearer tokens, and validates an Ed25519 node certificate signed by the persisted mesh CA. `collab/identity.py` manages the CA and encrypted node certificate registry. `collab/trust.py` signs and verifies canonical HMAC-SHA256 envelopes, rejects stale or replayed messages, limits relay operations, and blocks PII or personal-path payloads.

Runtime secrets are loaded from `MESH_KEY` and `COLLAB_OWNER_TOKEN`; when unset, secure local values are generated under `collab/.auth/`. For production, set both through the process supervisor or secret manager and never commit them. `COLLAB_DIR` can override the default repository-local `collab/` directory. The audit chain is stored in `collab/.auth/audit.jsonl`; the Ed25519 CA private key is stored in `collab/.auth/mesh_ca_private.pem`; node certificates are encrypted in `collab/.auth/nodes.enc`; and revoked node IDs are encrypted in `collab/.auth/revoked_nodes.enc`. Any ledger/audit mismatch causes new relay, file-write, and task mutations to fail closed with HTTP 503 until an operator investigates.

The following new routes are available. Owner-only routes require `X-Collab-Owner` or an owner bearer token; node routes require `Authorization: Bearer <rotating-token>` and a valid signed envelope where applicable.

| Method | Endpoint | Access | Purpose |
|---|---|---|---|
| POST | `/api/auth/invite` | owner | Generate a single-use join code with a bounded TTL. |
| POST | `/api/auth/join` | join code | Enroll a node and return a rotating bearer token. |
| POST | `/api/relay` | signed node | Verify and append a trusted relay event. |
| POST | `/api/collab/file` | signed node | Read/write only under `collab/{task_id}/`. |
| POST | `/api/collab/task` | signed node | Create, claim, or complete a collab task. |
| GET | `/api/collab/ledger` | signed node | Read a bounded ledger page with HMAC authentication. |
| POST | `/api/mesh/revoke/prepare` | owner | Issue a one-time 60-second mesh confirmation challenge. |
| POST | `/api/mesh/revoke` | owner + mesh confirmation | Revoke a node and invalidate its tokens. |

Run the backend security regression suite with:

```bash
python3 -m py_compile server.py collab/*.py tests/test_collab_core.py
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

For live and concurrent operational checks, use the committed scripts:

```bash
# Live state, invite/join, signed relay, and signed ledger read
python3 scripts/live_smoke.py --base http://127.0.0.1:8766

# Four spawned processes, 25 signed relay requests each; expect 429 with a low configured limit
python3 scripts/stress_concurrent.py --base http://127.0.0.1:8766 --workers 4 --requests-per-worker 25 --expect-429

# Read-only audit-chain and node-identity anomaly report
python3 scripts/audit_identity_scan.py --collab-dir ./collab
```

The tests exercise both API-level and direct module behavior. `test_signed_relay_and_replay_rejected` proves a valid HMAC message is accepted, a repeated nonce is rejected with `403`, and a tampered payload is rejected. `test_invite_join_single_use_and_bad_code` proves invalid and reused join codes fail. `test_file_whitelist_allows_collab_and_denies_personal_paths` proves traversal is blocked. `test_audit_tamper_is_detected_and_new_events_fail_closed` mutates `ledger.jsonl` and verifies the chain turns tampered and blocks new events. `test_certificate_integrity_and_revoke_persist_after_restart` mutates a certificate in memory, revokes a node, recreates the vault/auth objects, and proves the node remains revoked and its old token cannot authenticate.

## Run

```bash
python3 server.py
```

- Dashboard: `http://localhost:8766/`
- WebSocket: `ws://localhost:8765` (push/read events)
- REST state: `http://localhost:8766/api/state`

## Event protocol

All events: `{"type": string, "data": object, "timestamp": ISO}`

| Event | Purpose |
|-------|---------|
| `init` | Full state snapshot on connect |
| `tasks_update` | `{pending, processing, done}` on FS change |
| `agent_status` | Agent status (`working`/`idle`/`online`) |
| `health` | CPU / RAM / disk / uptime |
| `discussion` | Live discussion entry |
| `stats` | Derived task stats |
| `collab_activity` | Realtime audit, node, rate-limit, and kill-switch activity |

**Push a discussion entry** (WebSocket /ws or 8765):

```json
{"type": "add_discussion", "from": "yerin", "message": "text"}
```

Entries persist to `~/hermes-shared/log/live.jsonl` (reset by deleting that file + restart).

## Data locations

| Data | Path |
|------|------|
| Task state | `~/hermes-shared/tasks/{pending,processing,done}/` |
| Discussion log | `~/hermes-shared/log/live.jsonl` |
| Frontend | `frontend/index.html` |

Override paths with env `HERMES_SHARED`. Ports override with `K2_WS_PORT` / `K2_HTTP_PORT`. The server binds to `127.0.0.1` by default; set `K2_BIND_HOST=0.0.0.0` only behind an explicitly protected firewall/tunnel. Sensitive-route rate limiting uses the cross-process SQLite store under `collab/.auth/rate_limit.sqlite3`; tune it with `K2_RATE_LIMIT` and `K2_RATE_WINDOW_SECONDS`.

## Keep-alive (self-heal)

`/root/.hermes/scripts/k2-monitor-keep-alive.sh` — cron every 2 min, restarts server if port 8766 is down. Pidfile `/tmp/k2-monitor.pid`, log `/var/log/k2-monitor.log`.

## Frontend design rules

- Zero external CDN (system font stack) — works offline / SEA networks
- No emoji — inline SVG icon per agent
- Mobile responsive via `.dsk`/`.mob` class toggle
- Task board scrolls within fixed container (max 340px)

## License

MIT — concepts from OSSEC/Wazuh-style monitoring, implemented from scratch.
