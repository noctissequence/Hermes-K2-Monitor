# Hermes K2 Monitor

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

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

## Cross-VPS relay (Opsi B — partner forwarding)

Setiap event collab yang verified (relay / file-update / task) **diforward best-effort ke partner VPS** supaya ledger ter-replikasi lintas node. Forward re-sign memakai mesh key bersama; `TrustManager` di partner menegakkan nonce/timestamp/HMAC yang sama persis seperti relay lokal.

Konfigurasi (env pada node):

```bash
# daftar partner, pisah koma
COLLAB_PARTNER_URLS=https://relay-a.example.com,https://relay-b.example.com
# identitas lokal yang dipakai buat re-sign + Bearer auth ke partner (wajib terdaftar/<-join di partner)
COLLAB_LOCAL_NODE_ID=n7f2a9
COLLAB_LOCAL_NODE_TOKEN=<rotating token node yang udah join ke partner>
# opsional
COLLAB_RELAY_TIMEOUT=8
```

Tanpa `COLLAB_PARTNER_URLS`, `RelayClient` jadi no-op (`ready()=False`) — relay lokal tidak terpengaruh. Per-partner ada circuit breaker (3 gagal → isolasi 60s) dan bounded in-memory retry queue. Partner yang offline tidak menggagalkan relay lokal (best-effort).

Alur setup 2 VPS:
1. Tiap VPS jalankan server (auth gate aktif di port 8766, bind 127.0.0.1).
2. Daftarkan node silang: VPS-A `POST /api/auth/invite` → code → VPS-B join (dan sebaliknya). Tiap node dapat rotating token + cert.
3. Set `COLLAB_PARTNER_URLS` di tiap VPS menunjuk ke URL relay partner (via CF tunnel), serta `COLLAB_LOCAL_NODE_ID`/`TOKEN` = node yang barusan join ke partner.
4. Expose `/api/relay` tiap VPS via CF tunnel (jangan raw IP — anonim).
5. Event lokal otomatis forward → partner verify → diterima di ledger partner.

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
{"type": "add_discussion", "from": "hermes1", "message": "text"}
```

Entries persist to `~/hermes-shared/log/live.jsonl` (reset by deleting that file + restart).

## Data locations

| Data | Path |
|------|------|
| Task state | `~/hermes-shared/tasks/{pending,processing,done}/` |
| Discussion log | `~/hermes-shared/log/live.jsonl` |
| Frontend | `frontend/index.html` |

Override paths with env `HERMES_SHARED`. Ports override with `K2_WS_PORT` / `K2_HTTP_PORT`. The server binds to `127.0.0.1` by default; set `K2_BIND_HOST=0.0.0.0` only behind an explicitly protected firewall/tunnel. Sensitive-route rate limiting uses the cross-process SQLite store under `collab/.auth/rate_limit.sqlite3`; tune it with `K2_RATE_LIMIT` and `K2_RATE_WINDOW_SECONDS`.

## Viewer authentication (data-bearing endpoints)

Every endpoint that returns or mutates agent data — the raw WebSocket (`:8765`), `/ws`, `/api/state`, and `/api/security` — requires viewer authentication before it will serve a snapshot (agents, tasks, discussion, health, mesh certs, CA fingerprint, audit feed).

Two modes:

| Mode | Behavior |
|------|----------|
| Loopback-only (default) | No `K2_VIEW_TOKEN` set + binding `127.0.0.1` → requests from loopback are served; anything else is rejected with `403`. This is the safe default and closes the old no-auth gap. |
| Shared-secret | Set `K2_VIEW_TOKEN`. Then a valid token is required from **any** source: `X-View-Token: <token>` or `Authorization: Bearer <token>` (REST), or `?token=<token>` (browser WebSocket — browsers can't set custom headers on the WS handshake). |

Rationale: if the host is ever exposed (`K2_BIND_HOST=0.0.0.0`) or placed behind a tunnel, an unauthenticated snapshot would leak mesh cert expiry, CA fingerprint, and the audit feed — the same class of exposure as the original Hermes Monitor incident. The shared secret keeps the panel usable behind a proxy while closing that hole.

Serve the frontend behind a tunnel as `https://panel.example/?token=<secret>` — the JS picks the token up from the URL and passes it to `fetch(/api/...)` and the WebSocket automatically.

## Rate limiting behind a proxy

The collab-sensitive routes rate-limit by client. When served behind a trusted proxy / CF tunnel, the socket peer is the proxy IP, so all tunnel clients would share one bucket. Set `K2_TRUST_XFF=1` to take the real client from `X-Forwarded-For`. **Only enable this when the app is genuinely behind a trusted proxy** — directly exposing it with `K2_TRUST_XFF=1` lets clients spoof `X-Forwarded-For` and rotate buckets.

## Keep-alive (self-heal)

Deploy with a script (e.g. `k2-monitor-keep-alive.sh`) on a cron every 2 minutes that restarts the server if port 8766 is down. Pidfile under `/tmp/`, log under `/var/log/`.

## Frontend design rules

- Zero external CDN (system font stack) — works offline / SEA networks
- No emoji — inline SVG icon per agent
- Mobile responsive via `.dsk`/`.mob` class toggle
- Task board scrolls within fixed container (max 340px)

## License

MIT — concepts from OSSEC/Wazuh-style monitoring, implemented from scratch.
