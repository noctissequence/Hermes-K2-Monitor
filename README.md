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
pip install websockets aiohttp psutil
```

Tested on Python 3.11, websockets 17, aiohttp 3.14.

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

Override paths with env `HERMES_SHARED`. Ports override with `K2_WS_PORT` / `K2_HTTP_PORT`.

## Keep-alive (self-heal)

`/root/.hermes/scripts/k2-monitor-keep-alive.sh` — cron every 2 min, restarts server if port 8766 is down. Pidfile `/tmp/k2-monitor.pid`, log `/var/log/k2-monitor.log`.

## Frontend design rules

- Zero external CDN (system font stack) — works offline / SEA networks
- No emoji — inline SVG icon per agent
- Mobile responsive via `.dsk`/`.mob` class toggle
- Task board scrolls within fixed container (max 340px)

## License

MIT — concepts from OSSEC/Wazuh-style monitoring, implemented from scratch.
