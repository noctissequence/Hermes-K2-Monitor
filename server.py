#!/usr/bin/env python3
"""
Hermes K2 Monitor — real-time agent + system dashboard.
WebSocket (8765) + HTTP frontend (8766).
Pure Python / asyncio. No LLM. Self-contained.

Architecture (from agent-monitor-dashboard skill blueprint):
  - websockets lib on :8765  (primary WS — frontend connects here)
  - aiohttp on :8766          (serves frontend + /api/state + /ws alias)
  - File watcher on ~/hermes-shared/tasks/{pending,processing,done}
  - Discussion log ~/hermes-shared/log/live.jsonl
  - System health via psutil every 5s
"""
import asyncio
import datetime
import hashlib
import json
import logging
import os
import platform
import secrets
import time
from pathlib import Path

from collab.auth import AuthError, MeshAuth
from collab.ratelimit import SQLiteRateLimiter
from collab.relay import RelayClient
from collab.trust import TrustManager
from collab.vault import CollabVault, VaultError

logger = logging.getLogger("hermes-k2-monitor")

try:
    import websockets
    from websockets.server import serve as ws_serve
except ImportError:
    websockets = None
    ws_serve = None

try:
    import aiohttp
    from aiohttp import web
except ImportError:
    aiohttp = None

try:
    import psutil
except ImportError:
    psutil = None

# ---------------- paths & config ----------------
HOME = os.path.expanduser("~")
BASE = Path(__file__).resolve().parent
FRONTEND = BASE / "frontend" / "index.html"
SHARED = Path(os.environ.get("HERMES_SHARED", f"{HOME}/hermes-shared"))
TASKS = SHARED / "tasks"
PENDING, PROCESSING, DONE = TASKS / "pending", TASKS / "processing", TASKS / "done"
LOG_DIR = SHARED / "log"
LIVE_JSONL = LOG_DIR / "live.jsonl"
COLLAB_ROOT = Path(os.environ.get("COLLAB_DIR", str(BASE / "collab"))).expanduser()

WS_PORT = int(os.environ.get("K2_WS_PORT", "8765"))
HTTP_PORT = int(os.environ.get("K2_HTTP_PORT", "8766"))
BIND_HOST = os.environ.get("K2_BIND_HOST", "127.0.0.1")

# Viewer authentication. All data-bearing endpoints (WS /api/state /api/security)
# require this shared token via `X-View-Token` header or `?token=` query/WS-param.
# Empty token (default) => viewer endpoints are REJECTED unless bound to loopback;
# production behind a tunnel MUST set K2_VIEW_TOKEN and bind 0.0.0.0.
VIEW_TOKEN = os.environ.get("K2_VIEW_TOKEN", "")
# Whether to trust X-Forwarded-For for rate limiting identity. Only enable when the
# app is deliberately served behind a trusted proxy/CF tunnel that sets XFF.
TRUST_XFF = os.environ.get("K2_TRUST_XFF", "") == "1"

AGENTS = ("hermes1", "hermes2")
for d in (PENDING, PROCESSING, DONE, LOG_DIR):
    d.mkdir(parents=True, exist_ok=True)

# Collab Mesh storage is deliberately separate from the existing local Hermes data.
collab_vault = CollabVault(COLLAB_ROOT)
mesh_auth = MeshAuth(collab_vault.auth_dir, collab_vault)
mesh_trust = TrustManager(mesh_auth.mesh_key, collab_vault.auth_dir)

# Cross-VPS relay forwarder. No-op (ready()=False) until
# COLLAB_PARTNER_URLS is set. Signing reuses the local mesh_key from auth.
relay_client = RelayClient(
    mesh_key=mesh_auth.mesh_key,
    local_node_id=os.environ.get("COLLAB_LOCAL_NODE_ID", "mesh-local"),
    local_node_token=os.environ.get("COLLAB_LOCAL_NODE_TOKEN", ""),
    timeout=float(os.environ.get("COLLAB_RELAY_TIMEOUT", "8")),
    auth_dir=collab_vault.auth_dir,
)
rate_limiter = SQLiteRateLimiter(
    collab_vault.auth_dir / "rate_limit.sqlite3",
    limit=int(os.environ.get("K2_RATE_LIMIT", "60")),
    window_seconds=int(os.environ.get("K2_RATE_WINDOW_SECONDS", "60")),
)
ws_rate_limiter = SQLiteRateLimiter(
    collab_vault.auth_dir / "ws_rate_limit.sqlite3",
    limit=int(os.environ.get("K2_WS_RATE_LIMIT", "120")),
    window_seconds=int(os.environ.get("K2_WS_RATE_WINDOW_SECONDS", "60")),
)
VIEWER_ACCESS_PATH = collab_vault.auth_dir / "viewer_access.jsonl"

# ---------------- state ----------------
state = {
    "agents": {a: {"status": "online", "task": None} for a in AGENTS},
    "tasks": {"pending": [], "processing": [], "done": []},
    "discussion": [],
    "health": {"cpu": 0, "ram_used_mb": 0, "ram_total_mb": 0,
               "disk_used_gb": 0, "disk_total_gb": 0, "uptime": 0},
    "stats": {"tasks_done_today": 0, "success_rate": 0, "avg_response_s": 0},
}
clients = set()
collab_activity = []
collab_telemetry = {"rate_limit_429": 0, "last_rate_limit_429": None}
mesh_challenges = {}

try:
    BOOT_TS = psutil.boot_time() if psutil else time.time()
except (AttributeError, OSError, RuntimeError):
    BOOT_TS = time.time()

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def uptime_sec():
    return max(0, int(time.time() - BOOT_TS))

def load_discussion():
    if not LIVE_JSONL.exists():
        return []
    out = []
    try:
        with open(LIVE_JSONL, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        out.append(json.loads(line))
                    except (json.JSONDecodeError, TypeError) as exc:
                        logger.warning("Skipping malformed discussion line: %s", exc)
                        continue
    except OSError as exc:
        logger.warning("Could not load discussion log: %s", exc)
        return []
    return out

def append_discussion(from_, message):
    entry = {"from": from_, "message": message, "timestamp": now_iso()}
    try:
        with open(LIVE_JSONL, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except (OSError, TypeError) as exc:
        logger.warning("Could not persist discussion entry: %s", exc)
    state["discussion"].append(entry)
    if len(state["discussion"]) > 200:
        state["discussion"] = state["discussion"][-100:]
    return entry

def read_task(fname):
    try:
        with open(fname, encoding="utf-8") as f:
            d = json.load(f)
        return {"id": d.get("id", Path(fname).stem),
                "title": d.get("title", Path(fname).stem),
                "assigned_to": d.get("assigned_to", ""),
                "status": d.get("status", "")}
    except (OSError, json.JSONDecodeError, AttributeError, TypeError) as exc:
        logger.warning("Could not read task %s: %s", fname, exc)
        return {"id": Path(fname).stem, "title": Path(fname).stem,
                "assigned_to": "", "status": ""}

def scan_tasks():
    state["tasks"]["pending"] = [read_task(p) for p in sorted(PENDING.glob("*.json"))[:50]]
    state["tasks"]["processing"] = [read_task(p) for p in sorted(PROCESSING.glob("*.json"))[:50]]
    state["tasks"]["done"] = [read_task(p) for p in sorted(DONE.glob("*.json"))[:50]]

def update_agents():
    active = state["tasks"]["processing"]
    for a in AGENTS:
        mine = [t for t in active if t.get("assigned_to") == a]
        if mine:
            state["agents"][a] = {"status": "working", "task": mine[0].get("title")}
        else:
            prev = state["agents"][a].get("status")
            state["agents"][a] = {"status": "idle" if prev == "working" else "online",
                                  "task": None}

def compute_task_hash():
    raw = json.dumps(state["tasks"], sort_keys=True, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()

def get_health():
    if not psutil:
        return dict(state["health"], uptime=uptime_sec())
    try:
        vm = psutil.virtual_memory()
        du = psutil.disk_usage(os.sep)
        return {"cpu": psutil.cpu_percent(interval=0.2),
                "ram_used_mb": vm.used // 2**20, "ram_total_mb": vm.total // 2**20,
                "disk_used_gb": du.used // 2**30, "disk_total_gb": du.total // 2**30,
                "uptime": uptime_sec()}
    except (OSError, RuntimeError, ValueError) as exc:
        logger.warning("Could not collect system health: %s", exc)
        return dict(state["health"], uptime=uptime_sec())

# ---------------- broadcast ----------------
def broadcast(payload):
    if not clients:
        return
    msg = json.dumps(payload, default=str)
    dead = []
    for ws in clients:
        try:
            sender = ws.send_str(msg) if hasattr(ws, "send_str") else ws.send(msg)
            asyncio.create_task(sender)
        except (AttributeError, RuntimeError, TypeError, OSError):
            dead.append(ws)
    for ws in dead:
        clients.discard(ws)

async def periodic():
    last_hash = ""
    while True:
        try:
            scan_tasks()
            update_agents()
            h = compute_task_hash()
            if h != last_hash:
                broadcast({"type": "tasks_update", "data": state["tasks"], "timestamp": now_iso()})
                broadcast({"type": "agent_status", "data": state["agents"], "timestamp": now_iso()})
                last_hash = h
            state["health"] = get_health()
            broadcast({"type": "health", "data": state["health"], "timestamp": now_iso()})
        except Exception:
            logger.exception("Periodic monitor iteration failed")
        await asyncio.sleep(2)

async def mock_startup():
    await asyncio.sleep(4)
    entry = append_discussion("system", "Hermes K2 Monitor started on " + platform.node())
    broadcast({"type": "discussion", "from": "system", "message": entry["message"],
               "timestamp": entry["timestamp"]})

def _record_viewer_access(endpoint: str, identity: str, status: int = 200):
    item = {"timestamp": now_iso(), "endpoint": endpoint, "identity": identity, "status": status}
    try:
        with VIEWER_ACCESS_PATH.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n")
    except OSError as exc:
        logger.warning("Could not persist viewer access audit: %s", exc)
    return item


def _read_viewer_access(limit: int = 50):
    rows = []
    try:
        with VIEWER_ACCESS_PATH.open(encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    try:
                        item = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(item, dict):
                        rows.append(item)
    except OSError:
        return []
    return rows[-max(1, min(int(limit), 200)):]


def _ws_peer(ws):
    address = getattr(ws, "remote_address", None)
    if isinstance(address, tuple) and address:
        return str(address[0])
    return str(address or "unknown")


def _ws_rate_limited(ws):
    peer = _ws_peer(ws)
    decision = ws_rate_limiter.check("ws:" + peer)
    if decision.allowed:
        return None
    collab_telemetry["rate_limit_429"] += 1
    collab_telemetry["last_rate_limit_429"] = now_iso()
    _record_collab_activity("rate_limit", scope="ws", identity=peer, status=429, retry_after=decision.retry_after)
    return {"type": "rate_limit", "status": 429, "retry_after": decision.retry_after}


def snapshot():
    return {"type": "init",
            "data": {"agents": state["agents"], "tasks": state["tasks"],
                     "discussion": state["discussion"], "health": state["health"],
                     "stats": state["stats"], "collab": _collab_status()},
            "timestamp": now_iso()}

# ---------------- WebSocket (websockets lib :8765) ----------------
async def ws_handler(ws):
    clients.add(ws)
    try:
        await ws.send(json.dumps(snapshot(), default=str))
        async for raw in ws:
            limited = _ws_rate_limited(ws)
            if limited:
                await ws.send(json.dumps(limited))
                continue
            try:
                msg = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                logger.warning("Ignoring malformed websocket message")
                continue
            if msg.get("type") == "add_discussion":
                frm = msg.get("from") or "system"
                message = msg.get("message") or ""
                entry = append_discussion(frm, message)
                broadcast({"type": "discussion", "from": frm, "message": message,
                           "timestamp": entry["timestamp"]})
    except Exception:
        logger.info("Websocket client disconnected or failed", exc_info=True)
    finally:
        clients.discard(ws)

async def ws_server():
    if ws_serve is None:
        await asyncio.Future()

    from urllib.parse import parse_qs, urlparse

    async def process_request(path: str, request_headers):
        # raw WS (:8765) viewer auth via ?token= (browsers can't set custom
        # headers on WS handshake). No token configured => loopback only,
        # which is enforced by BIND_HOST anyway.
        if VIEW_TOKEN:
            try:
                qs = parse_qs(urlparse(path).query)
            except (TypeError, ValueError):
                qs = {}
            token = (qs.get("token") or [""])[0]
            if not secrets.compare_digest(token, VIEW_TOKEN):
                from aiohttp import web as _web
                return _web.Response(status=403, text="viewer auth required")

    async with ws_serve(ws_handler, BIND_HOST, WS_PORT, ping_interval=None,
                        max_queue=16, max_size=2**20, process_request=process_request):
        await asyncio.Future()

# ---------------- collab auth / route helpers ----------------
def _bearer(request):
    value = request.headers.get("Authorization", "")
    if value.lower().startswith("bearer "):
        return value[7:].strip()
    return request.headers.get("X-Mesh-Token")


def _owner_authorized(request):
    return mesh_auth.verify_owner(request.headers.get("X-Collab-Owner") or _bearer(request))


def _node_authorized(request):
    return mesh_auth.verify_token(_bearer(request))


def _client_ip(request):
    """Best-effort client IP for rate limiting.

    Behind a trusted proxy/CF tunnel the real client is in X-Forwarded-For;
    otherwise fall back to the socket peer. XFF is only honoured when
    K2_TRUST_XFF=1 to prevent spoofing when talking directly to clients.
    """
    if TRUST_XFF:
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            first = xff.split(",")[0].strip()
            if first:
                return first
    return request.remote or "unknown"


def _view_authorized(request):
    """Viewer endpoints: shared-secret via `X-View-Token` / Bearer / `?token=`.

    Returns True if the client proves knowledge of K2_VIEW_TOKEN. If no token is
    configured (K2_VIEW_TOKEN empty), the endpoint is only reachable on loopback.
    """
    if VIEW_TOKEN:
        supplied = (request.headers.get("X-View-Token")
                    or request.query.get("token")
                    or _bearer(request))
        return secrets.compare_digest(supplied or "", VIEW_TOKEN)
    return False


def _loopback_only(request):
    """Whether the request came from a loopback source (safe no-token fallback)."""
    peer = request.remote
    return peer in ("127.0.0.1", "::1", "localhost") or (peer or "").startswith("127.")


def _view_allowed(request):
    """True if a viewer endpoint may serve this request (auth-token OR loopback)."""
    if _view_authorized(request):
        return True
    # No token configured: unsafe to serve data-bearing endpoints off-loopback.
    if not VIEW_TOKEN:
        return _loopback_only(request)
    return False


def _record_collab_activity(kind: str, **data):
    item = {"kind": kind, "timestamp": now_iso(), **data}
    collab_activity.append(item)
    if len(collab_activity) > 160:
        del collab_activity[:-120]
    broadcast({"type": "collab_activity", "data": item, "timestamp": item["timestamp"]})
    return item


def _collab_activity_feed():
    persisted = []
    for entry in collab_vault.read_ledger(60):
        persisted.append({
            "kind": "audit",
            "timestamp": entry.get("ts"),
            "node_id": entry.get("node"),
            "op": entry.get("op"),
            "ledger_id": entry.get("id"),
            "status": "verified",
        })
    transient = [item for item in collab_activity if item.get("kind") != "audit"]
    return sorted(persisted + transient, key=lambda item: item.get("timestamp") or "")[-80:]


def _collab_status(snapshot_data=None):
    data = dict(snapshot_data or collab_vault.collab_state())
    active = [node for node in data.get("nodes", {}).values() if node.get("status") == "active"]
    data["mesh_status"] = "CONNECTED" if active else "PARTITIONED"
    enriched_nodes = {}
    for node_id, node in data.get("nodes", {}).items():
        cert = mesh_auth.identity.certificate(node_id)
        enriched = dict(node)
        enriched["certificate"] = {
            "valid": mesh_auth.identity.verify(node_id, cert),
            "expires_at": cert.get("expires_at") if cert else None,
            "revoked": bool(cert and cert.get("revoked")),
        }
        enriched_nodes[node_id] = enriched
    data["nodes"] = enriched_nodes
    data["ca_fingerprint"] = mesh_auth.identity.ca_public_fingerprint
    data["activity"] = _collab_activity_feed()
    data["telemetry"] = {
        "audit_entries": data.get("audit", {}).get("entries", 0),
        "audit_verified": data.get("audit", {}).get("verified", False),
        "audit_tampered": data.get("audit", {}).get("tampered", False),
        "rate_limit_429": collab_telemetry["rate_limit_429"],
        "last_rate_limit_429": collab_telemetry["last_rate_limit_429"],
    }
    return data


def _sentinel_status():
    """Aggregate security posture read from the local Sentinel Guard state.

    Deliberately REDACTING absolute paths / infra details that the dashboard
    exposes publicly: only status, counts, and sanitized finding types are
    returned. Nothing about the underlying host is leaked to the UI.
    """
    # NOTE: defaults are generic placeholders (no host-specific infra paths).
    # Deployments override via SENTINEL_LOG / SENTINEL_STATE env at runtime so
    # absolute server paths never appear in this public codebase.
    log_path = Path(os.environ.get("SENTINEL_LOG", "/var/log/service-watch.log"))
    state_dir = Path(os.environ.get("SENTINEL_STATE", "/var/tmp/service-watch"))
    findings_path = state_dir / "hunter_state" / "findings.txt"

    last_mtime = 0.0
    try:
        last_mtime = log_path.stat().st_mtime
    except OSError:
        last_mtime = 0.0

    now = time.time()
    last_run_ago = round(now - last_mtime, 1) if last_mtime else None
    uptime_min = round((now - last_mtime) / 60, 1) if last_mtime else None

    findings = []
    try:
        text = findings_path.read_text(encoding="utf-8", errors="ignore")
        for line in text.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split("|")
            if len(parts) >= 2:
                findings.append({"type": parts[0], "severity": parts[1]})
    except OSError:
        pass

    status = "clean" if not findings else "attention"
    return {
        "status": status,
        "findings_count": len(findings),
        "findings": findings,
        "last_run_ago_sec": last_run_ago,
        "uptime_min": uptime_min,
        "agent_watchdog": "active" if last_mtime else "unknown",
    }


async def _json_body(request):
    try:
        data = await request.json()
    except (json.JSONDecodeError, ValueError, TypeError):
        raise web.HTTPBadRequest(text=json.dumps({"error": "invalid JSON"}), content_type="application/json")
    if not isinstance(data, dict):
        raise web.HTTPBadRequest(text=json.dumps({"error": "JSON object required"}), content_type="application/json")
    return data


def _forbidden(reason="forbidden"):
    return web.json_response({"error": reason}, status=403)


def _rate_limit(request, scope: str, identity: str | None = None):
    peer = identity or _client_ip(request)
    bucket = f"{scope}:{peer}"
    decision = rate_limiter.check(bucket)
    if decision.allowed:
        return None
    collab_telemetry["rate_limit_429"] += 1
    collab_telemetry["last_rate_limit_429"] = now_iso()
    _record_collab_activity("rate_limit", scope=scope, identity=identity or peer, status=429, retry_after=decision.retry_after)
    return web.json_response(
        {"error": "rate limit exceeded", "retry_after": decision.retry_after, "limit": decision.limit, "window_seconds": rate_limiter.window_seconds},
        status=429,
        headers={"Retry-After": str(decision.retry_after)},
    )


# ---------------- aiohttp app (:8766) ----------------
def make_app():
    app = web.Application(client_max_size=2**20)

    async def index(request):
        if FRONTEND.exists():
            text = FRONTEND.read_text(encoding="utf-8")
            return web.Response(text=text, content_type="text/html", charset="utf-8")
        return web.Response(text="Hermes K2 Monitor: frontend missing", status=501)

    async def api_state(request):
        if not _view_allowed(request):
            return _forbidden("viewer auth required")
        _record_viewer_access("/api/state", _client_ip(request))
        scan_tasks(); update_agents()
        shared = {}
        try:
            cs = collab_vault.collab_state()
            shared = cs.get("tasks", {}) if isinstance(cs, dict) else {}
        except (OSError, TypeError, ValueError):
            shared = {}
        return web.json_response({"agents": state["agents"], "tasks": state["tasks"],
                                  "discussion": state["discussion"],
                                  "health": state["health"], "stats": state["stats"],
                                  "collab": _collab_status(), "shared_tasks": shared})

    async def api_security(request):
        if not _view_allowed(request):
            return _forbidden("viewer auth required")
        _record_viewer_access("/api/security", _client_ip(request))
        security = _sentinel_status()
        security["viewer_access"] = _read_viewer_access()
        return web.json_response({"security": security})

    async def api_invite(request):
        limited = _rate_limit(request, "auth-invite")
        if limited:
            return limited
        if not _owner_authorized(request):
            return _forbidden()
        body = await _json_body(request)
        node_id = body.get("node_id") or ("n" + secrets.token_hex(3))
        try:
            result = mesh_auth.create_invite(node_id=node_id, ttl=body.get("ttl", 300))
        except AuthError as exc:
            return web.json_response({"error": str(exc)}, status=400)
        return web.json_response(result)

    async def api_join(request):
        limited = _rate_limit(request, "auth-join")
        if limited:
            return limited
        body = await _json_body(request)
        try:
            result = mesh_auth.join(body.get("node_id"), body.get("conn_code") or body.get("code"), body.get("expires_at"))
        except AuthError:
            return _forbidden("invalid or expired code")
        broadcast({"type": "collab_node", "data": {"node_id": result["node_id"], "status": "active"}, "timestamp": now_iso()})
        _record_collab_activity("node", node_id=result["node_id"], status="active", certificate_expires_at=result.get("certificate", {}).get("expires_at"))
        return web.json_response(result)

    async def api_relay(request):
        node_id = _node_authorized(request)
        if not node_id:
            return _forbidden()
        limited = _rate_limit(request, "relay", node_id)
        if limited:
            return limited
        body = await _json_body(request)
        valid, reason, signed_node = mesh_trust.verify(body, expected_node_id=node_id)
        if not valid:
            _record_collab_activity("tamper", node_id=node_id, op=body.get("op", "unknown"), status=403, reason=reason)
            return web.json_response({"status": "rejected", "reason": reason}, status=403)
        try:
            entry = collab_vault.append_event(signed_node, body["op"], body["payload"], body["sig"])
        except VaultError as exc:
            return web.json_response({"status": "rejected", "reason": str(exc)}, status=503)
        broadcast({"type": "collab_event", "data": entry, "timestamp": entry["ts"]})
        _record_collab_activity("audit", node_id=entry["node"], op=entry["op"], ledger_id=entry["id"], status="verified")
        # best-effort replicate to partner VPS
        if relay_client.ready():
            relay_client.forward(body.get("op", "message"), body.get("payload", {}))
        return web.json_response({"status": "ok", "relayed": True, "ledger_id": entry["id"]})

    async def api_collab_file(request):
        node_id = _node_authorized(request)
        if not node_id:
            return _forbidden()
        limited = _rate_limit(request, "file", node_id)
        if limited:
            return limited
        body = await _json_body(request)
        valid, reason, _ = mesh_trust.verify(body, expected_node_id=node_id)
        if not valid:
            _record_collab_activity("tamper", node_id=node_id, op=body.get("op", "unknown"), status=403, reason=reason)
            return web.json_response({"status": "rejected", "reason": reason}, status=403)
        if body.get("op") != "file_update":
            return web.json_response({"status": "rejected", "reason": "operation not allowed"}, status=403)
        payload = body["payload"]
        action = payload.get("action", "read")
        path = payload.get("path")
        try:
            if action == "read":
                return web.json_response({"status": "ok", "path": path, "content": collab_vault.read_file(path)})
            if action == "write":
                try:
                    collab_vault.ensure_audit_clean()
                except VaultError as exc:
                    return web.json_response({"status": "rejected", "reason": str(exc)}, status=503)
                written = collab_vault.write_file(path, payload.get("content", ""))
                try:
                    entry = collab_vault.append_event(node_id, "file_update", {"action": "write", "path": written}, body["sig"])
                except VaultError as exc:
                    return web.json_response({"status": "rejected", "reason": str(exc)}, status=503)
                broadcast({"type": "collab_event", "data": entry, "timestamp": entry["ts"]})
                _record_collab_activity("audit", node_id=entry["node"], op=entry["op"], ledger_id=entry["id"], status="verified")
                if relay_client.ready():
                    relay_client.forward("file_update", {"action": "write", "path": written})
                return web.json_response({"status": "ok", "path": written, "ledger_id": entry["id"]})
            return web.json_response({"error": "action must be read or write"}, status=400)
        except VaultError:
            return _forbidden("forbidden collab path")
        except FileNotFoundError:
            return web.json_response({"error": "collab file not found"}, status=404)
        except UnicodeDecodeError:
            return web.json_response({"error": "collab file is not UTF-8"}, status=415)

    async def api_collab_task(request):
        node_id = _node_authorized(request)
        if not node_id:
            return _forbidden()
        limited = _rate_limit(request, "task", node_id)
        if limited:
            return limited
        body = await _json_body(request)
        valid, reason, _ = mesh_trust.verify(body, expected_node_id=node_id)
        if not valid:
            _record_collab_activity("tamper", node_id=node_id, op=body.get("op", "unknown"), status=403, reason=reason)
            return web.json_response({"status": "rejected", "reason": reason}, status=403)
        if body.get("op") != "task":
            return web.json_response({"status": "rejected", "reason": "operation not allowed"}, status=403)
        payload = body["payload"]
        action = payload.get("action", "create")
        task = payload.get("task") if isinstance(payload.get("task"), dict) else {key: value for key, value in payload.items() if key != "action"}
        if action == "claim":
            task["status"] = "processing"
            task["claimed_by"] = node_id
        elif action in {"complete", "done"}:
            task["status"] = "done"
            task["completed_by"] = node_id
        try:
            collab_vault.ensure_audit_clean()
        except VaultError as exc:
            return web.json_response({"status": "rejected", "reason": str(exc)}, status=503)
        try:
            saved = collab_vault.upsert_task(task)
        except VaultError as exc:
            return web.json_response({"error": str(exc)}, status=400)
        try:
            entry = collab_vault.append_event(node_id, "task", {"action": action, "task": saved}, body["sig"])
        except VaultError as exc:
            return web.json_response({"status": "rejected", "reason": str(exc)}, status=503)
        broadcast({"type": "collab_event", "data": entry, "timestamp": entry["ts"]})
        _record_collab_activity("audit", node_id=entry["node"], op=entry["op"], ledger_id=entry["id"], status="verified")
        if relay_client.ready():
            relay_client.forward("task", {"action": action, "task": saved})
        return web.json_response({"status": "ok", "task": saved, "ledger_id": entry["id"]})

    async def api_collab_adopt(request):
        # Copy a shared (collab) task into the local internal pending queue so the
        # local agent can pick it up. Viewer-auth + loopback (same gate as state).
        if not _view_allowed(request):
            return _forbidden("viewer auth required")
        limited = _rate_limit(request, "collab-adopt")
        if limited:
            return limited
        body = await _json_body(request)
        task_id = (body.get("task_id") or "").strip()
        if not task_id:
            return web.json_response({"error": "task_id required"}, status=400)
        found = None
        try:
            cs = collab_vault.collab_state()
            for bucket in ("pending", "processing", "done"):
                for t in (cs.get("tasks", {}).get(bucket, []) if isinstance(cs, dict) else []):
                    if str(t.get("id")) == task_id:
                        found = dict(t, status="pending", assigned_to="")
                        break
                if found:
                    break
        except (OSError, TypeError, ValueError):
            return web.json_response({"error": "vault read failed"}, status=503)
        if not found:
            return web.json_response({"error": "task not found"}, status=404)
        PENDING.mkdir(parents=True, exist_ok=True)
        target = PENDING / f"{task_id}.json"
        target.write_text(json.dumps(found, ensure_ascii=False, indent=2), encoding="utf-8")
        scan_tasks(); update_agents()
        broadcast({"type": "tasks_update", "data": state["tasks"]})
        return web.json_response({"status": "ok", "task": found, "path": str(target.name)})

    async def api_collab_export(request):
        """Copy a local Hermes task into the shared mesh task vault."""
        if not _view_allowed(request):
            return _forbidden("viewer auth required")
        limited = _rate_limit(request, "collab-export")
        if limited:
            return limited
        body = await _json_body(request)
        task_id = str(body.get("task_id") or "").strip()
        scan_tasks()
        source = None
        for bucket in ("pending", "processing", "done"):
            for task in state["tasks"].get(bucket, []):
                if str(task.get("id")) == task_id:
                    source = dict(task)
                    break
            if source:
                break
        if not source:
            return web.json_response({"error": "internal task not found"}, status=404)
        source["status"] = "processing" if source.get("status") in {"working", "processing"} else "done" if source.get("status") == "done" else "pending"
        source["exported_from"] = "hermes-internal"
        try:
            collab_vault.ensure_audit_clean()
            saved = collab_vault.upsert_task(source)
            entry = collab_vault.append_event(relay_client.local_node_id, "task", {"action": "export", "task": saved}, "local-export")
        except VaultError as exc:
            return web.json_response({"status": "rejected", "reason": str(exc)}, status=503)
        broadcast({"type": "collab_event", "data": entry, "timestamp": entry["ts"]})
        _record_collab_activity("audit", node_id=entry["node"], op=entry["op"], ledger_id=entry["id"], status="verified")
        if relay_client.ready():
            relay_client.forward("task", {"action": "export", "task": saved})
        return web.json_response({"status": "ok", "task": saved, "ledger_id": entry["id"]})

    async def api_collab_ledger(request):
        node_id = _node_authorized(request)
        if not node_id:
            return _forbidden()
        limited = _rate_limit(request, "ledger", node_id)
        if limited:
            return limited
        try:
            limit = int(request.query.get("limit", "100"))
        except ValueError:
            limit = 100
        try:
            limit = max(1, min(limit, 500))
        except (TypeError, ValueError):
            limit = 100
        nonce = request.query.get("nonce")
        ts = request.query.get("ts")
        sig = request.query.get("sig")
        if not nonce or not ts or not sig:
            return _forbidden("signed request required")
        signed = {"node_id": node_id, "op": "broadcast", "payload": {"action": "ledger_read", "limit": limit}, "nonce": nonce, "ts": ts, "sig": sig}
        valid, reason, _ = mesh_trust.verify(signed, expected_node_id=node_id)
        if not valid:
            _record_collab_activity("tamper", node_id=node_id, op="ledger_read", status=403, reason=reason)
            return web.json_response({"status": "rejected", "reason": reason}, status=403)
        return web.json_response({"ledger": collab_vault.read_ledger(limit), "state": _collab_status()})

    async def api_mesh_prepare_revoke(request):
        limited = _rate_limit(request, "mesh-revoke-prepare")
        if limited:
            return limited
        if not _owner_authorized(request):
            return _forbidden()
        body = await _json_body(request)
        node_id = body.get("node_id")
        node = collab_vault.collab_state().get("nodes", {}).get(node_id) if isinstance(node_id, str) else None
        if not node:
            return web.json_response({"error": "node not found"}, status=404)
        challenge = secrets.token_urlsafe(18)
        phrase = f"REVOKE {node_id}"
        mesh_challenges[challenge] = {"node_id": node_id, "phrase": phrase, "expires_at": time.time() + 60}
        _record_collab_activity("kill_switch", node_id=node_id, status="challenge_issued")
        return web.json_response({"status": "challenge_issued", "challenge": challenge, "phrase": phrase, "expires_in": 60})

    async def api_mesh_revoke(request):
        limited = _rate_limit(request, "mesh-revoke-confirm")
        if limited:
            return limited
        if not _owner_authorized(request):
            return _forbidden()
        body = await _json_body(request)
        challenge = body.get("challenge")
        record = mesh_challenges.pop(challenge, None) if isinstance(challenge, str) else None
        if not record or record["expires_at"] < time.time() or record["node_id"] != body.get("node_id"):
            return _forbidden("invalid or expired mesh challenge")
        if body.get("confirmation") != record["phrase"] or body.get("mesh_confirmation") != "CONFIRM MESH REVOKE":
            return web.json_response({"error": "mesh confirmation mismatch"}, status=400)
        node_id = record["node_id"]
        if not mesh_auth.revoke_node(node_id):
            return web.json_response({"error": "node not found"}, status=404)
        broadcast({"type": "collab_node", "data": {"node_id": node_id, "status": "revoked"}, "timestamp": now_iso()})
        _record_collab_activity("kill_switch", node_id=node_id, status="revoked")
        return web.json_response({"status": "ok", "revoked": node_id})

    async def aio_ws(request):
        # Viewer auth: accept ?token= (browser WS can't set custom headers).
        # _view_allowed() handles the no-token -> loopback-only fallback.
        if not _view_allowed(request):
            return web.json_response({"error": "viewer auth required"}, status=403)
        ws = web.WebSocketResponse(autoping=True)
        await ws.prepare(request)
        clients.add(ws)
        await ws.send_json(snapshot())
        try:
            async for raw in ws:
                limited = _ws_rate_limited(ws)
                if limited:
                    await ws.send_json(limited)
                    continue
                try:
                    msg = json.loads(raw)
                except (json.JSONDecodeError, TypeError):
                    logger.warning("Ignoring malformed aiohttp websocket message")
                    continue
                if msg.get("type") == "add_discussion":
                    # Write path requires explicit view auth (token or loopback).
                    if not _view_allowed(request):
                        continue
                    entry = append_discussion(msg.get("from") or "system",
                                              msg.get("message") or "")
                    broadcast({"type": "discussion", "from": entry["from"],
                               "message": entry["message"],
                               "timestamp": entry["timestamp"]})
        except Exception:
            logger.info("Aiohttp websocket client disconnected or failed", exc_info=True)
        finally:
            clients.discard(ws)
        return ws

    app.router.add_get("/", index)
    app.router.add_get("/index.html", index)
    app.router.add_get("/api/state", api_state)
    app.router.add_get("/api/security", api_security)
    app.router.add_post("/api/auth/invite", api_invite)
    app.router.add_post("/api/auth/join", api_join)
    app.router.add_post("/api/relay", api_relay)
    app.router.add_post("/api/collab/file", api_collab_file)
    app.router.add_post("/api/collab/task", api_collab_task)
    app.router.add_post("/api/collab/adopt", api_collab_adopt)
    app.router.add_post("/api/collab/export", api_collab_export)
    app.router.add_get("/api/collab/ledger", api_collab_ledger)
    app.router.add_post("/api/mesh/revoke/prepare", api_mesh_prepare_revoke)
    app.router.add_post("/api/mesh/revoke", api_mesh_revoke)
    app.router.add_get("/ws", aio_ws)
    return app

async def http_server():
    runner = web.AppRunner(make_app())
    await runner.setup()
    site = web.TCPSite(runner, BIND_HOST, HTTP_PORT)
    await site.start()
    await asyncio.Future()

# ---------------- main ----------------
def main():
    state["discussion"] = load_discussion()
    tasks = [periodic(), mock_startup()]
    if ws_serve is not None:
        tasks.append(ws_server())
    if aiohttp is not None:
        tasks.append(http_server())
    print(f"[k2-monitor] Hermes K2 Monitor\n  WS  : ws://{BIND_HOST}:{WS_PORT}\n  HTTP: http://{BIND_HOST}:{HTTP_PORT}\n  shared: {SHARED}", flush=True)
    try:
        asyncio.get_event_loop().run_until_complete(asyncio.gather(*tasks))
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
