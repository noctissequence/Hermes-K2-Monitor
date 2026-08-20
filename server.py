#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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
import asyncio, datetime, hashlib, json, os, platform, time
from pathlib import Path

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

WS_PORT = int(os.environ.get("K2_WS_PORT", "8765"))
HTTP_PORT = int(os.environ.get("K2_HTTP_PORT", "8766"))

AGENTS = ("hermes1", "hermes2")
for d in (PENDING, PROCESSING, DONE, LOG_DIR):
    d.mkdir(parents=True, exist_ok=True)

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

try:
    BOOT_TS = psutil.boot_time() if psutil else time.time()
except Exception:
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
                    except Exception:
                        continue
    except Exception:
        return []
    return out

def append_discussion(from_, message):
    entry = {"from": from_, "message": message, "timestamp": now_iso()}
    try:
        with open(LIVE_JSONL, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass
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
    except Exception:
        return {"id": Path(fname).stem, "title": Path(fname).stem,
                "assigned_to": "", "status": ""}

def scan_tasks():
    state["tasks"]["pending"] = [read_task(p) for p in sorted(PENDING.glob("*.json"))[:50]]
    state["tasks"]["processing"] = [read_task(p) for p in sorted(PROCESSING.glob("*.json"))[:50]]
    state["tasks"]["done"] = [read_task(p) for p in sorted(DONE.glob("*.json"))[:50]]

def update_agents():
    active = state["tasks"]["processing"]
    working_agents = set(t.get("assigned_to") for t in active if t.get("assigned_to"))
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
    return hashlib.md5(raw.encode()).hexdigest()

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
    except Exception:
        return dict(state["health"], uptime=uptime_sec())

# ---------------- broadcast ----------------
def broadcast(payload):
    if not clients:
        return
    msg = json.dumps(payload, default=str)
    dead = []
    for ws in clients:
        try:
            asyncio.create_task(ws.send(msg))
        except Exception:
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
            pass
        await asyncio.sleep(2)

async def mock_startup():
    await asyncio.sleep(4)
    entry = append_discussion("system", "Hermes K2 Monitor started on " + platform.node())
    broadcast({"type": "discussion", "from": "system", "message": entry["message"],
               "timestamp": entry["timestamp"]})

def snapshot():
    return {"type": "init",
            "data": {"agents": state["agents"], "tasks": state["tasks"],
                     "discussion": state["discussion"], "health": state["health"],
                     "stats": state["stats"]},
            "timestamp": now_iso()}

# ---------------- WebSocket (websockets lib :8765) ----------------
async def ws_handler(ws):
    clients.add(ws)
    try:
        await ws.send(json.dumps(snapshot(), default=str))
        async for raw in ws:
            try:
                msg = json.loads(raw)
            except Exception:
                continue
            if msg.get("type") == "add_discussion":
                frm = msg.get("from") or "system"
                message = msg.get("message") or ""
                entry = append_discussion(frm, message)
                broadcast({"type": "discussion", "from": frm, "message": message,
                           "timestamp": entry["timestamp"]})
    except Exception:
        pass
    finally:
        clients.discard(ws)

async def ws_server():
    if ws_serve is None:
        await asyncio.Future()
    async with ws_serve(ws_handler, "0.0.0.0", WS_PORT, ping_interval=None,
                        max_queue=16, max_size=2**20):
        await asyncio.Future()

# ---------------- aiohttp app (:8766) ----------------
def make_app():
    app = web.Application(client_max_size=2**20)

    async def index(request):
        if FRONTEND.exists():
            text = FRONTEND.read_text(encoding="utf-8")
            return web.Response(text=text, content_type="text/html", charset="utf-8")
        return web.Response(text="Hermes K2 Monitor: frontend missing", status=501)

    async def api_state(request):
        scan_tasks(); update_agents()
        return web.json_response({"agents": state["agents"], "tasks": state["tasks"],
                                  "discussion": state["discussion"],
                                  "health": state["health"], "stats": state["stats"]})

    async def aio_ws(request):
        ws = web.WebSocketResponse(autoping=True)
        await ws.prepare(request)
        try:
            async for raw in ws:
                try:
                    msg = json.loads(raw)
                except Exception:
                    continue
                if msg.get("type") == "add_discussion":
                    entry = append_discussion(msg.get("from") or "system",
                                              msg.get("message") or "")
                    broadcast({"type": "discussion", "from": entry["from"],
                               "message": entry["message"],
                               "timestamp": entry["timestamp"]})
        except Exception:
            pass
        return ws

    app.router.add_get("/", index)
    app.router.add_get("/index.html", index)
    app.router.add_get("/api/state", api_state)
    app.router.add_get("/ws", aio_ws)
    return app

async def http_server():
    runner = web.AppRunner(make_app())
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", HTTP_PORT)
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
    print(f"[k2-monitor] Hermes K2 Monitor\n  WS  : ws://0.0.0.0:{WS_PORT}\n  HTTP: http://0.0.0.0:{HTTP_PORT}\n  shared: {SHARED}", flush=True)
    try:
        asyncio.get_event_loop().run_until_complete(asyncio.gather(*tasks))
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
