#!/usr/bin/env python3
"""Live smoke test for the K2 Monitor state and Collab Mesh ledger endpoints."""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


def request_json(base: str, path: str, method: str = "GET", payload: dict | None = None, headers: dict | None = None) -> tuple[int, dict]:
    body = None
    request_headers = {"Accept": "application/json", **(headers or {})}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        request_headers["Content-Type"] = "application/json"
    request = urllib.request.Request(base.rstrip("/") + path, data=body, headers=request_headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            data = {"raw": raw}
        return exc.code, data


def canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def sign(mesh_key: bytes, node_id: str, op: str, payload: dict, nonce: str, ts: float) -> dict:
    material = f"{node_id}|{op}|{canonical(payload)}|{nonce}|{ts}".encode("utf-8")
    signature = hmac.new(mesh_key, material, hashlib.sha256).hexdigest()
    return {"node_id": node_id, "op": op, "payload": payload, "nonce": nonce, "ts": ts, "sig": signature}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default=os.environ.get("K2_BASE_URL", "http://127.0.0.1:8766"))
    parser.add_argument("--owner", default=os.environ.get("COLLAB_OWNER_TOKEN"))
    parser.add_argument("--mesh-key", default=os.environ.get("MESH_KEY"))
    parser.add_argument("--node-id", default="n-smoke")
    args = parser.parse_args()
    if not args.owner or not args.mesh_key:
        print("FAIL: provide --owner/--mesh-key or COLLAB_OWNER_TOKEN/MESH_KEY", file=sys.stderr)
        return 2
    mesh_key = hashlib.sha256(args.mesh_key.encode("utf-8")).digest()

    status, state = request_json(args.base, "/api/state")
    assert status == 200 and "agents" in state and "tasks" in state and "collab" in state, (status, state)
    print(f"PASS /api/state status={status} audit={state['collab'].get('audit', {})}")

    status, invite = request_json(args.base, "/api/auth/invite", "POST", {"node_id": args.node_id, "ttl": 60}, {"X-Collab-Owner": args.owner})
    assert status == 200 and invite.get("code"), (status, invite)
    status, credentials = request_json(args.base, "/api/auth/join", "POST", {"node_id": args.node_id, "conn_code": invite["code"], "expires_at": invite["expires_at"]})
    assert status == 200 and credentials.get("token"), (status, credentials)
    token_headers = {"Authorization": "Bearer " + credentials["token"]}
    print(f"PASS /api/auth/join status={status} node={args.node_id}")

    relay = sign(mesh_key, args.node_id, "message", {"text": "live-smoke"}, "nonce-" + secrets.token_urlsafe(8), time.time())
    status, relay_result = request_json(args.base, "/api/relay", "POST", relay, token_headers)
    assert status == 200 and relay_result.get("status") == "ok", (status, relay_result)
    print(f"PASS /api/relay status={status} ledger_id={relay_result.get('ledger_id')}")

    limit = 50
    nonce = "nonce-ledger-" + secrets.token_urlsafe(8)
    ts = str(time.time())
    ledger_payload = {"action": "ledger_read", "limit": limit}
    material = f"{args.node_id}|broadcast|{canonical(ledger_payload)}|{nonce}|{ts}".encode("utf-8")
    sig = hmac.new(mesh_key, material, hashlib.sha256).hexdigest()
    query = urllib.parse.urlencode({"limit": str(limit), "nonce": nonce, "ts": ts, "sig": sig})
    status, ledger = request_json(args.base, "/api/collab/ledger?" + query, "GET", headers=token_headers)
    assert status == 200 and isinstance(ledger.get("ledger"), list), (status, ledger)
    assert ledger["ledger"], ledger
    print(f"PASS /api/collab/ledger status={status} entries={len(ledger['ledger'])} audit={ledger.get('state', {}).get('audit', {})}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
