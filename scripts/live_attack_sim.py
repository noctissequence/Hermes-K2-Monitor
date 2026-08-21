#!/usr/bin/env python3
"""Generate safe, temporary rate-limit and node-tamper events for the dashboard preview."""
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


def validate_base(base: str) -> None:
    parsed = urllib.parse.urlsplit(base)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("base URL must use http or https")


def request_json(base: str, path: str, method: str = "GET", payload: dict | None = None, headers: dict | None = None) -> tuple[int, dict]:
    validate_base(base)
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    request_headers = {"Accept": "application/json", **(headers or {})}
    if body is not None:
        request_headers["Content-Type"] = "application/json"
    request = urllib.request.Request(base.rstrip("/") + path, data=body, headers=request_headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=5) as response:  # nosec B310
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            return exc.code, json.loads(raw)
        except json.JSONDecodeError:
            return exc.code, {"error": raw}


def canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def signed(mesh_key: bytes, node_id: str, payload: dict, nonce: str) -> dict:
    ts = time.time()
    material = f"{node_id}|message|{canonical(payload)}|{nonce}|{ts}".encode()
    return {"node_id": node_id, "op": "message", "payload": payload, "nonce": nonce, "ts": ts, "sig": hmac.new(mesh_key, material, hashlib.sha256).hexdigest()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default=os.environ.get("K2_BASE_URL", "http://127.0.0.1:8766"))
    parser.add_argument("--owner", default=os.environ.get("COLLAB_OWNER_TOKEN"))
    parser.add_argument("--mesh-key", default=os.environ.get("MESH_KEY"))
    parser.add_argument("--node-id", default="n-attack-" + secrets.token_hex(4))
    parser.add_argument("--attempts", type=int, default=6, help="relay attempts after tamper; low server limits trigger 429 sooner")
    args = parser.parse_args()
    validate_base(args.base)
    if not args.owner or not args.mesh_key:
        print("FAIL: provide owner and mesh key", file=sys.stderr)
        return 2
    if args.attempts < 1:
        parser.error("attempts must be positive")
    mesh_key = hashlib.sha256(args.mesh_key.encode()).digest()

    status, invite = request_json(args.base, "/api/auth/invite", "POST", {"node_id": args.node_id, "ttl": 300}, {"X-Collab-Owner": args.owner})
    if status != 200:
        raise RuntimeError(("invite", status, invite))
    status, credentials = request_json(args.base, "/api/auth/join", "POST", {"node_id": args.node_id, "conn_code": invite["code"], "expires_at": invite["expires_at"]})
    if status != 200:
        raise RuntimeError(("join", status, credentials))
    auth = {"Authorization": "Bearer " + credentials["token"]}

    tampered = signed(mesh_key, args.node_id, {"text": "original"}, "tamper-" + secrets.token_hex(6))
    tampered["payload"] = {"text": "modified-after-signing"}
    tamper_status, tamper_body = request_json(args.base, "/api/relay", "POST", tampered, auth)
    if tamper_status != 403:
        raise RuntimeError(("tamper", tamper_status, tamper_body))

    statuses = []
    for index in range(args.attempts):
        status, body = request_json(args.base, "/api/relay", "POST", signed(mesh_key, args.node_id, {"text": "rate-limit-simulation", "attempt": index}, f"rate-{index}-{secrets.token_hex(4)}"), auth)
        statuses.append({"status": status, "body": body})
    rate_limited = sum(item["status"] == 429 for item in statuses)
    print(json.dumps({"node_id": args.node_id, "tamper_status": tamper_status, "tamper_reason": tamper_body.get("reason"), "relay_statuses": [item["status"] for item in statuses], "rate_limited": rate_limited}, indent=2, sort_keys=True))
    if rate_limited == 0:
        print("FAIL: no HTTP 429 observed; start the server with a low K2_RATE_LIMIT", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
