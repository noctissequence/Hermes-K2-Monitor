#!/usr/bin/env python3
"""Concurrent multi-process stress test for the signed relay endpoint."""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import multiprocessing
import os
import secrets
import statistics
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass


@dataclass
class Result:
    status: int
    elapsed_ms: float
    error: str = ""


def canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def validate_base(base: str) -> None:
    parsed = urllib.parse.urlsplit(base)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("base URL must use http or https")


def request_json(url: str, method: str, payload: dict | None, headers: dict) -> tuple[int, dict]:
    validate_base(url)
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    request_headers = {"Accept": "application/json", **headers}
    if body is not None:
        request_headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=body, headers=request_headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:  # nosec B310
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            return exc.code, json.loads(raw)
        except json.JSONDecodeError:
            return exc.code, {"error": raw}


def provision(base: str, owner: str, node_id: str) -> tuple[str, str]:
    status, invite = request_json(
        base.rstrip("/") + "/api/auth/invite",
        "POST",
        {"node_id": node_id, "ttl": 300},
        {"X-Collab-Owner": owner},
    )
    if status != 200:
        raise RuntimeError(f"invite failed: HTTP {status} {invite}")
    status, joined = request_json(
        base.rstrip("/") + "/api/auth/join",
        "POST",
        {"node_id": node_id, "conn_code": invite["code"], "expires_at": invite["expires_at"]},
        {},
    )
    if status != 200:
        raise RuntimeError(f"join failed: HTTP {status} {joined}")
    return joined["token"], node_id


def worker(args: tuple[str, str, bytes, str, int, int]) -> list[Result]:
    base, token, mesh_key, node_id, count, worker_id = args
    results: list[Result] = []
    headers = {"Authorization": "Bearer " + token}
    for index in range(count):
        nonce = f"stress-{worker_id}-{index}-{secrets.token_hex(6)}"
        ts = time.time()
        payload = {"text": "stress", "worker": worker_id, "sequence": index}
        material = f"{node_id}|message|{canonical(payload)}|{nonce}|{ts}".encode()
        envelope = {"node_id": node_id, "op": "message", "payload": payload, "nonce": nonce, "ts": ts, "sig": hmac.new(mesh_key, material, hashlib.sha256).hexdigest()}
        started = time.perf_counter()
        try:
            status, body = request_json(base.rstrip("/") + "/api/relay", "POST", envelope, headers)
            error = body.get("error") or body.get("reason") or ""
        except (OSError, ValueError, RuntimeError) as exc:
            status, error = 0, str(exc)
        results.append(Result(status, (time.perf_counter() - started) * 1000, error))
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default=os.environ.get("K2_BASE_URL", "http://127.0.0.1:8766"))
    parser.add_argument("--owner", default=os.environ.get("COLLAB_OWNER_TOKEN"))
    parser.add_argument("--mesh-key", default=os.environ.get("MESH_KEY"))
    parser.add_argument("--token", help="existing node bearer token; omit to provision one with --owner")
    parser.add_argument("--node-id", default="n-stress-" + secrets.token_hex(4))
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--requests-per-worker", type=int, default=25)
    parser.add_argument("--expect-429", action="store_true", help="treat at least one HTTP 429 as a successful rate-limit observation")
    args = parser.parse_args()
    validate_base(args.base)
    if args.workers < 1 or args.requests_per_worker < 1:
        parser.error("workers and requests-per-worker must be positive")
    if not args.mesh_key:
        parser.error("provide --mesh-key or MESH_KEY")
    if not args.token:
        if not args.owner:
            parser.error("provide --token or --owner/COLLAB_OWNER_TOKEN")
        args.token, args.node_id = provision(args.base, args.owner, args.node_id)
    mesh_key = hashlib.sha256(args.mesh_key.encode("utf-8")).digest()
    work = [(args.base, args.token, mesh_key, args.node_id, args.requests_per_worker, worker_id) for worker_id in range(args.workers)]
    context = multiprocessing.get_context("spawn")
    with ProcessPoolExecutor(max_workers=args.workers, mp_context=context) as pool:
        result_groups = list(pool.map(worker, work))
    results = [item for group in result_groups for item in group]
    status_counts: dict[str, int] = {}
    for result in results:
        status_counts[str(result.status)] = status_counts.get(str(result.status), 0) + 1
    latencies = [result.elapsed_ms for result in results if result.status]
    rate_limited = status_counts.get("429", 0)
    print(json.dumps({"total": len(results), "status_counts": status_counts, "rate_limited": rate_limited, "latency_ms": {"p50": round(statistics.median(latencies), 2) if latencies else None, "max": round(max(latencies), 2) if latencies else None}}, indent=2, sort_keys=True))
    if any(result.status == 0 for result in results):
        return 1
    if args.expect_429 and rate_limited == 0:
        print("FAIL: expected at least one HTTP 429 but observed none", file=sys.stderr)
        return 1
    if not args.expect_429 and any(result.status >= 500 for result in results):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
