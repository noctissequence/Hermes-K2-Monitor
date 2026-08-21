#!/usr/bin/env python3
"""Offline scanner for Collab audit-chain and node-identity anomalies."""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from collab.auth import MeshAuth
from collab.vault import CollabVault


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                rows.append({"_anomaly": f"invalid JSON at line {line_number}: {exc.msg}"})
                continue
            if isinstance(value, dict):
                rows.append(value)
            else:
                rows.append({"_anomaly": f"non-object JSON at line {line_number}"})
    return rows


def scan(root: Path, mesh_key: str | None = None) -> dict[str, Any]:
    root = root.expanduser().resolve()
    vault = CollabVault(root)
    if mesh_key:
        os.environ["MESH_KEY"] = mesh_key
    auth = MeshAuth(vault.auth_dir, vault)
    ledger = load_jsonl(vault.ledger_path)
    audit = load_jsonl(vault.audit_path)
    anomalies: list[str] = []
    if not vault.verify_audit_chain():
        anomalies.append("audit chain invalid, truncated, reordered, or mismatched with ledger")
    if len(ledger) != len(audit):
        anomalies.append(f"ledger/audit count mismatch: ledger={len(ledger)} audit={len(audit)}")

    node_events = Counter()
    unknown_nodes: set[str] = set()
    for entry in ledger:
        node = entry.get("node")
        if not isinstance(node, str) or not node:
            anomalies.append(f"ledger entry {entry.get('id', '<unknown>')} has missing node identity")
            continue
        node_events[node] += 1
        node_state = vault.snapshot().get("nodes", {}).get(node)
        if node_state is None:
            unknown_nodes.add(node)
            anomalies.append(f"ledger node {node} is not registered in state")
        elif node_state.get("status") == "revoked":
            anomalies.append(f"revoked node {node} appears in ledger")
        if not auth.identity.verify(node):
            anomalies.append(f"node {node} has missing, expired, revoked, or invalid certificate")

    for node_id, node in vault.snapshot().get("nodes", {}).items():
        if not auth.identity.verify(node_id):
            anomalies.append(f"registered node {node_id} certificate verification failed")
        if node.get("status") == "revoked" and node_id not in auth.revoked_nodes():
            anomalies.append(f"node {node_id} is revoked in state but absent from persistent kill-switch store")

    return {
        "root": str(root),
        "audit": vault.audit_status(),
        "ledger_entries": len(ledger),
        "audit_entries": len(audit),
        "node_event_counts": dict(node_events),
        "unknown_nodes": sorted(unknown_nodes),
        "anomalies": sorted(set(anomalies)),
        "ok": not anomalies,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--collab-dir", default=os.environ.get("COLLAB_DIR", "collab"))
    parser.add_argument("--mesh-key", default=os.environ.get("MESH_KEY"))
    args = parser.parse_args()
    try:
        report = scan(Path(args.collab_dir), args.mesh_key)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print(json.dumps({"ok": False, "anomalies": [f"scanner error: {exc}"]}, indent=2), file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
