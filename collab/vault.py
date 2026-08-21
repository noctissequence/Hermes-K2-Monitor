"""Durable storage and path-isolated operations for Hermes Collab Mesh."""
from __future__ import annotations

import copy
import datetime as _dt
import hashlib
import json
import os
import tempfile
import uuid
from pathlib import Path
from typing import Any


class VaultError(ValueError):
    """Raised when a collab vault operation is invalid or unsafe."""


class CollabVault:
    """File-backed collab storage; personal Hermes paths are never exposed."""

    TASK_STATUSES = ("pending", "processing", "done")
    FORBIDDEN_PARTS = {".auth", ".hermes", "keys", "key", ".env", "config.yaml", "config.yml"}

    def __init__(self, root: str | os.PathLike[str]):
        self.root = Path(root).expanduser().resolve()
        self.auth_dir = self.root / ".auth"
        self.ledger_path = self.root / "ledger.jsonl"
        self.audit_path = self.auth_dir / "audit.jsonl"
        self.state_path = self.root / "state.json"
        self.tasks_root = self.root / "tasks"
        self.mirror_root = self.root / "mirror"
        self._ensure_layout()
        self._state = self._load_state()

    @staticmethod
    def now_iso() -> str:
        return _dt.datetime.now(_dt.timezone.utc).isoformat()

    def _ensure_layout(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self.auth_dir.mkdir(parents=True, exist_ok=True)
        self.mirror_root.mkdir(parents=True, exist_ok=True)
        for status in self.TASK_STATUSES:
            (self.tasks_root / status).mkdir(parents=True, exist_ok=True)
        if not self.state_path.exists():
            self._atomic_json_write(self.state_path, self._default_state())
        if not self.ledger_path.exists():
            self.ledger_path.touch(mode=0o600)
        if not self.audit_path.exists():
            self.audit_path.touch(mode=0o600)

    @staticmethod
    def _default_state() -> dict[str, Any]:
        return {
            "nodes": {},
            "tasks": {status: [] for status in CollabVault.TASK_STATUSES},
            "messages": [],
            "mesh_key_rotations": 0,
            "last_sync": None,
            "audit_tampered": False,
        }

    def _load_state(self) -> dict[str, Any]:
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
            base = self._default_state()
            if isinstance(data, dict):
                base.update(data)
            for status in self.TASK_STATUSES:
                if not isinstance(base.get("tasks", {}).get(status), list):
                    base["tasks"][status] = []
            return base
        except (OSError, json.JSONDecodeError, TypeError):
            return self._default_state()

    @staticmethod
    def _atomic_json_write(path: Path, value: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(value, handle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, path)
            os.chmod(path, 0o600)
        finally:
            try:
                os.unlink(tmp_name)
            except FileNotFoundError:
                pass

    def _save_state(self) -> None:
        self._atomic_json_write(self.state_path, self._state)

    def snapshot(self) -> dict[str, Any]:
        return copy.deepcopy(self._state)

    def register_node(self, node_id: str, role: str = "collab", ttl: int = 0) -> None:
        existing = self._state.setdefault("nodes", {}).get(node_id)
        if existing and existing.get("status") == "revoked":
            raise VaultError("node is revoked")
        now = self.now_iso()
        self._state.setdefault("nodes", {})[node_id] = {
            "status": "active",
            "joined_at": self._state.get("nodes", {}).get(node_id, {}).get("joined_at", now),
            "last_seen": now,
            "role": role,
            "ttl": int(ttl),
        }
        self._save_state()

    def touch_node(self, node_id: str) -> None:
        node = self._state.setdefault("nodes", {}).get(node_id)
        if node:
            node["last_seen"] = self.now_iso()
            self._save_state()

    def mark_revoked(self, node_id: str) -> None:
        node = self._state.setdefault("nodes", {}).setdefault(node_id, {"joined_at": None, "role": "collab", "ttl": 0})
        node["status"] = "revoked"
        node["last_seen"] = node.get("last_seen") or self.now_iso()
        self._save_state()

    def revoke_node(self, node_id: str) -> bool:
        node = self._state.setdefault("nodes", {}).get(node_id)
        if not node:
            return False
        node["status"] = "revoked"
        node["last_seen"] = self.now_iso()
        self._save_state()
        return True

    @staticmethod
    def _canonical(value: Any) -> bytes:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")

    def _audit_lines(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        try:
            with self.audit_path.open(encoding="utf-8") as handle:
                for line in handle:
                    if not line.strip():
                        continue
                    item = json.loads(line)
                    if not isinstance(item, dict):
                        return []
                    rows.append(item)
        except (OSError, json.JSONDecodeError, TypeError):
            return []
        return rows

    def verify_audit_chain(self) -> bool:
        try:
            ledger_rows = [json.loads(line) for line in self.ledger_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            audit_rows = self._audit_lines()
            if len(ledger_rows) != len(audit_rows):
                return False
            previous = ""
            for ledger, audit in zip(ledger_rows, audit_rows):
                if not isinstance(ledger, dict) or audit.get("ledger_id") != ledger.get("id"):
                    return False
                if audit.get("prev_hash", "") != previous:
                    return False
                entry_hash = hashlib.sha256(self._canonical(ledger)).hexdigest()
                if audit.get("entry_hash") != entry_hash:
                    return False
                current = hashlib.sha256(self._canonical({"ledger_id": audit["ledger_id"], "prev_hash": previous, "entry_hash": entry_hash})).hexdigest()
                if audit.get("hash") != current:
                    return False
                previous = current
            return True
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError):
            return False

    def ensure_audit_clean(self) -> None:
        if not self.verify_audit_chain():
            self._state["audit_tampered"] = True
            self._save_state()
            raise VaultError("audit chain tampered")

    def audit_status(self) -> dict[str, Any]:
        verified = self.verify_audit_chain()
        audit_rows = self._audit_lines()
        expected = 0
        try:
            expected = sum(1 for line in self.ledger_path.read_text(encoding="utf-8").splitlines() if line.strip())
        except OSError:
            pass
        self._state["audit_tampered"] = not verified
        return {"verified": verified, "tampered": not verified, "entries": len(audit_rows), "expected": expected, "last_hash": audit_rows[-1].get("hash") if audit_rows else ""}

    def append_event(self, node_id: str, op: str, payload: dict[str, Any], sig: str) -> dict[str, Any]:
        self.ensure_audit_clean()
        entry = {
            "id": str(uuid.uuid4()),
            "ts": self.now_iso(),
            "node": node_id,
            "op": op,
            "payload": copy.deepcopy(payload),
            "sig": sig,
        }
        ledger_line = json.dumps(entry, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        previous = self._audit_lines()[-1].get("hash", "") if self._audit_lines() else ""
        entry_hash = hashlib.sha256(self._canonical(entry)).hexdigest()
        audit_hash = hashlib.sha256(self._canonical({"ledger_id": entry["id"], "prev_hash": previous, "entry_hash": entry_hash})).hexdigest()
        audit_entry = {"ledger_id": entry["id"], "prev_hash": previous, "entry_hash": entry_hash, "hash": audit_hash, "ts": entry["ts"]}
        with self.ledger_path.open("a", encoding="utf-8") as handle:
            handle.write(ledger_line + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        with self.audit_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(audit_entry, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        self._apply_event(entry)
        self._state["last_sync"] = entry["ts"]
        self._state["audit_tampered"] = False
        self._save_state()
        return entry

    def _apply_event(self, entry: dict[str, Any]) -> None:
        op = entry.get("op")
        payload = entry.get("payload") or {}
        if op in {"message", "broadcast"}:
            messages = self._state.setdefault("messages", [])
            messages.append({"id": entry["id"], "ts": entry["ts"], "node": entry["node"], "op": op, "payload": payload})
            self._state["messages"] = messages[-200:]
        elif op == "task":
            task = payload.get("task") if isinstance(payload.get("task"), dict) else payload
            if isinstance(task, dict) and task.get("id"):
                self.upsert_task(task)
        elif op == "join":
            joined_id = payload.get("node_id")
            if isinstance(joined_id, str) and joined_id:
                self.register_node(joined_id, role=str(payload.get("role", "collab")))

    def read_ledger(self, limit: int = 100) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 500))
        rows: list[dict[str, Any]] = []
        try:
            with self.ledger_path.open(encoding="utf-8") as handle:
                for line in handle:
                    try:
                        item = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(item, dict):
                        rows.append(item)
        except OSError:
            return []
        return rows[-limit:]

    def safe_path(self, requested: str) -> Path:
        if not isinstance(requested, str) or not requested.strip():
            raise VaultError("invalid collab path")
        normalized = requested.replace("\\", "/")
        if normalized.startswith("/") or "\x00" in normalized:
            raise VaultError("forbidden collab path")
        parts = normalized.split("/")
        if parts and parts[0] == "collab":
            parts = parts[1:]
        if len(parts) < 2 or any(not part or part in {".", ".."} for part in parts):
            raise VaultError("forbidden collab path")
        if any(part.lower() in self.FORBIDDEN_PARTS or part.startswith(".") for part in parts):
            raise VaultError("forbidden collab path")
        candidate = (self.root.joinpath(*parts)).resolve()
        try:
            candidate.relative_to(self.root)
        except ValueError as exc:
            raise VaultError("forbidden collab path") from exc
        return candidate

    def read_file(self, requested: str) -> str:
        path = self.safe_path(requested)
        if not path.is_file():
            raise FileNotFoundError(requested)
        if path.stat().st_size > 1_048_576:
            raise VaultError("collab file too large")
        return path.read_text(encoding="utf-8")

    def write_file(self, requested: str, content: str) -> str:
        if not isinstance(content, str) or len(content.encode("utf-8")) > 1_048_576:
            raise VaultError("invalid or oversized collab file")
        path = self.safe_path(requested)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._atomic_text_write(path, content)
        return str(path.relative_to(self.root)).replace(os.sep, "/")

    @staticmethod
    def _atomic_text_write(path: Path, content: str) -> None:
        fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, path)
            os.chmod(path, 0o600)
        finally:
            try:
                os.unlink(tmp_name)
            except FileNotFoundError:
                pass

    def list_files(self, limit: int = 200) -> list[str]:
        paths: list[str] = []
        for path in sorted(self.root.glob("*/**/*")):
            if path.is_file() and path.parent != self.auth_dir and ".auth" not in path.parts:
                paths.append(str(path.relative_to(self.root)).replace(os.sep, "/"))
        return paths[: max(1, min(int(limit), 500))]

    def upsert_task(self, task: dict[str, Any]) -> dict[str, Any]:
        task = copy.deepcopy(task)
        task_id = str(task.get("id") or uuid.uuid4())
        status = str(task.get("status") or "pending").lower()
        if status == "working":
            status = "processing"
        if status not in self.TASK_STATUSES:
            raise VaultError("invalid collab task status")
        task["id"] = task_id
        task["status"] = status
        task.setdefault("updated_at", self.now_iso())
        for bucket in self.TASK_STATUSES:
            self._state["tasks"][bucket] = [x for x in self._state["tasks"].get(bucket, []) if x.get("id") != task_id]
        self._state["tasks"][status].append(task)
        self._state["tasks"][status] = self._state["tasks"][status][-200:]
        target = self.tasks_root / status / f"{task_id}.json"
        self._atomic_json_write(target, task)
        for other in self.TASK_STATUSES:
            if other != status:
                try:
                    (self.tasks_root / other / f"{task_id}.json").unlink()
                except FileNotFoundError:
                    pass
        self._save_state()
        return task

    def collab_state(self) -> dict[str, Any]:
        audit = self.audit_status()
        data = self.snapshot()
        data["files"] = self.list_files()
        data["audit"] = audit
        return data
