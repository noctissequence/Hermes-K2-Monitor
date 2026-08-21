"""Message trust controls for Hermes Collab Mesh."""
from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import tempfile
import time
from pathlib import Path
from typing import Any


ALLOWED_OPS = {"message", "task", "file_update", "broadcast", "join"}
FORBIDDEN_KEY_TERMS = {"api_key", "apikey", "secret", "password", "private_key", "env", "hostname", "email", "internal_ip"}
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class TrustError(ValueError):
    """Raised when a signed relay message is not trusted."""


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def timestamp_seconds(value: Any) -> float:
    if isinstance(value, bool):
        raise TrustError("invalid timestamp")
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return _dt.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except ValueError:
            try:
                return float(value)
            except ValueError as exc:
                raise TrustError("invalid timestamp") from exc
    raise TrustError("invalid timestamp")


class TrustManager:
    def __init__(self, mesh_key: bytes, auth_dir: str | Path, replay_window: int = 30, nonce_limit: int = 10_000):
        if not isinstance(mesh_key, bytes) or len(mesh_key) < 16:
            raise ValueError("mesh key must be at least 16 bytes")
        self.mesh_key = mesh_key
        self.auth_dir = Path(auth_dir)
        self.auth_dir.mkdir(parents=True, exist_ok=True)
        self.nonce_path = self.auth_dir / "nonces"
        self.replay_window = int(replay_window)
        self.nonce_limit = int(nonce_limit)
        self._nonces: dict[str, float] = self._load_nonces()

    def sign(self, node_id: str, op: str, payload: dict[str, Any], nonce: str | None = None, ts: Any = None) -> dict[str, Any]:
        if op not in ALLOWED_OPS:
            raise TrustError("operation not allowed")
        if not isinstance(payload, dict):
            raise TrustError("payload must be an object")
        self.validate_payload(payload)
        nonce = nonce or secrets.token_urlsafe(18)
        ts = time.time() if ts is None else ts
        message = self.signing_material(node_id, op, payload, nonce, ts)
        sig = hmac.new(self.mesh_key, message, hashlib.sha256).hexdigest()
        return {"node_id": node_id, "op": op, "payload": payload, "nonce": nonce, "ts": ts, "sig": sig}

    def signing_material(self, node_id: str, op: str, payload: dict[str, Any], nonce: str, ts: Any) -> bytes:
        return f"{node_id}|{op}|{canonical_json(payload)}|{nonce}|{ts}".encode("utf-8")

    def verify(self, message: dict[str, Any], expected_node_id: str | None = None) -> tuple[bool, str, str | None]:
        if not isinstance(message, dict):
            return False, "invalid message", None
        node_id = message.get("node_id")
        op = message.get("op")
        payload = message.get("payload")
        nonce = message.get("nonce")
        sig = message.get("sig")
        if not isinstance(node_id, str) or not node_id or expected_node_id and node_id != expected_node_id:
            return False, "invalid node", None
        if op not in ALLOWED_OPS:
            return False, "operation not allowed", node_id
        if not isinstance(payload, dict) or not isinstance(nonce, str) or not nonce or not isinstance(sig, str):
            return False, "invalid message fields", node_id
        try:
            ts = timestamp_seconds(message.get("ts"))
            if abs(time.time() - ts) > self.replay_window:
                return False, "stale timestamp", node_id
            self.validate_payload(payload)
            expected = hmac.new(self.mesh_key, self.signing_material(node_id, op, payload, nonce, message.get("ts")), hashlib.sha256).hexdigest()
        except (TrustError, TypeError, ValueError, OverflowError):
            return False, "invalid message", node_id
        if not hmac.compare_digest(expected, sig):
            return False, "invalid signature", node_id
        if not self._remember_nonce(nonce, ts):
            return False, "replayed nonce", node_id
        return True, "verified", node_id

    def validate_payload(self, value: Any, key_path: str = "payload") -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                key_text = str(key).lower().replace("-", "_")
                if key_text in FORBIDDEN_KEY_TERMS or any(term in key_text for term in ("api_key", "private_key", "password", "secret")):
                    raise TrustError("sensitive payload field denied")
                self.validate_payload(child, f"{key_path}.{key}")
            return
        if isinstance(value, list):
            for index, child in enumerate(value):
                self.validate_payload(child, f"{key_path}[{index}]")
            return
        if isinstance(value, str):
            stripped = value.strip()
            if EMAIL_RE.match(stripped):
                raise TrustError("PII payload denied")
            if stripped.startswith(("/", "~/")) or "\\" in stripped or "../" in stripped:
                raise TrustError("personal path denied")
            try:
                ip = ipaddress.ip_address(stripped)
                if ip.is_private or ip.is_loopback or ip.is_link_local:
                    raise TrustError("internal IP payload denied")
            except ValueError:
                pass

    def _load_nonces(self) -> dict[str, float]:
        try:
            data = json.loads(self.nonce_path.read_text(encoding="utf-8"))
            return {str(k): float(v) for k, v in data.items()} if isinstance(data, dict) else {}
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            return {}

    def _save_nonces(self) -> None:
        now = time.time()
        self._nonces = {nonce: ts for nonce, ts in self._nonces.items() if now - ts <= self.replay_window * 4}
        if len(self._nonces) > self.nonce_limit:
            keep = sorted(self._nonces.items(), key=lambda item: item[1], reverse=True)[: self.nonce_limit]
            self._nonces = dict(keep)
        fd, tmp_name = tempfile.mkstemp(prefix=".nonces.", dir=str(self.nonce_path.parent))
        try:
            with open(fd, "w", encoding="utf-8", closefd=True) as handle:
                json.dump(self._nonces, handle, sort_keys=True, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
            Path(tmp_name).replace(self.nonce_path)
            self.nonce_path.chmod(0o600)
        finally:
            try:
                Path(tmp_name).unlink()
            except FileNotFoundError:
                pass

    def _remember_nonce(self, nonce: str, ts: float) -> bool:
        if nonce in self._nonces:
            return False
        self._nonces[nonce] = ts
        self._save_nonces()
        return True
