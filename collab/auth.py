"""Authentication and enrollment primitives for Hermes Collab Mesh."""
from __future__ import annotations

import base64
import datetime as _dt
import fcntl
import hashlib
import hmac
import json
import os
import secrets
import tempfile
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from .identity import IdentityError, NodeIdentityManager


class AuthError(ValueError):
    """Raised when a mesh authentication operation is rejected."""


class AuthStoreError(AuthError):
    """Raised when encrypted auth state is missing, malformed, or tampered."""


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _iso(value: _dt.datetime) -> str:
    return value.astimezone(_dt.timezone.utc).isoformat()


def _parse_iso(value: str) -> _dt.datetime:
    return _dt.datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(_dt.timezone.utc)


class MeshAuth:
    """Stores only encrypted join records and token hashes on disk."""

    def __init__(self, auth_dir: str | os.PathLike[str], vault):
        self.auth_dir = Path(auth_dir).expanduser().resolve()
        self.auth_dir.mkdir(parents=True, exist_ok=True)
        self.vault = vault
        self.codes_path = self.auth_dir / "join_codes.enc"
        self.tokens_path = self.auth_dir / "tokens.enc"
        self.mesh_key_path = self.auth_dir / "mesh_key"
        self.owner_token_path = self.auth_dir / "owner_token"
        self.revoked_path = self.auth_dir / "revoked_nodes.enc"
        self._mesh_key = self._load_secret("MESH_KEY", self.mesh_key_path, 32)
        self._owner_token = self._load_secret("COLLAB_OWNER_TOKEN", self.owner_token_path, 32, text=True)
        fernet_key = base64.urlsafe_b64encode(hashlib.sha256(self._mesh_key).digest())
        self._fernet = Fernet(fernet_key)
        self.identity = NodeIdentityManager(self.auth_dir, encryption_key=self._mesh_key)
        self._ensure_store(self.codes_path, {"codes": []})
        self._ensure_store(self.tokens_path, {"tokens": []})
        self._ensure_store(self.revoked_path, {"nodes": []})
        for revoked_node in self._read_store(self.revoked_path, {"nodes": []}).get("nodes", []):
            self.vault.mark_revoked(str(revoked_node))

    @property
    def owner_token(self) -> str:
        return self._owner_token

    @property
    def mesh_key(self) -> bytes:
        return self._mesh_key

    def _load_secret(self, env_name: str, path: Path, size: int, text: bool = False) -> bytes | str:
        env_value = os.environ.get(env_name)
        if env_value:
            return env_value if text else hashlib.sha256(env_value.encode("utf-8")).digest()
        if path.exists():
            value = path.read_text(encoding="utf-8").strip()
            return value if text else base64.urlsafe_b64decode(value.encode("ascii"))
        raw = secrets.token_urlsafe(size) if text else secrets.token_bytes(size)
        encoded = raw if text else base64.urlsafe_b64encode(raw).decode("ascii")
        self._atomic_write(path, encoded + "\n")
        return raw

    @staticmethod
    def _atomic_write(path: Path, content: str) -> None:
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

    def _ensure_store(self, path: Path, default: dict[str, Any]) -> None:
        if not path.exists():
            self._write_store(path, default)

    def _read_store(self, path: Path, default: dict[str, Any]) -> dict[str, Any]:
        try:
            token = path.read_bytes()
            decoded = self._fernet.decrypt(token)
            data = json.loads(decoded.decode("utf-8"))
            return data if isinstance(data, dict) else default.copy()
        except InvalidToken as exc:
            raise AuthStoreError("encrypted auth store invalid") from exc
        except (OSError, json.JSONDecodeError, UnicodeDecodeError, TypeError) as exc:
            raise AuthStoreError("encrypted auth store unreadable") from exc

    def _write_store(self, path: Path, data: dict[str, Any]) -> None:
        encrypted = self._fernet.encrypt(json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        self._atomic_bytes(path, encrypted)

    @staticmethod
    def _atomic_bytes(path: Path, content: bytes) -> None:
        fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
        try:
            with os.fdopen(fd, "wb") as handle:
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

    @staticmethod
    def _hash(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    @staticmethod
    def _valid_node_id(node_id: Any) -> bool:
        if not isinstance(node_id, str) or not 3 <= len(node_id) <= 64:
            return False
        return all(char.isalnum() or char in "_-" for char in node_id)

    def create_invite(self, node_id: str | None = None, ttl: int = 300) -> dict[str, Any]:
        if node_id is not None and not self._valid_node_id(node_id):
            raise AuthError("invalid node_id")
        try:
            ttl = int(ttl)
        except (TypeError, ValueError) as exc:
            raise AuthError("invalid ttl") from exc
        if ttl < 1 or ttl > 86_400:
            raise AuthError("ttl must be between 1 and 86400 seconds")
        code = secrets.token_urlsafe(24)
        expires_at = _iso(_now() + _dt.timedelta(seconds=ttl))
        record = {"code_hash": self._hash(code), "node_id": node_id, "expires_at": expires_at, "used_at": None}
        with self.codes_path.open("a+b") as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            store = self._read_store(self.codes_path, {"codes": []})
            now = _now()
            store["codes"] = [item for item in store.get("codes", []) if not item.get("used_at") and _parse_iso(item["expires_at"]) > now]
            store["codes"].append(record)
            self._write_store(self.codes_path, store)
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        return {"code": code, "expires_at": expires_at, "node_id": node_id}

    def join(self, node_id: str, code: str, expires_at: str | None = None) -> dict[str, Any]:
        if not self._valid_node_id(node_id) or not isinstance(code, str) or not code:
            raise AuthError("invalid or expired code")
        with self.codes_path.open("a+b") as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            store = self._read_store(self.codes_path, {"codes": []})
            match = None
            for item in store.get("codes", []):
                if item.get("used_at") or not hmac.compare_digest(item.get("code_hash", ""), self._hash(code)):
                    continue
                try:
                    valid = _parse_iso(item["expires_at"]) > _now()
                except (KeyError, TypeError, ValueError):
                    valid = False
                if valid and (item.get("node_id") in (None, node_id)):
                    if expires_at:
                        try:
                            requested_expiry = _parse_iso(expires_at)
                        except (TypeError, ValueError):
                            requested_expiry = None
                        if requested_expiry is None or requested_expiry <= _now() or requested_expiry != _parse_iso(item["expires_at"]):
                            continue
                    match = item
                    break
            if match is None:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
                raise AuthError("invalid or expired code")
            existing = self.vault.snapshot().get("nodes", {}).get(node_id)
            if existing:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
                raise AuthError("node already registered")
            try:
                certificate = self.identity.issue(node_id)
            except IdentityError as exc:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
                raise AuthError(str(exc)) from exc
            match["used_at"] = _iso(_now())
            self._write_store(self.codes_path, store)
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        token = secrets.token_urlsafe(32)
        token_expires = _iso(_now() + _dt.timedelta(seconds=86_400))
        token_record = {"node_id": node_id, "token_hash": self._hash(token), "issued_at": _iso(_now()), "expires_at": token_expires, "revoked": False}
        with self.tokens_path.open("a+b") as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            store = self._read_store(self.tokens_path, {"tokens": []})
            store["tokens"] = [item for item in store.get("tokens", []) if not item.get("revoked") and _parse_iso(item["expires_at"]) > _now()]
            store["tokens"].append(token_record)
            self._write_store(self.tokens_path, store)
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        try:
            self.vault.register_node(node_id, role="collab", ttl=86_400)
        except Exception as exc:
            raise AuthError(str(exc)) from exc
        return {"node_id": node_id, "token": token, "expires_at": token_expires, "role": "collab", "certificate": certificate}

    def verify_owner(self, provided: str | None) -> bool:
        try:
            return bool(provided) and hmac.compare_digest(str(provided), self._owner_token)
        except AuthStoreError:
            return False

    def verify_token(self, token: str | None) -> str | None:
        if not isinstance(token, str) or not token:
            return None
        digest = self._hash(token)
        try:
            store = self._read_store(self.tokens_path, {"tokens": []})
        except AuthStoreError:
            return None
        now = _now()
        for item in store.get("tokens", []):
            try:
                valid = _parse_iso(item["expires_at"]) > now
            except (KeyError, TypeError, ValueError):
                valid = False
            if valid and not item.get("revoked") and hmac.compare_digest(item.get("token_hash", ""), digest):
                node_id = item.get("node_id")
                node = self.vault.snapshot().get("nodes", {}).get(node_id, {})
                if node.get("status") == "active" and not self._is_revoked(node_id) and self.identity.verify(node_id):
                    self.vault.touch_node(node_id)
                    return node_id
        return None

    def _is_revoked(self, node_id: str) -> bool:
        return node_id in set(self._read_store(self.revoked_path, {"nodes": []}).get("nodes", []))

    def revoke_node(self, node_id: str) -> bool:
        changed = self.vault.revoke_node(node_id)
        if not changed:
            return False
        self.identity.revoke(node_id)
        revoked = self._read_store(self.revoked_path, {"nodes": []})
        nodes = set(str(value) for value in revoked.get("nodes", []))
        nodes.add(node_id)
        self._write_store(self.revoked_path, {"nodes": sorted(nodes)})
        with self.tokens_path.open("a+b") as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            store = self._read_store(self.tokens_path, {"tokens": []})
            for item in store.get("tokens", []):
                if item.get("node_id") == node_id:
                    item["revoked"] = True
            self._write_store(self.tokens_path, store)
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        return True
