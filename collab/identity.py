"""Node identity certificates for Hermes Collab Mesh."""
from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


class IdentityError(ValueError):
    """Raised when a node certificate is invalid or cannot be issued."""


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _iso(value: _dt.datetime) -> str:
    return value.astimezone(_dt.timezone.utc).isoformat()


def _parse_iso(value: str) -> _dt.datetime:
    return _dt.datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(_dt.timezone.utc)


class NodeIdentityManager:
    """Issues compact Ed25519 certificates signed by a persisted mesh CA."""

    def __init__(self, auth_dir: str | os.PathLike[str], validity_seconds: int = 86_400, encryption_key: bytes | None = None):
        self.auth_dir = Path(auth_dir).expanduser().resolve()
        self.auth_dir.mkdir(parents=True, exist_ok=True)
        self.ca_key_path = self.auth_dir / "mesh_ca_private.pem"
        self.nodes_path = self.auth_dir / "nodes.enc"
        self.validity_seconds = int(validity_seconds)
        self._ca_private = self._load_or_create_ca()
        self._ca_public = self._ca_private.public_key()
        seed = encryption_key or self._ca_private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        self._fernet = Fernet(base64.urlsafe_b64encode(hashlib.sha256(seed).digest()))
        self._nodes = self._load_nodes()

    @property
    def ca_public_fingerprint(self) -> str:
        raw = self._ca_public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return hashlib.sha256(raw).hexdigest()

    def _load_or_create_ca(self) -> Ed25519PrivateKey:
        if self.ca_key_path.exists():
            try:
                return serialization.load_pem_private_key(self.ca_key_path.read_bytes(), password=None)
            except (ValueError, TypeError, OSError) as exc:
                raise IdentityError("invalid mesh CA key") from exc
        key = Ed25519PrivateKey.generate()
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        self._atomic_bytes(self.ca_key_path, pem)
        return key

    def _load_nodes(self) -> dict[str, dict[str, Any]]:
        if not self.nodes_path.exists():
            return {}
        try:
            raw = self._fernet.decrypt(self.nodes_path.read_bytes())
            data = json.loads(raw.decode("utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, InvalidToken, UnicodeDecodeError, json.JSONDecodeError, TypeError):
            raise IdentityError("invalid node certificate store")

    def _save_nodes(self) -> None:
        encoded = json.dumps(self._nodes, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self._atomic_bytes(self.nodes_path, self._fernet.encrypt(encoded))

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
    def _cert_material(cert: dict[str, Any]) -> bytes:
        return json.dumps({key: cert[key] for key in ("node_id", "public_key", "issued_at", "expires_at")}, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def issue(self, node_id: str, public_key: str | None = None) -> dict[str, Any]:
        if not isinstance(node_id, str) or not node_id or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for char in node_id):
            raise IdentityError("invalid node_id")
        if node_id in self._nodes and not self._nodes[node_id].get("revoked"):
            raise IdentityError("node certificate already exists")
        if public_key is None:
            node_private = Ed25519PrivateKey.generate()
            public_key = base64.urlsafe_b64encode(node_private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode("ascii")
        try:
            raw_public = base64.urlsafe_b64decode(public_key.encode("ascii"))
            Ed25519PublicKey.from_public_bytes(raw_public)
        except (ValueError, TypeError, base64.binascii.Error) as exc:
            raise IdentityError("invalid node public key") from exc
        issued = _now()
        expires = issued + _dt.timedelta(seconds=self.validity_seconds)
        cert = {"node_id": node_id, "public_key": public_key, "issued_at": _iso(issued), "expires_at": _iso(expires), "revoked": False}
        cert["signature"] = base64.urlsafe_b64encode(self._ca_private.sign(self._cert_material(cert))).decode("ascii")
        self._nodes[node_id] = cert
        self._save_nodes()
        return dict(cert)

    def revoke(self, node_id: str) -> bool:
        cert = self._nodes.get(node_id)
        if not cert:
            return False
        cert["revoked"] = True
        self._save_nodes()
        return True

    def certificate(self, node_id: str) -> dict[str, Any] | None:
        cert = self._nodes.get(node_id)
        return dict(cert) if cert else None

    def verify(self, node_id: str, certificate: dict[str, Any] | None = None) -> bool:
        cert = certificate or self._nodes.get(node_id)
        if not cert or cert.get("node_id") != node_id or cert.get("revoked"):
            return False
        try:
            if _parse_iso(cert["expires_at"]) <= _now():
                return False
            raw_public = base64.urlsafe_b64decode(cert["public_key"].encode("ascii"))
            signature = base64.urlsafe_b64decode(cert["signature"].encode("ascii"))
            self._ca_public.verify(signature, self._cert_material(cert))
            Ed25519PublicKey.from_public_bytes(raw_public)
            return True
        except (KeyError, TypeError, ValueError, InvalidSignature, base64.binascii.Error):
            return False

    def active_nodes(self) -> list[str]:
        return [node_id for node_id, cert in self._nodes.items() if self.verify(node_id, cert)]
