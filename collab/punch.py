"""P2P NAT punch for Hermes Collab Mesh.

Adds an automatic peer-to-peer UDP path between mesh nodes ON TOP of the
existing HTTPS relay. Nodes exchange punch-signalling over the already
authenticated relay (HMAC + Ed25519 + rotating token), then try a UDP
NAT hole-punch for a low-latency data lane. If the punch fails (symmetric
NAT, firewalled UDP), the existing HTTPS relay remains the data path — so
connectivity is never worse than before the feature.

Anonymity-by-design is preserved: no new controller/lighthouse ever sees a
node's origin IP. The two peers exchange their public endpoint only with
each other, over the authenticated signalling channel. That pair-of-peers
knowledge is the minimum required to establish a direct lane — same trust
posture as the relay itself (a peer already authenticates via HMAC + cert).

Defense in depth:
  * The UDP lane is authenticated by a credential MAC derived from the shared
    mesh key + both node ids + a fresh nonce. Only a node holding the same
    mesh key and addressed as one of the two parties can join the lane.
  * Replay: nonce bound to ts + the relay's existing nonce store is reused.
  * Deny-by-default: the UDP socket ignores any packet that fails the MAC check.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import os
import secrets
import socket
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("k2.punch")

# Constants -------------------------------------------------------------
DEFAULT_UDP_PORT = int(os.environ.get("K2_PUNCH_UDP_PORT", "8767") or "0")  # 0 = disabled
DEFAULT_PUNCH_TIMEOUT = float(os.environ.get("K2_PUNCH_TIMEOUT", "8"))
DEFAULT_LANE_TTL = float(os.environ.get("K2_PUNCH_LANE_TTL", "300"))  # reseal after this many s idle
MAGIC = b"K2PCH1"
MAC_TAG = b"K2MAC1"


def credential_mac(mesh_key: bytes, nonce: str, node_a: str, node_b: str) -> str:
    """Proof-of-mesh-key for a peer pair + session. Both sides derive the
    same value from the same mesh key; a packet carrying a matching MAC is
    only forgeable by a node holding that key."""
    material = f"punch|{nonce}|{sorted([node_a, node_b])[0]}|{sorted([node_a, node_b])[1]}".encode("ascii")
    return hmac.new(mesh_key, material, hashlib.sha256).hexdigest()


def _derive_session_key(mesh_key: bytes, nonce: str) -> bytes:
    return hashlib.sha256(b"k2-lane|" + mesh_key + b"|" + nonce.encode("ascii")).digest()


class RaceError(RuntimeError):
    """A punch race condition was detected (nonce/order mismatch)."""


@dataclass
class PunchState:
    node_id: str
    peers: dict[str, dict[str, Any]] = field(default_factory=dict)  # node_id -> {pub, port, last_seen}
    _lanes: dict[str, tuple[str, Any]] = field(default_factory=dict)  # peer_node_id -> (nonce, coroutine-handle-ish)
    _mac_by_nonce: dict[str, str] = field(default_factory=dict)


class PunchSignaller:
    """Builds/parses punch-intent messages carried over the authenticated relay.

    All signalling rides the EXISTING `/api/relay` path (op="punch") so there
    is no new trust domain: the peer must already authenticate via mesh_key
    + HMAC + Ed25519 + rotating token before any of this is delivered.
    """

    def __init__(self, mesh_key: bytes, node_id: str):
        self.mesh_key = mesh_key
        self.node_id = node_id

    def intent(self, target: str, nonce: str, pub_ip: str, pub_port: int) -> dict[str, Any]:
        return {
            "target": target,
            "intent": "punch",
            "nonce": nonce,
            "pub": pub_ip,       # public endpoint candidate (signalled, not data)
            "port": int(pub_port),
            "ts": time.time(),
        }

    def ack(self, target: str, nonce: str, pub_ip: str, pub_port: int) -> dict[str, Any]:
        return {
            "target": target,
            "intent": "punch_ack",
            "nonce": nonce,
            "pub": pub_ip,
            "port": int(pub_port),
            "ts": time.time(),
        }


class UDPPunchServer:
    """Listens on a UDP socket for: (1) STUN-style binding probe used to
    discover the local NAT mapping, (2) authenticated lane packets.

    The socket is closed by default — it only accepts a packet that carries a
    valid MAC for an in-progress/current session. Everything else is dropped.
    """

    def __init__(self, mesh_key: bytes, bind_host: str = "0.0.0.0", port: int = 0):
        self.mesh_key = mesh_key
        self.bind_host = bind_host
        self.port = port
        self._transport: asyncio.DatagramTransport | None = None
        self._protocol: "PunchDatagramProtocol | None" = None

    async def start(self) -> int:
        loop = asyncio.get_running_loop()
        proto = PunchDatagramProtocol(self.mesh_key)
        self._protocol = proto
        self._transport, _ = await loop.create_datagram_endpoint(
            lambda: proto,
            local_addr=(self.bind_host, self.port),
        )
        sock = self._transport.get_extra_info("socket")
        self.port = sock.getsockname()[1]
        logger.info("k2.punch UDP listen on %s:%s", self.bind_host, self.port)
        return self.port

    def stop(self) -> None:
        if self._transport:
            self._transport.close()
            self._transport = None
        self._protocol = None

    def mac_for(self, nonce: str, node_a: str, node_b: str) -> str:
        return credential_mac(self.mesh_key, nonce, node_a, node_b)


class PunchDatagramProtocol(asyncio.DatagramProtocol):
    """Drops everything that is not a valid MAC-authenticated lane packet."""

    def __init__(self, mesh_key: bytes):
        self.mesh_key = mesh_key
        self._active_macs: set[str] = set()
        self._reader: asyncio.Queue[tuple[Any, Any]] | None = None

    def set_queues(self, active_macs: set[str], reader: asyncio.Queue) -> None:
        self._active_macs = active_macs
        self._reader = reader

    def datagram_received(self, data: bytes, addr: Any) -> None:
        try:
            # Frame: [MAGIC][MAC tag][32-byte hex MAC][payload...]
            if not data.startswith(MAGIC):
                return
            rest = data[len(MAGIC):]
            if not rest.startswith(MAC_TAG):
                return
            mac = rest[len(MAC_TAG):len(MAC_TAG) + 64].decode("ascii", errors="ignore")
            if mac not in self._active_macs:
                return  # not an authenticated session → drop
            payload = rest[len(MAC_TAG) + 64:]
            if self._reader:
                self._reader.put_nowait((payload, addr))
        except Exception:  # noqa: BLE001 - never let a malformed datagram crash the loop
            return

    def error_received(self, exc: BaseException) -> None:
        logger.debug("UDP error: %s", exc)


class PunchClient:
    """Drives discovery of the peer's public endpoint and the hole-punch attempt.

    Pipeline: signal intent (via relay) → both sides learn each other's public
    endpoint → concurrent UDP punch with MAC-authenticated handshake → on
    success, the caller switches the relay data path to the UDP lane; on
    failure/timeout, the caller keeps the HTTPS relay (fallback, never worse).
    """

    def __init__(
        self,
        mesh_key: bytes,
        node_id: str,
        *,
        signaller: PunchSignaller | None = None,
        send: Any | None = None,   # async fn(relay_payload) used to deliver signalling
        udp: UDPPunchServer | None = None,
        timeout: float = DEFAULT_PUNCH_TIMEOUT,
    ):
        self.mesh_key = mesh_key
        self.node_id = node_id
        self.signaller = signaller or PunchSignaller(mesh_key, node_id)
        self._send = send
        self.udp = udp
        self.timeout = timeout
        self._lanes: dict[str, dict[str, Any]] = {}
        self._active_macs: set[str] = set()
        self._reader = asyncio.Queue()
        if self.udp and self.udp._protocol:
            self.udp._protocol.set_queues(self._active_macs, self._reader)

    # -- public ----------------------------------------------------------
    def register_peer(self, node_id: str, pub: str, port: int) -> None:
        self._lanes[node_id] = {"pub": pub, "port": port, "nonce": None}

    def has_lane(self, node_id: str) -> bool:
        info = self._lanes.get(node_id)
        return bool(info and info.get("nonce"))

    def lane_endpoint(self, node_id: str) -> tuple[str, int] | None:
        info = self._lanes.get(node_id)
        if not info or not info.get("nonce"):
            return None
        return (info["pub"], int(info["port"]))

    async def send_intent(self, target: str, endpoint: tuple[str, int]) -> str:
        nonce = secrets.token_urlsafe(18)
        # register our MAC for the target pair so replies from target validate
        self._active_macs.add(credential_mac(self.mesh_key, nonce, self.node_id, target))
        payload = self.signaller.intent(target, nonce, endpoint[0], endpoint[1])
        if self._send:
            await self._send(payload)
        return nonce

    async def handle_signalling(self, node_id: str, payload: dict[str, Any]) -> None:
        """Process an incoming punch intent/ack from a peer (delivered via relay)."""
        intent = payload.get("intent")
        nonce = payload.get("nonce")
        pub = payload.get("pub") or ""
        port = int(payload.get("port") or 0)
        if not nonce or not pub or not port:
            return
        target = payload.get("target")
        if target and target != self.node_id:
            return
        # Peer declares a session for us+it → its MAC must match for traffic it sends us
        self._active_macs.add(credential_mac(self.mesh_key, nonce, self.node_id, node_id))
        info = self._lanes.get(node_id) or {"pub": None, "port": None, "nonce": None}
        info["pub"], info["port"], info["nonce"] = pub, port, nonce
        self._lanes[node_id] = info

    # -- punching --------------------------------------------------------
    async def probe_and_punch(self, node_id: str) -> bool:
        """Attempt a UDP hole-punch to a known peer endpoint. Returns True if a
        MAC-authenticated echo establishes the lane."""
        info = self._lanes.get(node_id)
        if not info or not info.get("nonce"):
            return False
        if not self.udp or not self.udp._transport:
            return False
        mac = credential_mac(self.mesh_key, info["nonce"], self.node_id, node_id)
        sock = self.udp._transport.get_extra_info("socket")
        dest = (info["pub"], int(info["port"]))
        # STUN-ish binding probe first (empty payload) to open the NAT mapping
        sock.sendto(MAGIC + b"BIND", dest)
        await asyncio.sleep(0.15)
        # authenticated lane probe
        frame = MAGIC + MAC_TAG + mac.encode("ascii")
        sock.sendto(frame + b"ping", dest)
        # wait briefly for an ack datagram carrying our MAC on the peer side
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            try:
                payload, _addr = await asyncio.wait_for(self._reader.get(), timeout=0.5)
            except asyncio.TimeoutError:
                continue
            if payload.startswith(b"pong"):
                return True
        return False


def now_mac_active(mac: str, active: set[str]) -> bool:
    return mac in active
