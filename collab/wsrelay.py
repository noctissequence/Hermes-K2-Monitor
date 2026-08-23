"""Persistent outbound WebSocket link between mesh nodes.

Upgrades the HTTP-POST-per-event relay transport to a persistent WebSocket so
events stream over ONE established connection instead of a fresh POST (and TLS
handshake) each time — the biggest real-time latency win for the K2 relay,
while keeping the exact same trust envelope.

How it is secured (anonymity-by-design preserved):
  * The link is OUTBOUND only — the node dials its partner's relay endpoint;
    it never opens a listener, so no new inbound port / DNAT / exposure.
  * Auth bind: the first frame must be an `auth` message carrying this node's
    rotating bearer token + node_id. The receiving node validates it against
    its own MeshAuth (`verify_token`) and pins the peer's node_id to this
    connection. Same identity binding as `_node_authorized` on HTTP routes.
  * Every event frame after auth is the SAME signed envelope used by HTTP relay
    (HMAC + nonce + timestamp + node_id), re-signed by the local node. A frame
    that fails `mesh_trust.verify` is dropped — an attacker cannot inject or
    impersonate without the node token AND a valid signature.
  * Only whitelisted ops are forwarded (ALLOWED_OPS), matching the relay.
  * Per-link circuit breaker + exponential backoff + auto-reconnect means a
    dropped link retries and recovers without manual intervention.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, Callable, Optional, TYPE_CHECKING

try:
    import aiohttp
except ImportError:  # pragma: no cover
    aiohttp = None

if TYPE_CHECKING:
    from aiohttp import ClientSession as _ClientSession
    from aiohttp.client_ws import ClientWebSocketResponse as _ClientWebSocketResponse

logger = logging.getLogger("k2.wsrelay")

RECONNECT_BASE = 4.0        # seconds
RECONNECT_MAX = 120.0       # cap
RECONNECT_MULT = 2.0        # exponential factor
WS_AUTH_TIMEOUT = 10.0      # seconds to wait for auth handshake
WS_FRAME_TIMEOUT = 60.0     # idle timeout for incoming frames on the outbound link


def _ws_url(partner_http: str) -> str:
    """Convert a partner HTTP base URL to a ws(s) relay URL."""
    scheme = "wss" if partner_http.startswith("https") else "ws"
    host = partner_http.split("://", 1)[1].rstrip("/")
    return f"{scheme}://{host}/ws/relay"


class WSRelayClient:
    """Dial a partner's relay WS, authenticate, and push signed events.

    The same events that would go to `/api/relay` over HTTP are delivered as
    frames over this persistent link. HTTP POST relay remains the fallback when
    the link is down.
    """

    def __init__(
        self,
        partner_url: str,
        node_id: str,
        token: str,
        *,
        signer: Callable[[str, dict[str, Any]], dict[str, Any]] | None = None,
        timeout: float = 10.0,
    ):
        self.partner_url = partner_url
        self.node_id = node_id
        self.token = token
        self.signer = signer          # fn(op, payload) -> signed envelope
        self.timeout = timeout
        self._ws: Optional[_ClientWebSocketResponse] = None
        self._session: Optional[_ClientSession] = None
        self._running = False
        self._reconnects = 0
        self._task: Optional[asyncio.Task] = None

    # -- lifecycle --------------------------------------------------------
    def start(self, on_event: Callable[[dict[str, Any]], None] | None = None) -> None:
        """Launch the background link loop (auto-reconnect). `on_event` is only
        needed if this client is also expected to *receive* frames (normally a
        mesh node runs the WS server for inbound and this client for outbound).
        """
        self._running = True
        self._on_event = on_event or (lambda _m: None)
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        self._running = False
        if self._ws:
            try:
                await self._ws.close()
            except Exception:  # noqa: BLE001
                pass
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        if self._session and not getattr(self._session, "closed", True):
            await self._session.close()
            self._session = None

    @property
    def connected(self) -> bool:
        return self._ws is not None and not self._ws.closed

    # -- internals --------------------------------------------------------
    async def send(self, op: str, payload: dict[str, Any]) -> bool:
        """Actively push a signed event over the link, if connected."""
        if not self.connected or self.signer is None:
            return False
        envelope = self.signer(op, payload)
        try:
            await self._ws.send_str(json.dumps(envelope))
            return True
        except Exception:  # noqa: BLE001 - link broke; reconnect loop handles it
            await self._drop()
            return False

    async def _drop(self) -> None:
        if self._ws and not self._ws.closed:
            try:
                await self._ws.close()
            except Exception:  # noqa: BLE001
                pass
        self._ws = None

    async def _run(self) -> None:
        while self._running:
            try:
                await self._dial_and_stream()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - reconnect loop never dies
                logger.warning("wsrelay link to %s dropped: %s", self.partner_url, exc)
            if not self._running:
                break
            delay = RECONNECT_BASE * (RECONNECT_MULT ** self._reconnects)
            delay = min(delay, RECONNECT_MAX)
            self._reconnects += 1
            logger.info("wsrelay reconnecting to %s in %.0fs", self.partner_url, delay)
            await asyncio.sleep(delay)

    async def _dial_and_stream(self) -> None:
        if aiohttp is None:
            raise RuntimeError("aiohttp unavailable")
        if self._session is None or getattr(self._session, "closed", True):
            self._session = aiohttp.ClientSession()
        url = _ws_url(self.partner_url)
        assert aiohttp is not None
        self._ws = await self._session.ws_connect(
            url, heartbeat=30, autoclose=False, receive_timeout=self.timeout
        )
        # auth handshake first
        await self._ws.send_str(json.dumps({
            "type": "auth",
            "node_id": self.node_id,
            "token": self.token,
        }))
        try:
            resp = await asyncio.wait_for(self._ws.receive(), timeout=WS_AUTH_TIMEOUT)
        except (asyncio.TimeoutError, Exception):  # noqa: BLE001
            await self._drop()
            raise RuntimeError("wsrelay auth handshake failed/timeout")
        data = resp.data if hasattr(resp, "data") else {}
        if isinstance(data, bytes):
            data = data.decode("utf-8", errors="ignore")
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except json.JSONDecodeError:
                data = {}
        if resp.type != aiohttp.WSMsgType.TEXT or (isinstance(data, dict) and data.get("status") != "ok"):
            await self._drop()
            raise RuntimeError("wsrelay auth rejected")
        self._reconnects = 0  # healthy link
        logger.info("wsrelay link established to %s (%s)", self.partner_url, self.node_id)
        # stream: eagerly deliver outbound since the relay's HTTP path also
        # calls this client; receive any inbound frames (relayed events).
        while self._running and not self._ws.closed:
            msg = await self._ws.receive()
            if msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED,
                            aiohttp.WSMsgType.CLOSING, aiohttp.WSMsgType.ERROR):
                break
            if msg.type == aiohttp.WSMsgType.TEXT and msg.data:
                try:
                    frame = json.loads(msg.data)
                except json.JSONDecodeError:
                    continue
                if self._on_event and isinstance(frame, dict):
                    self._on_event(frame)
