"""Unit tests for the persistent WS relay link client (collab/wsrelay.py)."""
from __future__ import annotations

import asyncio
import unittest

from collab.wsrelay import WSRelayClient, _ws_url, RECONNECT_BASE, RECONNECT_MAX


class TestWsUrl(unittest.TestCase):
    def test_http_maps_to_ws(self):
        self.assertEqual(_ws_url("http://relay-a.example:8766"), "ws://relay-a.example:8766/ws/relay")

    def test_https_maps_to_wss(self):
        self.assertEqual(_ws_url("https://relay-a.example"), "wss://relay-a.example/ws/relay")

    def test_trailing_slash_stripped(self):
        self.assertEqual(_ws_url("https://relay-a.example/"), "wss://relay-a.example/ws/relay")


class TestClientState(unittest.IsolatedAsyncioTestCase):
    async def test_not_connected_initially(self):
        c = WSRelayClient("http://127.0.0.1:1", "n-a", "tok")
        self.assertFalse(c.connected)
        # send before connect is a no-op, not an error
        self.assertFalse(await c.send("message", {"x": 1}))

    async def test_stop_is_safe_when_never_started(self):
        c = WSRelayClient("http://127.0.0.1:1", "n-a", "tok")
        await c.stop()  # must not raise


if __name__ == "__main__":
    unittest.main()
