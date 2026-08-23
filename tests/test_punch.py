"""Unit tests for the K2 P2P NAT-punch module (collab/punch.py)."""
from __future__ import annotations

import asyncio
import unittest

from collab.punch import PunchSignaller, PunchClient, UDPPunchServer, credential_mac


class TestCredentialMac(unittest.TestCase):
    def test_deterministic_across_peers(self):
        key = b"x" * 32
        a = credential_mac(key, "nonce-1", "node-a", "node-b")
        b = credential_mac(key, "nonce-1", "node-b", "node-a")
        # Order of node ids must not change the credential (both derive same).
        self.assertEqual(a, b)

    def test_different_nonce_different_mac(self):
        key = b"x" * 32
        a = credential_mac(key, "n1", "a", "b")
        c = credential_mac(key, "n2", "a", "b")
        self.assertNotEqual(a, c)

    def test_different_key_different_mac(self):
        a = credential_mac(b"a" * 32, "n1", "x", "y")
        b = credential_mac(b"b" * 32, "n1", "x", "y")
        self.assertNotEqual(a, b)


class TestSignaller(unittest.TestCase):
    def test_intent_shape(self):
        sig = PunchSignaller(b"k" * 32, "node-local")
        intent = sig.intent("peer", "n1", "203.0.113.5", 9000)
        self.assertEqual(intent["intent"], "punch")
        self.assertEqual(intent["target"], "peer")
        self.assertEqual(intent["nonce"], "n1")
        self.assertEqual(intent["pub"], "203.0.113.5")
        self.assertEqual(intent["port"], 9000)

    def test_ack_shape(self):
        sig = PunchSignaller(b"k" * 32, "node-local")
        ack = sig.ack("peer", "n1", "198.51.100.7", 9001)
        self.assertEqual(ack["intent"], "punch_ack")
        self.assertEqual(ack["port"], 9001)


class TestPunchHandshake(unittest.IsolatedAsyncioTestCase):
    async def test_send_and_receive_intent_registers_mac(self):
        key = b"m" * 32
        sent: list[dict] = []

        async def fake_send(payload):
            sent.append(payload)

        client = PunchClient(key, "node-a", send=fake_send)
        server = UDPPunchServer(key, port=0)
        port = await server.start()
        try:
            # client sends intent to node-b
            await client.send_intent("node-b", ("1.2.3.4", port))
            self.assertEqual(len(sent), 1)
            self.assertEqual(sent[0]["intent"], "punch")

            # simulate node-b receiving the intent and registering the MAC
            client_b = PunchClient(key, "node-b")
            await client_b.handle_signalling("node-a", sent[0])
            self.assertTrue(client_b.has_lane("node-a"))
        finally:
            server.stop()


if __name__ == "__main__":
    unittest.main()
