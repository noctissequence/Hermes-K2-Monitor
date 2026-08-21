import asyncio
import hashlib
import hmac
import json
import os
import tempfile
import time
import unittest
from pathlib import Path

from aiohttp.test_utils import AioHTTPTestCase, unittest_run_loop

from collab.auth import MeshAuth
from collab.identity import NodeIdentityManager
from collab.trust import TrustError
from collab.vault import CollabVault, VaultError


class CollabCoreHTTPTests(AioHTTPTestCase):
    async def get_application(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["COLLAB_DIR"] = self.tmp.name
        os.environ["MESH_KEY"] = "test-mesh-key-for-hermes-collab"
        os.environ["COLLAB_OWNER_TOKEN"] = "owner-test-token"
        import importlib
        import server
        self.server_module = importlib.reload(server)
        return self.server_module.make_app()

    async def tearDownAsync(self):
        await super().tearDownAsync()
        self.tmp.cleanup()
        for key in ("COLLAB_DIR", "MESH_KEY", "COLLAB_OWNER_TOKEN"):
            os.environ.pop(key, None)

    @unittest_run_loop
    async def test_state_keeps_existing_shape_and_adds_collab(self):
        response = await self.client.request("GET", "/api/state")
        self.assertEqual(response.status, 200)
        data = await response.json()
        self.assertIn("agents", data)
        self.assertIn("tasks", data)
        self.assertIn("collab", data)
        self.assertIn("nodes", data["collab"])

    @unittest_run_loop
    async def test_invite_join_single_use_and_bad_code(self):
        response = await self.client.request(
            "POST", "/api/auth/invite", headers={"X-Collab-Owner": "owner-test-token"}, json={"node_id": "n-test", "ttl": 60}
        )
        self.assertEqual(response.status, 200)
        invite = await response.json()
        self.assertEqual(invite["node_id"], "n-test")
        self.assertNotEqual(invite["code"], "")

        bad = await self.client.request("POST", "/api/auth/join", json={"node_id": "n-test", "conn_code": "wrong"})
        self.assertEqual(bad.status, 403)

        joined = await self.client.request("POST", "/api/auth/join", json={"node_id": "n-test", "conn_code": invite["code"]})
        self.assertEqual(joined.status, 200)
        credentials = await joined.json()
        self.assertIn("token", credentials)

        reused = await self.client.request("POST", "/api/auth/join", json={"node_id": "n-other", "conn_code": invite["code"]})
        self.assertEqual(reused.status, 403)

    @unittest_run_loop
    async def test_auth_boundary_and_expired_invite_rejected(self):
        missing_owner = await self.client.request("POST", "/api/auth/invite", json={"node_id": "n-boundary"})
        self.assertEqual(missing_owner.status, 403)
        wrong_owner = await self.client.request("POST", "/api/auth/invite", headers={"X-Collab-Owner": "wrong"}, json={"node_id": "n-boundary"})
        self.assertEqual(wrong_owner.status, 403)
        invalid_node = await self.client.request("POST", "/api/auth/invite", headers={"X-Collab-Owner": "owner-test-token"}, json={"node_id": "../escape"})
        self.assertEqual(invalid_node.status, 400)

        invite_response = await self.client.request(
            "POST", "/api/auth/invite", headers={"X-Collab-Owner": "owner-test-token"}, json={"node_id": "n-expired", "ttl": 1}
        )
        invite = await invite_response.json()
        time.sleep(1.1)
        expired = await self.client.request("POST", "/api/auth/join", json={"node_id": "n-expired", "conn_code": invite["code"], "expires_at": invite["expires_at"]})
        self.assertEqual(expired.status, 403)

    @unittest_run_loop
    async def test_signed_relay_and_replay_rejected(self):
        invite_response = await self.client.request(
            "POST", "/api/auth/invite", headers={"X-Collab-Owner": "owner-test-token"}, json={"node_id": "n-relay"}
        )
        invite = await invite_response.json()
        joined = await self.client.request("POST", "/api/auth/join", json={"node_id": "n-relay", "conn_code": invite["code"]})
        credentials = await joined.json()
        signed = self.server_module.mesh_trust.sign("n-relay", "message", {"text": "hello"}, nonce="nonce-relay")
        headers = {"Authorization": "Bearer " + credentials["token"]}

        unauthenticated = await self.client.request("POST", "/api/relay", json=signed)
        self.assertEqual(unauthenticated.status, 403)
        accepted = await self.client.request("POST", "/api/relay", headers=headers, json=signed)
        self.assertEqual(accepted.status, 200)
        self.assertEqual((await accepted.json())["status"], "ok")

        replay = await self.client.request("POST", "/api/relay", headers=headers, json=signed)
        self.assertEqual(replay.status, 403)
        self.assertEqual((await replay.json())["reason"], "replayed nonce")

        tampered = dict(signed)
        tampered["payload"] = {"text": "tampered"}
        tampered["nonce"] = "nonce-tampered"
        rejected = await self.client.request("POST", "/api/relay", headers=headers, json=tampered)
        self.assertEqual(rejected.status, 403)

    @unittest_run_loop
    async def test_file_whitelist_allows_collab_and_denies_personal_paths(self):
        invite_response = await self.client.request(
            "POST", "/api/auth/invite", headers={"X-Collab-Owner": "owner-test-token"}, json={"node_id": "n-file"}
        )
        invite = await invite_response.json()
        joined = await self.client.request("POST", "/api/auth/join", json={"node_id": "n-file", "conn_code": invite["code"]})
        credentials = await joined.json()
        headers = {"Authorization": "Bearer " + credentials["token"]}

        write = self.server_module.mesh_trust.sign(
            "n-file", "file_update", {"action": "write", "path": "collab/task-1/result.json", "content": '{"ok":true}'}, nonce="nonce-write"
        )
        written = await self.client.request("POST", "/api/collab/file", headers=headers, json=write)
        self.assertEqual(written.status, 200)

        read = self.server_module.mesh_trust.sign(
            "n-file", "file_update", {"action": "read", "path": "collab/task-1/result.json"}, nonce="nonce-read"
        )
        read_response = await self.client.request("POST", "/api/collab/file", headers=headers, json=read)
        self.assertEqual(read_response.status, 200)
        self.assertEqual((await read_response.json())["content"], '{"ok":true}')

        traversal_payload = {"action": "read", "path": "../../.env"}
        traversal_nonce = "nonce-traversal"
        traversal_ts = time.time()
        traversal = {
            "node_id": "n-file", "op": "file_update", "payload": traversal_payload,
            "nonce": traversal_nonce, "ts": traversal_ts,
            "sig": hmac.new(
                self.server_module.mesh_auth.mesh_key,
                self.server_module.mesh_trust.signing_material("n-file", "file_update", traversal_payload, traversal_nonce, traversal_ts),
                hashlib.sha256,
            ).hexdigest(),
        }
        denied = await self.client.request("POST", "/api/collab/file", headers=headers, json=traversal)
        self.assertEqual(denied.status, 403)

    @unittest_run_loop
    async def test_trust_operation_and_path_edge_cases(self):
        trust = self.server_module.mesh_trust
        invalid_op = {"node_id": "n-edge", "op": "read_env", "payload": {}, "nonce": "nonce-op", "ts": time.time(), "sig": "00"}
        verified, reason, _ = trust.verify(invalid_op)
        self.assertFalse(verified)
        self.assertEqual(reason, "operation not allowed")
        future = trust.sign("n-edge", "message", {"text": "future"}, nonce="nonce-future", ts=time.time() + 31)
        verified, reason, _ = trust.verify(future)
        self.assertFalse(verified)
        self.assertEqual(reason, "stale timestamp")

        vault = self.server_module.collab_vault
        bad_paths = ["../../.env", "/root/.env", "~/.ssh/id_rsa", "collab/task/../escape", "collab\\task\\..\\escape", "collab/.auth/secret", "collab/task/" + chr(0)]
        for bad_path in bad_paths:
            with self.assertRaises(VaultError):
                vault.safe_path(bad_path)
        outside = Path(self.tmp.name).parent / "hermes-outside-test"
        outside.write_text("outside", encoding="utf-8")
        link = Path(self.tmp.name) / "task" / "link.txt"
        link.parent.mkdir(parents=True, exist_ok=True)
        try:
            link.symlink_to(outside)
            with self.assertRaises(VaultError):
                vault.safe_path("collab/task/link.txt")
        finally:
            link.unlink(missing_ok=True)
            outside.unlink(missing_ok=True)
        with self.assertRaises(VaultError):
            vault.write_file("collab/task/large.txt", "x" * (1024 * 1024 + 1))

    @unittest_run_loop
    async def test_revoke_invalidates_token(self):
        invite_response = await self.client.request(
            "POST", "/api/auth/invite", headers={"X-Collab-Owner": "owner-test-token"}, json={"node_id": "n-revoke"}
        )
        invite = await invite_response.json()
        joined = await self.client.request("POST", "/api/auth/join", json={"node_id": "n-revoke", "conn_code": invite["code"]})
        credentials = await joined.json()
        headers = {"Authorization": "Bearer " + credentials["token"]}
        revoked = await self.client.request("POST", "/api/mesh/revoke", headers={"X-Collab-Owner": "owner-test-token"}, json={"node_id": "n-revoke"})
        self.assertEqual(revoked.status, 200)
        denied = await self.client.request("GET", "/api/collab/ledger", headers=headers)
        self.assertEqual(denied.status, 403)

    @unittest_run_loop
    async def test_signed_task_and_ledger_read(self):
        invite_response = await self.client.request(
            "POST", "/api/auth/invite", headers={"X-Collab-Owner": "owner-test-token"}, json={"node_id": "n-task"}
        )
        invite = await invite_response.json()
        joined = await self.client.request("POST", "/api/auth/join", json={"node_id": "n-task", "conn_code": invite["code"]})
        credentials = await joined.json()
        headers = {"Authorization": "Bearer " + credentials["token"]}

        task = self.server_module.mesh_trust.sign(
            "n-task", "task", {"action": "create", "task": {"id": "task-1", "title": "Secure task", "status": "pending"}}, nonce="nonce-task"
        )
        created = await self.client.request("POST", "/api/collab/task", headers=headers, json=task)
        self.assertEqual(created.status, 200)
        self.assertEqual((await created.json())["task"]["id"], "task-1")

        ledger_payload = {"action": "ledger_read", "limit": 50}
        ledger_nonce = "nonce-ledger"
        ledger_ts = time.time()
        ledger_sig = hmac.new(
            self.server_module.mesh_auth.mesh_key,
            self.server_module.mesh_trust.signing_material("n-task", "broadcast", ledger_payload, ledger_nonce, ledger_ts),
            hashlib.sha256,
        ).hexdigest()
        query = {"limit": "50", "nonce": ledger_nonce, "ts": str(ledger_ts), "sig": ledger_sig}
        ledger = await self.client.request("GET", "/api/collab/ledger", headers=headers, params=query)
        self.assertEqual(ledger.status, 200)
        self.assertTrue((await ledger.json())["ledger"])

    @unittest_run_loop
    async def test_audit_tamper_is_detected_and_new_events_fail_closed(self):
        vault = self.server_module.collab_vault
        first = vault.append_event("n-audit", "message", {"text": "original"}, "sig")
        self.assertTrue(vault.verify_audit_chain())
        raw = vault.ledger_path.read_text(encoding="utf-8").replace("original", "tampered")
        vault.ledger_path.write_text(raw, encoding="utf-8")
        self.assertFalse(vault.verify_audit_chain())
        self.assertTrue(vault.audit_status()["tampered"])
        with self.assertRaises(VaultError):
            vault.append_event("n-audit", "message", {"text": "blocked"}, "sig")

    @unittest_run_loop
    async def test_certificate_integrity_and_revoke_persist_after_restart(self):
        invite_response = await self.client.request(
            "POST", "/api/auth/invite", headers={"X-Collab-Owner": "owner-test-token"}, json={"node_id": "n-persist"}
        )
        invite = await invite_response.json()
        joined = await self.client.request("POST", "/api/auth/join", json={"node_id": "n-persist", "conn_code": invite["code"]})
        credentials = await joined.json()
        certificate = credentials["certificate"]
        self.assertTrue(self.server_module.mesh_auth.identity.verify("n-persist", certificate))
        tampered = dict(certificate)
        tampered["node_id"] = "n-other"
        self.assertFalse(self.server_module.mesh_auth.identity.verify("n-persist", tampered))

        revoked = await self.client.request("POST", "/api/mesh/revoke", headers={"X-Collab-Owner": "owner-test-token"}, json={"node_id": "n-persist"})
        self.assertEqual(revoked.status, 200)
        restarted_vault = CollabVault(self.tmp.name)
        restarted_auth = MeshAuth(restarted_vault.auth_dir, restarted_vault)
        self.assertEqual(restarted_vault.snapshot()["nodes"]["n-persist"]["status"], "revoked")
        self.assertIsNone(restarted_auth.verify_token(credentials["token"]))
        self.assertFalse(restarted_auth.identity.verify("n-persist"))
        new_invite_response = await self.client.request(
            "POST", "/api/auth/invite", headers={"X-Collab-Owner": "owner-test-token"}, json={"node_id": "n-persist"}
        )
        new_invite = await new_invite_response.json()
        rejoin = await self.client.request("POST", "/api/auth/join", json={"node_id": "n-persist", "conn_code": new_invite["code"]})
        self.assertEqual(rejoin.status, 403)

    @unittest_run_loop
    async def test_certificate_expiry_and_audit_reorder_are_detected(self):
        expiring = NodeIdentityManager(Path(self.tmp.name) / "expiry", validity_seconds=0, encryption_key=self.server_module.mesh_auth.mesh_key)
        cert = expiring.issue("n-expiry")
        self.assertFalse(expiring.verify("n-expiry", cert))
        for field in ("public_key", "expires_at", "signature"):
            mutated = dict(cert)
            mutated[field] = "tampered"
            self.assertFalse(self.server_module.mesh_auth.identity.verify("n-expiry", mutated))

        vault = self.server_module.collab_vault
        vault.append_event("n-chain", "message", {"text": "one"}, "sig-1")
        vault.append_event("n-chain", "message", {"text": "two"}, "sig-2")
        audit_lines = vault.audit_path.read_text(encoding="utf-8").splitlines()
        vault.audit_path.write_text("\n".join(reversed(audit_lines)) + "\n", encoding="utf-8")
        self.assertFalse(vault.verify_audit_chain())

    @unittest_run_loop
    async def test_trust_rejects_stale_and_sensitive_payloads(self):
        trust = self.server_module.mesh_trust
        stale = trust.sign("n-trust", "message", {"text": "old"}, nonce="nonce-stale", ts=time.time() - 31)
        verified, reason, _ = trust.verify(stale)
        self.assertFalse(verified)
        self.assertEqual(reason, "stale timestamp")
        with self.assertRaises(TrustError):
            trust.sign("n-trust", "message", {"api_key": "should-never-cross-mesh"}, nonce="nonce-secret")

    @unittest_run_loop
    async def test_encrypted_auth_store_tamper_fails_closed(self):
        invite_response = await self.client.request(
            "POST", "/api/auth/invite", headers={"X-Collab-Owner": "owner-test-token"}, json={"node_id": "n-store"}
        )
        invite = await invite_response.json()
        joined = await self.client.request("POST", "/api/auth/join", json={"node_id": "n-store", "conn_code": invite["code"]})
        credentials = await joined.json()
        self.server_module.mesh_auth.tokens_path.write_bytes(b"not-a-fernet-store")
        self.assertIsNone(self.server_module.mesh_auth.verify_token(credentials["token"]))

if __name__ == "__main__":
    unittest.main()

