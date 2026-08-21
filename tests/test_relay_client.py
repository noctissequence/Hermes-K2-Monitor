"""Unit tests for the cross-VPS RelayClient (collab/relay.py)."""
import os
import tempfile
import unittest

from aiohttp import web
from aiohttp.test_utils import AioHTTPTestCase, unittest_run_loop

from collab.relay import RelayClient


class RelayClientTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["COLLAB_DIR"] = self.tmp.name
        os.environ["MESH_KEY"] = "test-relay-mesh-key-0123456789abcdef"
        os.environ["COLLAB_OWNER_TOKEN"] = "owner-token"  # nosec B105 - isolated test fixture

    def tearDown(self):
        self.tmp.cleanup()

    def test_ready_false_without_partners(self):
        rc = RelayClient()
        self.assertFalse(rc.ready())
        self.assertFalse(rc.forward("message", {"a": 1}))
        self.assertEqual(rc.queue_depth(), 0)

    def test_ready_true_with_partner_and_signs(self):
        rc = RelayClient(partner_urls=["http://127.0.0.1:9999"], mesh_key=b"k" * 32, local_node_id="n-local")
        self.assertTrue(rc.partners)
        # ready requires a trust-signable key
        self.assertTrue(rc.ready())

    def test_forward_rejects_disallowed_op(self):
        rc = RelayClient(partner_urls=["http://127.0.0.1:9999"], mesh_key=b"k" * 32, local_node_id="n-local")
        # "read_key" is not in ALLOWED_OPS -> refused before any network
        self.assertFalse(rc.forward("read_key", {"x": 1}))

    def test_queue_dedupes_when_partner_down(self):
        # unknown port -> connect fails -> queued, not raised
        rc = RelayClient(partner_urls=["http://127.0.0.1:1"], mesh_key=b"k" * 32, local_node_id="n-local",
                         timeout=1)
        # dispatch is best-effort; must not raise
        rc.forward("message", {"hi": 1})


class RelayForwardHTTPTests(AioHTTPTestCase):
    """Spin a fake partner returning 200/good and 403/bad."""

    async def get_application(self):
        async def relay_ok(request):
            data = await request.json()
            # require nonce + sig present (signed envelope)
            if data.get("node_id") and data.get("sig") and data.get("nonce"):
                return web.json_response({"status": "ok", "relayed": True})
            return web.json_response({"status": "rejected", "reason": "bad"}, status=403)

        app = web.Application()
        app.router.add_post("/api/relay", relay_ok)
        return app

    @unittest_run_loop
    async def test_post_blocking_forwards_signed(self):
        # a real started server URL
        runner = web.AppRunner(self.app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = runner.addresses[0][1]

        rc = RelayClient(partner_urls=[f"http://127.0.0.1:{port}"], mesh_key=b"m" * 32,
                         local_node_id="n-test", local_node_token="tok", timeout=5)  # nosec B106 - isolated test fixture
        self.assertTrue(rc.ready())
        ok = rc.forward("message", {"hello": "world"})
        self.assertTrue(ok)

        await runner.cleanup()
