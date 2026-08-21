import multiprocessing
import tempfile
import unittest
from pathlib import Path

from collab.ratelimit import SQLiteRateLimiter


def hit(args):
    db_path, bucket, limit = args
    limiter = SQLiteRateLimiter(db_path, limit=limit, window_seconds=60)
    return limiter.check(bucket).allowed


class RateLimiterTests(unittest.TestCase):
    def test_sliding_window_and_retry_after(self):
        with tempfile.TemporaryDirectory() as tmp:
            limiter = SQLiteRateLimiter(Path(tmp) / "rate.sqlite3", limit=2, window_seconds=10)
            self.assertTrue(limiter.check("bucket", now=100.0).allowed)
            self.assertTrue(limiter.check("bucket", now=100.1).allowed)
            blocked = limiter.check("bucket", now=100.2)
            self.assertFalse(blocked.allowed)
            self.assertGreaterEqual(blocked.retry_after, 9)
            self.assertTrue(limiter.check("bucket", now=111.0).allowed)

    def test_concurrent_processes_never_exceed_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(Path(tmp) / "rate.sqlite3")
            args = [(db_path, "shared-bucket", 8)] * 32
            context = multiprocessing.get_context("spawn")
            with context.Pool(processes=4) as pool:
                decisions = pool.map(hit, args)
            self.assertEqual(sum(decisions), 8)


if __name__ == "__main__":
    unittest.main()
