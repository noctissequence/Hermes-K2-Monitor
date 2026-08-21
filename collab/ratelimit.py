"""Small SQLite-backed sliding-window rate limiter for multi-process server use."""
from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Any


class RateLimitDecision:
    def __init__(self, allowed: bool, count: int, limit: int, retry_after: int = 0):
        self.allowed = allowed
        self.count = count
        self.limit = limit
        self.retry_after = max(0, int(retry_after))

    def as_dict(self) -> dict[str, Any]:
        return {"allowed": self.allowed, "count": self.count, "limit": self.limit, "retry_after": self.retry_after}


class SQLiteRateLimiter:
    """Atomic fixed-window counter that works across processes on one host."""

    def __init__(self, db_path: str | Path, limit: int = 60, window_seconds: int = 60):
        self.db_path = Path(db_path).expanduser().resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.limit = max(1, int(limit))
        self.window_seconds = max(1, int(window_seconds))
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=10, isolation_level=None)
        connection.execute("PRAGMA busy_timeout=10000")
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    def _init_db(self) -> None:
        with self._connect() as connection:
            connection.execute("CREATE TABLE IF NOT EXISTS rate_hits (bucket TEXT NOT NULL, hit_at REAL NOT NULL)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_rate_hits_bucket_time ON rate_hits(bucket, hit_at)")

    def check(self, bucket: str, now: float | None = None) -> RateLimitDecision:
        if not isinstance(bucket, str) or not bucket:
            raise ValueError("rate-limit bucket must be non-empty")
        now = time.time() if now is None else float(now)
        cutoff = now - self.window_seconds
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DELETE FROM rate_hits WHERE hit_at < ?", (cutoff,))
            row = connection.execute("SELECT COUNT(*) FROM rate_hits WHERE bucket = ?", (bucket,)).fetchone()
            count = int(row[0] if row else 0)
            if count >= self.limit:
                oldest = connection.execute("SELECT MIN(hit_at) FROM rate_hits WHERE bucket = ?", (bucket,)).fetchone()[0]
                retry_after = max(1, int(oldest + self.window_seconds - now + 0.999))
                connection.commit()
                return RateLimitDecision(False, count, self.limit, retry_after)
            connection.execute("INSERT INTO rate_hits(bucket, hit_at) VALUES (?, ?)", (bucket, now))
            connection.commit()
            return RateLimitDecision(True, count + 1, self.limit, 0)

    def reset(self, bucket: str | None = None) -> None:
        with self._connect() as connection:
            if bucket is None:
                connection.execute("DELETE FROM rate_hits")
            else:
                connection.execute("DELETE FROM rate_hits WHERE bucket = ?", (bucket,))
