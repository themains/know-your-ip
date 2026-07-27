"""On-disk result cache.

Two things this buys. Immediately: re-running an analysis costs no API quota,
which is what makes free tiers usable at research sample sizes - VirusTotal
allows 500 lookups a day, so a 5,000-address study is otherwise a ten-day job
that cannot be re-run.

Over time: because rows are appended rather than replaced, a cache that is
used repeatedly becomes a panel dataset. Enrich the same address list monthly
and after a year you hold a year of observations that no archival source could
have sold you retroactively. That only works if the decision is made before
people build caches, which is why it is the default here rather than an option.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS observations (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ip           TEXT NOT NULL,
    provider     TEXT NOT NULL,
    config_hash  TEXT NOT NULL,
    observed_at  TEXT NOT NULL,
    as_of        TEXT,
    payload      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_lookup
    ON observations (ip, provider, config_hash, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_history ON observations (ip, provider, observed_at);
"""


def config_fingerprint(values: dict[str, Any]) -> str:
    """Hash the settings that affect a provider's answer.

    A cached row is only reusable if it was produced under the same settings.
    AbuseIPDB's ``days`` window, for instance, changes the result, so a lookup
    made with a 30-day window must not satisfy a request for 365 days.

    Args:
        values: The provider settings that influence the response. Secrets
            should not be included; they do not change the answer and would be
            written to disk.

    Returns:
        A short hex digest.
    """
    canonical = json.dumps(values, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


class Cache:
    """An append-only SQLite cache of provider observations."""

    def __init__(self, path: Path) -> None:
        """Open (creating if needed) a cache database.

        Args:
            path: Location of the SQLite file. Parent directories are created.
        """
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        # Connections are per-thread, but close() has to reach all of them, so
        # they are also tracked centrally. Worker threads outlive no one here;
        # without this their connections leak until interpreter shutdown.
        self._connections: list[sqlite3.Connection] = []
        self._lock = threading.Lock()
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """Yield this thread's connection, committing on success.

        SQLite connections are not shareable across threads, and the enrichment
        pipeline is threaded, so each thread gets its own.
        """
        conn = getattr(self._local, "conn", None)
        if conn is None:
            # check_same_thread=False only so close() can reach connections
            # opened by worker threads; each connection is still used solely by
            # the thread that owns it, via the thread-local above.
            conn = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
            conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn = conn
            with self._lock:
                self._connections.append(conn)
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def get(
        self,
        ip: str,
        provider: str,
        config_hash: str,
        max_age: timedelta | None = None,
    ) -> dict[str, Any] | None:
        """Return the most recent usable observation, if any.

        Args:
            ip: The address.
            provider: Provider name.
            config_hash: Fingerprint from :func:`config_fingerprint`.
            max_age: How old an observation may be and still be returned. None
                accepts any age.

        Returns:
            The cached payload, or None if there is no usable row.
        """
        sql = (
            "SELECT payload, observed_at FROM observations "
            "WHERE ip = ? AND provider = ? AND config_hash = ? "
            "ORDER BY observed_at DESC LIMIT 1"
        )
        with self._connect() as conn:
            row = conn.execute(sql, (ip, provider, config_hash)).fetchone()

        if row is None:
            return None

        payload, observed_at = row
        if max_age is not None:
            age = datetime.now(UTC) - datetime.fromisoformat(observed_at)
            if age > max_age:
                return None

        return json.loads(payload)

    def put(
        self,
        ip: str,
        provider: str,
        config_hash: str,
        payload: dict[str, Any],
        as_of: str | None = None,
    ) -> None:
        """Append an observation.

        Existing rows are never modified, so the table accumulates a history
        rather than a snapshot.

        Args:
            ip: The address.
            provider: Provider name.
            config_hash: Fingerprint from :func:`config_fingerprint`.
            payload: The provider's result.
            as_of: The historical date this observation describes, if it is not
                a present-day reading.
        """
        sql = (
            "INSERT INTO observations "
            "(ip, provider, config_hash, observed_at, as_of, payload) "
            "VALUES (?, ?, ?, ?, ?, ?)"
        )
        with self._connect() as conn:
            conn.execute(
                sql,
                (
                    ip,
                    provider,
                    config_hash,
                    datetime.now(UTC).isoformat(),
                    as_of,
                    json.dumps(payload, default=str),
                ),
            )

    def history(self, ip: str, provider: str | None = None) -> list[dict[str, Any]]:
        """Every observation recorded for an address, oldest first.

        This is the panel view: repeated enrichment runs make it a time series.

        Args:
            ip: The address.
            provider: Restrict to one provider, or None for all.

        Returns:
            Observations, each with ``provider``, ``observed_at``, ``as_of``,
            and ``data``.
        """
        sql = (
            "SELECT provider, observed_at, as_of, payload FROM observations "
            "WHERE ip = ?"
        )
        params: list[Any] = [ip]
        if provider is not None:
            sql += " AND provider = ?"
            params.append(provider)
        sql += " ORDER BY observed_at"

        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()

        return [
            {
                "provider": name,
                "observed_at": observed_at,
                "as_of": as_of,
                "data": json.loads(payload),
            }
            for name, observed_at, as_of, payload in rows
        ]

    def stats(self) -> dict[str, Any]:
        """Summarize what the cache holds.

        Returns:
            Counts of observations, distinct addresses, and per-provider rows.
        """
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0]
            addresses = conn.execute(
                "SELECT COUNT(DISTINCT ip) FROM observations"
            ).fetchone()[0]
            per_provider = dict(
                conn.execute(
                    "SELECT provider, COUNT(*) FROM observations GROUP BY provider"
                ).fetchall()
            )
        return {
            "observations": total,
            "addresses": addresses,
            "by_provider": per_provider,
        }

    def close(self) -> None:
        """Close every connection this cache opened, on any thread."""
        with self._lock:
            for conn in self._connections:
                conn.close()
            self._connections.clear()
        self._local = threading.local()

    def __enter__(self) -> Cache:
        """Enter a context that closes the cache on exit.

        Returns:
            This cache.
        """
        return self

    def __exit__(self, *exc_info: object) -> None:
        """Close the cache."""
        self.close()


def default_cache_path() -> Path:
    """Where the cache lives when the caller does not choose.

    Returns:
        A path under the user's cache directory.
    """
    import os

    if xdg := os.environ.get("XDG_CACHE_HOME"):
        base = Path(xdg)
    else:
        base = Path.home() / ".cache"
    return base / "know-your-ip" / "observations.sqlite"
