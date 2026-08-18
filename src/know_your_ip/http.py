"""Shared HTTP transport: one session, real backoff, per-provider rate limits.

Every service previously carried its own copy of a retry loop, and none of them
limited request rate. Running several addresses concurrently against a free tier
therefore tripped 429 immediately. This module centralizes that behavior so a
provider only has to declare its published limit.
"""

from __future__ import annotations

import logging
import random
import threading
import time
from dataclasses import dataclass
from typing import Any

import requests

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30
MAX_ATTEMPTS = 5

# Statuses worth retrying. 401/403 are terminal (a bad key stays bad) and 404
# is an answer, not a failure.
RETRYABLE_STATUSES = frozenset({408, 429, 500, 502, 503, 504})


@dataclass(frozen=True)
class RateLimit:
    """A published request allowance.

    Args:
        requests: Number of requests permitted per ``per_seconds``.
        per_seconds: Length of the window, in seconds.

    Example:
        VirusTotal's public tier is 4 requests per minute::

            RateLimit(requests=4, per_seconds=60)
    """

    requests: int
    per_seconds: float

    @property
    def min_interval(self) -> float:
        """Seconds that must elapse between consecutive requests."""
        return self.per_seconds / self.requests


class TokenBucket:
    """A thread-safe token bucket.

    Threads block in :meth:`acquire` until the configured rate allows another
    request, so concurrency is bounded by the provider's published limit rather
    than by a single global worker count.
    """

    def __init__(self, rate_limit: RateLimit) -> None:
        """Initialize the bucket at full capacity.

        Args:
            rate_limit: The allowance to enforce.
        """
        self._limit = rate_limit
        self._tokens = float(rate_limit.requests)
        self._updated = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        """Block until a token is available, then consume it."""
        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self._updated
                self._updated = now
                self._tokens = min(
                    float(self._limit.requests),
                    self._tokens + elapsed / self._limit.min_interval,
                )
                if self._tokens >= 1:
                    self._tokens -= 1
                    return
                wait = (1 - self._tokens) * self._limit.min_interval
            time.sleep(wait)


_BUCKETS: dict[str, TokenBucket] = {}
_BUCKETS_LOCK = threading.Lock()


def limiter_for(provider: str, rate_limit: RateLimit | None) -> TokenBucket | None:
    """Return the shared token bucket for a provider.

    One bucket per provider name is shared across all threads, so the limit
    holds for the process rather than per call site.

    Args:
        provider: Provider name.
        rate_limit: The provider's allowance, or None for no limit.

    Returns:
        The bucket, or None if the provider declares no limit.
    """
    if rate_limit is None:
        return None
    with _BUCKETS_LOCK:
        bucket = _BUCKETS.get(provider)
        if bucket is None:
            bucket = TokenBucket(rate_limit)
            _BUCKETS[provider] = bucket
        return bucket


def reset_limiters() -> None:
    """Discard all token buckets. Intended for tests."""
    with _BUCKETS_LOCK:
        _BUCKETS.clear()


_SESSION: requests.Session | None = None
_SESSION_LOCK = threading.Lock()


def get_session() -> requests.Session:
    """Return the process-wide HTTP session.

    A single session gives connection pooling and TLS reuse; the previous code
    opened a fresh connection for every lookup.

    Returns:
        The shared session.
    """
    global _SESSION
    if _SESSION is None:
        with _SESSION_LOCK:
            if _SESSION is None:
                session = requests.Session()
                session.headers["User-Agent"] = _user_agent()
                _SESSION = session
    return _SESSION


def _user_agent() -> str:
    """Build a User-Agent identifying the package and version."""
    try:
        from importlib.metadata import version

        return f"know_your_ip/{version('know_your_ip')}"
    except Exception:  # pragma: no cover - metadata always present when installed
        return "know_your_ip"


def _sleep(seconds: float) -> None:
    """Wait between retry attempts.

    A named indirection so tests can stub retry backoff without patching
    ``time.sleep``. ``http.time`` *is* the time module, so patching through it
    disables sleeping for the entire process - which silently defeated
    concurrency tests elsewhere in the suite.

    Args:
        seconds: How long to wait.
    """
    time.sleep(seconds)


def _retry_delay(attempt: int, response: requests.Response | None) -> float:
    """Compute how long to wait before the next attempt.

    Honors ``Retry-After`` when the server supplies it, otherwise backs off
    exponentially with jitter. Jitter matters when many threads are retrying:
    without it they retry in lockstep and re-trigger the same limit.

    Args:
        attempt: Zero-based attempt number that just failed.
        response: The response received, if any.

    Returns:
        Seconds to sleep.
    """
    if response is not None:
        header = response.headers.get("Retry-After")
        if header:
            try:
                return min(float(header), 300.0)
            except ValueError:
                pass
    # Jitter spreads retries across threads; not a security context.
    return min(2**attempt, 60) * (0.5 + random.random() / 2)  # noqa: S311


class HTTPResult:
    """Outcome of an HTTP call: either a response or the error that ended it."""

    def __init__(
        self,
        response: requests.Response | None = None,
        error: str | None = None,
        attempts: int = 0,
    ) -> None:
        """Record a call outcome.

        Args:
            response: The final response, if one was received.
            error: Description of the transport failure, if any.
            attempts: How many attempts were made.
        """
        self.response = response
        self.error = error
        self.attempts = attempts

    @property
    def ok(self) -> bool:
        """True if a 2xx response was received."""
        return self.response is not None and self.response.ok

    @property
    def status_code(self) -> int | None:
        """The final HTTP status, or None if no response was received."""
        return self.response.status_code if self.response is not None else None

    def json(self) -> Any:
        """Decode the response body as JSON.

        Propagates ``requests.JSONDecodeError`` when the body is not JSON, so
        a provider can decide whether that is fatal for it.

        Returns:
            The decoded body, or ``{}`` if no response was received.
        """
        if self.response is None:
            return {}
        return self.response.json()


def request(
    provider: str,
    method: str,
    url: str,
    *,
    rate_limit: RateLimit | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    max_attempts: int = MAX_ATTEMPTS,
    **kwargs,
) -> HTTPResult:
    """Perform a rate-limited HTTP request with retries.

    Retries transport errors and the statuses in :data:`RETRYABLE_STATUSES`.
    Authentication failures and 404 are returned immediately, since retrying
    cannot change them.

    Args:
        provider: Provider name, used to select the shared token bucket.
        method: HTTP method.
        url: Target URL.
        rate_limit: The provider's published allowance, if any.
        timeout: Per-request timeout in seconds.
        max_attempts: Maximum number of attempts.
        **kwargs: Passed through to ``requests``.

    Returns:
        An :class:`HTTPResult`. Failures are values, not exceptions, so one
        failing service cannot abort a batch.
    """
    bucket = limiter_for(provider, rate_limit)
    session = get_session()
    last: requests.Response | None = None
    error: str | None = None

    for attempt in range(max_attempts):
        if bucket is not None:
            bucket.acquire()

        try:
            last = session.request(method, url, timeout=timeout, **kwargs)
            error = None
        except requests.RequestException as exc:
            last = None
            error = f"{type(exc).__name__}: {exc}"
            logger.warning("%s: %s", provider, error)
            if attempt + 1 < max_attempts:
                _sleep(_retry_delay(attempt, None))
            continue

        if last.status_code not in RETRYABLE_STATUSES:
            return HTTPResult(last, None, attempt + 1)

        logger.warning(
            "%s: HTTP %s (attempt %d/%d)",
            provider,
            last.status_code,
            attempt + 1,
            max_attempts,
        )
        if attempt + 1 < max_attempts:
            _sleep(_retry_delay(attempt, last))

    return HTTPResult(last, error, max_attempts)
