"""Tests for the shared HTTP transport: rate limiting, backoff, retries."""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from unittest import mock

import pytest
import requests
import responses

from know_your_ip.http import (
    RETRYABLE_STATUSES,
    HTTPResult,
    RateLimit,
    TokenBucket,
    get_session,
    limiter_for,
    request,
)

URL = "https://example.invalid/probe"


class TestRateLimit:
    def test_min_interval(self):
        assert RateLimit(requests=4, per_seconds=60).min_interval == 15.0

    def test_sub_second_limits(self):
        assert RateLimit(requests=1, per_seconds=2.5).min_interval == 2.5


class TestTokenBucket:
    @pytest.mark.real_sleep
    def test_initial_burst_is_not_throttled(self):
        """A bucket starts full, so the first N requests go straight through."""
        bucket = TokenBucket(RateLimit(requests=4, per_seconds=60))

        start = time.monotonic()
        for _ in range(4):
            bucket.acquire()

        assert time.monotonic() - start < 0.5

    @pytest.mark.real_sleep
    def test_throttles_once_drained(self):
        bucket = TokenBucket(RateLimit(requests=1, per_seconds=0.2))
        bucket.acquire()

        start = time.monotonic()
        bucket.acquire()

        assert time.monotonic() - start >= 0.15

    @pytest.mark.real_sleep
    def test_is_thread_safe(self):
        """Concurrent callers must not over-issue tokens."""
        bucket = TokenBucket(RateLimit(requests=2, per_seconds=0.4))
        bucket.acquire()
        bucket.acquire()

        start = time.monotonic()
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(lambda _: bucket.acquire(), range(4)))
        elapsed = time.monotonic() - start

        # Four more tokens at one per 0.2s cannot complete instantly.
        assert elapsed >= 0.5


class TestLimiterRegistry:
    def test_same_provider_shares_one_bucket(self):
        limit = RateLimit(requests=1, per_seconds=1)

        assert limiter_for("vt", limit) is limiter_for("vt", limit)

    def test_different_providers_are_independent(self):
        limit = RateLimit(requests=1, per_seconds=1)

        assert limiter_for("vt", limit) is not limiter_for("censys", limit)

    def test_no_limit_means_no_bucket(self):
        assert limiter_for("free", None) is None


class TestSession:
    def test_session_is_reused(self):
        assert get_session() is get_session()

    def test_identifies_itself(self):
        assert "know_your_ip" in get_session().headers["User-Agent"]


class TestRequest:
    @responses.activate
    def test_success_returns_first_response(self):
        responses.add(responses.GET, URL, json={"ok": True}, status=200)

        result = request("p", "GET", URL)

        assert result.ok
        assert result.status_code == 200
        assert result.attempts == 1

    @responses.activate
    @pytest.mark.parametrize("status", sorted(RETRYABLE_STATUSES))
    def test_retryable_statuses_are_retried(self, status):
        responses.add(responses.GET, URL, json={}, status=status)

        result = request("p", "GET", URL, max_attempts=3)

        assert len(responses.calls) == 3
        assert result.status_code == status

    @responses.activate
    @pytest.mark.parametrize("status", [400, 401, 403, 404, 422])
    def test_terminal_statuses_are_not_retried(self, status):
        """Retrying a bad key or a genuine 404 cannot change the answer."""
        responses.add(responses.GET, URL, json={}, status=status)

        request("p", "GET", URL)

        assert len(responses.calls) == 1

    @responses.activate
    def test_recovers_after_transient_failure(self):
        responses.add(responses.GET, URL, json={}, status=503)
        responses.add(responses.GET, URL, json={"ok": True}, status=200)

        result = request("p", "GET", URL)

        assert result.ok
        assert result.attempts == 2

    @responses.activate
    def test_transport_error_is_retried_then_reported(self):
        responses.add(responses.GET, URL, body=requests.ConnectionError("down"))

        result = request("p", "GET", URL, max_attempts=2)

        assert not result.ok
        assert result.error is not None
        assert "ConnectionError" in result.error

    @responses.activate
    def test_honors_retry_after_header(self):
        responses.add(
            responses.GET, URL, json={}, status=429, headers={"Retry-After": "7"}
        )
        responses.add(responses.GET, URL, json={}, status=200)

        with mock.patch("know_your_ip.http._sleep") as sleep:
            request("p", "GET", URL)

        assert sleep.call_args_list[0].args[0] == 7.0

    @responses.activate
    def test_caps_absurd_retry_after(self):
        """A server asking for a one-day wait must not hang the batch."""
        responses.add(
            responses.GET, URL, json={}, status=429, headers={"Retry-After": "86400"}
        )
        responses.add(responses.GET, URL, json={}, status=200)

        with mock.patch("know_your_ip.http._sleep") as sleep:
            request("p", "GET", URL)

        assert sleep.call_args_list[0].args[0] == 300.0

    @responses.activate
    def test_ignores_unparsable_retry_after(self):
        """Retry-After may be an HTTP date; fall back to backoff, don't crash."""
        responses.add(
            responses.GET,
            URL,
            json={},
            status=503,
            headers={"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"},
        )
        responses.add(responses.GET, URL, json={}, status=200)

        result = request("p", "GET", URL)

        assert result.ok

    @responses.activate
    def test_backoff_grows_and_is_jittered(self):
        responses.add(responses.GET, URL, json={}, status=500)

        with mock.patch("know_your_ip.http._sleep") as sleep:
            request("p", "GET", URL, max_attempts=4)

        delays = [c.args[0] for c in sleep.call_args_list]
        assert len(delays) == 3
        assert delays == sorted(delays)
        # Jitter keeps each delay within [0.5, 1.0] of the nominal 2**attempt.
        for attempt, delay in enumerate(delays):
            assert 0.5 * 2**attempt <= delay <= 2**attempt

    @responses.activate
    @pytest.mark.real_sleep
    def test_rate_limit_is_applied(self):
        responses.add(responses.GET, URL, json={}, status=200)
        limit = RateLimit(requests=1, per_seconds=0.3)

        request("p", "GET", URL, rate_limit=limit)
        start = time.monotonic()
        request("p", "GET", URL, rate_limit=limit)

        assert time.monotonic() - start >= 0.2

    @responses.activate
    def test_passes_through_headers_and_params(self):
        responses.add(responses.GET, URL, json={}, status=200)

        request("p", "GET", URL, headers={"X-Key": "abc"}, params={"ip": "8.8.8.8"})

        sent = responses.calls[0].request
        assert sent.headers["X-Key"] == "abc"
        assert "ip=8.8.8.8" in str(sent.url)


class TestHTTPResult:
    def test_no_response_is_not_ok(self):
        result = HTTPResult(None, "boom", 3)

        assert not result.ok
        assert result.status_code is None
