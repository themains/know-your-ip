"""Shared test fixtures.

Two pieces of process-global state need isolating between tests: the token
buckets in the HTTP layer, and the MaxMind reader cache. Without that, rate
limits accumulated by one test throttle the next one, and the suite spends
most of its wall-clock time asleep.
"""

from __future__ import annotations

import pytest

from know_your_ip import core
from know_your_ip.http import reset_limiters


@pytest.fixture(autouse=True)
def isolate_global_state():
    """Reset the shared token buckets and reader cache around every test."""
    reset_limiters()
    core._MAXMIND_READERS.clear()
    yield
    reset_limiters()
    core._MAXMIND_READERS.clear()


@pytest.fixture(autouse=True)
def no_backoff_sleep(request, monkeypatch):
    """Collapse retry backoff so tests do not wait out real delays.

    Tests that assert on timing opt out with ``@pytest.mark.real_sleep``; they
    need the genuine article, otherwise the token bucket busy-spins and the
    assertion passes for the wrong reason.
    """
    if "real_sleep" in request.keywords:
        return
    # Stub the retry backoff specifically. Patching know_your_ip.http.time.sleep
    # would patch the time module itself, disabling sleeping process-wide and
    # silently defeating any test that relies on real timing.
    monkeypatch.setattr("know_your_ip.http._sleep", lambda _: None)


@pytest.fixture(autouse=True)
def no_rate_limiting(request, monkeypatch):
    """Disable rate limiting except where a test is exercising it.

    VirusTotal's real allowance is 4/minute. Honoring that in unit tests would
    make the suite take minutes rather than seconds.
    """
    if "real_sleep" in request.keywords:
        return
    monkeypatch.setattr("know_your_ip.http.limiter_for", lambda *_: None)
