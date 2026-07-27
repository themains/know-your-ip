"""Tests for the append-only observation cache."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
import responses

from know_your_ip import KnowYourIPConfig, query_ip
from know_your_ip.cache import Cache, config_fingerprint, default_cache_path

VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8"
VT_PAYLOAD = {"data": {"attributes": {"reputation": 530, "asn": 15169}}}


@pytest.fixture
def cache(tmp_path):
    """A cache that is closed afterwards, so no connection leaks."""
    with Cache(tmp_path / "obs.sqlite") as c:
        yield c


@pytest.fixture
def config() -> KnowYourIPConfig:
    config = KnowYourIPConfig()
    config.maxmind.enabled = False
    config.network.enabled = False
    config.rdap.enabled = False
    config.virustotal.enabled = True
    config.virustotal.api_key = "k"
    return config


class TestFingerprint:
    def test_stable_across_key_order(self):
        assert config_fingerprint({"a": 1, "b": 2}) == config_fingerprint(
            {"b": 2, "a": 1}
        )

    def test_changes_with_values(self):
        """AbuseIPDB's lookback window changes the answer, so it must change
        the key: a 30-day result cannot satisfy a 365-day request."""
        assert config_fingerprint({"days": 30}) != config_fingerprint({"days": 365})


class TestCache:
    def test_miss_returns_none(self, cache):
        assert cache.get("8.8.8.8", "virustotal", "fp") is None

    def test_roundtrip(self, cache):
        cache.put("8.8.8.8", "virustotal", "fp", {"virustotal.reputation": 530})

        assert cache.get("8.8.8.8", "virustotal", "fp") == {
            "virustotal.reputation": 530
        }

    def test_isolated_by_provider(self, cache):
        cache.put("8.8.8.8", "virustotal", "fp", {"a": 1})

        assert cache.get("8.8.8.8", "abuseipdb", "fp") is None

    def test_isolated_by_config_fingerprint(self, cache):
        cache.put("8.8.8.8", "abuseipdb", "days30", {"a": 1})

        assert cache.get("8.8.8.8", "abuseipdb", "days365") is None

    def test_returns_most_recent(self, cache):
        cache.put("8.8.8.8", "virustotal", "fp", {"rep": 1})
        cache.put("8.8.8.8", "virustotal", "fp", {"rep": 2})

        assert cache.get("8.8.8.8", "virustotal", "fp") == {"rep": 2}

    def test_max_age_rejects_stale(self, cache):
        cache.put("8.8.8.8", "virustotal", "fp", {"rep": 1})

        assert cache.get("8.8.8.8", "virustotal", "fp", timedelta(0)) is None

    def test_max_age_accepts_fresh(self, cache):
        cache.put("8.8.8.8", "virustotal", "fp", {"rep": 1})

        assert cache.get("8.8.8.8", "virustotal", "fp", timedelta(hours=1)) is not None

    def test_survives_reopen(self, tmp_path):
        path = tmp_path / "obs.sqlite"
        with Cache(path) as first:
            first.put("8.8.8.8", "virustotal", "fp", {"rep": 1})

        with Cache(path) as second:
            assert second.get("8.8.8.8", "virustotal", "fp") == {"rep": 1}

    def test_usable_from_threads(self, cache):
        """The enrichment pipeline is threaded and SQLite connections are not
        shareable, so each thread must get its own."""
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(
                pool.map(
                    lambda i: cache.put(f"10.0.0.{i}", "p", "fp", {"i": i}), range(20)
                )
            )

        assert cache.stats()["observations"] == 20


class TestAppendOnlyHistory:
    """Repeated runs must accumulate observations, not overwrite them."""

    def test_writes_do_not_replace(self, cache):
        cache.put("8.8.8.8", "virustotal", "fp", {"rep": 100})
        cache.put("8.8.8.8", "virustotal", "fp", {"rep": 200})

        assert len(cache.history("8.8.8.8")) == 2

    def test_history_is_chronological(self, cache):
        for rep in (1, 2, 3):
            cache.put("8.8.8.8", "virustotal", "fp", {"rep": rep})

        reps = [row["data"]["rep"] for row in cache.history("8.8.8.8")]

        assert reps == [1, 2, 3]

    def test_history_records_observation_time(self, cache):
        cache.put("8.8.8.8", "virustotal", "fp", {"rep": 1})

        observed = cache.history("8.8.8.8")[0]["observed_at"]

        assert datetime.fromisoformat(observed) <= datetime.now(UTC)

    def test_history_filters_by_provider(self, cache):
        cache.put("8.8.8.8", "virustotal", "fp", {"a": 1})
        cache.put("8.8.8.8", "abuseipdb", "fp", {"b": 2})

        rows = cache.history("8.8.8.8", provider="abuseipdb")

        assert [r["provider"] for r in rows] == ["abuseipdb"]

    def test_as_of_is_recorded(self, cache):
        cache.put("8.8.8.8", "rir", "fp", {"asn": 15169}, as_of="2019-03-14")

        assert cache.history("8.8.8.8")[0]["as_of"] == "2019-03-14"

    def test_current_readings_have_no_as_of(self, cache):
        """A present-day reading must not look like a historical one."""
        cache.put("8.8.8.8", "virustotal", "fp", {"rep": 1})

        assert cache.history("8.8.8.8")[0]["as_of"] is None


class TestQueryIPIntegration:
    @responses.activate
    def test_second_lookup_costs_no_quota(self, config, cache):
        """This is what makes a 500/day free tier usable at sample sizes."""
        responses.add(responses.GET, VT_URL, json=VT_PAYLOAD, status=200)

        first = query_ip(config, "8.8.8.8", cache=cache)
        second = query_ip(config, "8.8.8.8", cache=cache)

        assert len(responses.calls) == 1
        assert first["virustotal.reputation"] == 530
        assert second["virustotal.reputation"] == 530

    @responses.activate
    def test_cached_results_are_marked(self, config, cache):
        responses.add(responses.GET, VT_URL, json=VT_PAYLOAD, status=200)

        query_ip(config, "8.8.8.8", cache=cache)
        second = query_ip(config, "8.8.8.8", cache=cache)

        assert second["virustotal.from_cache"] is True

    @responses.activate
    def test_stale_entries_are_refetched(self, config, cache):
        responses.add(responses.GET, VT_URL, json=VT_PAYLOAD, status=200)

        query_ip(config, "8.8.8.8", cache=cache)
        query_ip(config, "8.8.8.8", cache=cache, max_age=timedelta(0))

        assert len(responses.calls) == 2

    @responses.activate
    def test_repeated_runs_build_a_panel(self, config, cache):
        """Run monthly over a fixed list and the cache becomes a time series."""
        responses.add(responses.GET, VT_URL, json=VT_PAYLOAD, status=200)

        for _ in range(3):
            query_ip(config, "8.8.8.8", cache=cache, max_age=timedelta(0))

        assert len(cache.history("8.8.8.8", provider="virustotal")) == 3

    @responses.activate
    def test_no_cache_argument_means_no_caching(self, config):
        responses.add(responses.GET, VT_URL, json=VT_PAYLOAD, status=200)

        query_ip(config, "8.8.8.8")
        query_ip(config, "8.8.8.8")

        assert len(responses.calls) == 2


class TestDefaultPath:
    def test_respects_xdg_cache_home(self, monkeypatch, tmp_path):
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))

        assert default_cache_path().is_relative_to(tmp_path)

    def test_falls_back_to_home_cache(self, monkeypatch, tmp_path):
        monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
        monkeypatch.setattr("pathlib.Path.home", classmethod(lambda cls: tmp_path))

        assert default_cache_path().is_relative_to(tmp_path / ".cache")
