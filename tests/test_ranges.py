"""Tests for published-range membership.

Two things need proving here beyond correctness. That the parsers match what
each operator actually publishes - they differ in shape and one of them will
change - and that lookup survives a real batch, since AWS alone publishes
thousands of prefixes and the naive implementation is quadratic.
"""

from __future__ import annotations

import ipaddress
import json
import random
import time

import pytest
import responses

from know_your_ip import KnowYourIPConfig
from know_your_ip.ranges import (
    PARSERS,
    SOURCES,
    RangeIndex,
    RangeSource,
    build_index,
    get_index,
    range_lookup,
    reset_index,
)


@pytest.fixture(autouse=True)
def clean_index(tmp_path, monkeypatch):
    """Isolate from the process-wide index and the on-disk range cache."""
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    reset_index()
    yield
    reset_index()


@pytest.fixture
def config() -> KnowYourIPConfig:
    return KnowYourIPConfig()


class TestParsers:
    """Each operator publishes a different shape."""

    def test_aws(self):
        payload = json.dumps(
            {
                "prefixes": [{"ip_prefix": "13.32.0.0/15", "service": "CLOUDFRONT"}],
                "ipv6_prefixes": [{"ipv6_prefix": "2600:9000::/28"}],
            }
        )

        assert PARSERS["aws"](payload) == ["13.32.0.0/15", "2600:9000::/28"]

    def test_gcp(self):
        payload = json.dumps(
            {"prefixes": [{"ipv4Prefix": "34.64.0.0/11"}, {"ipv6Prefix": "2600::/28"}]}
        )

        assert PARSERS["gcp"](payload) == ["34.64.0.0/11", "2600::/28"]

    def test_fastly(self):
        payload = json.dumps(
            {"addresses": ["199.27.72.0/21"], "ipv6_addresses": ["2a04:4e40::/32"]}
        )

        assert PARSERS["fastly"](payload) == ["199.27.72.0/21", "2a04:4e40::/32"]

    def test_lines_skips_blanks_and_comments(self):
        """Tor publishes bare addresses, one per line."""
        payload = "# comment\n185.220.101.1\n\n185.220.101.2\n"

        assert PARSERS["lines"](payload) == ["185.220.101.1", "185.220.101.2"]

    def test_every_source_names_a_real_parser(self):
        for source in SOURCES:
            assert source.parser in PARSERS, source.name

    def test_every_source_declares_a_known_kind(self):
        for source in SOURCES:
            assert source.kind in {"cloud", "cdn", "tor", "bot"}, source.name


class TestIndex:
    def test_finds_a_containing_network(self):
        index = RangeIndex()
        index.add(["13.32.0.0/15"], "aws", "cloud")

        assert index.lookup("13.32.0.1") == [("aws", "cloud")]

    def test_reports_nothing_for_an_unlisted_address(self):
        index = RangeIndex()
        index.add(["13.32.0.0/15"], "aws", "cloud")

        assert index.lookup("8.8.8.8") == []

    def test_bare_addresses_become_host_routes(self):
        """Tor's list is addresses, not CIDRs."""
        index = RangeIndex()
        index.add(["185.220.101.1"], "tor", "tor")

        assert index.lookup("185.220.101.1") == [("tor", "tor")]
        assert index.lookup("185.220.101.2") == []

    def test_duplicate_prefixes_match_once(self):
        """AWS publishes the same prefix once per service; without dedup a
        single address yields aws|aws."""
        index = RangeIndex()
        index.add(["13.32.0.0/15", "13.32.0.0/15", "13.32.0.0/15"], "aws", "cloud")

        assert index.lookup("13.32.0.1") == [("aws", "cloud")]

    def test_an_address_can_match_several_sources(self):
        index = RangeIndex()
        index.add(["1.0.0.0/8"], "aws", "cloud")
        index.add(["1.0.0.0/8"], "tor", "tor")

        assert index.lookup("1.2.3.4") == [("aws", "cloud"), ("tor", "tor")]

    def test_ipv6_is_indexed(self):
        index = RangeIndex()
        index.add(["2600:9000::/28"], "aws", "cloud")

        assert index.lookup("2600:9000::1") == [("aws", "cloud")]

    def test_unparseable_ranges_are_skipped_not_fatal(self):
        """A publisher shipping one malformed entry must not break the run."""
        index = RangeIndex()

        added = index.add(["13.32.0.0/15", "not-a-cidr", ""], "aws", "cloud")

        assert added == 1
        assert index.lookup("13.32.0.1") == [("aws", "cloud")]

    def test_counts_and_sources(self):
        index = RangeIndex()
        index.add(["1.0.0.0/8", "2.0.0.0/8"], "aws", "cloud")

        assert len(index) == 2
        assert index.sources == {"aws"}


class TestPerformance:
    """AWS alone publishes thousands of prefixes; naive scanning is quadratic
    and would make a 10,000-address batch unusable."""

    @pytest.mark.real_sleep
    def test_lookup_survives_a_realistic_batch(self):
        index = RangeIndex()
        # Roughly the real published volume, spread across the address space.
        rng = random.Random(0)  # noqa: S311 - test data, not a security context
        cidrs = [
            f"{rng.randrange(1, 224)}.{rng.randrange(256)}.{rng.randrange(256)}.0/24"
            for _ in range(8000)
        ]
        index.add(cidrs, "aws", "cloud")

        addresses = [
            str(ipaddress.IPv4Address(rng.getrandbits(32))) for _ in range(1000)
        ]
        start = time.monotonic()
        for address in addresses:
            index.lookup(address)
        elapsed = time.monotonic() - start

        assert elapsed < 1.0, f"1000 lookups took {elapsed:.2f}s over {len(index)} nets"


class TestFetching:
    @responses.activate
    def test_builds_from_published_payloads(self):
        source = RangeSource("aws", "https://example.invalid/aws", "cloud", "aws")
        responses.add(
            responses.GET,
            source.url,
            json={"prefixes": [{"ip_prefix": "13.32.0.0/15"}]},
            status=200,
        )

        index = build_index(sources=(source,))

        assert index.lookup("13.32.0.1") == [("aws", "cloud")]

    @responses.activate
    def test_a_second_build_reuses_the_cached_copy(self):
        """One fetch per source per run, not one per address."""
        source = RangeSource("aws", "https://example.invalid/aws", "cloud", "aws")
        responses.add(
            responses.GET,
            source.url,
            json={"prefixes": [{"ip_prefix": "13.32.0.0/15"}]},
            status=200,
        )

        build_index(sources=(source,))
        build_index(sources=(source,))

        assert len(responses.calls) == 1

    @responses.activate
    def test_an_unreachable_source_is_skipped_not_fatal(self):
        """One publisher being down must not cost the other six."""
        up = RangeSource("aws", "https://example.invalid/aws", "cloud", "aws")
        down = RangeSource("gcp", "https://example.invalid/gcp", "cloud", "gcp")
        responses.add(
            responses.GET, up.url, json={"prefixes": [{"ip_prefix": "13.32.0.0/15"}]}
        )
        responses.add(responses.GET, down.url, status=503)

        index = build_index(sources=(up, down))

        assert index.sources == {"aws"}

    @responses.activate
    def test_malformed_payload_is_skipped_not_fatal(self):
        source = RangeSource("aws", "https://example.invalid/aws", "cloud", "aws")
        responses.add(responses.GET, source.url, body="<html>nope</html>", status=200)

        assert build_index(sources=(source,)).sources == set()

    @responses.activate
    def test_a_stale_copy_beats_nothing(self):
        """If a publisher is briefly unreachable, yesterday's list is better
        than no answer."""
        source = RangeSource("aws", "https://example.invalid/aws", "cloud", "aws")
        responses.add(
            responses.GET,
            source.url,
            json={"prefixes": [{"ip_prefix": "13.32.0.0/15"}]},
        )
        build_index(sources=(source,))

        responses.reset()
        responses.add(responses.GET, source.url, status=503)
        index = build_index(ttl=0, sources=(source,))

        assert index.lookup("13.32.0.1") == [("aws", "cloud")]


class TestProvider:
    def test_non_routable_addresses_are_not_looked_up(self, config):
        assert range_lookup(config, "192.168.1.1") == {
            "ranges.status": "not_globally_routable"
        }

    @responses.activate
    def test_reports_cloud_membership(self, config, monkeypatch):
        source = RangeSource("aws", "https://example.invalid/aws", "cloud", "aws")
        responses.add(
            responses.GET,
            source.url,
            json={"prefixes": [{"ip_prefix": "13.32.0.0/15"}]},
        )
        monkeypatch.setattr("know_your_ip.ranges.SOURCES", (source,))

        out = range_lookup(config, "13.32.0.1")

        assert out["ranges.is_cloud"] is True
        assert out["ranges.hosting_provider"] == "aws"
        assert out["ranges.is_tor_exit"] is False

    @responses.activate
    def test_reports_tor_membership(self, config, monkeypatch):
        source = RangeSource("tor", "https://example.invalid/tor", "tor", "lines")
        responses.add(responses.GET, source.url, body="185.220.101.1\n")
        monkeypatch.setattr("know_your_ip.ranges.SOURCES", (source,))

        out = range_lookup(config, "185.220.101.1")

        assert out["ranges.is_tor_exit"] is True
        assert "ranges.hosting_provider" not in out

    @responses.activate
    def test_unlisted_address_reports_all_false(self, config, monkeypatch):
        source = RangeSource("aws", "https://example.invalid/aws", "cloud", "aws")
        responses.add(
            responses.GET,
            source.url,
            json={"prefixes": [{"ip_prefix": "13.32.0.0/15"}]},
        )
        monkeypatch.setattr("know_your_ip.ranges.SOURCES", (source,))

        out = range_lookup(config, "8.8.8.8")

        assert out["ranges.is_cloud"] is False
        assert out["ranges.is_cdn"] is False
        assert out["ranges.is_tor_exit"] is False
        assert out["ranges.is_search_bot"] is False


class TestIndexIsSharedAcrossCalls:
    @responses.activate
    def test_index_is_built_once_per_process(self, monkeypatch):
        source = RangeSource("aws", "https://example.invalid/aws", "cloud", "aws")
        responses.add(
            responses.GET,
            source.url,
            json={"prefixes": [{"ip_prefix": "13.32.0.0/15"}]},
        )
        monkeypatch.setattr("know_your_ip.ranges.SOURCES", (source,))

        assert get_index() is get_index()
