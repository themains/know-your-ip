"""Regression tests for defects found by probing 0.6.0.

Every one of these was reproduced against a green suite at 95% coverage. That
is the interesting part: tests written alongside code encode the same
assumptions the code does, so none of them caught these. Each test here failed
before its fix.
"""

from __future__ import annotations

import csv
import shutil
import threading
import time
from unittest import mock

import pytest
import responses

import know_your_ip as kyi
from know_your_ip import KnowYourIPConfig, core, network, ranges
from know_your_ip.core import main
from know_your_ip.ranges import RangeIndex, RangeSource
from know_your_ip.schema import CANONICAL, canonicalize

FIXTURE = "tests/fixtures/GeoLite2-City-Test.mmdb"


@pytest.fixture
def offline() -> KnowYourIPConfig:
    """Only the offline classifier, so nothing touches the network."""
    config = KnowYourIPConfig()
    for section in ("maxmind", "rdap", "virustotal", "ranges"):
        getattr(config, section).enabled = False
    config.network.enabled = True
    config.network.reverse_dns = False
    return config


class TestB1CliAndLibraryAgreeOnDefaults:
    """The CLI and library produced different tables.

    "Canonical by default" landed in the library only; the CLI kept writing
    vendor-shaped columns. On identical input the two overlapped on `ip` alone.
    The existing differential test missed it by passing --all-columns, which
    compares raw to raw.
    """

    def test_default_shapes_match(self, tmp_path, monkeypatch):
        """Compared as unions over heterogeneous rows, not against one record.

        Providers return different fields for different addresses, so a
        single-address comparison would pass even if the two entry points
        disagreed about how to combine rows.
        """
        monkeypatch.chdir(tmp_path)
        src = tmp_path / "ips.txt"
        # Deliberately mixed: routable, private, and CGNAT yield different
        # field sets, so the union is what actually has to match.
        src.write_text("8.8.8.8\n192.168.1.1\n100.64.0.1\n")
        out = tmp_path / "cli.csv"

        assert main(["--file", str(src), "--providers", "network", "-o", str(out)]) == 0

        with out.open(newline="") as fh:
            cli_columns = next(csv.reader(fh))

        lib = kyi.enrich_csv(src, providers=["network"])
        lib_columns: list[str] = []
        for row in lib.canonical:
            for key in row:
                if key not in lib_columns:
                    lib_columns.append(key)

        assert cli_columns == lib_columns, (
            "CLI and library default output must be the same shape and order"
        )

    def test_default_rows_match(self, tmp_path, monkeypatch):
        """Same shape is not enough; the values have to agree too."""
        monkeypatch.chdir(tmp_path)
        src = tmp_path / "ips.txt"
        src.write_text("8.8.8.8\n192.168.1.1\n")
        out = tmp_path / "cli.csv"

        main(["--file", str(src), "--providers", "network", "-o", str(out)])

        with out.open(newline="") as fh:
            cli_rows = list(csv.DictReader(fh))

        lib_rows = kyi.enrich_csv(src, providers=["network"]).canonical

        assert [r["ip"] for r in cli_rows] == [r["ip"] for r in lib_rows]
        assert [r["is_routable"] for r in cli_rows] == [
            str(r["is_routable"]) for r in lib_rows
        ]

    def test_cli_default_is_canonical(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        src = tmp_path / "ips.txt"
        src.write_text("8.8.8.8\n")
        out = tmp_path / "cli.csv"

        main(["--file", str(src), "--providers", "network", "-o", str(out)])

        with out.open(newline="") as fh:
            columns = next(csv.reader(fh))

        assert "is_routable" in columns
        assert "network.is_routable" not in columns

    def test_raw_shape_is_still_reachable(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        src = tmp_path / "ips.txt"
        src.write_text("8.8.8.8\n")
        out = tmp_path / "cli.csv"

        main(
            [
                "--file",
                str(src),
                "--providers",
                "network",
                "--shape",
                "raw",
                "-o",
                str(out),
            ]
        )

        with out.open(newline="") as fh:
            columns = next(csv.reader(fh))

        assert "network.is_routable" in columns

    def test_tidy_shape(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        src = tmp_path / "ips.txt"
        src.write_text("8.8.8.8\n")
        out = tmp_path / "cli.csv"

        main(
            [
                "--file",
                str(src),
                "--providers",
                "network",
                "--shape",
                "tidy",
                "-o",
                str(out),
            ]
        )

        with out.open(newline="") as fh:
            assert next(csv.reader(fh)) == ["ip", "field", "source", "value"]

    def test_unknown_shape_is_rejected(self, tmp_path):
        with pytest.raises(SystemExit):
            main(["8.8.8.8", "--shape", "sideways", "-o", str(tmp_path / "x.csv")])


def _race(target, workers: int = 12) -> None:
    """Run target in N threads that are guaranteed to start together.

    A barrier rather than a sleep: timing-based race tests pass or fail on
    machine speed, which means they can go green while the bug is still there.
    The barrier makes the overlap deterministic.
    """
    barrier = threading.Barrier(workers)

    def run():
        barrier.wait()
        target()

    threads = [threading.Thread(target=run) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()


class TestB2LazyGlobalsAreBuiltOnce:
    """Three process-wide caches rebuilt under concurrency.

    All three are reached from the threaded batch path, so the cost scaled with
    worker count on every run.
    """

    def test_range_index_builds_once(self, monkeypatch, tmp_path):
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
        ranges.reset_index()
        calls = []
        real = ranges.build_index

        def counting(*args, **kwargs):
            calls.append(1)
            time.sleep(0.05)
            return real(*args, **kwargs)

        monkeypatch.setattr(ranges, "build_index", counting)
        monkeypatch.setattr(ranges, "SOURCES", ())

        _race(ranges.get_index)

        assert len(calls) == 1, (
            f"index built {len(calls)} times; each fetches every list"
        )

    def test_rdap_bootstrap_fetches_once(self, monkeypatch):
        """The invariant is one HTTP fetch, not one call: every thread may
        legitimately call _load_bootstrap, but only one should download."""
        network._BOOTSTRAP_CACHE.clear()

        def slow_response(*args, **kwargs):
            time.sleep(0.05)
            return mock.Mock(ok=True, json=lambda: {"services": []})

        with mock.patch.object(
            network.http, "request", side_effect=slow_response
        ) as request:
            _race(lambda: network.rdap_service_for("8.8.8.8"))

        assert request.call_count == 1, (
            f"IANA registry downloaded {request.call_count} times"
        )

    def test_maxmind_reader_opens_once(self, monkeypatch, tmp_path):
        """The worst of the three: every extra open leaks a memory-mapped
        reader that is never closed."""
        shutil.copy(FIXTURE, tmp_path / "GeoLite2-City.mmdb")
        config = KnowYourIPConfig()
        config.maxmind.db_path = tmp_path
        core._MAXMIND_READERS.clear()

        opens = []
        real = core.maxminddb.open_database

        def counting(path):
            opens.append(path)
            time.sleep(0.02)
            return real(path)

        monkeypatch.setattr(core.maxminddb, "open_database", counting)

        _race(lambda: core.maxmind_geocode_ip(config, "81.2.69.142"))

        assert len(opens) == 1, f"database opened {len(opens)} times, leaking readers"


class TestB3RangeIndexHonoursTtl:
    @responses.activate
    def test_ttl_is_not_ignored_after_the_first_call(self, monkeypatch, tmp_path):
        """get_index only honoured its ttl while the index was unbuilt, so the
        setting appeared to work and did nothing."""
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
        ranges.reset_index()
        source = RangeSource("aws", "https://example.invalid/aws", "cloud", "aws")
        monkeypatch.setattr(ranges, "SOURCES", (source,))
        responses.add(
            responses.GET,
            source.url,
            json={"prefixes": [{"ip_prefix": "13.32.0.0/15"}]},
        )

        ranges.get_index(ttl=86_400)
        ranges.get_index(ttl=0)  # expiry requested: must refetch

        assert len(responses.calls) == 2


class TestB4ManifestUsesConfigSections:
    def test_fingerprint_survives_a_name_section_mismatch(self, offline):
        """Provider.section exists because name and section need not match.
        Keying config by name works only while they coincide."""
        import importlib
        from datetime import UTC, datetime

        from know_your_ip.providers import REGISTRY, Provider

        # The exported `enrich` function shadows the module of the same name.
        enrich_module = importlib.import_module("know_your_ip.enrich")

        source = REGISTRY.get("network")
        assert source is not None
        renamed = Provider(
            name="net-classifier",  # deliberately unlike its section
            fetch=source.fetch,
            section="network",
            cost=source.cost,
        )

        manifest = enrich_module._build_manifest(
            offline,
            [renamed],
            None,
            datetime.now(UTC),
            [{"ip": "8.8.8.8"}],
            1,
            1,
            [],
        )

        # Keying by name would raise AttributeError or silently drop the
        # section, producing a fingerprint that does not describe the run.
        assert manifest["config_fingerprint"]
        assert manifest["providers"] == ["net-classifier"]

    def test_fingerprint_reflects_the_section_settings(self, offline):
        """A settings change must move the fingerprint, or reproducibility is
        a claim rather than a fact."""
        import importlib
        from datetime import UTC, datetime

        from know_your_ip.providers import REGISTRY

        enrich_module = importlib.import_module("know_your_ip.enrich")
        provider = REGISTRY.get("network")
        args = (None, datetime.now(UTC), [{"ip": "8.8.8.8"}], 1, 1, [])

        before = enrich_module._build_manifest(offline, [provider], *args)
        offline.network.reverse_dns = True
        after = enrich_module._build_manifest(offline, [provider], *args)

        assert before["config_fingerprint"] != after["config_fingerprint"]


class TestB5TieBreakingIsDocumentedAndDeterministic:
    def test_tie_is_broken_by_registry_order(self):
        """Two sources, two answers: the winner is the earlier entry in the
        canonical list. Deterministic, and now stated rather than accidental."""
        record = {"maxmind.country.iso_code": "GB", "censys.country_code": "US"}

        assert CANONICAL["country_code"].index("maxmind.country.iso_code") < CANONICAL[
            "country_code"
        ].index("censys.country_code")
        assert canonicalize(record)["country_code"] == "GB"

    def test_tie_break_is_independent_of_input_order(self):
        forwards = canonicalize(
            {"maxmind.country.iso_code": "GB", "censys.country_code": "US"}
        )
        backwards = canonicalize(
            {"censys.country_code": "US", "maxmind.country.iso_code": "GB"}
        )

        assert forwards["country_code"] == backwards["country_code"]

    def test_a_tie_still_reports_disagreement(self):
        record = {"maxmind.country.iso_code": "GB", "censys.country_code": "US"}

        out = canonicalize(record)

        assert out["country_code.agree"] is False
        assert set(out["country_code.values"].split("|")) == {"GB", "US"}


class TestB6DuplicatesAreFetchedOnce:
    @responses.activate
    def test_repeated_addresses_cost_one_request(self):
        """Real address lists repeat. Fetching each occurrence burns metered
        quota for no extra information."""
        config = KnowYourIPConfig()
        for section in ("maxmind", "network", "rdap", "ranges"):
            getattr(config, section).enabled = False
        config.virustotal.enabled = True
        config.virustotal.api_key = "k"
        url = "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8"
        responses.add(
            responses.GET, url, json={"data": {"attributes": {"reputation": 7}}}
        )

        result = kyi.enrich(["8.8.8.8"] * 5, config=config)

        assert len(responses.calls) == 1
        assert len(result) == 5

    def test_row_order_and_count_are_preserved(self, offline):
        addresses = ["9.9.9.9", "8.8.8.8", "9.9.9.9", "1.1.1.1", "8.8.8.8"]

        result = kyi.enrich(addresses, config=offline)

        assert [r["ip"] for r in result] == addresses

    def test_deduplication_is_reported(self, offline):
        result = kyi.enrich(["8.8.8.8", "8.8.8.8", "1.1.1.1"], config=offline)

        assert result.manifest["addresses_requested"] == 3
        assert result.manifest["addresses_unique"] == 2


class TestB7IPv6IsBucketed:
    def test_v6_networks_do_not_share_one_bucket(self):
        """All v6 in a single bucket is the quadratic behaviour the bucketing
        exists to avoid."""
        index = RangeIndex()
        # Realistic spread: published v6 ranges differ in their second byte
        # (2600::, 2a04::, 2404::), not just the first.
        index.add(
            ["2600:9000::/28", "2a04:4e40::/32", "2404:6800::/32", "2620:11a::/32"],
            "test",
            "cloud",
        )

        assert len(index._buckets) > 1

    def test_v6_lookup_still_correct_after_bucketing(self):
        index = RangeIndex()
        index.add(["2600:9000::/28", "2a04:4e40::/32"], "test", "cloud")

        assert index.lookup("2600:9000::1") == [("test", "cloud")]
        assert index.lookup("2a04:4e40::1") == [("test", "cloud")]
        assert index.lookup("2001:4860:4860::8888") == []


class TestB8PublicApi:
    @pytest.mark.parametrize(
        "name", ["canonicalize", "tidy", "range_lookup", "enrich", "EnrichResult"]
    )
    def test_join_helpers_are_exported(self, name):
        assert hasattr(kyi, name), f"{name} should be importable from the package"

    def test_everything_exported_is_in_all(self):
        for name in ["canonicalize", "tidy", "range_lookup"]:
            assert name in kyi.__all__
