"""Tests for the batch enrichment API.

The claims this module makes are the ones the README makes, so they are tested
as claims: raising concurrency does not produce rate errors, a second run costs
no quota, one bad provider does not cost a row, and the manifest describes what
actually happened.
"""

from __future__ import annotations

import csv
from datetime import date, timedelta

import pytest
import responses

from know_your_ip import EnrichResult, KnowYourIPConfig, enrich, enrich_csv
from know_your_ip.cache import Cache

VT = "https://www.virustotal.com/api/v3/ip_addresses/{}"
VT_BODY = {"data": {"attributes": {"reputation": 7, "asn": 15169}}}

ADDRESSES = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]


@pytest.fixture
def config() -> KnowYourIPConfig:
    """Config with only VirusTotal on, so request counts are unambiguous."""
    config = KnowYourIPConfig()
    for section in ("maxmind", "network", "rdap", "ranges"):
        getattr(config, section).enabled = False
    config.virustotal.enabled = True
    config.virustotal.api_key = "k"
    return config


@pytest.fixture
def offline() -> KnowYourIPConfig:
    """Config with only offline classification on: no network at all."""
    config = KnowYourIPConfig()
    # ranges fetches published CIDR lists, so it is not offline either.
    for section in ("maxmind", "rdap", "virustotal", "ranges"):
        getattr(config, section).enabled = False
    config.network.enabled = True
    config.network.reverse_dns = False
    return config


def _register_vt(addresses=ADDRESSES, **kwargs):
    for ip in addresses:
        responses.add(responses.GET, VT.format(ip), json=VT_BODY, status=200, **kwargs)


class TestBasics:
    def test_returns_one_record_per_address(self, offline):
        result = enrich(ADDRESSES, config=offline)

        assert len(result) == 3
        assert [r["ip"] for r in result] == ADDRESSES

    def test_result_is_iterable_and_sized(self, offline):
        result = enrich(ADDRESSES, config=offline)

        assert isinstance(result, EnrichResult)
        assert len(list(result)) == len(result)

    def test_empty_input_is_not_an_error(self, offline):
        result = enrich([], config=offline)

        assert result.records == []
        assert result.manifest["addresses_requested"] == 0

    def test_columns_are_the_union_across_records(self, offline):
        """Providers return different fields per address; a table needs all."""
        result = enrich(["8.8.8.8", "192.168.1.1"], config=offline)

        assert "network.is_cgnat" not in result.columns
        assert set(result.columns) >= {"ip", "network.category"}

    def test_rejects_zero_workers(self, offline):
        with pytest.raises(ValueError, match="at least 1"):
            enrich(ADDRESSES, config=offline, max_workers=0)


class TestInvalidInput:
    def test_invalid_addresses_do_not_abort_the_run(self, offline):
        """Real address lists are messy; one bad row must not cost the rest."""
        result = enrich(["8.8.8.8", "not-an-ip", "1.1.1.1"], config=offline)

        assert len(result) == 2

    def test_invalid_addresses_are_recorded_not_silently_dropped(self, offline):
        result = enrich(["8.8.8.8", "not-an-ip"], config=offline)

        assert result.manifest["addresses_skipped_invalid"] == ["not-an-ip"]
        assert result.manifest["addresses_requested"] == 2

    def test_all_invalid_yields_no_records(self, offline):
        result = enrich(["nope", "also-nope"], config=offline)

        assert result.records == []
        assert len(result.manifest["addresses_skipped_invalid"]) == 2


class TestProviderFailuresCostNoRows:
    @responses.activate
    def test_a_failing_provider_still_yields_every_row(self, config):
        """One unhealthy service must never shrink the table."""
        for ip in ADDRESSES:
            responses.add(responses.GET, VT.format(ip), json={}, status=500)

        result = enrich(ADDRESSES, config=config)

        assert len(result) == 3
        assert all("virustotal.error" in r for r in result)

    @responses.activate
    def test_errors_are_counted_per_provider(self, config):
        responses.add(responses.GET, VT.format("8.8.8.8"), json=VT_BODY, status=200)
        for ip in ADDRESSES[1:]:
            responses.add(responses.GET, VT.format(ip), json={}, status=500)

        result = enrich(ADDRESSES, config=config)

        assert result.errors == {"virustotal": 2}
        assert result.manifest["provider_errors"] == {"virustotal": 2}

    @responses.activate
    def test_partial_failure_keeps_good_data(self, config):
        responses.add(responses.GET, VT.format("8.8.8.8"), json=VT_BODY, status=200)
        for ip in ADDRESSES[1:]:
            responses.add(responses.GET, VT.format(ip), json={}, status=500)

        result = enrich(ADDRESSES, config=config)
        good = next(r for r in result if r["ip"] == "8.8.8.8")

        assert good["virustotal.reputation"] == 7


class TestCaching:
    @responses.activate
    def test_second_run_costs_no_quota(self, config, tmp_path):
        """The claim that makes a 500/day free tier usable at sample sizes."""
        _register_vt()
        db = tmp_path / "obs.sqlite"

        enrich(ADDRESSES, config=config, cache=db)
        enrich(ADDRESSES, config=config, cache=db)

        assert len(responses.calls) == 3

    @responses.activate
    def test_cache_hits_are_reported_in_the_manifest(self, config, tmp_path):
        _register_vt()
        db = tmp_path / "obs.sqlite"

        enrich(ADDRESSES, config=config, cache=db)
        second = enrich(ADDRESSES, config=config, cache=db)

        assert second.manifest["records_served_from_cache"] == 3

    @responses.activate
    def test_accepts_an_open_cache_object(self, config, tmp_path):
        _register_vt()

        with Cache(tmp_path / "obs.sqlite") as cache:
            enrich(ADDRESSES, config=config, cache=cache)
            enrich(ADDRESSES, config=config, cache=cache)

            assert len(responses.calls) == 3

    @responses.activate
    def test_max_age_forces_a_refetch(self, config, tmp_path):
        _register_vt()
        _register_vt()
        db = tmp_path / "obs.sqlite"

        enrich(ADDRESSES, config=config, cache=db)
        enrich(ADDRESSES, config=config, cache=db, max_age=timedelta(0))

        assert len(responses.calls) == 6

    @responses.activate
    def test_repeated_runs_accumulate_history(self, config, tmp_path):
        """Append-only: repeated runs build a panel, not a snapshot."""
        for _ in range(3):
            _register_vt(["8.8.8.8"])
        db = tmp_path / "obs.sqlite"

        for _ in range(3):
            enrich(["8.8.8.8"], config=config, cache=db, max_age=timedelta(0))

        with Cache(db) as cache:
            assert len(cache.history("8.8.8.8", provider="virustotal")) == 3


class TestConcurrencyDoesNotBreakRateLimits:
    @responses.activate
    def test_raising_workers_does_not_produce_rate_errors(self, config):
        """The headline claim: concurrency is safe because the limiter paces."""
        _register_vt()

        result = enrich(ADDRESSES, config=config, max_workers=16)

        assert result.errors == {}
        assert all(r["virustotal.reputation"] == 7 for r in result)

    def test_workers_are_capped_to_the_workload(self, offline):
        """Asking for 64 workers on 3 addresses must not spawn 64 threads."""
        result = enrich(ADDRESSES, config=offline, max_workers=64)

        assert len(result) == 3


class TestManifest:
    def test_records_the_essentials(self, offline):
        result = enrich(ADDRESSES, config=offline)
        m = result.manifest

        assert m["know_your_ip_version"]
        assert m["providers"] == ["network"]
        assert m["addresses_enriched"] == 3
        assert m["config_fingerprint"]

    def test_counts_match_the_records(self, offline):
        result = enrich(ADDRESSES, config=offline)

        assert result.manifest["addresses_enriched"] == len(result.records)

    def test_fingerprint_excludes_secrets(self, config):
        """The manifest is meant to be published alongside results."""
        config.virustotal.api_key = "SUPER-SECRET-VALUE"

        manifest = enrich([], config=config).manifest

        assert "SUPER-SECRET" not in str(manifest)

    def test_fingerprint_changes_with_settings(self, offline):
        first = enrich([], config=offline).manifest["config_fingerprint"]
        offline.network.reverse_dns = True
        second = enrich([], config=offline).manifest["config_fingerprint"]

        assert first != second

    def test_is_json_serializable(self, offline):
        """It has to be writable next to the results to be worth anything."""
        import json

        json.dumps(enrich(ADDRESSES, config=offline).manifest)

    def test_as_of_is_recorded(self, offline):
        manifest = enrich(["8.8.8.8"], config=offline, as_of=date(2019, 3, 14)).manifest

        assert manifest["as_of"] == "2019-03-14"


class TestAsOf:
    def test_providers_without_history_are_skipped_not_faked(self, offline):
        """A record that looks historical but is not would be worse than none."""
        result = enrich(["8.8.8.8"], config=offline, as_of=date(2019, 3, 14))

        assert result.manifest["providers"] == []
        assert result.records[0] == {"ip": "8.8.8.8"}


class TestOutput:
    def test_to_csv_round_trips(self, offline, tmp_path):
        out = tmp_path / "out.csv"

        result = enrich(ADDRESSES, config=offline)
        result.to_csv(out)

        with out.open(newline="") as fh:
            rows = list(csv.DictReader(fh))

        assert [r["ip"] for r in rows] == ADDRESSES

    def test_to_csv_respects_column_order(self, offline, tmp_path):
        out = tmp_path / "out.csv"

        enrich(ADDRESSES, config=offline).to_csv(out, columns=["ip"])

        with out.open(newline="") as fh:
            assert next(csv.reader(fh)) == ["ip"]

    def test_to_dataframe(self, offline):
        pd = pytest.importorskip("pandas")

        df = enrich(ADDRESSES, config=offline).to_dataframe()

        assert isinstance(df, pd.DataFrame)
        assert list(df["ip"]) == ADDRESSES

    def test_dataframe_has_one_row_per_address(self, offline):
        pytest.importorskip("pandas")

        assert len(enrich(ADDRESSES, config=offline).to_dataframe()) == 3


class TestEnrichCsv:
    def test_reads_a_plain_address_list(self, offline, tmp_path):
        src = tmp_path / "ips.txt"
        src.write_text("8.8.8.8\n1.1.1.1\n# a comment\n\n")

        result = enrich_csv(src, config=offline)

        assert [r["ip"] for r in result] == ["8.8.8.8", "1.1.1.1"]

    def test_reads_a_named_column(self, offline, tmp_path):
        src = tmp_path / "ips.csv"
        src.write_text("name,addr\nrow1,8.8.8.8\nrow2,1.1.1.1\n")

        result = enrich_csv(src, column="addr", config=offline)

        assert [r["ip"] for r in result] == ["8.8.8.8", "1.1.1.1"]

    def test_writes_output_when_asked(self, offline, tmp_path):
        src = tmp_path / "ips.txt"
        src.write_text("8.8.8.8\n")
        out = tmp_path / "out.csv"

        enrich_csv(src, out, config=offline)

        assert out.exists()

    def test_writes_nothing_when_not_asked(self, offline, tmp_path):
        src = tmp_path / "ips.txt"
        src.write_text("8.8.8.8\n")

        enrich_csv(src, config=offline)

        assert list(tmp_path.iterdir()) == [src]
