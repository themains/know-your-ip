"""Tests for GeoLite2 download and the collapsed-failure logging."""

from __future__ import annotations

import io
import shutil
import tarfile
from pathlib import Path

import pytest
import responses

from know_your_ip import KnowYourIPConfig, query_ip
from know_your_ip.core import FAILURES, _FailureTally
from know_your_ip.maxmind_db import (
    _safe_mmdb_member,
    database_dir,
    download_all,
    download_database,
    find_database,
)

DOWNLOAD_URL = "https://download.maxmind.com/geoip/databases/GeoLite2-City/download"
ASN_URL = "https://download.maxmind.com/geoip/databases/GeoLite2-ASN/download"


def _archive(members: dict[str, bytes]) -> bytes:
    """Build a gzipped tar containing the given name -> content mapping."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name, content in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


REAL_SHAPE = {"GeoLite2-City_20260727/GeoLite2-City.mmdb": b"MMDB-CONTENT"}


class TestSafeExtraction:
    """Member names come from a remote archive and are untrusted."""

    def test_finds_the_mmdb(self):
        with tarfile.open(fileobj=io.BytesIO(_archive(REAL_SHAPE)), mode="r:gz") as tar:
            member = _safe_mmdb_member(tar, "GeoLite2-City")

        # Flattened, so extraction cannot escape the target directory.
        assert member.name == "GeoLite2-City.mmdb"

    def test_rejects_parent_traversal(self):
        payload = _archive({"../../evil/GeoLite2-City.mmdb": b"x"})

        with (
            tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as tar,
            pytest.raises(ValueError, match="unsafe archive member"),
        ):
            _safe_mmdb_member(tar, "GeoLite2-City")

    def test_rejects_absolute_path(self):
        payload = _archive({"/etc/GeoLite2-City.mmdb": b"x"})

        with (
            tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as tar,
            pytest.raises(ValueError, match="unsafe archive member"),
        ):
            _safe_mmdb_member(tar, "GeoLite2-City")

    def test_archive_without_a_database_is_an_error(self):
        payload = _archive({"GeoLite2-City_20260727/COPYRIGHT.txt": b"x"})

        with (
            tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as tar,
            pytest.raises(ValueError, match=r"No \.mmdb file"),
        ):
            _safe_mmdb_member(tar, "GeoLite2-City")


class TestDownload:
    @responses.activate
    def test_writes_the_database(self, tmp_path):
        responses.add(
            responses.GET, DOWNLOAD_URL, body=_archive(REAL_SHAPE), status=200
        )

        path = download_database("acct", "key", target_dir=tmp_path)

        assert path == tmp_path / "GeoLite2-City.mmdb"
        assert path.read_bytes() == b"MMDB-CONTENT"

    @responses.activate
    def test_uses_basic_auth(self, tmp_path):
        responses.add(
            responses.GET, DOWNLOAD_URL, body=_archive(REAL_SHAPE), status=200
        )

        download_database("acct", "key", target_dir=tmp_path)

        assert responses.calls[0].request.headers["Authorization"].startswith("Basic ")

    @responses.activate
    def test_bad_credentials_explain_where_to_get_them(self, tmp_path):
        responses.add(responses.GET, DOWNLOAD_URL, status=401)

        with pytest.raises(RuntimeError, match="license-key"):
            download_database("acct", "bad", target_dir=tmp_path)

    @responses.activate
    def test_quota_message_names_the_real_limit(self, tmp_path):
        """GeoLite2 allows 30 downloads per 24 hours."""
        responses.add(responses.GET, DOWNLOAD_URL, status=429)

        with pytest.raises(RuntimeError, match="30 per 24 hours"):
            download_database("acct", "key", target_dir=tmp_path)

    @responses.activate
    def test_one_failing_edition_does_not_stop_the_others(self, tmp_path):
        responses.add(
            responses.GET, DOWNLOAD_URL, body=_archive(REAL_SHAPE), status=200
        )
        responses.add(responses.GET, ASN_URL, status=401)

        written = download_all("acct", "key", target_dir=tmp_path)

        assert [p.name for p in written] == ["GeoLite2-City.mmdb"]


class TestFindDatabase:
    def test_configured_path_wins(self, tmp_path):
        (tmp_path / "GeoLite2-City.mmdb").write_bytes(b"x")

        assert find_database(tmp_path) == tmp_path / "GeoLite2-City.mmdb"

    def test_falls_back_to_download_directory(self, tmp_path, monkeypatch):
        """download-db then a plain run must work with no configuration."""
        downloaded = tmp_path / "dl"
        downloaded.mkdir()
        (downloaded / "GeoLite2-City.mmdb").write_bytes(b"x")
        monkeypatch.setattr("know_your_ip.maxmind_db.database_dir", lambda: downloaded)

        found = find_database(tmp_path / "nowhere")

        assert found == downloaded / "GeoLite2-City.mmdb"

    def test_reports_the_configured_path_when_nothing_exists(self, tmp_path):
        """The error should name what the user configured, not a cache path
        they never chose."""
        missing = tmp_path / "nowhere"

        assert find_database(missing) == missing / "GeoLite2-City.mmdb"

    def test_database_dir_is_under_the_cache_dir(self, monkeypatch, tmp_path):
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))

        assert database_dir().is_relative_to(tmp_path)


class TestFailureTally:
    """A misconfiguration fails identically for every address in a batch."""

    def test_first_occurrence_is_reported(self):
        tally = _FailureTally()

        assert tally.record("maxmind", "missing") is True

    def test_repeats_are_not(self):
        tally = _FailureTally()
        tally.record("maxmind", "missing")

        assert tally.record("maxmind", "missing") is False

    def test_different_messages_are_tracked_separately(self):
        tally = _FailureTally()
        tally.record("maxmind", "missing")

        assert tally.record("maxmind", "corrupt") is True

    def test_summary_counts_repeats_only(self):
        tally = _FailureTally()
        for _ in range(4):
            tally.record("maxmind", "missing")
        tally.record("censys", "once")

        summary = tally.summary()

        assert summary == ["maxmind: 4 addresses failed - missing"]

    def test_summary_empty_when_nothing_repeated(self):
        tally = _FailureTally()
        tally.record("maxmind", "missing")

        assert tally.summary() == []


class TestFailuresAreLoggedOnceButRecordedAlways:
    @pytest.fixture(autouse=True)
    def clear_tally(self):
        FAILURES.reset()
        yield
        FAILURES.reset()

    def test_every_record_still_carries_the_error(self, tmp_path, caplog):
        """Collapsing the logs must not hide the per-row data: a batch that
        silently produced a column of errors would be worse than noise."""
        config = KnowYourIPConfig()
        config.maxmind.db_path = tmp_path / "nowhere"
        config.network.enabled = False
        config.rdap.enabled = False

        records = [query_ip(config, ip) for ip in ("8.8.8.8", "1.1.1.1", "9.9.9.9")]

        assert all("maxmind.error" in r for r in records)

    def test_identical_failure_warns_once(self, tmp_path, caplog):
        import logging

        caplog.set_level(logging.WARNING)
        config = KnowYourIPConfig()
        config.maxmind.db_path = tmp_path / "nowhere"
        config.network.enabled = False
        config.rdap.enabled = False

        for ip in ("8.8.8.8", "1.1.1.1", "9.9.9.9"):
            query_ip(config, ip)

        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) == 1


class TestMaxMindProviderAgainstRealDatabase:
    """Exercise the provider against a genuine .mmdb file.

    MaxMind publishes small test databases under Apache-2.0 in the MaxMind-DB
    repository, so the provider can be verified against the real binary format
    without a licence key or a 60 MB download. Everything before this was
    mocked, which would not have caught a change in the record shape - and a
    change in the record shape is exactly what broke this provider when geoip2
    5.0 removed `.raw`.
    """

    @pytest.fixture
    def config(self, tmp_path):
        from know_your_ip import KnowYourIPConfig

        fixture = Path(__file__).parent / "fixtures" / "GeoLite2-City-Test.mmdb"
        shutil.copy(fixture, tmp_path / "GeoLite2-City.mmdb")
        config = KnowYourIPConfig()
        config.maxmind.db_path = tmp_path
        return config

    def test_returns_real_geolocation(self, config):
        from know_your_ip import maxmind_geocode_ip

        out = maxmind_geocode_ip(config, "81.2.69.142")

        assert out["maxmind.country.names.en"] == "United Kingdom"
        assert out["maxmind.city.names.en"] == "London"

    def test_produces_the_documented_column_names(self, config):
        """The default output columns must match what the provider emits."""
        from know_your_ip import maxmind_geocode_ip
        from know_your_ip.config import DEFAULT_OUTPUT_COLUMNS

        out = maxmind_geocode_ip(config, "81.2.69.142")
        expected = {c for c in DEFAULT_OUTPUT_COLUMNS if c.startswith("maxmind.")}

        assert expected & set(out), (
            "no default maxmind.* column is produced by the provider"
        )

    def test_supplies_coordinates_for_downstream_providers(self, config):
        """query_ip feeds these to the coordinate-based providers."""
        from know_your_ip import maxmind_geocode_ip

        out = maxmind_geocode_ip(config, "81.2.69.142")

        assert isinstance(out["maxmind.location.latitude"], float)
        assert isinstance(out["maxmind.location.longitude"], float)

    def test_absent_address_returns_empty(self, config):
        from know_your_ip import maxmind_geocode_ip

        assert maxmind_geocode_ip(config, "203.0.113.99") == {}

    def test_query_ip_end_to_end(self, config):
        from know_your_ip import query_ip

        config.network.enabled = False
        config.rdap.enabled = False

        record = query_ip(config, "81.2.69.142")

        assert record["maxmind.country.names.en"] == "United Kingdom"
        assert "maxmind.error" not in record
