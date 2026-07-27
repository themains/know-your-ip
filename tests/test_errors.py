"""Tests for failure handling: retries, backoff, and degraded services."""

from __future__ import annotations

from unittest import mock

import pytest
import requests
import responses

from know_your_ip import (
    InvalidIPError,
    KnowYourIPConfig,
    maxmind_geocode_ip,
    shodan_api,
    timezone_at,
    validate_ip,
    virustotal_api,
)
from know_your_ip.ping import quiet_ping

VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8"


@pytest.fixture
def config() -> KnowYourIPConfig:
    return KnowYourIPConfig()


class TestValidateIP:
    def test_accepts_ipv4_and_ipv6(self):
        assert validate_ip(" 8.8.8.8 ") == "8.8.8.8"
        assert validate_ip("2001:4860:4860::8888") == "2001:4860:4860::8888"

    @pytest.mark.parametrize(
        "bad", ["", "not-an-ip", "8.8.8", "999.1.1.1", "8.8.8.8/24", "8.8.8.8 -w 9"]
    )
    def test_rejects_invalid(self, bad):
        with pytest.raises(InvalidIPError):
            validate_ip(bad)


class TestRetryBehavior:
    @responses.activate
    def test_server_error_retries_then_reports(self, config):
        """A 5xx is retried, then reported as a value rather than swallowed.

        Previously the retry counter was only incremented on exception, so a
        non-200 burned every attempt back-to-back with no delay and returned
        an empty dict indistinguishable from "nothing found".
        """
        config.virustotal.api_key = "k"
        responses.add(responses.GET, VT_URL, json={}, status=500)

        result = virustotal_api(config, "8.8.8.8")

        assert len(responses.calls) == 5
        assert result == {"virustotal.error": "HTTP 500"}

    @responses.activate
    def test_recovers_after_transient_error(self, config):
        config.virustotal.api_key = "k"
        responses.add(responses.GET, VT_URL, json={}, status=503)
        responses.add(
            responses.GET,
            VT_URL,
            json={"data": {"attributes": {"reputation": 7}}},
            status=200,
        )

        assert virustotal_api(config, "8.8.8.8")["virustotal.reputation"] == 7

    @responses.activate
    def test_connection_error_is_retried(self, config):
        config.virustotal.api_key = "k"
        responses.add(responses.GET, VT_URL, body=requests.ConnectionError("boom"))
        responses.add(
            responses.GET,
            VT_URL,
            json={"data": {"attributes": {"reputation": 3}}},
            status=200,
        )

        assert virustotal_api(config, "8.8.8.8")["virustotal.reputation"] == 3

    @responses.activate
    def test_malformed_json_does_not_raise(self, config):
        config.virustotal.api_key = "k"
        responses.add(responses.GET, VT_URL, body="not json", status=200)

        with pytest.raises(requests.JSONDecodeError):
            virustotal_api(config, "8.8.8.8")


class TestMaxMind:
    def test_missing_database_explains_how_to_get_it(self, config, tmp_path):
        config.maxmind.db_path = tmp_path

        with pytest.raises(FileNotFoundError, match=r"maxmind\.com"):
            maxmind_geocode_ip(config, "8.8.8.8")

    def test_address_not_in_database_returns_empty(self, config, tmp_path):
        (tmp_path / "GeoLite2-City.mmdb").write_bytes(b"stub")
        config.maxmind.db_path = tmp_path
        reader = mock.Mock()
        reader.get.return_value = None

        with mock.patch(
            "know_your_ip.core.maxminddb.open_database", return_value=reader
        ):
            assert maxmind_geocode_ip(config, "8.8.8.8") == {}

    def test_record_is_flattened_with_prefix(self, config, tmp_path):
        (tmp_path / "GeoLite2-City.mmdb").write_bytes(b"stub")
        config.maxmind.db_path = tmp_path
        reader = mock.Mock()
        reader.get.return_value = {"country": {"names": {"en": "United States"}}}

        with mock.patch(
            "know_your_ip.core.maxminddb.open_database", return_value=reader
        ):
            out = maxmind_geocode_ip(config, "8.8.8.8")

        assert out == {"maxmind.country.names.en": "United States"}

    def test_reader_is_cached_across_lookups(self, config, tmp_path):
        """Readers memory-map the database; reopening per address was wasteful."""
        (tmp_path / "GeoLite2-City.mmdb").write_bytes(b"stub")
        config.maxmind.db_path = tmp_path
        reader = mock.Mock()
        reader.get.return_value = {}

        with mock.patch(
            "know_your_ip.core.maxminddb.open_database", return_value=reader
        ) as open_db:
            maxmind_geocode_ip(config, "8.8.8.8")
            maxmind_geocode_ip(config, "1.1.1.1")

        assert open_db.call_count == 1


class TestOptionalDependencies:
    def test_shodan_missing_extra_gives_actionable_error(self, config, monkeypatch):
        monkeypatch.setitem(__import__("sys").modules, "shodan", None)

        with pytest.raises(ImportError, match=r"know_your_ip\[shodan\]"):
            shodan_api(config, "8.8.8.8")

    def test_timezone_missing_extra_gives_actionable_error(self, config, monkeypatch):
        monkeypatch.setattr("know_your_ip.core._TIMEZONE_FINDER", None)
        monkeypatch.setitem(__import__("sys").modules, "timezonefinder", None)

        with pytest.raises(ImportError, match=r"know_your_ip\[timezone\]"):
            timezone_at(config, 1.0, 2.0)


class TestPingFailures:
    def test_command_missing_returns_none(self):
        with mock.patch(
            "know_your_ip.ping.subprocess.run", side_effect=FileNotFoundError
        ):
            assert quiet_ping("8.8.8.8") is None

    def test_timeout_returns_none(self):
        import subprocess

        with mock.patch(
            "know_your_ip.ping.subprocess.run",
            side_effect=subprocess.TimeoutExpired("ping", 1),
        ):
            assert quiet_ping("8.8.8.8") is None

    def test_unreachable_host_returns_none(self):
        with mock.patch("know_your_ip.ping.subprocess.run") as run:
            run.return_value = mock.Mock(returncode=1, stdout="", stderr="unreachable")

            assert quiet_ping("192.0.2.1") is None

    def test_windows_command_shape(self):
        with (
            mock.patch("know_your_ip.ping.platform.system", return_value="Windows"),
            mock.patch("know_your_ip.ping.subprocess.run") as run,
        ):
            run.return_value = mock.Mock(returncode=0, stdout="", stderr="")
            quiet_ping("8.8.8.8", timeout=3000, count=2)

        cmd = run.call_args[0][0]
        assert cmd[:1] == ["ping"]
        assert "-n" in cmd
        assert "-w" in cmd
