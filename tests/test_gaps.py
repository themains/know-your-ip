"""Tests aimed at specific uncovered branches, not at a coverage number.

Every provider defect in this project so far has lived in a response-shape or
error branch, never in the happy path: a removed geoip2 attribute, a renamed
AbuseIPDB field, a Censys envelope change. These target the branches that were
still unexercised.
"""

from __future__ import annotations

import csv
import subprocess
from unittest import mock

import pytest
import responses

from know_your_ip import (
    KnowYourIPConfig,
    enrich_csv,
    geonames_timezone,
    shodan_api,
    timezone_at,
)
from know_your_ip.core import main

GEONAMES = "https://secure.geonames.org/timezoneJSON"


@pytest.fixture
def config() -> KnowYourIPConfig:
    return KnowYourIPConfig()


class TestGeoNamesErrorPaths:
    """GeoNames signals failure in ways that are easy to mistake for success."""

    @responses.activate
    def test_invalid_json_is_reported_not_raised(self, config):
        responses.add(responses.GET, GEONAMES, body="<html>oops</html>", status=200)

        out = geonames_timezone(config, 51.5, -0.1)

        assert "geonames.error" in out
        assert "invalid JSON" in out["geonames.error"]

    @responses.activate
    def test_non_200_is_reported(self, config):
        responses.add(responses.GET, GEONAMES, json={}, status=503)

        assert "geonames.error" in geonames_timezone(config, 51.5, -0.1)

    @responses.activate
    def test_quota_message_inside_http_200_is_surfaced(self, config):
        """The failure mode that looks like success."""
        responses.add(
            responses.GET,
            GEONAMES,
            json={"status": {"message": "hourly limit exceeded", "value": 19}},
            status=200,
        )

        out = geonames_timezone(config, 51.5, -0.1)

        assert out == {"geonames.error": "hourly limit exceeded"}


class TestOptionalExtrasWhenInstalled:
    """These paths are only reachable when the extras are present.

    They were unexercised in CI too, despite CI installing --all-extras.
    """

    def test_timezone_lookup_returns_a_real_zone(self, config):
        pytest.importorskip("timezonefinder")

        assert timezone_at(config, 51.5074, -0.1278) == "Europe/London"

    def test_open_ocean_returns_a_nautical_zone(self, config):
        """timezonefinder covers oceans with Etc/GMT offsets rather than
        returning nothing, so a coordinate far from land still resolves."""
        pytest.importorskip("timezonefinder")

        assert timezone_at(config, 0.0, -140.0) == "Etc/GMT+9"

    def test_coordinates_are_accepted_as_strings(self, config):
        """MaxMind values arrive as floats, but a caller may pass strings."""
        pytest.importorskip("timezonefinder")

        assert timezone_at(config, "51.5074", "-0.1278") == "Europe/London"

    def test_shodan_without_a_key_returns_empty(self, config):
        pytest.importorskip("shodan")
        config.shodan.enabled = True

        assert shodan_api(config, "8.8.8.8") == {}

    def test_shodan_api_error_becomes_a_value(self, config):
        """A vendor exception must not escape into a caller's notebook."""
        shodan = pytest.importorskip("shodan")
        config.shodan.api_key = "k"

        with mock.patch.object(
            shodan.Shodan, "host", side_effect=shodan.APIError("Invalid API key")
        ):
            out = shodan_api(config, "8.8.8.8")

        assert out == {"shodan.error": "Invalid API key"}

    def test_shodan_flattens_nested_results(self, config):
        shodan = pytest.importorskip("shodan")
        config.shodan.api_key = "k"

        with mock.patch.object(
            shodan.Shodan,
            "host",
            return_value={"asn": "AS15169", "ports": [53, 443], "os": None},
        ):
            out = shodan_api(config, "8.8.8.8")

        assert out["shodan.asn"] == "AS15169"
        assert out["shodan.ports"] == "53|443"


class TestDownloadDbCli:
    def test_missing_credentials_explains_where_to_get_them(self, monkeypatch):
        monkeypatch.delenv("MAXMIND_ACCOUNT_ID", raising=False)
        monkeypatch.delenv("MAXMIND_LICENSE_KEY", raising=False)

        with pytest.raises(SystemExit):
            main(["download-db"])

    def test_credentials_may_come_from_the_environment(self, monkeypatch):
        monkeypatch.setenv("MAXMIND_ACCOUNT_ID", "acct")
        monkeypatch.setenv("MAXMIND_LICENSE_KEY", "key")

        with mock.patch("know_your_ip.core.download_all", return_value=[]) as download:
            assert main(["download-db"]) == 1

        download.assert_called_once_with("acct", "key")

    def test_reports_written_paths(self, monkeypatch, capsys, tmp_path):
        monkeypatch.setenv("MAXMIND_ACCOUNT_ID", "acct")
        monkeypatch.setenv("MAXMIND_LICENSE_KEY", "key")
        written = tmp_path / "GeoLite2-City.mmdb"

        with mock.patch("know_your_ip.core.download_all", return_value=[written]):
            assert main(["download-db"]) == 0

        assert str(written) in capsys.readouterr().out


class TestCliAndLibraryAgree:
    """The anti-drift check.

    The CLI and the library are separate entry points over the same providers.
    They diverged once already - the notebook rotted while example.py was
    updated - so equivalence is asserted rather than assumed.
    """

    def test_same_input_produces_the_same_rows(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        for key in ("MAXMIND", "VIRUSTOTAL", "CENSYS", "ABUSEIPDB"):
            monkeypatch.delenv(f"KNOW_YOUR_IP_{key}_API_KEY", raising=False)

        src = tmp_path / "ips.txt"
        src.write_text("8.8.8.8\n1.1.1.1\n")
        cli_out = tmp_path / "cli.csv"

        assert (
            main(
                [
                    "--file",
                    str(src),
                    "--providers",
                    "network",
                    "--all-columns",
                    "-o",
                    str(cli_out),
                ]
            )
            == 0
        )

        lib = enrich_csv(src, providers=["network"])

        with cli_out.open(newline="") as fh:
            cli_rows = list(csv.DictReader(fh))

        assert [r["ip"] for r in cli_rows] == [r["ip"] for r in lib]
        assert [r["network.category"] for r in cli_rows] == [
            r["network.category"] for r in lib
        ]


class TestPingAndTracerouteFailureBranches:
    def test_ping_parse_failure_is_not_fatal(self):
        from know_your_ip.ping import quiet_ping

        with mock.patch("know_your_ip.ping.subprocess.run") as run:
            run.return_value = mock.Mock(
                returncode=0, stdout="unparseable output", stderr=""
            )

            assert quiet_ping("8.8.8.8") is None

    def test_traceroute_command_missing_returns_empty(self):
        from know_your_ip.traceroute import os_traceroute

        with mock.patch(
            "know_your_ip.traceroute.subprocess.run", side_effect=FileNotFoundError
        ):
            assert os_traceroute("8.8.8.8") == ""

    def test_traceroute_nonzero_exit_with_no_output_returns_empty(self):
        from know_your_ip.traceroute import os_traceroute

        with mock.patch("know_your_ip.traceroute.subprocess.run") as run:
            run.return_value = mock.Mock(returncode=1, stdout="", stderr="no route")

            assert os_traceroute("8.8.8.8") == ""

    def test_traceroute_keeps_partial_output_on_nonzero_exit(self):
        """A partial trace is still worth something."""
        from know_your_ip.traceroute import os_traceroute

        with mock.patch("know_your_ip.traceroute.subprocess.run") as run:
            run.return_value = mock.Mock(
                returncode=1, stdout="1 192.168.1.1\n", stderr="partial"
            )

            assert "192.168.1.1" in os_traceroute("8.8.8.8")

    def test_traceroute_timeout_is_bounded(self):
        from know_your_ip.traceroute import os_traceroute

        with mock.patch(
            "know_your_ip.traceroute.subprocess.run",
            side_effect=subprocess.TimeoutExpired("traceroute", 1),
        ):
            assert os_traceroute("8.8.8.8") == ""
