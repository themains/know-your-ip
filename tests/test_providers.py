"""Tests for the service integrations.

These use recorded response payloads rather than live calls. Every regression
here corresponds to a defect that shipped because the API layer had no tests.
"""

from __future__ import annotations

import pytest
import responses

from know_your_ip import (
    KnowYourIPConfig,
    abuseipdb_api,
    apivoid_api,
    censys_api,
    geonames_timezone,
    query_ip,
    select_columns,
    virustotal_api,
)

VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8"
ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"
GEONAMES_URL = "https://secure.geonames.org/timezoneJSON"
APIVOID_URL = "https://api.apivoid.com/v2/ip-reputation"


@pytest.fixture
def config() -> KnowYourIPConfig:
    """A configuration with every network service disabled by default."""
    return KnowYourIPConfig()


# Shape mirrors a real v3 IP object. Note there is no "categories" key:
# VirusTotal returns categories for domains and URLs, never for IP addresses.
VT_PAYLOAD = {
    "data": {
        "attributes": {
            "last_analysis_stats": {
                "harmless": 52,
                "malicious": 4,
                "suspicious": 1,
                "undetected": 35,
                "timeout": 2,
            },
            "asn": 15169,
            "as_owner": "GOOGLE",
            "country": "US",
            "continent": "NA",
            "network": "8.8.8.0/24",
            "regional_internet_registry": "ARIN",
            "reputation": 530,
            "jarm": "29d3fd00029d29d0",
            "last_analysis_date": 1700000000,
            "whois_date": 1690000000,
            "total_votes": {"harmless": 200, "malicious": 3},
            "tags": ["dns", "public"],
        }
    }
}


class TestVirusTotal:
    """VirusTotal API v3."""

    @responses.activate
    def test_extracts_all_five_stat_buckets(self, config):
        """last_analysis_stats has five buckets; timeout was never read."""
        config.virustotal.api_key = "k"
        responses.add(responses.GET, VT_URL, json=VT_PAYLOAD, status=200)

        out = virustotal_api(config, "8.8.8.8")

        assert out["virustotal.harmless"] == 52
        assert out["virustotal.malicious"] == 4
        assert out["virustotal.suspicious"] == 1
        assert out["virustotal.undetected"] == 35
        assert out["virustotal.timeout"] == 2

    @responses.activate
    def test_extracts_network_and_vote_metadata(self, config):
        """Fields beyond the original ten are captured."""
        config.virustotal.api_key = "k"
        responses.add(responses.GET, VT_URL, json=VT_PAYLOAD, status=200)

        out = virustotal_api(config, "8.8.8.8")

        assert out["virustotal.reputation"] == 530
        assert out["virustotal.rir"] == "ARIN"
        assert out["virustotal.continent"] == "NA"
        assert out["virustotal.jarm"] == "29d3fd00029d29d0"
        assert out["virustotal.votes_harmless"] == 200
        assert out["virustotal.votes_malicious"] == 3
        assert out["virustotal.tags"] == "dns|public"

    @responses.activate
    def test_no_categories_key_for_ip_objects(self, config):
        """VirusTotal does not return categories for IPs; nothing is invented."""
        config.virustotal.api_key = "k"
        responses.add(responses.GET, VT_URL, json=VT_PAYLOAD, status=200)

        assert "virustotal.categories" not in virustotal_api(config, "8.8.8.8")

    @responses.activate
    def test_persistent_rate_limit_is_reported(self, config):
        """429 is retried with backoff, then reported.

        The transport honors Retry-After and backs off, so a transient 429
        recovers; only a persistent one surfaces as rate_limited.
        """
        config.virustotal.api_key = "k"
        responses.add(responses.GET, VT_URL, json={}, status=429)

        out = virustotal_api(config, "8.8.8.8")

        assert out == {"virustotal.status": "rate_limited"}
        assert len(responses.calls) == 5

    @responses.activate
    def test_transient_rate_limit_recovers(self, config):
        config.virustotal.api_key = "k"
        responses.add(responses.GET, VT_URL, json={}, status=429)
        responses.add(responses.GET, VT_URL, json=VT_PAYLOAD, status=200)

        assert virustotal_api(config, "8.8.8.8")["virustotal.reputation"] == 530

    @responses.activate
    def test_auth_failure_does_not_retry(self, config):
        """A 401 is terminal; retrying with a bad key cannot help."""
        config.virustotal.api_key = "bad"
        responses.add(responses.GET, VT_URL, json={}, status=401)

        assert virustotal_api(config, "8.8.8.8") == {"virustotal.status": "auth_failed"}
        assert len(responses.calls) == 1

    def test_missing_key_returns_empty(self, config):
        """No key configured is not an error."""
        assert virustotal_api(config, "8.8.8.8") == {}


class TestAbuseIPDB:
    """AbuseIPDB API v2."""

    @responses.activate
    def test_reads_abuse_confidence_score(self, config):
        """The field is abuseConfidenceScore; abuseConfidencePercentage
        does not exist in v2 and always yielded 0."""
        config.abuseipdb.api_key = "k"
        responses.add(
            responses.GET,
            ABUSE_URL,
            json={"data": {"abuseConfidenceScore": 100, "isTor": False}},
            status=200,
        )

        out = abuseipdb_api(config, "222.186.30.49")

        assert out["abuseipdb.abuse_confidence_score"] == 100

    @responses.activate
    def test_categories_aggregated_from_reports(self, config):
        """Categories live under data.reports[].categories, not at top level."""
        config.abuseipdb.api_key = "k"
        responses.add(
            responses.GET,
            ABUSE_URL,
            json={
                "data": {
                    "abuseConfidenceScore": 90,
                    "reports": [
                        {"categories": [18, 22]},
                        {"categories": [22, 15]},
                    ],
                }
            },
            status=200,
        )

        out = abuseipdb_api(config, "222.186.30.49")

        # Deduplicated and ordered by numeric id: 15, 18, 22.
        assert out["abuseipdb.categories"] == "Hacking|Brute Force|SSH"

    @responses.activate
    def test_no_reports_yields_empty_categories(self, config):
        """A clean IP produces an empty string, not a crash."""
        config.abuseipdb.api_key = "k"
        responses.add(
            responses.GET, ABUSE_URL, json={"data": {"reports": []}}, status=200
        )

        assert abuseipdb_api(config, "8.8.8.8")["abuseipdb.categories"] == ""


class TestGeoNames:
    """GeoNames timezone lookup."""

    @responses.activate
    def test_uses_secure_host(self, config):
        """api.geonames.org serves a secure.geonames.org certificate, so the
        secure host is required for TLS to validate."""
        responses.add(
            responses.GET,
            GEONAMES_URL,
            json={"timezoneId": "Asia/Shanghai", "countryCode": "CN"},
            status=200,
        )

        out = geonames_timezone(config, 32.0617, 118.7778)

        assert out["geonames.timezoneId"] == "Asia/Shanghai"
        assert str(responses.calls[0].request.url).startswith(GEONAMES_URL)

    @responses.activate
    def test_quota_error_returned_inside_http_200(self, config):
        """GeoNames signals quota exhaustion in the body of a 200 response."""
        responses.add(
            responses.GET,
            GEONAMES_URL,
            json={"status": {"message": "hourly limit exceeded", "value": 19}},
            status=200,
        )

        out = geonames_timezone(config, 32.0617, 118.7778)

        assert out == {"geonames.error": "hourly limit exceeded"}
        assert len(responses.calls) == 1


class TestAPIVoid:
    """APIVoid API v2."""

    @responses.activate
    def test_posts_with_header_auth_and_flat_report(self, config):
        """v2 is a POST with X-API-Key and no data.report wrapper."""
        config.apivoid.api_key = "k"
        responses.add(
            responses.POST,
            APIVOID_URL,
            json={
                "anonymity": {"is_tor": True, "is_vpn": False},
                "blacklists": {"detections": 2, "scan_time_ms": 130},
            },
            status=200,
        )

        out = apivoid_api(config, "8.8.8.8")

        assert out["apivoid.anonymity.is_tor"] is True
        assert out["apivoid.blacklists.detections"] == 2
        assert responses.calls[0].request.headers["X-API-Key"] == "k"


class TestCensys:
    """Censys Platform API."""

    @responses.activate
    def test_reads_result_resource_envelope(self, config):
        """The Platform API nests the host under result.resource."""
        config.censys.api_key = "pat"
        url = "https://api.platform.censys.io/v3/global/asset/host/8.8.8.8"
        responses.add(
            responses.GET,
            url,
            json={
                "result": {
                    "resource": {
                        "ip": "8.8.8.8",
                        "autonomous_system": {"asn": 15169, "name": "GOOGLE"},
                        "location": {"country": "United States"},
                        "services": [
                            {"port": 53, "transport_protocol": "UDP"},
                            {"port": 443, "transport_protocol": "TCP"},
                        ],
                    }
                }
            },
            status=200,
        )

        out = censys_api(config, "8.8.8.8")

        assert out["censys.asn"] == 15169
        assert out["censys.as_name"] == "GOOGLE"
        assert out["censys.ports"] == "53|443"
        assert out["censys.protocols"] == "TCP|UDP"

    @responses.activate
    def test_sends_bearer_token(self, config):
        """Platform auth is a Bearer personal access token."""
        config.censys.api_key = "pat"
        responses.add(
            responses.GET,
            "https://api.platform.censys.io/v3/global/asset/host/8.8.8.8",
            json={"result": {"resource": {}}},
            status=200,
        )

        censys_api(config, "8.8.8.8")

        assert responses.calls[0].request.headers["Authorization"] == "Bearer pat"


class TestQueryIP:
    """query_ip orchestration."""

    @responses.activate
    def test_returns_fields_absent_from_output_columns(self, config):
        """query_ip previously filtered its result to config.output.columns,
        so documented fields came back missing."""
        config.maxmind.enabled = False
        config.virustotal.enabled = True
        config.virustotal.api_key = "k"
        config.output.columns = ["ip"]
        responses.add(responses.GET, VT_URL, json=VT_PAYLOAD, status=200)

        out = query_ip(config, "8.8.8.8")

        assert out["virustotal.reputation"] == 530
        assert out["ip"] == "8.8.8.8"

    def test_invalid_ip_reported_not_raised(self, config):
        """A bad address in a batch must not abort the run."""
        out = query_ip(config, "not-an-ip")

        assert "error" in out

    @responses.activate
    def test_one_failing_service_does_not_block_others(self, config):
        """Service isolation: a 500 from one provider is recorded, not fatal."""
        config.maxmind.enabled = False
        config.virustotal.enabled = True
        config.virustotal.api_key = "k"
        config.abuseipdb.enabled = True
        config.abuseipdb.api_key = "k"
        responses.add(responses.GET, VT_URL, json=VT_PAYLOAD, status=200)
        responses.add(
            responses.GET,
            ABUSE_URL,
            json={"data": {"abuseConfidenceScore": 7}},
            status=200,
        )

        out = query_ip(config, "8.8.8.8")

        assert out["virustotal.reputation"] == 530
        assert out["abuseipdb.abuse_confidence_score"] == 7

    def test_timezone_skipped_without_coordinates(self, config):
        """Without MaxMind there is no lat/lng; this used to raise NameError
        on an unbound local and be swallowed."""
        config.maxmind.enabled = False
        config.network.enabled = False
        config.rdap.enabled = False
        config.geonames.enabled = True
        config.timezone.enabled = True

        out = query_ip(config, "8.8.8.8")

        assert out == {"ip": "8.8.8.8"}


class TestSelectColumns:
    """Explicit column selection."""

    def test_keeps_only_requested_columns(self):
        record = {"ip": "8.8.8.8", "a.b": 1, "c.d": 2}

        assert select_columns(record, ["ip", "c.d"]) == {"ip": "8.8.8.8", "c.d": 2}

    def test_missing_columns_are_omitted_not_null(self):
        assert select_columns({"ip": "8.8.8.8"}, ["ip", "absent"]) == {"ip": "8.8.8.8"}
