"""Tests for the keyless classification, reverse DNS, and RDAP providers."""

from __future__ import annotations

from unittest import mock

import pytest
import responses

from know_your_ip import KnowYourIPConfig
from know_your_ip.network import (
    _abuse_contact,
    _parse_rdap,
    classify_ip,
    network_info,
    rdap_lookup,
    rdap_service_for,
    reverse_dns,
)

BOOTSTRAP_V4 = "https://data.iana.org/rdap/ipv4.json"
BOOTSTRAP_PAYLOAD = {
    "services": [
        [["8.0.0.0/8", "12.0.0.0/8"], ["https://rdap.arin.net/registry/"]],
        [["8.8.8.0/24"], ["https://more-specific.example/"]],
    ]
}


@pytest.fixture
def config() -> KnowYourIPConfig:
    return KnowYourIPConfig()


@pytest.fixture(autouse=True)
def clear_bootstrap():
    """The bootstrap registry is cached per process; isolate tests from it."""
    from know_your_ip import network

    network._BOOTSTRAP_CACHE.clear()
    yield
    network._BOOTSTRAP_CACHE.clear()


class TestClassify:
    @pytest.mark.parametrize(
        ("ip", "category"),
        [
            ("8.8.8.8", "public"),
            ("192.168.1.1", "private"),
            ("10.0.0.1", "private"),
            ("127.0.0.1", "loopback"),
            ("169.254.1.1", "link_local"),
            ("224.0.0.1", "multicast"),
            ("100.64.0.1", "cgnat"),
            ("2001:4860:4860::8888", "public"),
            ("::1", "loopback"),
        ],
    )
    def test_categories(self, ip, category):
        assert classify_ip(ip)["network.category"] == category

    def test_loopback_beats_private(self):
        """127.0.0.1 is private by the stdlib's reckoning; the narrower label
        is the informative one."""
        assert classify_ip("127.0.0.1")["network.category"] == "loopback"

    def test_cgnat_is_flagged(self):
        """Carrier-grade NAT is shared by many subscribers, so anything
        inferred about an individual behind it is unusually weak."""
        data = classify_ip("100.64.0.1")

        assert data["network.is_cgnat"] is True
        assert data["network.is_routable"] is False

    def test_routable_public_address(self):
        data = classify_ip("8.8.8.8")

        assert data["network.is_routable"] is True
        assert data["network.version"] == 4

    def test_multicast_is_not_routable(self):
        assert classify_ip("224.0.0.1")["network.is_routable"] is False

    def test_rejects_non_ip(self):
        with pytest.raises(ValueError, match="does not appear to be"):
            classify_ip("not-an-ip")


class TestReverseDNS:
    def test_returns_hostname(self):
        with mock.patch(
            "know_your_ip.network.socket.gethostbyaddr",
            return_value=("dns.google", [], []),
        ):
            assert reverse_dns("8.8.8.8") == {"network.reverse_dns": "dns.google"}

    def test_absent_ptr_is_not_an_error(self):
        with mock.patch(
            "know_your_ip.network.socket.gethostbyaddr", side_effect=OSError
        ):
            assert reverse_dns("8.8.8.8") == {}

    def test_restores_default_timeout(self):
        """A global socket timeout left behind would affect unrelated code."""
        import socket

        before = socket.getdefaulttimeout()
        with mock.patch(
            "know_your_ip.network.socket.gethostbyaddr", side_effect=OSError
        ):
            reverse_dns("8.8.8.8", timeout=1.0)

        assert socket.getdefaulttimeout() == before


class TestNetworkInfo:
    def test_skips_reverse_dns_for_private_addresses(self, config):
        with mock.patch("know_your_ip.network.socket.gethostbyaddr") as lookup:
            network_info(config, "192.168.1.1")

        lookup.assert_not_called()

    def test_reverse_dns_can_be_disabled(self, config):
        config.network.reverse_dns = False

        with mock.patch("know_your_ip.network.socket.gethostbyaddr") as lookup:
            network_info(config, "8.8.8.8")

        lookup.assert_not_called()


class TestBootstrap:
    @responses.activate
    def test_prefers_most_specific_prefix(self):
        """Registries overlap; the longest matching prefix is authoritative."""
        responses.add(responses.GET, BOOTSTRAP_V4, json=BOOTSTRAP_PAYLOAD, status=200)

        assert rdap_service_for("8.8.8.8") == "https://more-specific.example/"

    @responses.activate
    def test_falls_back_to_broader_prefix(self):
        responses.add(responses.GET, BOOTSTRAP_V4, json=BOOTSTRAP_PAYLOAD, status=200)

        assert rdap_service_for("12.0.0.1") == "https://rdap.arin.net/registry/"

    @responses.activate
    def test_unmatched_address_returns_none(self):
        responses.add(responses.GET, BOOTSTRAP_V4, json=BOOTSTRAP_PAYLOAD, status=200)

        assert rdap_service_for("203.0.113.1") is None

    @responses.activate
    def test_registry_fetched_once_per_process(self):
        responses.add(responses.GET, BOOTSTRAP_V4, json=BOOTSTRAP_PAYLOAD, status=200)

        rdap_service_for("8.8.8.8")
        rdap_service_for("12.0.0.1")

        assert len(responses.calls) == 1

    @responses.activate
    def test_unavailable_registry_is_not_fatal(self):
        responses.add(responses.GET, BOOTSTRAP_V4, json={}, status=503)

        assert rdap_service_for("8.8.8.8") is None


class TestRDAPLookup:
    def test_skips_non_routable_addresses(self, config):
        """No registry holds RFC1918 space; asking wastes a request."""
        assert rdap_lookup(config, "192.168.1.1") == {
            "rdap.status": "not_globally_routable"
        }

    @responses.activate
    def test_parses_a_response(self, config):
        responses.add(responses.GET, BOOTSTRAP_V4, json=BOOTSTRAP_PAYLOAD, status=200)
        responses.add(
            responses.GET,
            "https://more-specific.example/ip/8.8.8.8",
            json={
                "handle": "NET-8-8-8-0-2",
                "name": "GOGL",
                "type": "DIRECT ALLOCATION",
                "startAddress": "8.8.8.0",
                "endAddress": "8.8.8.255",
                "ipVersion": "v4",
                "status": ["active"],
                "events": [
                    {"eventAction": "registration", "eventDate": "2023-12-28"},
                    {"eventAction": "last changed", "eventDate": "2024-01-02"},
                ],
                "entities": [
                    {
                        "roles": ["abuse"],
                        "vcardArray": [
                            "vcard",
                            [["email", {}, "text", "abuse@example.com"]],
                        ],
                    }
                ],
            },
            status=200,
        )

        out = rdap_lookup(config, "8.8.8.8")

        assert out["rdap.handle"] == "NET-8-8-8-0-2"
        assert out["rdap.registration"] == "2023-12-28"
        assert out["rdap.last_changed"] == "2024-01-02"
        assert out["rdap.abuse_email"] == "abuse@example.com"

    @responses.activate
    def test_not_found_is_reported_as_status(self, config):
        responses.add(responses.GET, BOOTSTRAP_V4, json=BOOTSTRAP_PAYLOAD, status=200)
        responses.add(
            responses.GET, "https://more-specific.example/ip/8.8.8.8", status=404
        )

        assert rdap_lookup(config, "8.8.8.8") == {"rdap.status": "not_found"}


class TestAbuseContact:
    def test_finds_nested_contact(self):
        """RIRs commonly nest the abuse role one level down."""
        entities = [
            {
                "roles": ["registrant"],
                "entities": [
                    {
                        "roles": ["abuse"],
                        "vcardArray": [
                            "vcard",
                            [["email", {}, "text", "deep@example.com"]],
                        ],
                    }
                ],
            }
        ]

        assert _abuse_contact(entities) == "deep@example.com"

    def test_absent_contact_returns_none(self):
        assert _abuse_contact([{"roles": ["registrant"]}]) is None

    def test_malformed_vcard_does_not_raise(self):
        assert (
            _abuse_contact([{"roles": ["abuse"], "vcardArray": ["vcard", []]}]) is None
        )


class TestParseRDAP:
    def test_empty_payload_yields_no_values(self):
        parsed = _parse_rdap({})

        assert all(v is None for v in parsed.values())
