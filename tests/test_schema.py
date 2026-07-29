"""Tests for the canonical join.

The risk here is not that the mapping is incomplete but that it is wrong:
merging two fields that mean different things would silently corrupt an
analysis, and would be harder to notice than no mapping at all. Several of these
tests exist to keep specific pairs apart.
"""

from __future__ import annotations

import shutil

import pytest

from know_your_ip import KnowYourIPConfig, maxmind_geocode_ip
from know_your_ip.schema import (
    CANONICAL,
    SEPARATE_BY_DESIGN,
    SET_FIELDS,
    canonical_columns,
    canonicalize,
    tidy,
)

FIXTURE = "tests/fixtures/GeoLite2-City-Test.mmdb"


class TestTheJoin:
    def test_five_spellings_of_country_become_one_column(self):
        """The whole point: one variable, one column."""
        record = {
            "ip": "8.8.8.8",
            "maxmind.country.iso_code": "US",
            "censys.country_code": "US",
            "abuseipdb.country_code": "US",
            "virustotal.country": "US",
            "rdap.country": "US",
        }

        out = canonicalize(record)

        assert out["country_code"] == "US"
        assert out["country_code.agree"] is True
        assert out["country_code.sources"] == "abuseipdb|censys|maxmind|rdap|virustotal"

    def test_three_spellings_of_asn_become_one(self):
        record = {"censys.asn": 15169, "virustotal.asn": 15169, "shodan.asn": 15169}

        assert canonicalize(record)["asn"] == 15169

    def test_absent_fields_produce_no_columns(self):
        """A provider that did not run should not leave empty columns behind."""
        out = canonicalize({"ip": "8.8.8.8"})

        assert out == {"ip": "8.8.8.8"}

    def test_empty_values_are_not_treated_as_answers(self):
        out = canonicalize({"censys.country_code": "", "rdap.country": "GB"})

        assert out["country_code"] == "GB"
        assert out["country_code.sources"] == "rdap"


class TestDisagreementIsSurfaced:
    """Sources genuinely differ. Hiding that is worse than showing it."""

    def test_disagreement_is_flagged(self):
        record = {"maxmind.country.iso_code": "GB", "censys.country_code": "US"}

        out = canonicalize(record)

        assert out["country_code.agree"] is False

    def test_all_distinct_answers_are_kept(self):
        record = {"maxmind.country.iso_code": "GB", "censys.country_code": "US"}

        assert set(canonicalize(record)["country_code.values"].split("|")) == {
            "GB",
            "US",
        }

    def test_majority_wins(self):
        record = {
            "maxmind.country.iso_code": "US",
            "censys.country_code": "US",
            "rdap.country": "GB",
        }

        out = canonicalize(record)

        assert out["country_code"] == "US"
        assert out["country_code.agree"] is False

    def test_one_source_is_not_a_consensus(self):
        """agree must be absent, not True: nothing was corroborated."""
        out = canonicalize({"rdap.country": "GB"})

        assert out["country_code"] == "GB"
        assert "country_code.agree" not in out

    def test_agreement_needs_no_values_column(self):
        out = canonicalize(
            {"maxmind.country.iso_code": "US", "censys.country_code": "US"}
        )

        assert "country_code.values" not in out


class TestFieldsKeptApartOnPurpose:
    """Merging any of these would corrupt an analysis silently."""

    def test_registered_country_is_not_country(self):
        """The case that motivated the distinction: a UK-geolocated address
        registered in the US. Merging them would make the column meaningless."""
        record = {
            "maxmind.country.iso_code": "GB",
            "maxmind.registered_country.iso_code": "US",
        }

        out = canonicalize(record)

        assert out["country_code"] == "GB"
        assert out["registered_country_code"] == "US"
        assert out["country_code.sources"] == "maxmind"

    def test_registered_country_never_feeds_country_code(self):
        assert "maxmind.registered_country.iso_code" not in CANONICAL["country_code"]

    def test_as_country_is_not_the_address_country(self):
        assert "censys.as_country_code" not in CANONICAL["country_code"]

    def test_org_country_is_not_the_address_country(self):
        assert "censys.whois_org_country" not in CANONICAL["country_code"]

    def test_isp_is_not_as_name(self):
        assert "abuseipdb.isp" not in CANONICAL["as_name"]

    def test_every_declared_separation_is_enforced(self):
        """The registry cannot drift away from its own documented constraints.

        Note these keys are not banned outright - abuseipdb.isp is the source
        for the canonical `isp` field. They are banned from one specific field
        each, which is what makes the constraint meaningful.
        """
        for (key, forbidden_field), reason in SEPARATE_BY_DESIGN.items():
            assert reason, f"{key} -> {forbidden_field} has no stated reason"
            assert key not in CANONICAL.get(forbidden_field, []), (
                f"{key} must not feed {forbidden_field}: {reason}"
            )

    def test_isp_is_still_used_where_it_belongs(self):
        """Guards the test above from being satisfied by deleting the field."""
        assert "abuseipdb.isp" in CANONICAL["isp"]


class TestLocalizedNamesAreSidestepped:
    def test_country_code_reads_iso_not_localized_names(self):
        """MaxMind emits each place name in ten languages; the ISO code avoids
        the question entirely."""
        assert "maxmind.country.iso_code" in CANONICAL["country_code"]
        assert not any(
            k.startswith("maxmind.country.names.") for k in CANONICAL["country_code"]
        )


class TestSetFields:
    def test_ports_are_unioned_not_voted_on(self):
        """Two scanners seeing different ports have not disagreed."""
        record = {"censys.ports": "53|443", "shodan.ports": "443|8080"}

        assert canonicalize(record)["ports"] == "53|443|8080"

    def test_ports_sort_numerically(self):
        record = {"censys.ports": "8080|53|443"}

        assert canonicalize(record)["ports"] == "53|443|8080"

    def test_identical_sets_agree(self):
        record = {"censys.ports": "53|443", "shodan.ports": "443|53"}

        assert canonicalize(record)["ports.agree"] is True

    def test_different_sets_do_not_agree(self):
        record = {"censys.ports": "53", "shodan.ports": "443"}

        assert canonicalize(record)["ports.agree"] is False


class TestAgainstRealProviderOutput:
    """Mappings must match what providers actually emit, not what I remember."""

    @pytest.fixture
    def maxmind_record(self, tmp_path):
        shutil.copy(FIXTURE, tmp_path / "GeoLite2-City.mmdb")
        config = KnowYourIPConfig()
        config.maxmind.db_path = tmp_path
        return maxmind_geocode_ip(config, "81.2.69.142")

    def test_real_maxmind_output_canonicalizes(self, maxmind_record):
        out = canonicalize(maxmind_record)

        assert out["country_code"] == "GB"
        assert out["city"] == "London"
        assert isinstance(out["latitude"], float)

    def test_real_maxmind_keeps_registration_separate(self, maxmind_record):
        """81.2.69.142 is geolocated in GB and registered in the US - the exact
        case that makes this distinction matter."""
        out = canonicalize(maxmind_record)

        assert out["country_code"] == "GB"
        assert out["registered_country_code"] == "US"

    def test_real_censys_output_canonicalizes(self):
        import json

        from know_your_ip.core import _parse_censys

        with open("tests/fixtures/censys_host_8.8.8.8.json") as fh:
            resource = json.load(fh)["result"]["resource"]

        out = canonicalize(_parse_censys(resource))

        assert out["country_code"] == "US"
        assert out["asn"] == 15169
        assert out["network"] == "8.8.8.0/24"


class TestTidy:
    def test_one_row_per_field_and_source(self):
        rows = tidy([{"ip": "8.8.8.8", "censys.asn": 15169, "virustotal.asn": 15169}])

        assert len(rows) == 2
        assert {r["source"] for r in rows} == {"censys", "virustotal"}
        assert all(r["field"] == "asn" for r in rows)

    def test_carries_the_address(self):
        rows = tidy([{"ip": "8.8.8.8", "rdap.country": "US"}])

        assert rows[0] == {
            "ip": "8.8.8.8",
            "field": "country_code",
            "source": "rdap",
            "value": "US",
        }

    def test_nothing_is_lost_relative_to_the_wide_form(self):
        record = {
            "ip": "8.8.8.8",
            "maxmind.country.iso_code": "GB",
            "censys.country_code": "US",
            "censys.asn": 15169,
        }

        wide = canonicalize(record)
        long_fields = {r["field"] for r in tidy([record])}

        assert long_fields == {k for k in wide if "." not in k and k != "ip"}

    def test_empty_input(self):
        assert tidy([]) == []


class TestCanonicalColumns:
    def test_includes_every_registered_field(self):
        columns = canonical_columns()

        for name in list(CANONICAL) + list(SET_FIELDS):
            assert name in columns

    def test_starts_with_the_key(self):
        assert canonical_columns()[0] == "ip"

    def test_no_duplicates(self):
        columns = canonical_columns()

        assert len(columns) == len(set(columns))
