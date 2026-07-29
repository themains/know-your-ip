"""The join: one column per variable, not one per vendor.

Providers describe the same things in different words. For a single address,
MaxMind reports ``country.iso_code`` plus country names in ten languages, Censys
reports ``country_code``, AbuseIPDB ``country_code``, VirusTotal ``country``,
and RDAP ``country`` - about fifteen columns naming three different concepts.
Reconciling that is work every user would otherwise repeat.

This module maps provider fields onto canonical names, and records whether the
sources agreed. Disagreement is reported rather than resolved away: geolocation
sources genuinely differ, and a table that hides that is worse than one that
shows it.

The mapping is deliberately conservative. Two fields merge only when they mean
the same thing, and several near-misses are kept apart on purpose - see
:data:`SEPARATE_BY_DESIGN`.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

# Canonical name -> provider keys that feed it.
#
# The value is chosen by agreement, so ordering usually does not matter. It does
# on a tie: with two sources reporting two values, the earlier entry wins. Each
# list is therefore ordered most-authoritative-first deliberately - a dedicated
# geolocation database before a reputation service's incidental country field.
CANONICAL: dict[str, list[str]] = {
    # Geolocation. Reads ISO codes rather than localized names, which sidesteps
    # MaxMind emitting each place name in ten languages.
    "country_code": [
        "maxmind.country.iso_code",
        "censys.country_code",
        "abuseipdb.country_code",
        "virustotal.country",
        "rdap.country",
    ],
    "country_name": ["maxmind.country.names.en", "censys.country"],
    "city": ["maxmind.city.names.en", "censys.city"],
    "latitude": ["maxmind.location.latitude", "censys.latitude"],
    "longitude": ["maxmind.location.longitude", "censys.longitude"],
    "timezone": [
        "maxmind.location.time_zone",
        "censys.timezone",
        "timezone.name",
        "geonames.timezoneId",
    ],
    # Where the block is registered, which is not where it is used. Kept
    # separate from country_code on purpose.
    "registered_country_code": ["maxmind.registered_country.iso_code"],
    # Network identity.
    "asn": ["censys.asn", "virustotal.asn", "shodan.asn"],
    "as_name": ["censys.as_name", "virustotal.as_owner"],
    "network": ["censys.bgp_prefix", "virustotal.network"],
    "isp": ["abuseipdb.isp"],
    "reverse_dns": ["network.reverse_dns"],
    # Registry.
    "abuse_email": ["rdap.abuse_email", "censys.whois_abuse_email"],
    "registry_handle": ["rdap.handle", "censys.whois_handle"],
    "allocated_at": ["rdap.registration", "censys.whois_created"],
    # Classification and reputation.
    "is_routable": ["network.is_routable"],
    "is_tor": ["abuseipdb.is_tor", "apivoid.anonymity.is_tor", "ranges.is_tor_exit"],
    "is_hosting": ["apivoid.anonymity.is_hosting", "ranges.is_cloud"],
    "hosting_provider": ["ranges.hosting_provider"],
    "is_cdn": ["ranges.is_cdn"],
    "is_search_bot": ["ranges.is_search_bot"],
    "bot_name": ["ranges.bot_name"],
    "abuse_score": ["abuseipdb.abuse_confidence_score"],
    "malicious_count": ["virustotal.malicious"],
}

# Set-valued fields. These join by union rather than by consensus: two scanners
# reporting different ports have not disagreed, they have each seen a subset.
SET_FIELDS: dict[str, list[str]] = {
    "ports": ["censys.ports", "shodan.ports"],
}

# (provider key, canonical field it must NOT feed) -> why.
#
# These are near-misses: fields close enough to something else that merging them
# is tempting, and wrong. A wrong merge is worse than no merge, because the
# resulting column looks authoritative while meaning two things. The pairing is
# explicit so a test can enforce it rather than a comment asking nicely.
SEPARATE_BY_DESIGN: dict[tuple[str, str], str] = {
    ("maxmind.registered_country.iso_code", "country_code"): (
        "Where the block is registered, not where the address is used. These "
        "differ routinely - a UK-geolocated address can be US-registered."
    ),
    ("censys.as_country_code", "country_code"): (
        "The autonomous system's country, not the address's. A US-run AS "
        "announces prefixes used worldwide."
    ),
    ("censys.whois_org_country", "country_code"): (
        "The registrant organization's country, not the address's."
    ),
    ("abuseipdb.isp", "as_name"): (
        "An ISP name is not an AS name; they coincide often enough to be "
        "misleading and differ often enough to matter."
    ),
    ("maxmind.registered_country.names.en", "country_name"): (
        "Same distinction as the ISO code above."
    ),
}


def _present(record: dict[str, Any], keys: list[str]) -> list[tuple[str, Any]]:
    """Return (source, value) for each key present with a usable value.

    Args:
        record: A record from ``query_ip``.
        keys: Provider keys feeding one canonical field.

    Returns:
        Pairs of provider name and value, skipping absent or empty values.
    """
    found = []
    for key in keys:
        value = record.get(key)
        if value is None or value == "":
            continue
        found.append((key.split(".", 1)[0], value))
    return found


def _consensus(values: list[Any]) -> tuple[Any, bool | None, list[Any]]:
    """Pick the modal value and describe how much the sources agreed.

    Args:
        values: The reported values, one per source.

    Returns:
        ``(value, agree, distinct)``. ``agree`` is None when fewer than two
        sources reported, since one source is not a consensus. ``distinct`` is
        populated only when sources disagreed.
    """
    # Values may be unhashable (lists); compare on their string form but return
    # the original object.
    counts = Counter(str(v) for v in values)
    winner_repr, _ = counts.most_common(1)[0]
    winner = next(v for v in values if str(v) == winner_repr)

    if len(values) < 2:
        return winner, None, []
    if len(counts) == 1:
        return winner, True, []

    seen: list[Any] = []
    for value in values:
        if str(value) not in {str(s) for s in seen}:
            seen.append(value)
    return winner, False, seen


def canonicalize(record: dict[str, Any]) -> dict[str, Any]:
    """Reduce a record's vendor-shaped fields to canonical columns.

    Args:
        record: A record as returned by ``query_ip``.

    Returns:
        Canonical fields, each accompanied by ``<field>.sources`` and, where
        more than one source reported, ``<field>.agree``. ``<field>.values``
        appears only when sources disagreed.

    Example:
        >>> canonicalize({"ip": "8.8.8.8", "censys.asn": 15169})["asn"]
        15169
    """
    out: dict[str, Any] = {}
    if "ip" in record:
        out["ip"] = record["ip"]

    for name, keys in CANONICAL.items():
        found = _present(record, keys)
        if not found:
            continue

        value, agree, distinct = _consensus([v for _, v in found])
        out[name] = value
        out[f"{name}.sources"] = "|".join(sorted({s for s, _ in found}))
        if agree is not None:
            out[f"{name}.agree"] = agree
        if distinct:
            out[f"{name}.values"] = "|".join(str(v) for v in distinct)

    for name, keys in SET_FIELDS.items():
        found = _present(record, keys)
        if not found:
            continue

        members: list[str] = []
        per_source = []
        for _source, value in found:
            parts = str(value).split("|") if value else []
            per_source.append(frozenset(parts))
            members.extend(p for p in parts if p and p not in members)

        out[name] = "|".join(sorted(members, key=_sort_key))
        out[f"{name}.sources"] = "|".join(sorted({s for s, _ in found}))
        if len(per_source) > 1:
            # For a set field, "agreement" means the sources saw the same set.
            out[f"{name}.agree"] = len(set(per_source)) == 1

    return out


def _sort_key(value: str) -> tuple[int, Any]:
    """Sort numerically when possible, so ports read 53|443|8080 not 443|53.

    Args:
        value: A set member.

    Returns:
        A sort key placing numeric values first, in numeric order.
    """
    return (0, int(value)) if value.isdigit() else (1, value)


def canonical_columns() -> list[str]:
    """Every column :func:`canonicalize` can produce, in registry order.

    Returns:
        Column names, suitable as a default CSV header.
    """
    columns = ["ip"]
    for name in list(CANONICAL) + list(SET_FIELDS):
        columns += [name, f"{name}.sources", f"{name}.agree", f"{name}.values"]
    return columns


def tidy(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Reshape records into one row per (address, field, source).

    The long form is what comparing sources actually wants, and what belongs in
    a paper's appendix: it makes "which sources disagreed, and how" a groupby
    rather than a manual reading of forty columns.

    Args:
        records: Records as returned by ``query_ip``.

    Returns:
        Rows of ``{ip, field, source, value}``.
    """
    rows = []
    for record in records:
        ip = record.get("ip")
        for name, keys in {**CANONICAL, **SET_FIELDS}.items():
            for source, value in _present(record, keys):
                rows.append({"ip": ip, "field": name, "source": source, "value": value})
    return rows
