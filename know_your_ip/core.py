#!/usr/bin/env python

"""Query IP address metadata and reputation from multiple services."""

from __future__ import annotations

import argparse
import ipaddress
import logging
import os
import re
import sys
import threading
from csv import DictWriter
from datetime import date, timedelta
from functools import partial
from multiprocessing.pool import ThreadPool
from pathlib import Path
from typing import Any

import maxminddb

from . import http
from .cache import Cache, config_fingerprint, default_cache_path
from .config import KnowYourIPConfig
from .config import load_config as load_modern_config
from .maxmind_db import download_all, find_database
from .ping import quiet_ping
from .providers import REGISTRY, Provider, build_default_registry
from .traceroute import os_traceroute

logger = logging.getLogger(__name__)

# Published free-tier allowances. The shared transport paces requests to
# these, so concurrency no longer means instant 429s.
RATE_LIMITS = {
    "virustotal": http.RateLimit(requests=4, per_seconds=60),
    "abuseipdb": http.RateLimit(requests=1000, per_seconds=86400),
    # Censys: a conservative guess, not a published figure. The Platform API
    # returns no rate-limit headers, and the free tier is metered as a monthly
    # credit quota (100/month) rather than a request rate.
    "censys": http.RateLimit(requests=1, per_seconds=2.5),
    "geonames": http.RateLimit(requests=1000, per_seconds=3600),
    "apivoid": http.RateLimit(requests=10, per_seconds=60),
}

# Official AbuseIPDB category codes.
# Source: https://docs.abuseipdb.com/ and https://www.abuseipdb.com/categories
ABUSEIPDB_CATEGORIES = {
    "1": "DNS Compromise",
    "2": "DNS Poisoning",
    "3": "Fraud Orders",
    "4": "DDoS Attack",
    "5": "FTP Brute-Force",
    "6": "Ping of Death",
    "7": "Phishing",
    "8": "Fraud VoIP",
    "9": "Open Proxy",
    "10": "Web Spam",
    "11": "Email Spam",
    "12": "Blog Spam",
    "13": "VPN IP",
    "14": "Port Scan",
    "15": "Hacking",
    "16": "SQL Injection",
    "17": "Spoofing",
    "18": "Brute Force",
    "19": "Bad Web Bot",
    "20": "Exploited Host",
    "21": "Web App Attack",
    "22": "SSH",
    "23": "IoT Targeted",
}


class InvalidIPError(ValueError):
    """Raised when a value is not a valid IP address."""


def setup_logger(verbose: bool = False, log_file: Path | None = None) -> None:
    """Configure logging for the command line interface.

    Only ``main()`` should call this. Library callers configure their own
    handlers; this package's modules log to ``logging.getLogger(__name__)``
    and never touch the root logger's configuration on import.

    Args:
        verbose: Emit DEBUG-level records instead of INFO.
        log_file: Append log records to this file in addition to stderr.
    """
    level = logging.DEBUG if verbose else logging.INFO
    root = logging.getLogger()
    root.setLevel(level)

    # Remove handlers this function added previously. main() may run more than
    # once in a process (tests, or an embedding caller), and without this each
    # run stacks another console and file handler, duplicating every record
    # and holding the old log file open.
    for existing in [h for h in root.handlers if getattr(h, "_kyip", False)]:
        root.removeHandler(existing)
        existing.close()

    console = logging.StreamHandler()
    console.setLevel(level)
    console.setFormatter(logging.Formatter("%(message)s"))
    console._kyip = True  # type: ignore[attr-defined]
    root.addHandler(console)

    if log_file is not None:
        handler = logging.FileHandler(log_file, mode="a", encoding="utf-8")
        handler.setLevel(level)
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s %(levelname)-8s %(name)s %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        handler._kyip = True  # type: ignore[attr-defined]
        root.addHandler(handler)

    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def validate_ip(ip: str) -> str:
    """Validate and normalize an IP address.

    Args:
        ip: Candidate IPv4 or IPv6 address.

    Returns:
        The normalized string form of the address.

    Raises:
        InvalidIPError: If ``ip`` is not a valid IP address.

    Example:
        >>> validate_ip(" 8.8.8.8 ")
        '8.8.8.8'
    """
    try:
        return str(ipaddress.ip_address(str(ip).strip()))
    except ValueError as exc:
        raise InvalidIPError(f"Not a valid IP address: {ip!r}") from exc


def flatten_dict(dd: Any, separator: str = "_", prefix: str = "") -> dict[str, Any]:
    """Flatten a nested dictionary into a single level.

    Args:
        dd: Value to flatten. Non-dict values are returned keyed by ``prefix``.
        separator: String joining nested key components.
        prefix: Prefix applied to every key.

    Returns:
        A flat dictionary.

    Example:
        >>> flatten_dict({"a": {"b": 1}}, separator=".")
        {'a.b': 1}
    """
    return (
        {
            prefix + separator + k if prefix else k: v
            for kk, vv in dd.items()
            for k, v in flatten_dict(vv, separator, kk).items()
        }
        if isinstance(dd, dict)
        else {prefix: dd}
    )


def clean_colname(name: str) -> str:
    """Normalize a string into a lowercase identifier-safe column name.

    Args:
        name: Raw column label.

    Returns:
        The cleaned column name.

    Example:
        >>> clean_colname("Test Column")
        'test_column'
    """
    c = re.sub(r"\W|^(?=\d)", "_", name)
    return (re.sub("_+", "_", c)).lower()


def select_columns(record: dict[str, Any], columns: list[str]) -> dict[str, Any]:
    """Restrict a record to a set of columns.

    ``query_ip`` returns every field it collected. Use this when you want only
    the subset named in ``config.output.columns``.

    Args:
        record: A record as returned by :func:`query_ip`.
        columns: Column names to keep.

    Returns:
        A new dict containing only keys present in both ``record`` and
        ``columns``.
    """
    wanted = set(columns)
    return {k: v for k, v in record.items() if k in wanted}


def load_config(config_file: str | Path | None = None) -> KnowYourIPConfig:
    """Load configuration from a TOML file and environment variables.

    Args:
        config_file: Path to a configuration file. If None, standard locations
            are searched.

    Returns:
        A validated configuration object.
    """
    if isinstance(config_file, str):
        config_file = Path(config_file)

    return load_modern_config(config_file)


_MAXMIND_READERS: dict[Path, Any] = {}
_MAXMIND_LOCK = threading.Lock()


def _maxmind_reader(db_file: Path) -> Any:
    """Return a cached MaxMind database reader for ``db_file``.

    The reader memory-maps the database, so opening one per lookup is wasteful.
    Readers are cached for the lifetime of the process.

    Args:
        db_file: Path to a ``.mmdb`` file.

    Returns:
        An open ``maxminddb`` reader.
    """
    reader = _MAXMIND_READERS.get(db_file)
    if reader is not None:
        return reader

    # Double-checked locking. Without it, concurrent first use opens the
    # database once per worker and keeps only the last - the others are
    # memory-mapped readers that are never closed.
    with _MAXMIND_LOCK:
        reader = _MAXMIND_READERS.get(db_file)
        if reader is None:
            reader = maxminddb.open_database(db_file)
            _MAXMIND_READERS[db_file] = reader
        return reader


def maxmind_geocode_ip(config: KnowYourIPConfig, ip: str) -> dict[str, Any]:
    """Look up an IP address in the MaxMind GeoLite2 City database.

    Args:
        config: Configuration object.
        ip: An IP address.

    Returns:
        Geolocation fields prefixed with ``maxmind.``. Empty if the address is
        absent from the database.

    Raises:
        FileNotFoundError: If ``GeoLite2-City.mmdb`` is not at the configured
            ``db_path``.

    Note:
        Reads the database directly with ``maxminddb``. The ``geoip2`` wrapper
        removed its ``raw`` attribute in 5.0 and pulls in ``aiohttp``;
        ``maxminddb.Reader.get()`` returns the same underlying record with no
        additional dependencies.

        A MaxMind account and license key are required to download GeoLite2;
        anonymous downloads ended in 2019.
    """
    ip = validate_ip(ip)
    # Falls back to a database fetched by `know_your_ip download-db`, so that
    # downloading then running needs no further configuration.
    db_file = find_database(config.maxmind.db_path)
    if not db_file.exists():
        raise FileNotFoundError(
            f"MaxMind database not found at {db_file}. Run "
            "'know_your_ip download-db --account-id ID --license-key KEY' "
            "(free account at https://www.maxmind.com/en/geolite2/signup), "
            "or set [maxmind] db_path to a directory containing "
            "GeoLite2-City.mmdb."
        )

    record = _maxmind_reader(db_file).get(ip)
    if record is None:
        logger.info("maxmind: %s not found in database", ip)
        return {}

    out = flatten_dict(record, separator=".")
    return {f"maxmind.{k}": v for k, v in out.items()}


def geonames_timezone(
    config: KnowYourIPConfig, lat: float, lng: float
) -> dict[str, Any]:
    """Get timezone information for a coordinate from GeoNames.

    Args:
        config: Configuration object.
        lat: Latitude.
        lng: Longitude.

    Returns:
        GeoNames fields prefixed with ``geonames.``.

    Note:
        Free tier is 10,000 credits/day and 1,000/hour per username.

    Example:
        >>> geonames_timezone(config, 32.0617, 118.7778)  # doctest: +SKIP
    """
    payload = {"lat": lat, "lng": lng, "username": config.geonames.username}

    result = http.request(
        "geonames",
        "GET",
        "https://secure.geonames.org/timezoneJSON",
        params=payload,
        rate_limit=RATE_LIMITS["geonames"],
    )
    if not result.ok:
        return {"geonames.error": result.error or f"HTTP {result.status_code}"}

    try:
        out = result.json()
    except ValueError as exc:
        return {"geonames.error": f"invalid JSON: {exc}"}

    # GeoNames reports quota and auth failures inside an HTTP 200 body.
    if "status" in out:
        message = out["status"].get("message")
        logger.error("geonames: %s", message)
        return {"geonames.error": message}

    return {f"geonames.{k}": v for k, v in out.items()}


_TIMEZONE_FINDER = None


def timezone_at(config: KnowYourIPConfig, lat: float, lng: float) -> str | None:
    """Get the timezone name for a coordinate, offline.

    Args:
        config: Configuration object.
        lat: Latitude.
        lng: Longitude.

    Returns:
        An IANA timezone name, or None if the coordinate maps to no timezone.

    Raises:
        ImportError: If the optional ``timezone`` extra is not installed.

    Note:
        Backed by ``timezonefinder``. The finder loads a polygon dataset on
        first use and is cached for the lifetime of the process.

        MaxMind's City database already reports ``location.time_zone``, so this
        is useful mainly as an independent cross-check.

    Example:
        >>> timezone_at(config, 32.0617, 118.7778)  # doctest: +SKIP
        'Asia/Shanghai'
    """
    global _TIMEZONE_FINDER
    if _TIMEZONE_FINDER is None:
        try:
            from timezonefinder import (  # pyright: ignore[reportMissingImports]
                TimezoneFinder,
            )
        except ImportError as exc:  # pragma: no cover - depends on extras
            raise ImportError(
                "Offline timezone lookup requires the optional dependency. "
                "Install it with: pip install 'know_your_ip[timezone]'"
            ) from exc

        _TIMEZONE_FINDER = TimezoneFinder()
    return _TIMEZONE_FINDER.timezone_at(lat=float(lat), lng=float(lng))


def _terminal_status(provider: str, status: int | None) -> dict[str, Any] | None:
    """Map a non-retryable HTTP status to a recorded outcome.

    Args:
        provider: Provider name, used to prefix the key.
        status: HTTP status code, if a response was received.

    Returns:
        A one-key result dict, or None if the status is not terminal.
    """
    match status:
        case 404:
            return {f"{provider}.status": "not_found"}
        case 429:
            logger.warning("%s: rate limit exceeded", provider)
            return {f"{provider}.status": "rate_limited"}
        case 401 | 403:
            logger.error("%s: authentication failed - check API key", provider)
            return {f"{provider}.status": "auth_failed"}
        case _:
            return None


def abuseipdb_api(config: KnowYourIPConfig, ip: str) -> dict[str, Any]:
    """Check an IP address against AbuseIPDB.

    Args:
        config: Configuration object holding the AbuseIPDB API key and lookback
            window.
        ip: An IP address.

    Returns:
        Abuse fields prefixed with ``abuseipdb.``.

    References:
        https://docs.abuseipdb.com/

    Example:
        >>> abuseipdb_api(config, "222.186.30.49")  # doctest: +SKIP
    """
    ip = validate_ip(ip)

    if not config.abuseipdb.api_key:
        logger.warning("AbuseIPDB API key not configured")
        return {}

    result = http.request(
        "abuseipdb",
        "GET",
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": config.abuseipdb.api_key, "Accept": "application/json"},
        params={
            "ipAddress": ip,
            "maxAgeInDays": config.abuseipdb.days,
            "verbose": "",
        },
        rate_limit=RATE_LIMITS["abuseipdb"],
    )

    if not result.ok:
        terminal = _terminal_status("abuseipdb", result.status_code)
        if terminal is not None:
            return terminal
        return {"abuseipdb.error": result.error or f"HTTP {result.status_code}"}

    data = result.json().get("data", {})
    return {
        "abuseipdb.abuse_confidence_score": data.get("abuseConfidenceScore", 0),
        "abuseipdb.country_code": data.get("countryCode"),
        "abuseipdb.usage_type": data.get("usageType"),
        "abuseipdb.isp": data.get("isp"),
        "abuseipdb.domain": data.get("domain"),
        "abuseipdb.is_public": data.get("isPublic"),
        "abuseipdb.is_whitelisted": data.get("isWhitelisted"),
        "abuseipdb.is_tor": data.get("isTor"),
        "abuseipdb.total_reports": data.get("totalReports", 0),
        "abuseipdb.num_distinct_users": data.get("numDistinctUsers", 0),
        "abuseipdb.last_reported_at": data.get("lastReportedAt"),
        "abuseipdb.categories": _abuseipdb_categories(data),
    }


def _abuseipdb_categories(data: dict[str, Any]) -> str:
    """Map AbuseIPDB numeric category ids to their names.

    Categories appear per-report in the verbose response, so they are collected
    across all reports and de-duplicated.

    Args:
        data: The ``data`` object from an AbuseIPDB check response.

    Returns:
        Pipe-separated category names, or an empty string.
    """
    ids: set[str] = set()
    for report in data.get("reports") or []:
        for cat_id in report.get("categories") or []:
            ids.add(str(cat_id))
    for cat_id in data.get("categories") or []:
        ids.add(str(cat_id))

    names = [
        ABUSEIPDB_CATEGORIES[c]
        for c in sorted(ids, key=int)
        if c in ABUSEIPDB_CATEGORIES
    ]
    return "|".join(names)


def apivoid_api(config: KnowYourIPConfig, ip: str) -> dict[str, Any]:
    """Get IP reputation data from APIVoid.

    Args:
        config: Configuration object holding the APIVoid API key.
        ip: An IP address.

    Returns:
        Reputation fields prefixed with ``apivoid.``.

    Note:
        Uses APIVoid API v2. The v1 endpoint reached its announced end of life
        in February 2026. v2 is a POST with an ``X-API-Key`` header and returns
        the report at the top level rather than under ``data.report``.

        There is no permanent free tier - only a 30-day trial.

    References:
        https://www.apivoid.com/api/ip-reputation/
    """
    ip = validate_ip(ip)

    if not config.apivoid.api_key:
        logger.warning("APIVoid API key not configured")
        return {}

    result = http.request(
        "apivoid",
        "POST",
        "https://api.apivoid.com/v2/ip-reputation",
        headers={
            "X-API-Key": config.apivoid.api_key,
            "Content-Type": "application/json",
        },
        json={"ip": ip},
        rate_limit=RATE_LIMITS["apivoid"],
    )

    if not result.ok:
        terminal = _terminal_status("apivoid", result.status_code)
        if terminal is not None:
            return terminal
        return {"apivoid.error": result.error or f"HTTP {result.status_code}"}

    try:
        out = result.json()
    except ValueError as exc:
        return {"apivoid.error": f"invalid JSON: {exc}"}

    if "error" in out:
        logger.error("apivoid: %s", out["error"])
        return {"apivoid.error": out["error"]}

    data: dict[str, Any] = {}
    for k, v in flatten_dict(out, separator=".").items():
        data[f"apivoid.{k}"] = "|".join(str(i) for i in v) if isinstance(v, list) else v
    return data


def censys_api(config: KnowYourIPConfig, ip: str) -> dict[str, Any]:
    """Get host data from the Censys Platform API.

    Args:
        config: Configuration object holding the Censys base URL and API key.
        ip: An IP address.

    Returns:
        Host fields prefixed with ``censys.``.

    Note:
        Legacy Search (``search.censys.io``) was disabled for free accounts in
        March 2025 and is deprecated entirely in September 2026. Authentication
        is a Personal Access Token. ``organization_id`` is optional and should
        be omitted on the free tier, which allows 100 credits/month.

    References:
        https://docs.censys.com/docs/platform-api-transition-guide
    """
    ip = validate_ip(ip)

    if not config.censys.api_key:
        logger.warning("Censys API key not configured")
        return {}

    params = {}
    if config.censys.organization_id:
        params["organization_id"] = config.censys.organization_id

    result = http.request(
        "censys",
        "GET",
        f"{config.censys.api_url.rstrip('/')}/v3/global/asset/host/{ip}",
        headers={
            "Authorization": f"Bearer {config.censys.api_key}",
            "Accept": "application/vnd.censys.api.v3.host.v1+json",
        },
        params=params,
        rate_limit=RATE_LIMITS["censys"],
    )

    if not result.ok:
        terminal = _terminal_status("censys", result.status_code)
        if terminal is not None:
            return terminal
        return {"censys.error": result.error or f"HTTP {result.status_code}"}

    # The Platform API nests the host under result.resource.
    return _parse_censys(result.json().get("result", {}).get("resource", {}))


def _parse_censys(resource: dict[str, Any]) -> dict[str, Any]:
    """Reduce a Censys host resource to a flat set of fields.

    One host response is around 30 KB across seven top-level sections. This
    keeps the parts that describe the address and deliberately drops the bulky
    ones: ``dns.names`` alone runs to a hundred hostnames and ``dns.forward_dns``
    to several thousand, either of which would swamp a CSV row. Counts are kept
    instead.

    Args:
        resource: The ``result.resource`` object from a host response.

    Returns:
        Fields prefixed with ``censys.``.
    """
    asn = resource.get("autonomous_system") or {}
    loc = resource.get("location") or {}
    coords = loc.get("coordinates") or {}
    services = resource.get("services") or []
    whois = resource.get("whois") or {}
    whois_net = whois.get("network") or {}
    whois_org = whois.get("organization") or {}

    data: dict[str, Any] = {
        "censys.ip": resource.get("ip"),
        # Autonomous system, including the announced prefix - routing data at
        # no extra request.
        "censys.asn": asn.get("asn"),
        "censys.as_name": asn.get("name"),
        "censys.as_description": asn.get("description"),
        "censys.as_country_code": asn.get("country_code"),
        "censys.bgp_prefix": asn.get("bgp_prefix"),
        # A second, independent geolocation. Comparing it against MaxMind is
        # what makes cross-source disagreement visible.
        "censys.country": loc.get("country"),
        "censys.country_code": loc.get("country_code"),
        "censys.continent": loc.get("continent"),
        "censys.city": loc.get("city"),
        "censys.province": loc.get("province"),
        "censys.postal_code": loc.get("postal_code"),
        "censys.timezone": loc.get("timezone"),
        "censys.latitude": coords.get("latitude"),
        "censys.longitude": coords.get("longitude"),
        # Registry data, which cross-checks the rdap provider rather than
        # duplicating it.
        "censys.whois_handle": whois_net.get("handle"),
        "censys.whois_name": whois_net.get("name"),
        "censys.whois_cidrs": "|".join(whois_net.get("cidrs") or []),
        "censys.whois_allocation_type": whois_net.get("allocation_type"),
        "censys.whois_created": whois_net.get("created"),
        "censys.whois_updated": whois_net.get("updated"),
        "censys.whois_org_name": whois_org.get("name"),
        "censys.whois_org_country": whois_org.get("country"),
        "censys.whois_abuse_email": _first_contact_email(
            whois_org.get("abuse_contacts")
        ),
        "censys.service_count": resource.get("service_count"),
        "censys.dns_name_count": len((resource.get("dns") or {}).get("names") or []),
    }

    # Ports, and the two distinct protocol notions the API reports: the
    # application protocol (DNS, HTTP) and the transport (tcp, udp, quic).
    # Transport values are lowercase.
    # Deduplicated and numerically sorted: a host commonly exposes the same
    # port over more than one transport (443 over both TCP and QUIC), and a
    # column reading "443|443" is noise. service_count keeps the raw total.
    data["censys.ports"] = "|".join(
        str(p)
        for p in sorted({s["port"] for s in services if s.get("port") is not None})
    )
    data["censys.transport_protocols"] = "|".join(
        sorted(
            {s["transport_protocol"] for s in services if s.get("transport_protocol")}
        )
    )
    data["censys.services"] = "|".join(
        sorted({s["protocol"] for s in services if s.get("protocol")})
    )

    # When Censys last observed this host, which is the provenance stamp for
    # everything in the services block.
    scan_times = sorted(s["scan_time"] for s in services if s.get("scan_time"))
    if scan_times:
        data["censys.last_scan_time"] = scan_times[-1]

    return data


def _first_contact_email(contacts: list[dict[str, Any]] | None) -> str | None:
    """Return the first email address from an RDAP-style contact list.

    Args:
        contacts: A ``whois.organization.*_contacts`` array, or None.

    Returns:
        The first email found, or None.
    """
    for contact in contacts or []:
        if email := contact.get("email"):
            return str(email)
    return None


def shodan_api(config: KnowYourIPConfig, ip: str) -> dict[str, Any]:
    """Get host data from Shodan.

    Args:
        config: Configuration object holding the Shodan API key.
        ip: An IP address.

    Returns:
        Host fields prefixed with ``shodan.``.

    Raises:
        ImportError: If the optional ``shodan`` extra is not installed.

    Note:
        IP lookups require a paid membership; free API keys cannot call the
        host endpoint.
    """
    ip = validate_ip(ip)
    try:
        import shodan  # pyright: ignore[reportMissingImports]
    except ImportError as exc:  # pragma: no cover - depends on install extras
        raise ImportError(
            "Shodan support requires the optional dependency. "
            "Install it with: pip install 'know_your_ip[shodan]'"
        ) from exc

    if not config.shodan.api_key:
        logger.warning("Shodan API key not configured")
        return {}

    api = shodan.Shodan(config.shodan.api_key)
    try:
        out = flatten_dict(api.host(ip), separator=".")
    except shodan.APIError as exc:
        logger.warning("shodan(%s): %s", ip, exc)
        return {"shodan.error": str(exc)}

    return {
        f"shodan.{k}": "|".join(str(i) for i in v) if isinstance(v, list) else v
        for k, v in out.items()
    }


def virustotal_api(config: KnowYourIPConfig, ip: str) -> dict[str, Any]:
    """Get an IP address report from VirusTotal API v3.

    Args:
        config: Configuration object holding the VirusTotal API key.
        ip: An IP address.

    Returns:
        Fields prefixed with ``virustotal.``, including analysis counts,
        reputation, network metadata, and vote totals.

    Note:
        Public API limits are 500 requests/day and 4 requests/minute.

        VirusTotal does not return a ``categories`` attribute for IP address
        objects; ``categories`` exists only on domain and URL objects.

    References:
        https://docs.virustotal.com/reference/ip-info

    Example:
        >>> virustotal_api(config, "8.8.8.8")  # doctest: +SKIP
    """
    ip = validate_ip(ip)

    if not config.virustotal.api_key:
        logger.warning("VirusTotal API key not configured")
        return {}

    result = http.request(
        "virustotal",
        "GET",
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers={"x-apikey": config.virustotal.api_key},
        rate_limit=RATE_LIMITS["virustotal"],
    )

    if not result.ok:
        terminal = _terminal_status("virustotal", result.status_code)
        if terminal is not None:
            return terminal
        return {"virustotal.error": result.error or f"HTTP {result.status_code}"}

    attributes = result.json().get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats") or {}
    votes = attributes.get("total_votes") or {}

    return {
        "virustotal.harmless": stats.get("harmless", 0),
        "virustotal.malicious": stats.get("malicious", 0),
        "virustotal.suspicious": stats.get("suspicious", 0),
        "virustotal.undetected": stats.get("undetected", 0),
        "virustotal.timeout": stats.get("timeout", 0),
        "virustotal.asn": attributes.get("asn"),
        "virustotal.as_owner": attributes.get("as_owner"),
        "virustotal.country": attributes.get("country"),
        "virustotal.continent": attributes.get("continent"),
        "virustotal.network": attributes.get("network"),
        "virustotal.rir": attributes.get("regional_internet_registry"),
        "virustotal.reputation": attributes.get("reputation", 0),
        "virustotal.jarm": attributes.get("jarm"),
        "virustotal.last_analysis_date": attributes.get("last_analysis_date"),
        "virustotal.whois_date": attributes.get("whois_date"),
        "virustotal.votes_harmless": votes.get("harmless", 0),
        "virustotal.votes_malicious": votes.get("malicious", 0),
        "virustotal.tags": "|".join(str(t) for t in attributes.get("tags") or []),
    }


def ping(config: KnowYourIPConfig, ip: str) -> dict[str, Any]:
    """Measure round-trip time to an IP address.

    Args:
        config: Configuration object holding ping count and timeout.
        ip: An IP address.

    Returns:
        Fields prefixed with ``ping.``. Timing keys are absent if the host did
        not respond.
    """
    ip = validate_ip(ip)
    data: dict[str, Any] = {
        "ping.count": config.ping.count,
        "ping.timeout": config.ping.timeout,
    }
    stat = quiet_ping(
        ip,
        timeout=config.ping.timeout,
        count=config.ping.count,
        ipv6=ipaddress.ip_address(ip).version == 6,
    )
    if stat:
        data["ping.max"] = stat[0]
        data["ping.min"] = stat[1]
        data["ping.avg"] = stat[2]
        data["ping.percent_loss"] = stat[3] * 100
    return data


def traceroute(config: KnowYourIPConfig, ip: str) -> dict[str, Any]:
    """Trace the network path to an IP address.

    Args:
        config: Configuration object holding the hop limit.
        ip: An IP address.

    Returns:
        Fields prefixed with ``traceroute.``.
    """
    ip = validate_ip(ip)
    return {
        "traceroute.max_hops": config.traceroute.max_hops,
        "traceroute.hops": os_traceroute(ip, max_hops=config.traceroute.max_hops),
    }


def _provider_config_values(config: KnowYourIPConfig, section: str) -> dict[str, Any]:
    """Extract the settings that affect a provider's answer.

    Secrets are excluded: they do not change the result, and the fingerprint is
    written to disk.

    Args:
        config: Configuration object.
        section: Attribute name of the provider's config section.

    Returns:
        A dict of the influencing settings.
    """
    model = getattr(config, section, None)
    if model is None:
        return {}
    secret_fields = {"api_key", "username", "organization_id"}
    return {
        name: value
        for name, value in model.model_dump().items()
        if name not in secret_fields and name != "enabled"
    }


def query_ip(
    config: KnowYourIPConfig,
    ip: str,
    *,
    providers: list[str] | None = None,
    as_of: date | None = None,
    cache: Cache | None = None,
    max_age: timedelta | None = None,
) -> dict[str, Any]:
    """Collect data on an IP address from every selected provider.

    Each provider is isolated: a failure in one is recorded under
    ``<provider>.error`` without preventing the others from running.

    Args:
        config: Configuration object.
        ip: An IP address.
        providers: Provider names to run. Defaults to those enabled in
            ``config``.
        as_of: Ask what was true on this date. Providers without historical
            support are skipped rather than answering with present-day data.
        cache: Cache to read from and append to, if any.
        max_age: How stale a cached observation may be before it is refetched.

    Returns:
        Every field collected, keyed by ``<provider>.<field>``. Use
        :func:`select_columns` to restrict the result to a chosen subset.

    Example:
        >>> query_ip(config, "8.8.8.8")  # doctest: +SKIP
        {'ip': '8.8.8.8', 'maxmind.country.names.en': 'United States', ...}
    """
    try:
        ip = validate_ip(ip)
    except InvalidIPError as e:
        logger.error("%s", e)
        return {"ip": ip, "error": str(e)}

    data: dict[str, Any] = {"ip": ip}
    selected = REGISTRY.for_as_of(REGISTRY.selected(config, providers), as_of)

    # Coordinate-based providers need a geolocation first, so they run in a
    # second pass once the geolocating providers have contributed.
    coordinate_providers = [p for p in selected if p.needs_coordinates]
    address_providers = [p for p in selected if not p.needs_coordinates]

    for provider in address_providers:
        _run_provider(provider, config, ip, data, as_of, cache, max_age, (ip,))

    lat = data.get("maxmind.location.latitude")
    lng = data.get("maxmind.location.longitude")

    if lat is not None and lng is not None:
        for provider in coordinate_providers:
            _run_provider(provider, config, ip, data, as_of, cache, max_age, (lat, lng))
        if config.timezone.enabled:
            try:
                data["timezone.name"] = timezone_at(config, lat, lng)
            except Exception as e:
                _report_provider_failure("timezone", ip, str(e))
                data["timezone.error"] = str(e)
    elif coordinate_providers or config.timezone.enabled:
        logger.info(
            "coordinate lookups skipped for %s: no latitude/longitude "
            "(enable [maxmind] to supply them)",
            ip,
        )

    return data


class _FailureTally:
    """Counts identical provider failures so they are logged once, not per address.

    A misconfiguration - a missing MaxMind database, an invalid key - fails the
    same way for every address in a batch. Logging it per address turns a
    10,000-row job into 10,000 identical lines and buries anything else. The
    per-record ``<provider>.error`` field is unaffected: only the logging is
    collapsed, never the data.
    """

    def __init__(self) -> None:
        """Start with no failures recorded."""
        self._counts: dict[tuple[str, str], int] = {}
        self._lock = threading.Lock()

    def record(self, provider: str, message: str) -> bool:
        """Record a failure and say whether it is the first of its kind.

        Args:
            provider: Provider name.
            message: The error text.

        Returns:
            True if this is the first occurrence, so the caller should log it
            prominently.
        """
        key = (provider, message)
        with self._lock:
            first = key not in self._counts
            self._counts[key] = self._counts.get(key, 0) + 1
        return first

    def summary(self) -> list[str]:
        """Describe repeated failures, one line per distinct failure.

        Returns:
            Human-readable lines, empty if nothing failed more than once.
        """
        return [
            f"{provider}: {count} addresses failed - {message}"
            for (provider, message), count in sorted(self._counts.items())
            if count > 1
        ]

    def reset(self) -> None:
        """Forget every recorded failure."""
        with self._lock:
            self._counts.clear()


FAILURES = _FailureTally()


def _report_provider_failure(provider: str, ip: str, message: str) -> None:
    """Log a provider failure, in full the first time and quietly after.

    Args:
        provider: Provider name.
        ip: The address being queried.
        message: The error text.
    """
    if FAILURES.record(provider, message):
        logger.warning("%s(%s): %s", provider, ip, message)
    else:
        logger.debug("%s(%s): %s", provider, ip, message)


def _run_provider(
    provider: Provider,
    config: KnowYourIPConfig,
    ip: str,
    data: dict[str, Any],
    as_of: date | None,
    cache: Cache | None,
    max_age: timedelta | None,
    args: tuple[Any, ...],
) -> None:
    """Run one provider, serving from cache when possible.

    Failures are recorded in ``data`` rather than raised, so one unhealthy
    service cannot abort a batch.

    Args:
        provider: The provider to run.
        config: Configuration object.
        ip: The address being queried, used for cache keys and logging.
        data: Result dict, updated in place.
        as_of: Historical date, or None.
        cache: Cache to consult and append to, if any.
        max_age: Staleness tolerance for cached rows.
        args: Positional arguments after ``config`` for the fetch call.
    """
    fingerprint = ""
    if cache is not None:
        fingerprint = config_fingerprint(
            _provider_config_values(config, provider.section)
        )
        cached = cache.get(ip, provider.name, fingerprint, max_age)
        if cached is not None:
            data.update(cached)
            data[f"{provider.name}.from_cache"] = True
            return

    try:
        result = (
            provider.fetch(config, *args, as_of=as_of)
            if provider.supports_as_of
            else provider.fetch(config, *args)
        )
    except Exception as e:  # one bad provider must not stop the rest
        _report_provider_failure(provider.name, ip, str(e))
        data[f"{provider.name}.error"] = str(e)
        return

    data.update(result)
    if cache is not None:
        cache.put(
            ip,
            provider.name,
            fingerprint,
            result,
            as_of.isoformat() if as_of else None,
        )


def read_ip_file(path: Path) -> list[str]:
    """Read IP addresses from a text or single-column CSV file.

    Blank lines and lines beginning with ``#`` are ignored.

    Args:
        path: File to read.

    Returns:
        The addresses found, in file order.
    """
    lines = path.read_text(encoding="utf-8").splitlines()
    return [
        stripped
        for line in lines
        if (stripped := line.strip()) and not stripped.startswith("#")
    ]


def _download_databases(parser: argparse.ArgumentParser, args: Any) -> int:
    """Fetch the MaxMind databases into the user cache directory.

    Args:
        parser: The argument parser, used to report usage errors.
        args: Parsed arguments carrying the MaxMind credentials.

    Returns:
        Process exit status.
    """
    account_id = args.account_id or os.environ.get("MAXMIND_ACCOUNT_ID")
    license_key = args.license_key or os.environ.get("MAXMIND_LICENSE_KEY")

    if not account_id or not license_key:
        parser.error(
            "download-db needs --account-id and --license-key (or the "
            "MAXMIND_ACCOUNT_ID and MAXMIND_LICENSE_KEY environment "
            "variables). Both come free from "
            "https://www.maxmind.com/en/geolite2/signup"
        )

    written = download_all(account_id, license_key)
    if not written:
        logger.error("No databases were downloaded")
        return 1

    for path in written:
        sys.stdout.write(f"{path}\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Entry point for the ``know_your_ip`` command.

    Args:
        argv: Argument list. Defaults to ``sys.argv[1:]``.

    Returns:
        Process exit status.
    """
    parser = argparse.ArgumentParser(
        prog="know_your_ip",
        description="Know Your IP - comprehensive IP address analysis",
    )
    parser.add_argument(
        "ip",
        nargs="*",
        help="IP address(es) to analyze, or the literal 'download-db' to fetch "
        "the MaxMind databases",
    )
    parser.add_argument("-f", "--file", help="File listing IP addresses")
    parser.add_argument("-c", "--config", help="Configuration file (TOML format)")
    parser.add_argument("-o", "--output", default="output.csv", help="Output CSV file")
    parser.add_argument(
        "-n", "--max-conn", type=int, default=5, help="Max concurrent requests"
    )
    parser.add_argument("--from", default=0, type=int, dest="from_row", help="From row")
    parser.add_argument("--to", default=0, type=int, help="To row (0 means all)")
    parser.add_argument(
        "--shape",
        choices=["canonical", "raw", "tidy"],
        default="canonical",
        help="Output shape: canonical joins each variable into one column "
        "(default); raw keeps every vendor-shaped field; tidy is long form",
    )
    parser.add_argument(
        "--all-columns",
        action="store_true",
        help="Deprecated alias for --shape raw",
    )
    parser.add_argument(
        "--providers",
        help="Comma-separated provider names to run, overriding [*] enabled flags",
    )
    parser.add_argument(
        "--as-of",
        help="Ask what was true on this date (YYYY-MM-DD). Providers without "
        "historical support are skipped rather than answering with current data",
    )
    parser.add_argument(
        "--cache",
        nargs="?",
        const="",
        metavar="PATH",
        help="Cache results in SQLite; omit PATH for the default location",
    )
    parser.add_argument(
        "--max-age",
        type=int,
        metavar="HOURS",
        help="Refetch cached entries older than this many hours",
    )
    parser.add_argument(
        "--account-id",
        help="MaxMind account ID, for download-db",
    )
    parser.add_argument(
        "--license-key",
        help="MaxMind license key, for download-db. GeoLite2 allows 30 "
        "downloads per 24 hours",
    )
    parser.add_argument(
        "--list-providers",
        action="store_true",
        help="List registered providers and exit",
    )
    parser.add_argument("--log-file", help="Also write logs to this file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode")
    parser.add_argument(
        "--no-header",
        dest="header",
        action="store_false",
        help="Omit the CSV header row",
    )
    parser.set_defaults(header=True)

    args = parser.parse_args(argv)
    setup_logger(args.verbose, Path(args.log_file) if args.log_file else None)

    if args.ip and args.ip[0] == "download-db":
        return _download_databases(parser, args)

    if args.list_providers:
        for provider in REGISTRY.providers:
            key = "key required" if provider.requires_key else "no key"
            history = "as-of" if provider.supports_as_of else "current only"
            # Program output, not logging: it belongs on stdout so it can be
            # piped, and must not be suppressed by the log level.
            sys.stdout.write(
                f"{provider.name:<12} {provider.cost:<9} {key:<13} {history}\n"
            )
        return 0

    if args.file is None and not args.ip:
        parser.error("at least one IP address or --file is required")

    config = load_config(args.config)

    provider_names = (
        [n.strip() for n in args.providers.split(",")] if args.providers else None
    )
    if provider_names:
        try:
            REGISTRY.selected(config, provider_names)
        except KeyError as exc:
            parser.error(str(exc))

    as_of = None
    if args.as_of:
        try:
            as_of = date.fromisoformat(args.as_of)
        except ValueError:
            parser.error(f"--as-of must be YYYY-MM-DD, got {args.as_of!r}")

    raw_ips = list(args.ip)
    if args.file:
        raw_ips.extend(read_ip_file(Path(args.file)))

    ips: list[str] = []
    for candidate in raw_ips:
        try:
            ips.append(validate_ip(candidate))
        except InvalidIPError as e:
            logger.error("Skipping: %s", e)

    if not ips:
        logger.error("No valid IP addresses to process")
        return 1

    end = args.to if args.to else len(ips)
    ips = ips[args.from_row : end]
    if not ips:
        logger.error("Row range --from/--to selected no addresses")
        return 1

    if args.max_conn < 1:
        parser.error("--max-conn must be at least 1")

    logger.info("Processing %d address(es)", len(ips))

    cache = None
    if args.cache is not None:
        cache_path = Path(args.cache) if args.cache else default_cache_path()
        cache = Cache(cache_path)
        logger.info("Caching results in %s", cache_path)

    max_age = timedelta(hours=args.max_age) if args.max_age is not None else None
    query = partial(
        query_ip,
        config,
        providers=provider_names,
        as_of=as_of,
        cache=cache,
        max_age=max_age,
    )

    try:
        return _write_results(args, ips, query)
    finally:
        if cache is not None:
            cache.close()


def _union_columns(rows: list[dict[str, Any]]) -> list[str]:
    """Every key across rows, in first-seen order.

    Args:
        rows: Records that may not share a shape.

    Returns:
        Ordered column names.
    """
    seen: dict[str, None] = {}
    for row in rows:
        seen.update(dict.fromkeys(row))
    return list(seen)


def _write_results(args: argparse.Namespace, ips: list[str], query: Any) -> int:
    """Run the query over every address and write the CSV.

    Args:
        args: Parsed command line arguments.
        ips: Validated addresses to process.
        query: Callable taking an address and returning a record.

    Returns:
        Process exit status.
    """
    from .enrich import EnrichResult

    shape = "raw" if args.all_columns else args.shape

    records: list[dict[str, Any]] = []
    with ThreadPool(processes=args.max_conn) as pool:
        try:
            for i, record in enumerate(pool.imap(query, ips), start=1):
                records.append(record)
                if i % 100 == 0:
                    logger.info("Processed %d/%d", i, len(ips))
        except KeyboardInterrupt:
            logger.warning("Interrupted; writing partial results to %s", args.output)
            pool.terminate()
            EnrichResult(records=records).to_csv(args.output, shape=shape)
            return 130

    # Written through EnrichResult so the command line and the library cannot
    # produce different tables from the same input.
    result = EnrichResult(records=records)
    rows = {
        "canonical": result.canonical,
        "raw": result.records,
        "tidy": result.tidy(),
    }[shape]
    with open(args.output, "w", newline="", encoding="utf-8") as fh:
        writer = DictWriter(fh, fieldnames=_union_columns(rows), extrasaction="ignore")
        if args.header:
            writer.writeheader()
        writer.writerows(rows)

    for line in FAILURES.summary():
        logger.warning("%s", line)
    logger.info("Wrote %s", args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())


# Registration happens at import so the registry is populated for any caller.
build_default_registry()
