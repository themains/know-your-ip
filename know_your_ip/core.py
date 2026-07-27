#!/usr/bin/env python

"""Query IP address metadata and reputation from multiple services."""

from __future__ import annotations

import argparse
import ipaddress
import logging
import re
import sys
import time
from csv import DictWriter
from functools import partial
from multiprocessing.pool import ThreadPool
from pathlib import Path
from typing import Any

import maxminddb
import requests

from .config import KnowYourIPConfig
from .config import load_config as load_modern_config
from .ping import quiet_ping
from .traceroute import os_traceroute

logger = logging.getLogger(__name__)

MAX_RETRIES = 5

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

    console = logging.StreamHandler()
    console.setLevel(level)
    console.setFormatter(logging.Formatter("%(message)s"))
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
    db_file = config.maxmind.db_path / "GeoLite2-City.mmdb"
    if not db_file.exists():
        raise FileNotFoundError(
            f"MaxMind database not found at {db_file}. Download GeoLite2-City "
            "from https://www.maxmind.com/en/accounts/current/geoip/downloads "
            "and set [maxmind] db_path in your configuration."
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
    data: dict[str, Any] = {}
    payload = {"lat": lat, "lng": lng, "username": config.geonames.username}

    for attempt in range(MAX_RETRIES):
        try:
            r = requests.get(
                "https://secure.geonames.org/timezoneJSON", params=payload, timeout=30
            )
        except requests.RequestException as e:
            logger.warning("geonames_timezone: %s", e)
            _backoff(attempt)
            continue

        if r.status_code == 200:
            try:
                out = r.json()
            except ValueError as e:
                logger.warning("geonames_timezone: bad JSON: %s", e)
                _backoff(attempt)
                continue
            # GeoNames signals quota and auth errors inside a 200 response.
            if "status" in out:
                logger.error("geonames_timezone: %s", out["status"].get("message"))
                return {"geonames.error": out["status"].get("message")}
            return {f"geonames.{k}": v for k, v in out.items()}

        logger.warning("geonames_timezone: HTTP %s", r.status_code)
        _backoff(attempt)

    return data


def _backoff(attempt: int) -> None:
    """Sleep for an exponentially increasing interval.

    Args:
        attempt: Zero-based attempt number.
    """
    time.sleep(min(2**attempt, 30))


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
            from timezonefinder import TimezoneFinder
        except ImportError as exc:  # pragma: no cover - depends on extras
            raise ImportError(
                "Offline timezone lookup requires the optional dependency. "
                "Install it with: pip install 'know_your_ip[timezone]'"
            ) from exc

        _TIMEZONE_FINDER = TimezoneFinder()
    return _TIMEZONE_FINDER.timezone_at(lat=float(lat), lng=float(lng))


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
    out: dict[str, Any] = {}

    if not config.abuseipdb.api_key:
        logger.warning("AbuseIPDB API key not configured")
        return out

    headers = {"Key": config.abuseipdb.api_key, "Accept": "application/json"}
    params = {
        "ipAddress": ip,
        "maxAgeInDays": config.abuseipdb.days,
        "verbose": "",
    }

    for attempt in range(MAX_RETRIES):
        try:
            r = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers=headers,
                params=params,
                timeout=30,
            )
        except requests.RequestException as e:
            logger.warning("abuseipdb_api: %s", e)
            _backoff(attempt)
            continue

        match r.status_code:
            case 200:
                data = r.json().get("data", {})
                out["abuseipdb.abuse_confidence_score"] = data.get(
                    "abuseConfidenceScore", 0
                )
                out["abuseipdb.country_code"] = data.get("countryCode")
                out["abuseipdb.usage_type"] = data.get("usageType")
                out["abuseipdb.isp"] = data.get("isp")
                out["abuseipdb.domain"] = data.get("domain")
                out["abuseipdb.is_public"] = data.get("isPublic")
                out["abuseipdb.is_whitelisted"] = data.get("isWhitelisted")
                out["abuseipdb.is_tor"] = data.get("isTor")
                out["abuseipdb.total_reports"] = data.get("totalReports", 0)
                out["abuseipdb.num_distinct_users"] = data.get("numDistinctUsers", 0)
                out["abuseipdb.last_reported_at"] = data.get("lastReportedAt")
                out["abuseipdb.categories"] = _abuseipdb_categories(data)
                return out
            case 429:
                logger.warning("AbuseIPDB rate limit exceeded")
                return {"abuseipdb.status": "rate_limited"}
            case 401 | 403:
                logger.error("AbuseIPDB authentication failed - check API key")
                return {"abuseipdb.status": "auth_failed"}
            case _:
                logger.warning("AbuseIPDB returned HTTP %s", r.status_code)
                _backoff(attempt)

    return out


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
        Uses APIVoid API v2. The v1 endpoint
        (``endpoint.apivoid.com/iprep/v1/``) reached its announced end of life
        in February 2026. v2 is a POST with an ``X-API-Key`` header and returns
        the report at the top level rather than under ``data.report``.

        There is no permanent free tier - only a 30-day trial.

    References:
        https://www.apivoid.com/api/ip-reputation/
    """
    ip = validate_ip(ip)
    data: dict[str, Any] = {}

    if not config.apivoid.api_key:
        logger.warning("APIVoid API key not configured")
        return data

    url = "https://api.apivoid.com/v2/ip-reputation"
    headers = {
        "X-API-Key": config.apivoid.api_key,
        "Content-Type": "application/json",
    }

    for attempt in range(MAX_RETRIES):
        try:
            r = requests.post(url, headers=headers, json={"ip": ip}, timeout=30)
        except requests.RequestException as e:
            logger.warning("apivoid_api: %s", e)
            _backoff(attempt)
            continue

        if r.status_code == 200:
            try:
                out = r.json()
            except ValueError as e:
                logger.warning("apivoid_api: bad JSON: %s", e)
                _backoff(attempt)
                continue

            if "error" in out:
                logger.error("apivoid_api: %s", out["error"])
                return {"apivoid.error": out["error"]}

            for k, v in flatten_dict(out, separator=".").items():
                data[f"apivoid.{k}"] = (
                    "|".join(str(i) for i in v) if isinstance(v, list) else v
                )
            return data

        logger.warning("apivoid_api: HTTP %s", r.status_code)
        _backoff(attempt)

    return data


def censys_api(config: KnowYourIPConfig, ip: str) -> dict[str, Any]:
    """Get host data from the Censys API.

    Args:
        config: Configuration object holding the Censys base URL and API key.
        ip: An IP address.

    Returns:
        Host fields prefixed with ``censys.``.

    Note:
        Targets the Censys Platform API. Legacy Search (``search.censys.io``)
        was disabled for free accounts in March 2025 and is deprecated
        entirely in September 2026. Authentication is a Personal Access Token.
        ``organization_id`` is optional and should be omitted on the free tier.

        The free tier is 100 credits/month.

    References:
        https://docs.censys.com/docs/platform-api-transition-guide
    """
    ip = validate_ip(ip)
    data: dict[str, Any] = {}

    if not config.censys.api_key:
        logger.warning("Censys API key not configured")
        return data

    headers = {
        "Authorization": f"Bearer {config.censys.api_key}",
        "Accept": "application/vnd.censys.api.v3.host.v1+json",
    }
    params = {}
    if config.censys.organization_id:
        params["organization_id"] = config.censys.organization_id
    url = f"{config.censys.api_url.rstrip('/')}/v3/global/asset/host/{ip}"

    for attempt in range(MAX_RETRIES):
        try:
            r = requests.get(url, headers=headers, params=params, timeout=30)
        except requests.RequestException as e:
            logger.warning("censys_api: %s", e)
            _backoff(attempt)
            continue

        match r.status_code:
            case 200:
                # Platform API nests the host under result.resource.
                result = r.json().get("result", {}).get("resource", {})
                data["censys.ip"] = result.get("ip")

                asn_data = result.get("autonomous_system") or {}
                data["censys.asn"] = asn_data.get("asn")
                data["censys.as_name"] = asn_data.get("name")
                data["censys.as_country_code"] = asn_data.get("country_code")

                loc = result.get("location") or {}
                data["censys.country"] = loc.get("country")
                data["censys.country_code"] = loc.get("country_code")
                data["censys.city"] = loc.get("city")
                data["censys.timezone"] = loc.get("timezone")

                services = result.get("services") or []
                data["censys.ports"] = "|".join(
                    str(s["port"]) for s in services if "port" in s
                )
                data["censys.protocols"] = "|".join(
                    sorted(
                        {
                            s["transport_protocol"]
                            for s in services
                            if s.get("transport_protocol")
                        }
                    )
                )
                return data
            case 404:
                logger.info("censys: %s not found", ip)
                return {"censys.status": "not_found"}
            case 429:
                logger.warning("Censys rate limit exceeded")
                return {"censys.status": "rate_limited"}
            case 401 | 403:
                logger.error("Censys authentication failed - check API key")
                return {"censys.status": "auth_failed"}
            case _:
                logger.warning("Censys returned HTTP %s", r.status_code)
                _backoff(attempt)

    return data


def shodan_api(config: KnowYourIPConfig, ip: str) -> dict[str, Any]:
    """Get host data from Shodan.

    Args:
        config: Configuration object holding the Shodan API key.
        ip: An IP address.

    Returns:
        Host fields prefixed with ``shodan.``.

    Raises:
        ImportError: If the optional ``shodan`` extra is not installed.
    """
    ip = validate_ip(ip)
    try:
        import shodan
    except ImportError as exc:  # pragma: no cover - depends on install extras
        raise ImportError(
            "Shodan support requires the optional dependency. "
            "Install it with: pip install 'know_your_ip[shodan]'"
        ) from exc

    if not config.shodan.api_key:
        logger.warning("Shodan API key not configured")
        return {}

    api = shodan.Shodan(config.shodan.api_key)
    data: dict[str, Any] = {}
    try:
        out = flatten_dict(api.host(ip), separator=".")
    except shodan.APIError as e:
        logger.warning("shodan_api(%s): %s", ip, e)
        return {"shodan.error": str(e)}

    for k, v in out.items():
        data[f"shodan.{k}"] = "|".join(str(i) for i in v) if isinstance(v, list) else v
    return data


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
    data: dict[str, Any] = {}

    if not config.virustotal.api_key:
        logger.warning("VirusTotal API key not configured")
        return data

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": config.virustotal.api_key}

    for attempt in range(MAX_RETRIES):
        try:
            r = requests.get(url, headers=headers, timeout=30)
        except requests.RequestException as e:
            logger.warning("virustotal_api: %s", e)
            _backoff(attempt)
            continue

        match r.status_code:
            case 200:
                attributes = r.json().get("data", {}).get("attributes", {})

                stats = attributes.get("last_analysis_stats") or {}
                data["virustotal.harmless"] = stats.get("harmless", 0)
                data["virustotal.malicious"] = stats.get("malicious", 0)
                data["virustotal.suspicious"] = stats.get("suspicious", 0)
                data["virustotal.undetected"] = stats.get("undetected", 0)
                data["virustotal.timeout"] = stats.get("timeout", 0)

                data["virustotal.asn"] = attributes.get("asn")
                data["virustotal.as_owner"] = attributes.get("as_owner")
                data["virustotal.country"] = attributes.get("country")
                data["virustotal.continent"] = attributes.get("continent")
                data["virustotal.network"] = attributes.get("network")
                data["virustotal.rir"] = attributes.get("regional_internet_registry")
                data["virustotal.reputation"] = attributes.get("reputation", 0)
                data["virustotal.jarm"] = attributes.get("jarm")
                data["virustotal.last_analysis_date"] = attributes.get(
                    "last_analysis_date"
                )
                data["virustotal.whois_date"] = attributes.get("whois_date")

                votes = attributes.get("total_votes") or {}
                data["virustotal.votes_harmless"] = votes.get("harmless", 0)
                data["virustotal.votes_malicious"] = votes.get("malicious", 0)

                tags = attributes.get("tags") or []
                data["virustotal.tags"] = "|".join(str(t) for t in tags)
                return data
            case 404:
                logger.info("virustotal: %s not found", ip)
                return {"virustotal.status": "not_found"}
            case 429:
                logger.warning("VirusTotal rate limit exceeded")
                return {"virustotal.status": "rate_limited"}
            case 401 | 403:
                logger.error("VirusTotal authentication failed - check API key")
                return {"virustotal.status": "auth_failed"}
            case _:
                logger.warning("VirusTotal returned HTTP %s", r.status_code)
                _backoff(attempt)

    return data


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


def query_ip(config: KnowYourIPConfig, ip: str) -> dict[str, Any]:
    """Collect data on an IP address from every enabled service.

    Each service is isolated: a failure in one is logged and recorded under
    ``<service>.error`` without preventing the others from running.

    Args:
        config: Configuration object.
        ip: An IP address.

    Returns:
        Every field collected, keyed by ``<service>.<field>``. Use
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
    lat: float | None = None
    lng: float | None = None

    def run(name: str, fn, *args) -> None:
        """Run one service, recording failures rather than raising."""
        try:
            data.update(fn(*args))
        except Exception as e:  # noqa: BLE001 - one bad service must not stop the rest
            logger.warning("%s(%s): %s", name, ip, e)
            data[f"{name}.error"] = str(e)

    if config.ping.enabled:
        run("ping", ping, config, ip)
    if config.traceroute.enabled:
        run("traceroute", traceroute, config, ip)

    if config.maxmind.enabled:
        run("maxmind", maxmind_geocode_ip, config, ip)
        lat = data.get("maxmind.location.latitude")
        lng = data.get("maxmind.location.longitude")

    if lat is not None and lng is not None:
        if config.geonames.enabled:
            run("geonames", geonames_timezone, config, lat, lng)
        if config.timezone.enabled:
            try:
                data["timezone.name"] = timezone_at(config, lat, lng)
            except Exception as e:  # noqa: BLE001
                logger.warning("timezone(%s): %s", ip, e)
                data["timezone.error"] = str(e)
    elif config.geonames.enabled or config.timezone.enabled:
        logger.info(
            "timezone lookup skipped for %s: no coordinates "
            "(enable [maxmind] to supply them)",
            ip,
        )

    if config.abuseipdb.enabled:
        run("abuseipdb", abuseipdb_api, config, ip)
    if config.apivoid.enabled:
        run("apivoid", apivoid_api, config, ip)
    if config.censys.enabled:
        run("censys", censys_api, config, ip)
    if config.shodan.enabled:
        run("shodan", shodan_api, config, ip)
    if config.virustotal.enabled:
        run("virustotal", virustotal_api, config, ip)

    return data


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
    parser.add_argument("ip", nargs="*", help="IP address(es) to analyze")
    parser.add_argument("-f", "--file", help="File listing IP addresses")
    parser.add_argument("-c", "--config", help="Configuration file (TOML format)")
    parser.add_argument("-o", "--output", default="output.csv", help="Output CSV file")
    parser.add_argument(
        "-n", "--max-conn", type=int, default=5, help="Max concurrent requests"
    )
    parser.add_argument("--from", default=0, type=int, dest="from_row", help="From row")
    parser.add_argument("--to", default=0, type=int, help="To row (0 means all)")
    parser.add_argument(
        "--all-columns",
        action="store_true",
        help="Write every collected field instead of [output] columns",
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

    if args.file is None and not args.ip:
        parser.error("at least one IP address or --file is required")

    config = load_config(args.config)

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

    with open(args.output, "w", newline="", encoding="utf-8") as fh:
        writer: DictWriter | None = None
        if not args.all_columns:
            writer = DictWriter(
                fh, fieldnames=config.output.columns, extrasaction="ignore"
            )
            if args.header:
                writer.writeheader()

        with ThreadPool(processes=args.max_conn) as pool:
            try:
                for i, record in enumerate(
                    pool.imap(partial(query_ip, config), ips), start=1
                ):
                    if writer is None:
                        writer = DictWriter(
                            fh, fieldnames=list(record), extrasaction="ignore"
                        )
                        if args.header:
                            writer.writeheader()
                    writer.writerow(record)
                    if i % 100 == 0:
                        logger.info("Processed %d/%d", i, len(ips))
            except KeyboardInterrupt:
                logger.warning(
                    "Interrupted; partial results written to %s", args.output
                )
                pool.terminate()
                return 130

    logger.info("Wrote %s", args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
