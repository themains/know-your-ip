#!/usr/bin/env python

from __future__ import annotations

import argparse
import logging
import re
import signal
import sys
import time
from collections import defaultdict
from csv import DictWriter
from functools import partial
from multiprocessing import Pool
from pathlib import Path
from typing import Any

import geoip2.database
import geoip2.webservice
import requests
import shodan
from bs4 import BeautifulSoup

from .config import KnowYourIPConfig
from .config import load_config as load_modern_config
from .ping import quiet_ping
from .traceroute import os_traceroute

logging.getLogger("requests").setLevel(logging.WARNING)

LOG_FILE = Path("know_your_ip.log")

MAX_RETRIES = 5

# Official AbuseIPDB category codes (as of 2024)
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


def setup_logger() -> None:
    """Set up logging."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s %(message)s",
        datefmt="%m-%d %H:%M",
        filename=LOG_FILE,
        filemode="w",
    )
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    formatter = logging.Formatter("%(message)s")
    console.setFormatter(formatter)
    logging.getLogger("").addHandler(console)


def table_to_list(table: Any) -> list[list[str]]:
    """Convert BeautifulSoup table to list of lists."""
    dct = table_to_2d_dict(table)
    return list(iter_2d_dict(dct))


def table_to_2d_dict(table: Any) -> dict[int, dict[int, str]]:
    """Convert BeautifulSoup table to 2D dictionary."""
    result = defaultdict(lambda: defaultdict())
    for row_i, row in enumerate(table.find_all("tr")):
        for col_i, col in enumerate(row.find_all(["td", "th"])):
            colspan = int(col.get("colspan", 1))
            rowspan = int(col.get("rowspan", 1))
            col_data = col.text
            while row_i in result and col_i in result[row_i]:
                col_i += 1
            for i in range(row_i, row_i + rowspan):
                for j in range(col_i, col_i + colspan):
                    result[i][j] = col_data
    return result


def iter_2d_dict(dct: dict[int, dict[int, str]]) -> list[str]:
    """Iterate over 2D dictionary and yield column lists."""
    for _i, row in sorted(dct.items()):
        cols = []
        for _j, col in sorted(row.items()):
            cols.append(col)
        yield cols


def flatten_dict(dd: Any, separator: str = "_", prefix: str = "") -> dict[str, Any]:
    """Flatten nested dictionary using separator."""
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
    """Clean column name to be valid identifier."""
    c = re.sub(r"\W|^(?=\d)", "_", name)
    return (re.sub("_+", "_", c)).lower()


def load_config(config_file: str | Path | None = None) -> KnowYourIPConfig:
    """Load configuration using modern Pydantic-based system.

    Args:
        config_file: Path to configuration file. If None, searches standard locations.

    Returns:
        Typed and validated configuration object.
    """
    if isinstance(config_file, str):
        config_file = Path(config_file)

    return load_modern_config(config_file)


def maxmind_geocode_ip(config: KnowYourIPConfig, ip: str) -> dict[str, Any]:
    """Get location of IP address from Maxmind City database (GeoLite2-City.mmdb)

    Args:
        config: Typed configuration object.
        ip: an IP address

    Returns:
        dict: Geolocation data

    Notes:
        There are other Maxmind databases including:
            * Country Database (GeoLite2-Country.mmdb)
            * Anonymous IP Database (GeoIP2-Anonymouse-IP.mmdb)
            * Connection-Type Database (GeoIP2-Connection-Type.mmdb)
            * Domain Database (GeoIP2-Domain.mmdb)
            * ISP Database (GeoIP2-ISP.mmdb)
    """

    reader = geoip2.database.Reader(config.maxmind.db_path / "GeoLite2-City.mmdb")
    response = reader.city(ip)
    out = flatten_dict(response.raw, separator=".")
    reader.close()
    result = {}
    for k in out.keys():
        result[f"maxmind.{k}"] = out[k]
    return result


def geonames_timezone(
    config: KnowYourIPConfig, lat: float, lng: float
) -> dict[str, Any]:
    """Get timezone for a latitude/longitude from GeoNames

    Args:
        config: Typed configuration object.
        lat (float): latitude
        lng (float): longitude

    Returns:
        dict: GeoNames data

    Notes:
        Please visit `this link <http://www.geonames.org/export/ws-overview.html>`_
        for more information about GeoNames.org Web Services

        e.g. URL: http://api.geonames.org/timezone?lat=47.01&lng=10.2&username=demo

        Limit:
            30,000 credits daily limit per application
            (identified by the parameter 'username'), the hourly limit is
            2000 credits. A credit is a web service request hit for most services.
            An exception is thrown when the limit is exceeded.

    Example:
        geonames_timezone(config, 32.0617, 118.7778)
    """

    data = {}
    payload = {"lat": lat, "lng": lng, "username": config.geonames.username}
    retry = 0
    while retry < MAX_RETRIES:
        try:
            r = requests.get(
                "http://api.geonames.org/timezoneJSON", params=payload, timeout=30
            )
            if r.status_code == 200:
                out = r.json()
                for k in out.keys():
                    data[f"geonames.{k}"] = out[k]
                break
        except (requests.RequestException, ValueError, KeyError) as e:
            logging.warning(f"geonames_timezone: {e}")
            retry += 1
            time.sleep(retry)
    return data


def tzwhere_timezone(config: KnowYourIPConfig, lat: float, lng: float) -> str | None:
    """Get timezone of a latitude/longitude using the tzwhere package.

    Args:
        config: Typed configuration object.
        lat (float): latitude
        lng (float): longitude

    Returns:
        dict: timezone data

    Example:
        tzwhere_timezone(args, 32.0617, 118.7778)
    """

    from tzwhere import tzwhere

    # Note: This function now requires static initialization
    # Since we can't cache on the config object, we'll create fresh instance each time
    tz_finder = tzwhere.tzwhere()
    return tz_finder.tzNameAt(lat, lng)


def abuseipdb_api(config: KnowYourIPConfig, ip: str) -> dict[str, Any]:
    """Get abuse information for an IP address from AbuseIPDB API.

    Args:
        config: Configuration object containing AbuseIPDB settings including
            API key, days lookback period, and category mappings.
        ip: IP address to check for abuse reports.

    Returns:
        Dictionary containing AbuseIPDB analysis results with keys:
            - abuseipdb.categories: Human-readable abuse categories (e.g., "DDoS Attack|Phishing")
            - abuseipdb.confidence: Abuse confidence percentage
            - abuseipdb.country: Country of origin
            - abuseipdb.reports: Number of reports
            - Other fields from API response

    Note:
        Uses embedded category mapping to convert numeric category IDs
        (e.g., 4, 7, 15) to descriptive names (e.g., "DDoS Attack", "Phishing", "Hacking").

    References:
        https://www.abuseipdb.com/api.html
        https://docs.abuseipdb.com/

    Example:
        >>> config = KnowYourIPConfig()
        >>> config.abuseipdb.api_key = "your_api_key"
        >>> config.abuseipdb.days = 90
        >>> result = abuseipdb_api(config, '222.186.30.49')
        >>> print(result.get('abuseipdb.categories', 'Clean'))
        SSH|Brute Force
    """

    out = {}
    # Use embedded category mapping for better performance and reliability
    categories = ABUSEIPDB_CATEGORIES

    retry = 0
    while retry < MAX_RETRIES:
        try:
            headers = {"Key": config.abuseipdb.api_key, "Accept": "application/json"}
            params = {
                "ipAddress": ip,
                "maxAgeInDays": config.abuseipdb.days,
                "verbose": "",
            }
            r = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers=headers,
                params=params,
                timeout=30,
            )
            if r.status_code == 200:
                response = r.json()
                if "data" in response:
                    data = response["data"]
                    out = {}

                    # Core fields
                    out["abuseipdb.abuse_confidence_score"] = data.get(
                        "abuseConfidencePercentage", 0
                    )
                    out["abuseipdb.country_code"] = data.get("countryCode")
                    out["abuseipdb.usage_type"] = data.get("usageType")
                    out["abuseipdb.isp"] = data.get("isp")
                    out["abuseipdb.domain"] = data.get("domain")
                    out["abuseipdb.is_public"] = data.get("isPublic")
                    out["abuseipdb.is_whitelisted"] = data.get("isWhitelisted")
                    out["abuseipdb.total_reports"] = data.get("totalReports", 0)
                    out["abuseipdb.num_distinct_users"] = data.get(
                        "numDistinctUsers", 0
                    )
                    out["abuseipdb.last_reported_at"] = data.get("lastReportedAt")

                    # Process categories with embedded mapping
                    if "categories" in data and data["categories"]:
                        category_names = []
                        for cat_id in data["categories"]:
                            cat_str = str(cat_id)
                            if cat_str in categories:
                                category_names.append(categories[cat_str])
                        out["abuseipdb.categories"] = (
                            "|".join(category_names) if category_names else ""
                        )
                    else:
                        out["abuseipdb.categories"] = ""
                break
            elif r.status_code == 429:
                logging.warning("AbuseIPDB rate limit exceeded")
                out["abuseipdb.status"] = "rate_limited"
                break
            elif r.status_code == 401:
                logging.error("AbuseIPDB authentication failed - check API key")
                out["abuseipdb.status"] = "auth_failed"
                break
            else:
                logging.warning(
                    f"AbuseIPDB API returned status {r.status_code}: {r.text}"
                )
                retry += 1
                if retry < MAX_RETRIES:
                    time.sleep(retry * 2)  # Exponential backoff
        except requests.RequestException as e:
            logging.warning(f"abuseipdb_api request error: {e}")
            retry += 1
            if retry < MAX_RETRIES:
                time.sleep(retry)
    return out


def abuseipdb_web(config: KnowYourIPConfig, ip: str) -> dict[str, Any]:
    """Get information from `AbuseIPDB website <https://www.abuseipdb.com/>`_

    Args:
        config: Typed configuration object.
        ip (str): an IP address

    Returns:
        dict: AbuseIPDB information

    References:
        e.g. http://www.abuseipdb.com/check/94.31.29.154

    Example:
        abuseipdb_web(args, '222.186.30.49')
    """

    data = {}
    retry = 0
    while retry < MAX_RETRIES:
        try:
            r = requests.get("http://www.abuseipdb.com/check/" + ip, timeout=30)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "lxml")
                for t in soup.select("table"):
                    table = table_to_list(t)
                    for r in table:
                        col = r[0].strip()
                        col = clean_colname(col)
                        data["abuseipdb." + col] = r[1]
                    break
                div = soup.select("div#body div.well")[0]
                result = div.text
                if result.find("was not found") != -1:
                    data["abuseipdb.found"] = 0
                else:
                    data["abuseipdb.found"] = 1
                count = 0
                for m in re.finditer(r"was reported (\d+) time", result):
                    count = int(m.group(1))
                    break
                if count:
                    for t in soup.select("table")[1:]:
                        table = table_to_list(t)
                        rows = []
                        for r in table:
                            rows.append("|".join(r))
                        break
                    data["abuseipdb.history"] = "\n".join(rows)
                break
        except (requests.RequestException, ValueError, KeyError) as e:
            logging.warning(f"abuseipdb_web: {e}")
            retry += 1
            time.sleep(retry)
    return data


def ipvoid_scan(config: KnowYourIPConfig, ip: str) -> dict[str, Any]:
    """Get Blacklist information from `IPVoid website <http://www.ipvoid.com/ip-blacklist-check>`_

    Args:
        config: Typed configuration object.
        ip (str): an IP address

    Returns:
        dict: IPVoid information

    Example:
        ipvoid_scan(args, '222.186.30.49')
    """

    retry = 0
    while retry < MAX_RETRIES:
        try:
            data = {}
            r = requests.post(
                "http://www.ipvoid.com/ip-blacklist-check/", data={"ip": ip}, timeout=30
            )
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "lxml")
                data = {}
                tables = soup.select("table")
                table = table_to_list(tables[0])
                for r in table:
                    col = "ipvoid." + clean_colname(r[0])
                    data[col] = r[1]
                alerts = []
                for tr in tables[1].select("tr"):
                    tds = tr.select("td")
                    if len(tds) == 2:
                        if len(tds[0].select("i.text-danger")):
                            alerts.append(tds[0].text.strip())
                data["ipvoid.alerts"] = "|".join(alerts)
                break
        except (requests.RequestException, ValueError, KeyError) as e:
            logging.warning(f"ipvoid_scan: {e}")
            retry += 1
            time.sleep(retry)
    return data


def apivoid_api(config: KnowYourIPConfig, ip: str) -> dict[str, Any]:
    """Get information from APIVoid `IP Reputation API <https://www.apivoid.com/api/ip-reputation/>`_

    Args:
        config: Typed configuration object.
        ip (str): an IP address

    Returns:
        dict: IP Reputation API information

    Notes:
        Must register and get 25 free API credits valid for 30 days

    Example:
        apivoid_api(args, '222.186.30.49')
    """

    url = "https://endpoint.apivoid.com/iprep/v1/pay-as-you-go/"
    params = {"ip": ip, "key": config.apivoid.api_key}
    retry = 0
    data = {}
    while retry < MAX_RETRIES:
        try:
            r = requests.get(url, params=params, timeout=30)
            if r.status_code == 200:
                out = r.json()
                logging.info(
                    f"apivoid_api: credit_remained: {out['credits_remained']:.2f}, estimated_queries: {out['estimated_queries']}"
                )
                out = flatten_dict(out["data"]["report"], separator=".")
                for k in out.keys():
                    if isinstance(out[k], list):
                        out[k] = "|".join([str(i) for i in out[k]])
                    data["apivoid." + k] = out[k]
                break
        except (requests.RequestException, ValueError, KeyError) as e:
            logging.warning(f"apivoid_api: {e}")
            retry += 1
            time.sleep(retry)
    return data


def censys_api(config: KnowYourIPConfig, ip: str) -> dict[str, Any]:
    """Get information from Censys Platform API.

    Note: Legacy Censys Search v1/v2 APIs are deprecated as of 2025.
    This uses the new Censys Platform API with updated authentication.

    Args:
        config: Typed configuration object containing Censys settings.
        ip: IP address to query.

    Returns:
        Dictionary containing Censys data with 'censys.' prefixed keys.

    Rate Limits:
        Free tier: 250 requests/month, 1 request per 2.5 seconds

    References:
        https://search.censys.io/api
        https://docs.censys.com/reference/get-started

    Example:
        >>> config.censys.enabled = True
        >>> config.censys.api_key = "your_api_key"
        >>> result = censys_api(config, '8.8.8.8')
        >>> print(result.get('censys.autonomous_system.name'))
    """

    data = {}

    if not config.censys.api_key:
        logging.warning("Censys API key not configured")
        return data

    headers = {
        "Authorization": f"Bearer {config.censys.api_key}",
        "Content-Type": "application/json",
    }

    retry = 0
    while retry < MAX_RETRIES:
        try:
            # Use the new Platform API endpoint for host lookup
            url = f"{config.censys.api_url}/v2/hosts/{ip}"
            r = requests.get(url, headers=headers, timeout=30)

            match r.status_code:
                case 200:
                    result = r.json()
                    if "result" in result:
                        host_data = result["result"]

                        # Extract key information with flattened keys
                        data["censys.ip"] = host_data.get("ip")

                        # Autonomous System information
                        if "autonomous_system" in host_data:
                            asn_data = host_data["autonomous_system"]
                            data["censys.asn"] = asn_data.get("asn")
                            data["censys.as_name"] = asn_data.get("name")
                            data["censys.as_country_code"] = asn_data.get(
                                "country_code"
                            )

                        # Location information
                        if "location" in host_data:
                            loc_data = host_data["location"]
                            data["censys.country"] = loc_data.get("country")
                            data["censys.country_code"] = loc_data.get("country_code")
                            data["censys.city"] = loc_data.get("city")
                            data["censys.timezone"] = loc_data.get("timezone")

                        # Services information
                        if "services" in host_data and host_data["services"]:
                            services = host_data["services"]
                            ports = [
                                str(s.get("port", "")) for s in services if "port" in s
                            ]
                            data["censys.ports"] = "|".join(ports) if ports else ""

                            protocols = [
                                s.get("transport_protocol", "")
                                for s in services
                                if "transport_protocol" in s
                            ]
                            data["censys.protocols"] = "|".join(
                                {p for p in protocols if p}
                            )
                    break

                case 404:
                    logging.info(f"IP {ip} not found in Censys database")
                    data["censys.status"] = "not_found"
                    break

                case 429:
                    logging.warning("Censys rate limit exceeded")
                    data["censys.status"] = "rate_limited"
                    break

                case 401 | 403:
                    logging.error("Censys authentication failed - check API key")
                    data["censys.status"] = "auth_failed"
                    break

                case _:
                    logging.warning(
                        f"Censys API returned status {r.status_code}: {r.text}"
                    )
                    retry += 1
                    if retry < MAX_RETRIES:
                        time.sleep(retry * 2)  # Exponential backoff

        except requests.RequestException as e:
            logging.warning(f"censys_api request error: {e}")
            retry += 1
            if retry < MAX_RETRIES:
                time.sleep(retry)

    return data


def shodan_api(config: KnowYourIPConfig, ip: str) -> dict[str, Any]:
    """Get information from Shodan

    Args:
        config: Typed configuration object.
        ip (str): an IP address

    Returns:
        dict: Shodan information

    Example:
        shodan_api(args, '222.186.30.49')
    """

    api = shodan.Shodan(config.shodan.api_key)
    data = {}
    try:
        out = api.host(ip)
        out = flatten_dict(out)
        for k in out.keys():
            if isinstance(out[k], list):
                out[k] = "|".join([str(i) for i in out[k]])
            data["shodan." + k] = out[k]
    except shodan.APIError as e:
        logging.warning(f"shodan_api(ip={ip}): {e}")
    return data


def virustotal_api(config: KnowYourIPConfig, ip: str) -> dict[str, Any]:
    """Get information from VirusTotal API v3.

    Args:
        config: Typed configuration object containing VirusTotal settings.
        ip: IP address to analyze.

    Returns:
        Dictionary containing VirusTotal analysis results with keys:
            - virustotal.harmless: Number of harmless detections
            - virustotal.malicious: Number of malicious detections
            - virustotal.suspicious: Number of suspicious detections
            - virustotal.undetected: Number of undetected results
            - virustotal.asn: Autonomous System Number
            - virustotal.as_owner: AS owner name
            - virustotal.country: Country code
            - virustotal.network: Network range
            - virustotal.reputation: Reputation score
            - virustotal.categories: Threat categories (if available)

    Note:
        VirusTotal API v3 Rate Limits:
            * Public API: 500 requests/day, 4 requests/minute
            * Premium API: Higher limits based on subscription

        Uses HTTP requests with improved error handling. Official vt-py client
        dependency is available for future async improvements.

    References:
        https://developers.virustotal.com/reference/ip-info
        https://docs.virustotal.com/reference/overview

    Example:
        >>> config = KnowYourIPConfig()
        >>> config.virustotal.api_key = "your_api_key"
        >>> result = virustotal_api(config, '8.8.8.8')
        >>> print(result['virustotal.reputation'])
        530
    """

    data = {}

    if not config.virustotal.api_key:
        logging.warning("VirusTotal API key not configured")
        return data

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": config.virustotal.api_key}
    retry = 0

    while retry < MAX_RETRIES:
        try:
            r = requests.get(url, headers=headers, timeout=30)
            match r.status_code:
                case 200:
                    response_data = r.json()
                    if "data" in response_data:
                        # Extract key attributes from v3 API response
                        attributes = response_data["data"].get("attributes", {})

                        # Process reputation and detection info
                        if "last_analysis_stats" in attributes:
                            stats = attributes["last_analysis_stats"]
                            data["virustotal.harmless"] = stats.get("harmless", 0)
                            data["virustotal.malicious"] = stats.get("malicious", 0)
                            data["virustotal.suspicious"] = stats.get("suspicious", 0)
                            data["virustotal.undetected"] = stats.get("undetected", 0)

                        # Network info
                        data["virustotal.asn"] = attributes.get("asn")
                        data["virustotal.as_owner"] = attributes.get("as_owner")
                        data["virustotal.country"] = attributes.get("country")
                        data["virustotal.network"] = attributes.get("network")

                        # Reputation score
                        data["virustotal.reputation"] = attributes.get("reputation", 0)

                        # Categories (if available)
                        if "categories" in attributes:
                            categories = attributes["categories"]
                            if isinstance(categories, dict):
                                data["virustotal.categories"] = "|".join(
                                    categories.keys()
                                )
                            elif isinstance(categories, list):
                                data["virustotal.categories"] = "|".join(
                                    [str(c) for c in categories]
                                )
                    break
                case 404:
                    # IP not found in VirusTotal database
                    logging.info(f"IP {ip} not found in VirusTotal database")
                    data["virustotal.status"] = "not_found"
                    break
                case 429:
                    # Rate limit exceeded
                    logging.warning("VirusTotal rate limit exceeded")
                    data["virustotal.status"] = "rate_limited"
                    break
                case 401 | 403:
                    # Authentication error
                    logging.error("VirusTotal authentication failed - check API key")
                    data["virustotal.status"] = "auth_failed"
                    break
                case _:
                    # Other HTTP errors
                    logging.warning(
                        f"VirusTotal API returned status {r.status_code}: {r.text}"
                    )
                    retry += 1
                    if retry < MAX_RETRIES:
                        time.sleep(retry * 2)  # Exponential backoff

        except requests.RequestException as e:
            logging.warning(f"virustotal_api request error: {e}")
            retry += 1
            if retry < MAX_RETRIES:
                time.sleep(retry)

    return data


def ping(config: KnowYourIPConfig, ip: str) -> dict[str, Any]:
    """Get information using Ping (ICMP protocol)

    Args:
        config: Typed configuration object.
        ip (str): an IP address

    Returns:
        dict: Ping statistics information

    Notes:
        Ping function is based on a pure python ping implementation using
        raw socket and you must have root (on Linux) or Admin (on Windows)
        privileges to run.

    Example:
        ping(args, '222.186.30.49')
    """

    data = {}
    data["ping.count"] = config.ping.count
    data["ping.timeout"] = config.ping.timeout
    stat = quiet_ping(ip, timeout=config.ping.timeout, count=config.ping.count)
    if stat:
        data["ping.max"] = stat[0]
        data["ping.min"] = stat[1]
        data["ping.avg"] = stat[2]
        data["ping.percent_loss"] = stat[3] * 100
    return data


def traceroute(config: KnowYourIPConfig, ip: str) -> dict[str, Any]:
    """Get information using traceroute

    Args:
        config: Typed configuration object.
        ip (str): an IP address

    Returns:
        dict: traceroute information

    Notes:
        Currently traceroute uses the operating system command traceroute on
        Linux and tracert on Windows.

    Example:
        traceroute(args, '222.186.30.49')
    """

    data = {}
    hops = os_traceroute(ip, max_hops=config.traceroute.max_hops)
    data["traceroute.max_hops"] = config.traceroute.max_hops
    data["traceroute.hops"] = hops
    return data


def init_worker():
    signal.signal(signal.SIGINT, signal.SIG_IGN)


def query_ip(config: KnowYourIPConfig, ip: str) -> dict[str, Any]:
    """Get all information of IP address

    Args:
        config: Typed configuration object.
        ip (str): an IP address

    Returns:
        dict: Information on the given IP address

    Example:
        query_ip(args, '222.186.30.49')
    """

    data = {"ip": ip}
    udata = {}
    try:
        if config.ping.enabled:
            out = ping(config, ip)
            data.update(out)
        if config.traceroute.enabled:
            out = traceroute(config, ip)
            data.update(out)
        try:
            if config.maxmind.enabled:
                out = maxmind_geocode_ip(config, ip)
                lat = out["maxmind.location.latitude"]
                lng = out["maxmind.location.longitude"]
                data.update(out)
            if config.geonames.enabled:
                out = geonames_timezone(config, lat, lng)
                data.update(out)
            if config.tzwhere.enabled:
                tz = tzwhere_timezone(config, lat, lng)
                data["tzwhere.timezone"] = tz
        except Exception as e:
            logging.error(e)
        if config.abuseipdb.enabled:
            out = abuseipdb_api(config, ip)
            data.update(out)
            out = abuseipdb_web(config, ip)
            data.update(out)
        if config.ipvoid.enabled:
            out = ipvoid_scan(config, ip)
            data.update(out)
        if config.apivoid.enabled:
            out = apivoid_api(config, ip)
            data.update(out)
        if config.censys.enabled:
            out = censys_api(config, ip)
            data.update(out)
        if config.shodan.enabled:
            out = shodan_api(config, ip)
            data.update(out)
        if config.virustotal.enabled:
            out = virustotal_api(config, ip)
            data.update(out)
        # Encode columns to UTF-8 where possible, fallback to original value
        for k, v in data.items():
            if k in config.output.columns:
                try:
                    udata[k] = v.encode("utf-8")
                except (AttributeError, UnicodeEncodeError):
                    udata[k] = v
    except Exception as e:
        logging.error(e)
        # Note: verbose flag removed - logging should be controlled by logging level
        import traceback

        traceback.print_exc()
    return udata


def main() -> None:
    setup_logger()

    parser = argparse.ArgumentParser(description="Know Your IP")
    parser.add_argument("ip", nargs="*", help="IP Address(es)")
    parser.add_argument("-f", "--file", help="List of IP addresses file")
    parser.add_argument("-c", "--config", help="Configuration file (TOML format)")
    parser.add_argument(
        "-o", "--output", default="output.csv", help="Output CSV file name"
    )
    parser.add_argument(
        "-n", "--max-conn", type=int, default=5, help="Max concurrent connections"
    )
    parser.add_argument(
        "--from", default=0, type=int, dest="from_row", help="From row number"
    )
    parser.add_argument("--to", default=0, type=int, help="To row number")
    parser.add_argument(
        "-v", "--verbose", dest="verbose", action="store_true", help="Verbose mode"
    )
    parser.add_argument(
        "--no-header",
        dest="header",
        action="store_false",
        help="Output without header at the first row",
    )
    parser.set_defaults(header=True)
    parser.set_defaults(verbose=False)

    args = parser.parse_args()

    if args.file is None and len(args.ip) == 0:
        parser.error("at least one of IP address and --file is required")

    # Load configuration
    config = load_config(args.config)

    pool = Pool(processes=args.max_conn, initializer=init_worker)

    if args.file:
        with open(args.file) as f:
            args.ip = [
                a.strip()
                for a in f.read().split("\n")
                if ((a.strip() != "") and not a.startswith("#"))
            ]

    f = open(args.output, "w")
    writer = DictWriter(f, fieldnames=config.output.columns)
    if args.header:
        writer.writeheader()
    row = 0
    while row < len(args.ip):
        if row < args.from_row:
            row += 1
            continue
        if args.to != 0 and row >= args.to:
            logging.info(f"Stop at row {row}")
            break
        logging.info(f"Row: {row}")
        try:
            partial_query_ip = partial(query_ip, config)
            ips = args.ip[row : row + args.max_conn]
            results = pool.map(partial_query_ip, ips)
            for data in results:
                edata = {}
                for k, v in data.items():
                    if v is not None:
                        try:
                            edata[k] = v.decode("utf-8")
                        except (AttributeError, UnicodeDecodeError):
                            edata[k] = v
                writer.writerow(edata)
                row += 1
        except KeyboardInterrupt:
            pool.terminate()
            pool.join()
            break
        except Exception as e:
            logging.error(e)
            if args.verbose:
                import traceback

                traceback.print_exc()
    f.close()


if __name__ == "__main__":
    sys.exit(main())
