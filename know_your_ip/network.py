"""Keyless address facts: classification, reverse DNS, and RDAP registry data.

Nothing here needs an API key or an account, which matters more than it sounds:
the single biggest barrier to using a tool like this on a large address list is
that every useful source wants a key and meters it. These work on a hundred
thousand addresses as readily as on one.

Classification also pays for itself directly. Real research data is full of
RFC1918 addresses, loopback, and CGNAT ranges. Spending metered VirusTotal
quota to be told that 192.168.1.1 is private is pure waste, so knowing which
addresses are not globally routable lets a caller skip them.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import threading
from typing import Any

from . import http

logger = logging.getLogger(__name__)

# IANA's RDAP bootstrap registry: maps address ranges to the RDAP service of
# the RIR responsible for them. Fetched once per process and reused.
BOOTSTRAP_URLS = {
    4: "https://data.iana.org/rdap/ipv4.json",
    6: "https://data.iana.org/rdap/ipv6.json",
}

RDAP_RATE_LIMIT = http.RateLimit(requests=10, per_seconds=60)

_BOOTSTRAP_CACHE: dict[int, list[tuple[list[str], list[str]]]] = {}
_BOOTSTRAP_LOCK = threading.Lock()


def classify_ip(ip: str) -> dict[str, Any]:
    """Describe an address without touching the network.

    Args:
        ip: An IPv4 or IPv6 address.

    Returns:
        Fields prefixed with ``network.``: version, whether the address is
        globally routable, and which special-use category it falls into.

    Example:
        >>> classify_ip("192.168.1.1")["network.is_private"]
        True
    """
    address = ipaddress.ip_address(ip)

    # Ordered most specific first: loopback and link-local are also "private"
    # by the stdlib's reckoning, and the narrower label is the useful one.
    categories = [
        ("loopback", address.is_loopback),
        ("link_local", address.is_link_local),
        ("multicast", address.is_multicast),
        ("unspecified", address.is_unspecified),
        ("reserved", address.is_reserved),
        ("private", address.is_private),
    ]
    category = next((name for name, matches in categories if matches), "public")

    data: dict[str, Any] = {
        "network.version": address.version,
        "network.category": category,
        "network.is_global": address.is_global,
        "network.is_private": address.is_private,
        "network.is_routable": address.is_global and not address.is_multicast,
    }

    if address.version == 4 and ipaddress.ip_address(ip) in ipaddress.ip_network(
        "100.64.0.0/10"
    ):
        # Carrier-grade NAT: shared between many subscribers, so anything
        # inferred about the "user" behind it is unusually weak.
        data["network.category"] = "cgnat"
        data["network.is_cgnat"] = True

    return data


def reverse_dns(ip: str, timeout: float = 5.0) -> dict[str, Any]:
    """Look up the PTR record for an address.

    Args:
        ip: An IP address.
        timeout: Seconds to wait for the resolver.

    Returns:
        ``network.reverse_dns`` when a name is found, otherwise an empty dict.
    """
    original = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
    except (OSError, socket.herror, socket.gaierror):
        return {}
    finally:
        socket.setdefaulttimeout(original)
    return {"network.reverse_dns": hostname}


def network_info(config: Any, ip: str) -> dict[str, Any]:
    """Collect keyless facts about an address.

    Args:
        config: Configuration object, holding the ``network`` section.
        ip: An IP address.

    Returns:
        Fields prefixed with ``network.``.
    """
    data = classify_ip(ip)

    if config.network.reverse_dns and data.get("network.is_routable"):
        data.update(reverse_dns(ip, timeout=config.network.dns_timeout))

    return data


def _load_bootstrap(version: int) -> list[tuple[list[str], list[str]]]:
    """Fetch and cache IANA's RDAP bootstrap registry for an address family.

    Args:
        version: 4 or 6.

    Returns:
        Pairs of (CIDR list, RDAP base URL list). Empty if the registry could
        not be fetched.
    """
    if version in _BOOTSTRAP_CACHE:
        return _BOOTSTRAP_CACHE[version]

    # Double-checked locking: enrichment is threaded, and without this every
    # worker downloads the IANA registry on first use.
    with _BOOTSTRAP_LOCK:
        if version in _BOOTSTRAP_CACHE:
            return _BOOTSTRAP_CACHE[version]

        result = http.request("rdap-bootstrap", "GET", BOOTSTRAP_URLS[version])
        if not result.ok:
            logger.warning(
                "rdap: could not fetch bootstrap registry for IPv%d", version
            )
            return []

        services = result.json().get("services", [])
        entries = [(prefixes, urls) for prefixes, urls in services]
        _BOOTSTRAP_CACHE[version] = entries
        return entries


def rdap_service_for(ip: str) -> str | None:
    """Find the RDAP service responsible for an address.

    Args:
        ip: An IP address.

    Returns:
        The base URL of the responsible RIR's RDAP service, or None.
    """
    address = ipaddress.ip_address(ip)
    best_url: str | None = None
    best_length = -1

    for prefixes, urls in _load_bootstrap(address.version):
        for prefix in prefixes:
            try:
                network = ipaddress.ip_network(prefix)
            except ValueError:
                continue
            # Registries overlap; the most specific prefix is authoritative.
            if address in network and network.prefixlen > best_length:
                best_length = network.prefixlen
                best_url = next((u for u in urls if u.startswith("https://")), urls[0])

    return best_url


def rdap_lookup(config: Any, ip: str) -> dict[str, Any]:
    """Query the responsible RIR's RDAP service for an address.

    RDAP is the IETF successor to port-43 WHOIS. It is free, keyless, and
    authoritative for allocation data - which registry holds the block, who is
    responsible for it, when it was allocated, and where to report abuse.

    Args:
        config: Configuration object.
        ip: An IP address.

    Returns:
        Fields prefixed with ``rdap.``.

    References:
        https://datatracker.ietf.org/doc/html/rfc7483
    """
    address = ipaddress.ip_address(ip)
    if not address.is_global:
        return {"rdap.status": "not_globally_routable"}

    service = rdap_service_for(ip)
    if service is None:
        return {"rdap.error": "no RDAP service found for this address"}

    result = http.request(
        "rdap",
        "GET",
        f"{service.rstrip('/')}/ip/{ip}",
        headers={"Accept": "application/rdap+json"},
        rate_limit=RDAP_RATE_LIMIT,
    )

    if not result.ok:
        if result.status_code == 404:
            return {"rdap.status": "not_found"}
        return {"rdap.error": result.error or f"HTTP {result.status_code}"}

    try:
        payload = result.json()
    except ValueError as exc:
        return {"rdap.error": f"invalid JSON: {exc}"}

    return _parse_rdap(payload)


def _parse_rdap(payload: dict[str, Any]) -> dict[str, Any]:
    """Reduce an RDAP response to a flat, stable set of fields.

    RIRs return the same information in noticeably different shapes, so this
    keeps only what all of them agree on.

    Args:
        payload: Decoded RDAP response.

    Returns:
        Fields prefixed with ``rdap.``.
    """
    data: dict[str, Any] = {
        "rdap.handle": payload.get("handle"),
        "rdap.name": payload.get("name"),
        "rdap.type": payload.get("type"),
        "rdap.country": payload.get("country"),
        "rdap.start_address": payload.get("startAddress"),
        "rdap.end_address": payload.get("endAddress"),
        "rdap.ip_version": payload.get("ipVersion"),
    }

    if parent := payload.get("parentHandle"):
        data["rdap.parent_handle"] = parent

    status = payload.get("status")
    if status:
        data["rdap.status"] = "|".join(str(s) for s in status)

    for event in payload.get("events") or []:
        action = event.get("eventAction")
        if action in {"registration", "last changed"}:
            key = action.replace(" ", "_")
            data[f"rdap.{key}"] = event.get("eventDate")

    abuse = _abuse_contact(payload.get("entities") or [])
    if abuse:
        data["rdap.abuse_email"] = abuse

    return data


def _abuse_contact(entities: list[dict[str, Any]]) -> str | None:
    """Find an abuse-reporting email address in RDAP entities.

    Args:
        entities: The ``entities`` array from an RDAP response.

    Returns:
        The first abuse email found, or None.
    """
    for entity in entities:
        roles = entity.get("roles") or []
        if "abuse" in roles:
            for item in entity.get("vcardArray", [None, []])[1] or []:
                if len(item) >= 4 and item[0] == "email":
                    return str(item[3])
        # Abuse contacts are frequently nested one level down.
        if nested := _abuse_contact(entity.get("entities") or []):
            return nested
    return None
