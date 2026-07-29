"""Membership in published network ranges: clouds, CDNs, Tor exits, crawlers.

Tor's exit list, AWS's ``ip-ranges.json``, GCP's ``cloud.json``, Cloudflare's
address list, Fastly's, and Google's and Bing's crawler ranges are all the same
operation - fetch a published list of CIDRs and test membership. That is one
implementation, not six.

Every source here is the operator's own published file: free, keyless, and
authoritative in a way a third-party guess about "is this a datacenter" is not.
For research the question these answer is often the real one - whether an
address is a person or a machine.

Lists are cached on disk, so a batch run costs one fetch per source rather than
one per address.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import http
from .cache import user_cache_dir

logger = logging.getLogger(__name__)

# Refetch published lists at most this often. AWS and Tor change through the
# day; a day-old answer is fine for research and a fresh fetch per run is not.
DEFAULT_TTL_SECONDS = 86_400


@dataclass(frozen=True)
class RangeSource:
    """A published list of network ranges.

    Args:
        name: Identifier used in output, e.g. ``aws``.
        url: Where the list is published.
        kind: What membership implies - ``cloud``, ``cdn``, ``tor``, or ``bot``.
        parser: Name of the function that turns the payload into CIDRs.
    """

    name: str
    url: str
    kind: str
    parser: str


SOURCES: tuple[RangeSource, ...] = (
    RangeSource(
        "aws", "https://ip-ranges.amazonaws.com/ip-ranges.json", "cloud", "aws"
    ),
    RangeSource("gcp", "https://www.gstatic.com/ipranges/cloud.json", "cloud", "gcp"),
    RangeSource("cloudflare", "https://www.cloudflare.com/ips-v4", "cdn", "lines"),
    RangeSource("fastly", "https://api.fastly.com/public-ip-list", "cdn", "fastly"),
    RangeSource("tor", "https://check.torproject.org/torbulkexitlist", "tor", "lines"),
    RangeSource(
        "googlebot",
        "https://developers.google.com/static/search/apis/ipranges/googlebot.json",
        "bot",
        "google_bot",
    ),
    RangeSource(
        "bingbot",
        "https://www.bing.com/toolbox/bingbot.json",
        "bot",
        "google_bot",
    ),
)


def _parse_aws(payload: str) -> list[str]:
    """Extract IPv4 and IPv6 prefixes from AWS's ip-ranges.json."""
    data = json.loads(payload)
    return [p["ip_prefix"] for p in data.get("prefixes", [])] + [
        p["ipv6_prefix"] for p in data.get("ipv6_prefixes", [])
    ]


def _parse_gcp(payload: str) -> list[str]:
    """Extract prefixes from Google Cloud's cloud.json."""
    data = json.loads(payload)
    out = []
    for entry in data.get("prefixes", []):
        if prefix := entry.get("ipv4Prefix") or entry.get("ipv6Prefix"):
            out.append(prefix)
    return out


def _parse_fastly(payload: str) -> list[str]:
    """Extract prefixes from Fastly's public-ip-list."""
    data = json.loads(payload)
    return list(data.get("addresses", [])) + list(data.get("ipv6_addresses", []))


def _parse_google_bot(payload: str) -> list[str]:
    """Extract prefixes from Google's and Bing's crawler range files.

    Both publish the same shape: a ``prefixes`` array of objects carrying
    either ``ipv4Prefix`` or ``ipv6Prefix``.
    """
    return _parse_gcp(payload)


def _parse_lines(payload: str) -> list[str]:
    """Read one address or CIDR per line, ignoring blanks and comments.

    Tor publishes bare addresses rather than CIDRs; those become /32 or /128.
    """
    out = []
    for raw in payload.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line)
    return out


PARSERS = {
    "aws": _parse_aws,
    "gcp": _parse_gcp,
    "fastly": _parse_fastly,
    "google_bot": _parse_google_bot,
    "lines": _parse_lines,
}


class RangeIndex:
    """Membership lookup over many networks.

    AWS alone publishes around seven thousand prefixes, so scanning every
    network for every address does not survive a real batch: ten thousand
    addresses would be seventy million comparisons. Networks are bucketed by
    their first octet, which reduces a lookup to a few dozen comparisons.
    """

    def __init__(self) -> None:
        """Create an empty index."""
        # first octet (or -1 for IPv6) -> [(network, source name, kind)]
        self._buckets: dict[int, list[tuple[Any, str, str]]] = {}
        self._sources: set[str] = set()

    def add(self, cidrs: list[str], source: str, kind: str) -> int:
        """Index a source's networks.

        Args:
            cidrs: Networks or bare addresses.
            source: Source name.
            kind: What membership implies.

        Returns:
            How many entries were indexed.
        """
        added = 0
        for cidr in cidrs:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                logger.debug("%s: skipping unparseable range %r", source, cidr)
                continue
            self._buckets.setdefault(self._bucket(network), []).append(
                (network, source, kind)
            )
            added += 1
        if added:
            self._sources.add(source)
        return added

    @staticmethod
    def _bucket(network: Any) -> int:
        """Bucket key for a network or address.

        IPv6 shares one bucket: the published v6 ranges are few enough that
        splitting them buys nothing.
        """
        if network.version == 6:
            return -1
        return int(str(network.network_address).split(".", 1)[0])

    def lookup(self, ip: str) -> list[tuple[str, str]]:
        """Find every source whose ranges contain an address.

        Args:
            ip: The address.

        Returns:
            ``(source, kind)`` pairs, possibly empty.
        """
        address = ipaddress.ip_address(ip)
        key = -1 if address.version == 6 else int(str(address).split(".", 1)[0])
        # Deduplicated: AWS publishes the same prefix once per service, so a
        # single address legitimately matches it many times.
        matches = {
            (source, kind)
            for network, source, kind in self._buckets.get(key, ())
            if address in network
        }
        return sorted(matches)

    @property
    def sources(self) -> set[str]:
        """Names of the sources indexed."""
        return set(self._sources)

    def __len__(self) -> int:
        """Total networks indexed."""
        return sum(len(v) for v in self._buckets.values())


def _cache_path(source: RangeSource) -> Path:
    """Where a source's payload is cached."""
    return user_cache_dir() / "ranges" / f"{source.name}.txt"


def _fetch(source: RangeSource, ttl: int) -> str | None:
    """Return a source's payload, from disk when recent enough.

    Args:
        source: The source to fetch.
        ttl: Seconds a cached copy stays usable.

    Returns:
        The payload, or None if it could not be obtained.
    """
    path = _cache_path(source)
    if path.exists() and (time.time() - path.stat().st_mtime) < ttl:
        return path.read_text(encoding="utf-8")

    result = http.request(f"ranges-{source.name}", "GET", source.url, timeout=60)
    if not result.ok or result.response is None:
        # A stale copy beats nothing when the publisher is briefly unreachable.
        if path.exists():
            logger.warning(
                "%s: fetch failed (%s); using cached copy",
                source.name,
                result.error or f"HTTP {result.status_code}",
            )
            return path.read_text(encoding="utf-8")
        logger.warning("%s: could not fetch range list", source.name)
        return None

    payload = result.response.text
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8")
    return payload


_INDEX: RangeIndex | None = None


def build_index(
    ttl: int = DEFAULT_TTL_SECONDS,
    sources: tuple[RangeSource, ...] | None = None,
) -> RangeIndex:
    """Fetch and index every configured source.

    Args:
        ttl: Seconds a cached list stays usable.
        sources: Sources to index. Defaults to :data:`SOURCES`, resolved at call
            time rather than bound as a default argument so the module-level
            list stays overridable.

    Returns:
        The populated index. Sources that could not be fetched are skipped
        with a warning rather than failing the run.
    """
    index = RangeIndex()
    for source in SOURCES if sources is None else sources:
        payload = _fetch(source, ttl)
        if payload is None:
            continue
        try:
            cidrs = PARSERS[source.parser](payload)
        except (ValueError, KeyError, TypeError) as exc:
            logger.warning("%s: could not parse range list: %s", source.name, exc)
            continue
        count = index.add(cidrs, source.name, source.kind)
        logger.debug("%s: indexed %d ranges", source.name, count)
    return index


def get_index(ttl: int = DEFAULT_TTL_SECONDS) -> RangeIndex:
    """Return the process-wide index, building it on first use.

    Args:
        ttl: Seconds a cached list stays usable.

    Returns:
        The shared index.
    """
    global _INDEX
    if _INDEX is None:
        _INDEX = build_index(ttl)
    return _INDEX


def reset_index() -> None:
    """Discard the cached index. Intended for tests."""
    global _INDEX
    _INDEX = None


def range_lookup(config: Any, ip: str) -> dict[str, Any]:
    """Report which published networks an address belongs to.

    Args:
        config: Configuration object holding the ``ranges`` section.
        ip: An IP address.

    Returns:
        Fields prefixed with ``ranges.``.
    """
    address = ipaddress.ip_address(ip)
    if not address.is_global:
        return {"ranges.status": "not_globally_routable"}

    matches = get_index(config.ranges.ttl_seconds).lookup(ip)
    kinds = {kind for _, kind in matches}

    data: dict[str, Any] = {
        "ranges.is_cloud": "cloud" in kinds,
        "ranges.is_cdn": "cdn" in kinds,
        "ranges.is_tor_exit": "tor" in kinds,
        "ranges.is_search_bot": "bot" in kinds,
    }

    hosts = [name for name, kind in matches if kind in {"cloud", "cdn"}]
    if hosts:
        data["ranges.hosting_provider"] = "|".join(sorted(hosts))

    bots = [name for name, kind in matches if kind == "bot"]
    if bots:
        data["ranges.bot_name"] = "|".join(sorted(bots))

    return data
