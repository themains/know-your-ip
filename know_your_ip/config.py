"""Configuration models and loading for know_your_ip."""

from __future__ import annotations

import logging
import os
import tomllib
from pathlib import Path
from typing import Annotated, Any

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field

logger = logging.getLogger(__name__)


class ConfigurationError(Exception):
    """Raised when configuration cannot be loaded or fails validation."""


def _blank_placeholder(v: str | None) -> str | None:
    """Treat an unedited template placeholder as an unset value.

    Args:
        v: A configured secret, or None.

    Returns:
        None if ``v`` is a ``<<<...>>>`` placeholder, otherwise ``v``.
    """
    if isinstance(v, str) and v.startswith("<<<"):
        return None
    return v


# A secret that may be left as a `<<<PLACEHOLDER>>>` in a generated config.
Secret = Annotated[str | None, BeforeValidator(_blank_placeholder)]


class _Section(BaseModel):
    """Base for configuration sections; rejects unknown keys."""

    model_config = ConfigDict(extra="forbid")


def _resolve_path(v: str | Path) -> Path:
    """Resolve a possibly-relative path against the current working directory.

    Args:
        v: A path from configuration.

    Returns:
        An absolute path.
    """
    return Path(v).expanduser().resolve()


class MaxMindConfig(_Section):
    """MaxMind GeoLite2 configuration.

    Note:
        Relative ``db_path`` values resolve against the current working
        directory. Anonymous GeoLite2 downloads ended in 2019; a MaxMind
        account and license key are required to obtain the database.
    """

    enabled: bool = True
    # validate_default so the default and an explicitly configured "./db"
    # resolve identically; previously only the latter was made absolute.
    db_path: Annotated[Path, BeforeValidator(_resolve_path)] = Field(
        default=Path("./db"), validate_default=True
    )


class GeoNamesConfig(_Section):
    """GeoNames.org configuration.

    Note:
        Free tier is 10,000 credits/day and 1,000/hour. The account must
        separately enable the free web service.
    """

    enabled: bool = False
    username: Secret = None


class AbuseIPDBConfig(_Section):
    """AbuseIPDB configuration.

    Note:
        ``days`` is the report lookback window; the API maximum is 365.
    """

    enabled: bool = False
    api_key: Secret = None
    days: int = Field(default=180, ge=1, le=365)


class PingConfig(_Section):
    """ICMP ping configuration."""

    enabled: bool = False
    timeout: int = Field(default=3000, ge=1, description="Milliseconds")
    count: int = Field(default=3, ge=1)


class TracerouteConfig(_Section):
    """Traceroute configuration."""

    enabled: bool = False
    max_hops: int = Field(default=30, ge=1, le=255)


class TimezoneConfig(_Section):
    """Offline timezone lookup configuration.

    Note:
        Requires the ``timezone`` extra, which pulls in ``timezonefinder``.
        That package is large and ships wheels only for linux-x86_64, so it is
        off by default. MaxMind's City database already reports
        ``location.time_zone``; enable this for an independent cross-check.

        Replaces the abandoned ``tzwhere`` package, which is incompatible with
        NumPy 1.24 and later.
    """

    enabled: bool = False


class NetworkConfig(_Section):
    """Keyless address classification and reverse DNS.

    Note:
        Classification is offline and free. It also identifies addresses that
        are not globally routable, which are worth skipping before spending
        metered quota on them.
    """

    enabled: bool = True
    reverse_dns: bool = True
    dns_timeout: float = Field(default=5.0, gt=0)


class RangesConfig(_Section):
    """Membership in published network ranges.

    Note:
        Sources are the operators' own published files - AWS, GCP, Cloudflare,
        Fastly, the Tor Project, Google, and Bing. Free, keyless, and fetched
        at most once per TTL rather than once per address.
    """

    enabled: bool = True
    ttl_seconds: int = Field(default=86_400, ge=60)


class RDAPConfig(_Section):
    """Registry data via RDAP, the IETF successor to port-43 WHOIS.

    Note:
        Free and keyless. Gives the responsible registry, allocation dates,
        and an abuse contact.
    """

    enabled: bool = True


class APIVoidConfig(_Section):
    """APIVoid IP reputation configuration.

    Note:
        Uses API v2. There is no permanent free tier.
    """

    enabled: bool = False
    api_key: Secret = None


class CensysConfig(_Section):
    """Censys Platform API configuration.

    Note:
        Legacy Search (``search.censys.io``) was disabled for free accounts in
        March 2025 and is fully deprecated in September 2026. ``api_key`` is a
        Personal Access Token. ``organization_id`` should be left unset on the
        free tier.
    """

    enabled: bool = False
    api_url: str = "https://api.platform.censys.io"
    api_key: Secret = None
    organization_id: Secret = None


class ShodanConfig(_Section):
    """Shodan configuration.

    Note:
        IP lookups require a paid membership; free API keys cannot call the
        host endpoint. Requires the ``shodan`` optional dependency.
    """

    enabled: bool = False
    api_key: Secret = None


class VirusTotalConfig(_Section):
    """VirusTotal API v3 configuration.

    Note:
        Public API limits are 500 requests/day and 4 requests/minute.
    """

    enabled: bool = False
    api_key: Secret = None


DEFAULT_OUTPUT_COLUMNS = [
    "ip",
    "network.version",
    "network.category",
    "network.is_routable",
    "network.reverse_dns",
    "rdap.handle",
    "rdap.name",
    "rdap.country",
    "rdap.registration",
    "rdap.abuse_email",
    "maxmind.continent.names.en",
    "maxmind.country.names.en",
    "maxmind.city.names.en",
    "maxmind.location.latitude",
    "maxmind.location.longitude",
    "maxmind.location.time_zone",
    "maxmind.postal.code",
    "maxmind.registered_country.names.en",
    "timezone.name",
    "abuseipdb.abuse_confidence_score",
    "abuseipdb.categories",
    "abuseipdb.country_code",
    "abuseipdb.isp",
    "abuseipdb.usage_type",
    "abuseipdb.total_reports",
    "abuseipdb.is_tor",
    "virustotal.harmless",
    "virustotal.malicious",
    "virustotal.suspicious",
    "virustotal.reputation",
    "virustotal.asn",
    "virustotal.as_owner",
    "virustotal.country",
    "virustotal.network",
    "virustotal.rir",
    "virustotal.tags",
    "censys.asn",
    "censys.as_name",
    "censys.bgp_prefix",
    "censys.country",
    "censys.city",
    "censys.latitude",
    "censys.longitude",
    "censys.ports",
    "censys.services",
    "censys.transport_protocols",
    "censys.whois_handle",
    "censys.whois_abuse_email",
    "censys.last_scan_time",
    "apivoid.anonymity.is_hosting",
    "apivoid.anonymity.is_proxy",
    "apivoid.anonymity.is_tor",
    "apivoid.anonymity.is_vpn",
    "apivoid.anonymity.is_webproxy",
    "apivoid.blacklists.detection_rate",
    "apivoid.blacklists.detections",
    "shodan.asn",
    "shodan.isp",
    "shodan.vulns",
    "shodan.os",
    "shodan.ports",
]


class OutputConfig(_Section):
    """Output column selection for CSV writing.

    Note:
        This list controls the CSV written by the command line interface only.
        :func:`know_your_ip.query_ip` always returns every field it collected.
    """

    columns: list[str] = Field(default_factory=lambda: list(DEFAULT_OUTPUT_COLUMNS))


class KnowYourIPConfig(BaseModel):
    """Top-level configuration."""

    model_config = ConfigDict(extra="forbid")

    maxmind: MaxMindConfig = Field(default_factory=MaxMindConfig)
    geonames: GeoNamesConfig = Field(default_factory=GeoNamesConfig)
    abuseipdb: AbuseIPDBConfig = Field(default_factory=AbuseIPDBConfig)
    ping: PingConfig = Field(default_factory=PingConfig)
    traceroute: TracerouteConfig = Field(default_factory=TracerouteConfig)
    timezone: TimezoneConfig = Field(default_factory=TimezoneConfig)
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    rdap: RDAPConfig = Field(default_factory=RDAPConfig)
    ranges: RangesConfig = Field(default_factory=RangesConfig)
    apivoid: APIVoidConfig = Field(default_factory=APIVoidConfig)
    censys: CensysConfig = Field(default_factory=CensysConfig)
    shodan: ShodanConfig = Field(default_factory=ShodanConfig)
    virustotal: VirusTotalConfig = Field(default_factory=VirusTotalConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)


ENV_PREFIX = "KNOW_YOUR_IP_"


def load_from_env() -> dict[str, Any]:
    """Read configuration overrides from environment variables.

    Variables are named ``KNOW_YOUR_IP_<SECTION>_<FIELD>``. Section names are
    matched against the known sections so that a field name containing an
    underscore (``API_KEY``, ``DB_PATH``) is split correctly, and an
    unrecognized variable produces a warning rather than being dropped.

    Returns:
        A nested dict suitable for validation by :class:`KnowYourIPConfig`.

    Example:
        ``KNOW_YOUR_IP_VIRUSTOTAL_API_KEY=abc`` becomes
        ``{"virustotal": {"api_key": "abc"}}``.
    """
    sections = set(KnowYourIPConfig.model_fields)
    config: dict[str, Any] = {}

    for key, raw in os.environ.items():
        if not key.startswith(ENV_PREFIX):
            continue

        remainder = key[len(ENV_PREFIX) :].lower()
        section = next(
            (s for s in sections if remainder.startswith(f"{s}_")),
            None,
        )
        if section is None:
            logger.warning("Ignoring unrecognized environment variable %s", key)
            continue

        field = remainder[len(section) + 1 :]
        model = KnowYourIPConfig.model_fields[section].annotation
        if field not in getattr(model, "model_fields", {}):
            logger.warning(
                "Ignoring %s: %r is not a field of [%s]", key, field, section
            )
            continue

        config.setdefault(section, {})[field] = _coerce(raw)

    return config


def _coerce(value: str) -> str | bool | int:
    """Convert an environment variable string to bool or int where obvious.

    Args:
        value: Raw environment variable value.

    Returns:
        The converted value, or the original string.
    """
    match value.lower():
        case "true" | "1" | "yes" | "on":
            return True
        case "false" | "0" | "no" | "off":
            return False
        case _:
            return int(value) if value.lstrip("-").isdigit() else value


def find_config_file() -> Path | None:
    """Find a configuration file in the standard locations.

    Search order is ``./know_your_ip.toml``, then
    ``~/.config/know-your-ip/config.toml``, then ``~/.know-your-ip.toml``.

    Returns:
        The first path that exists, or None.
    """
    candidates = [
        Path.cwd() / "know_your_ip.toml",
        Path.home() / ".config" / "know-your-ip" / "config.toml",
        Path.home() / ".know-your-ip.toml",
    ]
    return next((c for c in candidates if c.exists()), None)


def load_config(config_file: Path | None = None) -> KnowYourIPConfig:
    """Load configuration from a TOML file and environment variables.

    Defaults are overridden by the file, which is overridden by environment
    variables.

    Args:
        config_file: Path to a configuration file. If None, standard locations
            are searched.

    Returns:
        A validated configuration object.

    Raises:
        ConfigurationError: If the file cannot be read or validation fails.
    """
    config_dict: dict[str, Any] = {}

    if config_file is None:
        config_file = find_config_file()

    if config_file and config_file.exists():
        try:
            with open(config_file, "rb") as f:
                config_dict.update(tomllib.load(f))
        except (OSError, tomllib.TOMLDecodeError) as e:
            raise ConfigurationError(
                f"Failed to load config file {config_file}: {e}"
            ) from e

    for section, values in load_from_env().items():
        config_dict.setdefault(section, {}).update(values)

    try:
        return KnowYourIPConfig(**config_dict)
    except Exception as e:
        raise ConfigurationError(f"Configuration validation failed: {e}") from e


def render_default_config() -> str:
    """Render a commented default configuration file.

    The service sections and the output column list are generated from the
    models, so this cannot drift from :class:`KnowYourIPConfig`.

    Returns:
        TOML text.
    """
    registration = {
        "geonames": "https://www.geonames.org/login",
        "abuseipdb": "https://www.abuseipdb.com/register",
        "apivoid": "https://app.apivoid.com/register",
        "censys": "https://platform.censys.io/",
        "shodan": "https://account.shodan.io/register",
        "virustotal": "https://www.virustotal.com/gui/join-us",
    }

    lines = [
        "# Know Your IP configuration",
        "# See https://github.com/themains/know-your-ip",
        "",
    ]

    for name, field in KnowYourIPConfig.model_fields.items():
        if name == "output":
            continue
        model = field.annotation
        if not (isinstance(model, type) and issubclass(model, BaseModel)):
            continue
        lines.append(f"[{name}]")
        for fname, finfo in model.model_fields.items():
            default = finfo.get_default(call_default_factory=True)
            if fname in {"api_key", "username", "organization_id"}:
                url = registration.get(name)
                hint = f"  # Register at {url}" if url else ""
                lines.append(f'# {fname} = "your_value_here"{hint}')
            elif isinstance(default, bool):
                lines.append(f"{fname} = {str(default).lower()}")
            elif isinstance(default, Path):
                lines.append(f'{fname} = "./db"')
            elif isinstance(default, str):
                lines.append(f'{fname} = "{default}"')
            else:
                lines.append(f"{fname} = {default}")
        lines.append("")

    lines.append("[output]")
    lines.append("columns = [")
    lines.extend(f'    "{c}",' for c in DEFAULT_OUTPUT_COLUMNS)
    lines.append("]")
    lines.append("")

    return "\n".join(lines)


def create_default_config(output_file: Path) -> None:
    """Write a default configuration file.

    Args:
        output_file: Destination path. Parent directories are created.
    """
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(render_default_config(), encoding="utf-8")
