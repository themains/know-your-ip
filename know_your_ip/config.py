"""Modern configuration system using Pydantic for validation and type safety."""

from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator


class MaxMindConfig(BaseModel):
    """MaxMind GeoIP configuration."""

    enabled: bool = True
    db_path: Path = Path("./db")

    @field_validator("db_path", mode="before")
    @classmethod
    def resolve_db_path(cls, v: str | Path) -> Path:
        """Resolve relative paths to absolute paths."""
        path = Path(v)
        if not path.is_absolute():
            # If relative, make it relative to package directory
            package_dir = Path(__file__).parent
            path = package_dir / path
        return path


class GeoNamesConfig(BaseModel):
    """GeoNames.org configuration."""

    enabled: bool = False
    username: str | None = None

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str | None) -> str | None:
        """Validate that username is provided if enabled."""
        if v and v.startswith("<<<"):
            return None  # Placeholder value
        return v


class AbuseIPDBConfig(BaseModel):
    """AbuseIPDB configuration."""

    enabled: bool = False
    api_key: str | None = None
    days: int = 180

    @field_validator("api_key")
    @classmethod
    def validate_api_key(cls, v: str | None) -> str | None:
        """Validate that API key is provided if enabled."""
        if v and v.startswith("<<<"):
            return None  # Placeholder value
        return v


class PingConfig(BaseModel):
    """Ping configuration."""

    enabled: bool = False
    timeout: int = 3000
    count: int = 3


class TracerouteConfig(BaseModel):
    """Traceroute configuration."""

    enabled: bool = False
    max_hops: int = 30


class TzwhereConfig(BaseModel):
    """tzwhere configuration."""

    enabled: bool = True


class IPVoidConfig(BaseModel):
    """IPVoid configuration."""

    enabled: bool = True


class APIVoidConfig(BaseModel):
    """APIVoid configuration."""

    enabled: bool = False
    api_key: str | None = None

    @field_validator("api_key")
    @classmethod
    def validate_api_key(cls, v: str | None) -> str | None:
        """Validate that API key is provided if enabled."""
        if v and v.startswith("<<<"):
            return None  # Placeholder value
        return v


class CensysConfig(BaseModel):
    """Censys Platform API configuration.

    Note: Legacy Censys Search v1/v2 APIs are deprecated as of 2025.
    This uses the new Censys Platform API.
    """

    enabled: bool = False
    api_url: str = "https://search.censys.io/api"
    api_key: str | None = None

    @field_validator("api_key")
    @classmethod
    def validate_api_key(cls, v: str | None) -> str | None:
        """Validate that API key is provided if enabled."""
        if v and v.startswith("<<<"):
            return None  # Placeholder value
        return v


class ShodanConfig(BaseModel):
    """Shodan configuration."""

    enabled: bool = False
    api_key: str | None = None

    @field_validator("api_key")
    @classmethod
    def validate_api_key(cls, v: str | None) -> str | None:
        """Validate that API key is provided if enabled."""
        if v and v.startswith("<<<"):
            return None  # Placeholder value
        return v


class VirusTotalConfig(BaseModel):
    """VirusTotal configuration."""

    enabled: bool = False
    api_key: str | None = None

    @field_validator("api_key")
    @classmethod
    def validate_api_key(cls, v: str | None) -> str | None:
        """Validate that API key is provided if enabled."""
        if v and v.startswith("<<<"):
            return None  # Placeholder value
        return v


class OutputConfig(BaseModel):
    """Output configuration."""

    columns: list[str] = Field(
        default=[
            "ip",
            "maxmind.continent.names.en",
            "maxmind.country.names.en",
            "maxmind.location.time_zone",
            "maxmind.postal.code",
            "maxmind.registered_country.names.en",
            "tzwhere.timezone",
            "abuseipdb.bad_isp",
            "abuseipdb.categories",
            "ipvoid.blacklist_status",
            "ipvoid.reverse_dns",
            "apivoid.anonymity.is_hosting",
            "apivoid.anonymity.is_proxy",
            "apivoid.anonymity.is_tor",
            "apivoid.anonymity.is_vpn",
            "apivoid.anonymity.is_webproxy",
            "apivoid.blacklists.detection_rate",
            "apivoid.blacklists.detections",
            "apivoid.blacklists.engines_count",
            "apivoid.blacklists.scantime",
            "apivoid.information.city_name",
            "apivoid.information.continent_code",
            "apivoid.information.continent_name",
            "apivoid.information.country_calling_code",
            "apivoid.information.country_code",
            "apivoid.information.country_currency",
            "apivoid.information.country_name",
            "apivoid.information.isp",
            "apivoid.information.latitude",
            "apivoid.information.longitude",
            "apivoid.information.region_name",
            "apivoid.information.reverse_dns",
            "shodan.asn",
            "shodan.isp",
            "shodan.vulns",
            "shodan.os",
            "shodan.ports",
        ]
    )


class KnowYourIPConfig(BaseModel):
    """Main configuration for Know Your IP."""

    maxmind: MaxMindConfig = MaxMindConfig()
    geonames: GeoNamesConfig = GeoNamesConfig()
    abuseipdb: AbuseIPDBConfig = AbuseIPDBConfig()
    ping: PingConfig = PingConfig()
    traceroute: TracerouteConfig = TracerouteConfig()
    tzwhere: TzwhereConfig = TzwhereConfig()
    ipvoid: IPVoidConfig = IPVoidConfig()
    apivoid: APIVoidConfig = APIVoidConfig()
    censys: CensysConfig = CensysConfig()
    shodan: ShodanConfig = ShodanConfig()
    virustotal: VirusTotalConfig = VirusTotalConfig()
    output: OutputConfig = OutputConfig()


def load_from_env() -> dict[str, Any]:
    """Load configuration from environment variables.

    Environment variables should follow the pattern:
    KNOW_YOUR_IP_<SECTION>_<KEY>=value

    Examples:
        KNOW_YOUR_IP_MAXMIND_ENABLED=true
        KNOW_YOUR_IP_GEONAMES_USERNAME=myusername
        KNOW_YOUR_IP_ABUSEIPDB_API_KEY=myapikey
    """
    config = {}
    prefix = "KNOW_YOUR_IP_"

    for key, value in os.environ.items():
        if not key.startswith(prefix):
            continue

        # Remove prefix and split into section and field
        config_key = key[len(prefix) :].lower()
        parts = config_key.split("_", 1)

        if len(parts) != 2:
            continue

        section, field = parts

        # Convert string values to appropriate types
        match value.lower():
            case "true" | "1" | "yes" | "on":
                value = True
            case "false" | "0" | "no" | "off":
                value = False
            case _ if value.isdigit():
                value = int(value)

        # Create nested dict structure
        if section not in config:
            config[section] = {}
        config[section][field] = value

    return config


def find_config_file() -> Path | None:
    """Find configuration file in standard locations.

    Search order:
    1. ./know_your_ip.toml (current directory)
    2. ~/.config/know-your-ip/config.toml (XDG config)
    3. ~/.know-your-ip.toml (home directory)
    """
    candidates = [
        Path.cwd() / "know_your_ip.toml",
        Path.home() / ".config" / "know-your-ip" / "config.toml",
        Path.home() / ".know-your-ip.toml",
    ]

    for candidate in candidates:
        if candidate.exists():
            return candidate

    return None


def load_config(config_file: Path | None = None) -> KnowYourIPConfig:
    """Load configuration from multiple sources with proper validation.

    Sources are loaded in this order (later sources override earlier ones):
    1. Default configuration (embedded in code)
    2. Configuration file (TOML format)
    3. Environment variables

    Args:
        config_file: Path to configuration file. If None, will search standard locations.

    Returns:
        Validated configuration object.

    Raises:
        ConfigurationError: If configuration is invalid.
    """
    config_dict = {}

    # Load from file if provided or found
    if config_file is None:
        config_file = find_config_file()

    if config_file and config_file.exists():
        try:
            with open(config_file, "rb") as f:
                file_config = tomllib.load(f)
                config_dict.update(file_config)
        except (OSError, tomllib.TOMLDecodeError) as e:
            raise ConfigurationError(
                f"Failed to load config file {config_file}: {e}"
            ) from e

    # Override with environment variables
    env_config = load_from_env()
    for section, values in env_config.items():
        if section not in config_dict:
            config_dict[section] = {}
        config_dict[section].update(values)

    # Validate and return typed config
    try:
        return KnowYourIPConfig(**config_dict)
    except Exception as e:
        raise ConfigurationError(f"Configuration validation failed: {e}") from e


def create_default_config(output_file: Path) -> None:
    """Create a default configuration file with sensible defaults."""

    toml_content = """# Know Your IP Configuration
# See https://github.com/themains/know-your-ip for documentation

[maxmind]
enabled = true
db_path = "./db"

[geonames]
enabled = false
# username = "your_username_here"  # Register at http://www.geonames.org/login

[abuseipdb]
enabled = false
# api_key = "your_api_key_here"  # Register at https://www.abuseipdb.com/register
days = 180

[ping]
enabled = false
timeout = 3000
count = 3

[traceroute]
enabled = false
max_hops = 30

[tzwhere]
enabled = true

[ipvoid]
enabled = true

[apivoid]
enabled = false
# api_key = "your_api_key_here"  # Register at https://app.apivoid.com/register

[censys]
enabled = false
api_url = "https://search.censys.io/api"
# api_key = "your_api_key_here"  # Register at https://search.censys.io/register

[shodan]
enabled = false
# api_key = "your_api_key_here"  # Register at https://account.shodan.io/register

[virustotal]
enabled = false
# api_key = "your_api_key_here"  # Register at https://www.virustotal.com/

[output]
columns = [
    "ip",
    "maxmind.continent.names.en",
    "maxmind.country.names.en",
    "maxmind.location.time_zone",
    "maxmind.postal.code",
    "maxmind.registered_country.names.en",
    "tzwhere.timezone",
    "abuseipdb.bad_isp",
    "abuseipdb.categories",
    "ipvoid.blacklist_status",
    "ipvoid.reverse_dns",
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
"""

    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(toml_content)


class ConfigurationError(Exception):
    """Configuration-related errors."""

    pass
