"""Provider registry.

Each data source is described once, here, rather than as another ``if
config.x.enabled:`` branch inside ``query_ip``. A provider declares what it
costs, whether it needs a key, and - importantly - whether it can answer a
question about a date in the past.

The ``as_of`` parameter exists from the outset even though no provider honors
it yet. The failure mode worth designing out is a provider quietly returning
today's answer when asked about 2019: a result that looks historical and is
not. A provider either honors ``as_of`` or declines, and never substitutes.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date
from typing import Any, Literal

from .config import KnowYourIPConfig

logger = logging.getLogger(__name__)

Cost = Literal["free", "freemium", "paid"]

# A provider's fetch signature. as_of is passed positionally by the registry so
# that providers gaining historical support later need no call-site changes.
FetchFn = Callable[..., dict[str, Any]]


@dataclass(frozen=True)
class Provider:
    """A registered data source.

    Args:
        name: Short identifier, also the prefix on every field it returns and
            the key used for rate limiting and caching.
        fetch: Callable taking ``(config, ip)`` and returning a flat dict of
            ``name.field`` keys.
        section: Attribute on :class:`KnowYourIPConfig` holding this provider's
            settings. Must expose ``enabled``.
        cost: Whether the source is free, freemium, or paid.
        requires_key: Whether an API key is needed at all.
        supports_as_of: Whether ``fetch`` accepts an ``as_of`` date and returns
            data for that date rather than for now.
        needs_coordinates: Whether the provider takes a latitude/longitude
            pair instead of an IP address.
    """

    name: str
    fetch: FetchFn
    section: str
    cost: Cost = "free"
    requires_key: bool = False
    supports_as_of: bool = False
    needs_coordinates: bool = False

    def is_enabled(self, config: KnowYourIPConfig) -> bool:
        """Whether this provider is turned on in ``config``.

        Args:
            config: Configuration object.

        Returns:
            True if the provider's section exists and is enabled.
        """
        section = getattr(config, self.section, None)
        return bool(getattr(section, "enabled", False))


@dataclass
class Registry:
    """An ordered collection of providers."""

    providers: list[Provider] = field(default_factory=list)

    def register(self, provider: Provider) -> Provider:
        """Add a provider, replacing any existing one with the same name.

        Args:
            provider: The provider to add.

        Returns:
            The provider, so this can be used as a decorator-style helper.
        """
        self.providers = [p for p in self.providers if p.name != provider.name]
        self.providers.append(provider)
        return provider

    def get(self, name: str) -> Provider | None:
        """Look up a provider by name.

        Args:
            name: Provider name.

        Returns:
            The provider, or None if it is not registered.
        """
        return next((p for p in self.providers if p.name == name), None)

    def enabled(self, config: KnowYourIPConfig) -> list[Provider]:
        """Providers turned on in ``config``, in registration order.

        Args:
            config: Configuration object.

        Returns:
            The enabled providers.
        """
        return [p for p in self.providers if p.is_enabled(config)]

    def selected(
        self, config: KnowYourIPConfig, names: list[str] | None = None
    ) -> list[Provider]:
        """Providers to run for a query.

        Args:
            config: Configuration object.
            names: Explicit provider names. When given, these are used instead
                of the ``enabled`` flags, so a caller can ask for a source
                without editing configuration.

        Returns:
            The providers to run.

        Raises:
            KeyError: If a requested name is not registered.
        """
        if names is None:
            return self.enabled(config)

        chosen = []
        for name in names:
            provider = self.get(name)
            if provider is None:
                known = ", ".join(sorted(p.name for p in self.providers))
                raise KeyError(f"Unknown provider {name!r}. Registered: {known}")
            chosen.append(provider)
        return chosen

    def for_as_of(
        self, providers: list[Provider], as_of: date | None
    ) -> list[Provider]:
        """Filter providers to those that can answer for ``as_of``.

        Args:
            providers: Candidate providers.
            as_of: The date being asked about, or None for current data.

        Returns:
            The providers able to answer. When ``as_of`` is set, providers that
            cannot are dropped with a warning rather than silently returning
            present-day data under a historical label.
        """
        if as_of is None:
            return providers

        usable, skipped = [], []
        for provider in providers:
            (usable if provider.supports_as_of else skipped).append(provider)

        if skipped:
            logger.warning(
                "as_of=%s requested; skipping providers with no historical support: %s",
                as_of,
                ", ".join(p.name for p in skipped),
            )
        return usable


REGISTRY = Registry()


def build_default_registry() -> Registry:
    """Register the built-in providers.

    Imported lazily to avoid a circular import: the provider implementations
    live in :mod:`know_your_ip.core`, which imports this module.

    Returns:
        The populated registry.
    """
    from . import core, network, ranges

    for provider in [
        Provider(
            name="network",
            fetch=network.network_info,
            section="network",
            cost="free",
        ),
        Provider(
            name="ranges",
            fetch=ranges.range_lookup,
            section="ranges",
            cost="free",
        ),
        Provider(
            name="rdap",
            fetch=network.rdap_lookup,
            section="rdap",
            cost="free",
        ),
        Provider(
            name="maxmind",
            fetch=core.maxmind_geocode_ip,
            section="maxmind",
            cost="free",
        ),
        Provider(
            name="abuseipdb",
            fetch=core.abuseipdb_api,
            section="abuseipdb",
            cost="freemium",
            requires_key=True,
        ),
        Provider(
            name="virustotal",
            fetch=core.virustotal_api,
            section="virustotal",
            cost="freemium",
            requires_key=True,
        ),
        Provider(
            name="censys",
            fetch=core.censys_api,
            section="censys",
            cost="freemium",
            requires_key=True,
        ),
        Provider(
            name="shodan",
            fetch=core.shodan_api,
            section="shodan",
            cost="paid",
            requires_key=True,
        ),
        Provider(
            name="apivoid",
            fetch=core.apivoid_api,
            section="apivoid",
            cost="paid",
            requires_key=True,
        ),
        Provider(name="ping", fetch=core.ping, section="ping", cost="free"),
        Provider(
            name="traceroute",
            fetch=core.traceroute,
            section="traceroute",
            cost="free",
        ),
        Provider(
            name="geonames",
            fetch=core.geonames_timezone,
            section="geonames",
            cost="freemium",
            requires_key=True,
            needs_coordinates=True,
        ),
    ]:
        REGISTRY.register(provider)

    return REGISTRY
