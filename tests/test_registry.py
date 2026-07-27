"""Tests for the provider registry and the as_of contract."""

from __future__ import annotations

from datetime import date

import pytest

from know_your_ip import KnowYourIPConfig
from know_your_ip.providers import REGISTRY, Provider, Registry


def _stub(name: str, **kwargs) -> Provider:
    """Build a provider whose fetch records the call."""
    return Provider(
        name=name,
        fetch=kwargs.pop("fetch", lambda config, ip: {f"{name}.ok": True}),
        section=kwargs.pop("section", name),
        **kwargs,
    )


@pytest.fixture
def config() -> KnowYourIPConfig:
    return KnowYourIPConfig()


class TestRegistry:
    def test_register_and_get(self):
        registry = Registry()
        provider = _stub("alpha")

        registry.register(provider)

        assert registry.get("alpha") is provider

    def test_register_replaces_same_name(self):
        """Re-registering a name overrides it rather than duplicating."""
        registry = Registry()
        registry.register(_stub("alpha"))
        replacement = _stub("alpha", cost="paid")

        registry.register(replacement)

        assert registry.providers == [replacement]

    def test_get_unknown_returns_none(self):
        assert Registry().get("nope") is None

    def test_enabled_reflects_config(self, config):
        registry = Registry()
        registry.register(_stub("maxmind", section="maxmind"))
        registry.register(_stub("shodan", section="shodan"))

        names = [p.name for p in registry.enabled(config)]

        # maxmind is on by default, shodan is not.
        assert names == ["maxmind"]

    def test_selected_overrides_enabled_flags(self, config):
        """Naming a provider runs it without editing configuration."""
        registry = Registry()
        registry.register(_stub("shodan", section="shodan"))

        assert [p.name for p in registry.selected(config, ["shodan"])] == ["shodan"]

    def test_selected_rejects_unknown_name(self, config):
        registry = Registry()
        registry.register(_stub("alpha"))

        with pytest.raises(KeyError, match="Unknown provider"):
            registry.selected(config, ["typo"])

    def test_selected_error_lists_known_names(self, config):
        registry = Registry()
        registry.register(_stub("alpha"))

        with pytest.raises(KeyError, match="alpha"):
            registry.selected(config, ["typo"])


class TestAsOfContract:
    """A provider must never answer a historical question with current data."""

    def test_no_as_of_keeps_everything(self):
        registry = Registry()
        providers = [_stub("a"), _stub("b")]

        assert registry.for_as_of(providers, None) == providers

    def test_as_of_drops_providers_without_support(self):
        registry = Registry()
        current_only = _stub("current")
        historical = _stub("historical", supports_as_of=True)

        usable = registry.for_as_of([current_only, historical], date(2019, 3, 14))

        assert [p.name for p in usable] == ["historical"]

    def test_dropped_providers_are_reported(self, caplog):
        """Silently dropping them would look like the source had no data."""
        registry = Registry()

        registry.for_as_of([_stub("current")], date(2019, 3, 14))

        assert "current" in caplog.text
        assert "historical support" in caplog.text

    def test_every_builtin_declares_no_historical_support_yet(self):
        """Guards against a provider claiming as_of support it lacks."""
        assert [p.name for p in REGISTRY.providers if p.supports_as_of] == []


class TestDefaultRegistry:
    def test_all_expected_providers_registered(self):
        names = {p.name for p in REGISTRY.providers}

        assert names == {
            "maxmind",
            "abuseipdb",
            "virustotal",
            "censys",
            "shodan",
            "apivoid",
            "ping",
            "traceroute",
            "geonames",
        }

    def test_sections_exist_on_config(self, config):
        """A typo'd section would silently disable the provider."""
        for provider in REGISTRY.providers:
            assert hasattr(config, provider.section), provider.name

    def test_keyless_providers_are_marked_free(self):
        for provider in REGISTRY.providers:
            if not provider.requires_key:
                assert provider.cost == "free", provider.name

    def test_geonames_is_the_only_coordinate_provider(self):
        coordinate = [p.name for p in REGISTRY.providers if p.needs_coordinates]

        assert coordinate == ["geonames"]
