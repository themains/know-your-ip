"""Tests for configuration models and loading."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest
from pydantic import ValidationError

from know_your_ip import KnowYourIPConfig, load_config
from know_your_ip.config import (
    AbuseIPDBConfig,
    ConfigurationError,
    MaxMindConfig,
    create_default_config,
    find_config_file,
    load_from_env,
    render_default_config,
)


@pytest.fixture
def clean_env(monkeypatch):
    """Remove any KNOW_YOUR_IP_* variables inherited from the environment."""
    for key in list(os.environ):
        if key.startswith("KNOW_YOUR_IP_"):
            monkeypatch.delenv(key, raising=False)


class TestConfigModels:
    """Configuration model behavior."""

    def test_maxmind_default_path_is_resolved(self):
        """The default and an explicit './db' must resolve identically.

        Previously the validator ran only on explicit values, so the default
        stayed relative while a configured './db' became absolute - and it
        resolved against the installed package directory, not the cwd.
        """
        assert MaxMindConfig().db_path == MaxMindConfig(db_path=Path("./db")).db_path

    def test_relative_path_resolves_against_cwd(self):
        assert MaxMindConfig(db_path=Path("./db")).db_path == Path.cwd() / "db"

    def test_abuseipdb_defaults(self):
        config = AbuseIPDBConfig()

        assert config.enabled is False
        assert config.api_key is None
        assert config.days == 180

    def test_abuseipdb_days_bounded_to_api_maximum(self):
        """The AbuseIPDB API rejects maxAgeInDays above 365."""
        with pytest.raises(ValidationError):
            AbuseIPDBConfig(days=400)

    def test_placeholder_api_key_becomes_none(self):
        assert AbuseIPDBConfig(api_key="<<<YOUR_API_KEY_HERE>>>").api_key is None

    def test_real_api_key_preserved(self):
        assert AbuseIPDBConfig(api_key="valid_key_123").api_key == "valid_key_123"

    def test_unknown_key_is_rejected(self):
        """Silently ignoring unknown keys hid a stale Censys uid/secret block
        in the shipped example configuration."""
        with pytest.raises(ValidationError):
            AbuseIPDBConfig(api_kye="typo")  # type: ignore[call-arg]

    def test_timezone_disabled_by_default(self):
        """timezonefinder is a large optional dependency."""
        assert KnowYourIPConfig().timezone.enabled is False


class TestLoadConfig:
    """Loading configuration from files."""

    def test_defaults_when_no_file(self, clean_env, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        config = load_config()

        assert isinstance(config, KnowYourIPConfig)
        assert config.maxmind.enabled is True
        assert config.geonames.enabled is False
        assert config.output.columns

    def test_nonexistent_file_falls_back_to_defaults(self):
        assert isinstance(
            load_config(Path("/nonexistent/config.toml")), KnowYourIPConfig
        )

    def test_loads_toml(self, clean_env):
        toml_content = """
[maxmind]
enabled = false
db_path = "/custom/path"

[geonames]
enabled = true
username = "test_user"
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "config.toml"
            config_file.write_text(toml_content)

            config = load_config(config_file)

        assert config.maxmind.enabled is False
        # Paths are resolved, and on Windows that prepends a drive letter, so
        # compare the meaningful components rather than the literal string.
        assert config.maxmind.db_path.is_absolute()
        assert config.maxmind.db_path.parts[-2:] == ("custom", "path")
        assert config.geonames.username == "test_user"

    def test_invalid_toml_raises(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "invalid.toml"
            config_file.write_text("invalid toml content [[[")

            with pytest.raises(ConfigurationError, match="Failed to load config file"):
                load_config(config_file)

    def test_unknown_section_raises(self, clean_env):
        """A typo'd section name should fail loudly rather than be ignored."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "config.toml"
            config_file.write_text("[ipvoid]\nenabled = true\n")

            with pytest.raises(ConfigurationError, match="validation failed"):
                load_config(config_file)


class TestEnvironmentConfig:
    """Environment variable overrides."""

    def test_empty_when_unset(self, clean_env):
        assert load_from_env() == {}

    def test_reads_values(self, clean_env, monkeypatch):
        monkeypatch.setenv("KNOW_YOUR_IP_MAXMIND_ENABLED", "false")
        monkeypatch.setenv("KNOW_YOUR_IP_GEONAMES_USERNAME", "test_user")
        monkeypatch.setenv("KNOW_YOUR_IP_ABUSEIPDB_DAYS", "30")

        config = load_from_env()

        assert config["maxmind"]["enabled"] is False
        assert config["geonames"]["username"] == "test_user"
        assert config["abuseipdb"]["days"] == 30

    def test_multi_word_field_names(self, clean_env, monkeypatch, tmp_path):
        """Splitting on the first underscore mangles fields like API_KEY."""
        monkeypatch.setenv("KNOW_YOUR_IP_VIRUSTOTAL_API_KEY", "secret")
        monkeypatch.setenv("KNOW_YOUR_IP_MAXMIND_DB_PATH", str(tmp_path / "db"))

        config = load_from_env()

        assert config["virustotal"]["api_key"] == "secret"
        assert config["maxmind"]["db_path"] == str(tmp_path / "db")

    def test_unknown_variable_ignored_with_warning(
        self, clean_env, monkeypatch, caplog
    ):
        """Unrecognized variables used to vanish silently."""
        monkeypatch.setenv("KNOW_YOUR_IP_NOSUCHSECTION_FIELD", "x")

        assert load_from_env() == {}
        assert "unrecognized" in caplog.text.lower()

    def test_unknown_field_ignored_with_warning(self, clean_env, monkeypatch, caplog):
        monkeypatch.setenv("KNOW_YOUR_IP_VIRUSTOTAL_NOSUCHFIELD", "x")

        assert load_from_env() == {}
        assert "not a field" in caplog.text

    def test_env_overrides_file(self, clean_env, monkeypatch):
        monkeypatch.setenv("KNOW_YOUR_IP_GEONAMES_USERNAME", "from_env")
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "config.toml"
            config_file.write_text('[geonames]\nusername = "from_file"\n')

            assert load_config(config_file).geonames.username == "from_env"


class TestConfigUtils:
    """Configuration file discovery and generation."""

    def test_find_config_file_returns_none_in_empty_dir(self, monkeypatch, tmp_path):
        """Previously asserted 'None or Path', which cannot fail."""
        monkeypatch.chdir(tmp_path)
        # Path.home() reads USERPROFILE on Windows, so setting HOME is not
        # enough; patch the function the code actually calls.
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))

        assert find_config_file() is None

    def test_find_config_file_finds_cwd_file(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        expected = tmp_path / "know_your_ip.toml"
        expected.write_text("")

        assert find_config_file() == expected

    def test_create_default_config(self, tmp_path):
        config_path = tmp_path / "test_config.toml"
        create_default_config(config_path)

        content = config_path.read_text()

        assert "[maxmind]" in content
        assert "[geonames]" in content

    def test_generated_config_is_valid_and_matches_defaults(self, clean_env, tmp_path):
        """The generated file is rendered from the models, so it cannot drift
        from them the way the previous hardcoded string had."""
        config_path = tmp_path / "generated.toml"
        create_default_config(config_path)

        loaded = load_config(config_path)

        assert loaded.output.columns == KnowYourIPConfig().output.columns

    def test_generated_config_has_no_removed_sections(self):
        rendered = render_default_config()

        assert "[ipvoid]" not in rendered
        assert "[tzwhere]" not in rendered
