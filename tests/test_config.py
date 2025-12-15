"""Tests for configuration loading."""

import os
import tempfile
from pathlib import Path

import pytest

from know_your_ip import KnowYourIPConfig, load_config
from know_your_ip.config import (
    AbuseIPDBConfig,
    ConfigurationError,
    MaxMindConfig,
    create_default_config,
    find_config_file,
    load_from_env,
)


class TestConfigModels:
    """Test the configuration model classes."""

    def test_maxmind_config_defaults(self):
        """Test MaxMind configuration defaults."""
        config = MaxMindConfig()
        assert config.enabled is True
        assert config.db_path == Path("./db")

    def test_maxmind_config_path_resolution(self):
        """Test path resolution for MaxMind database."""
        config = MaxMindConfig(db_path="./test")
        assert isinstance(config.db_path, Path)
        assert config.db_path.is_absolute()

    def test_abuseipdb_config_defaults(self):
        """Test AbuseIPDB configuration defaults."""
        config = AbuseIPDBConfig()
        assert config.enabled is False
        assert config.api_key is None
        assert config.days == 180

    def test_abuseipdb_config_placeholder_api_key(self):
        """Test placeholder API key handling."""
        config = AbuseIPDBConfig(api_key="<<<YOUR_API_KEY_HERE>>>")
        assert config.api_key is None  # Should be converted to None

    def test_abuseipdb_config_valid_api_key(self):
        """Test valid API key handling."""
        config = AbuseIPDBConfig(api_key="valid_key_123")
        assert config.api_key == "valid_key_123"


class TestLoadConfig:
    """Test the load_config function."""

    def test_load_default_config(self):
        """Test loading default configuration."""
        config = load_config()
        assert isinstance(config, KnowYourIPConfig)
        assert hasattr(config, "maxmind")
        assert hasattr(config, "output")
        assert isinstance(config.output.columns, list)
        assert len(config.output.columns) > 0
        assert config.maxmind.enabled is True
        assert config.geonames.enabled is False

    def test_load_nonexistent_config(self):
        """Test loading non-existent configuration file."""
        config = load_config(Path("/nonexistent/config.toml"))
        assert isinstance(config, KnowYourIPConfig)

    def test_load_config_from_toml_file(self):
        """Test loading configuration from TOML file."""
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
            # Cross-platform path check
            assert "custom" in str(config.maxmind.db_path) and "path" in str(
                config.maxmind.db_path
            )
            assert config.geonames.enabled is True
            assert config.geonames.username == "test_user"

    def test_load_config_invalid_toml(self):
        """Test loading invalid TOML file raises error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "invalid.toml"
            config_file.write_text("invalid toml content [[[")

            with pytest.raises(ConfigurationError, match="Failed to load config file"):
                load_config(config_file)


class TestEnvironmentConfig:
    """Test environment variable configuration loading."""

    def test_load_from_env_empty(self):
        """Test loading from environment when no variables are set."""
        # Save current environment
        original_env = dict(os.environ)

        try:
            # Clear any KNOW_YOUR_IP variables
            for key in list(os.environ.keys()):
                if key.startswith("KNOW_YOUR_IP_"):
                    del os.environ[key]

            config = load_from_env()
            assert config == {}
        finally:
            # Restore environment
            os.environ.clear()
            os.environ.update(original_env)

    def test_load_from_env_with_variables(self):
        """Test loading from environment variables."""
        original_env = dict(os.environ)

        try:
            # Set test environment variables
            os.environ["KNOW_YOUR_IP_MAXMIND_ENABLED"] = "false"
            os.environ["KNOW_YOUR_IP_GEONAMES_USERNAME"] = "test_user"
            os.environ["KNOW_YOUR_IP_ABUSEIPDB_DAYS"] = "30"

            config = load_from_env()

            assert config["maxmind"]["enabled"] is False
            assert config["geonames"]["username"] == "test_user"
            assert config["abuseipdb"]["days"] == 30
        finally:
            os.environ.clear()
            os.environ.update(original_env)

    def test_environment_variable_type_conversion(self):
        """Test type conversion for environment variables."""
        original_env = dict(os.environ)

        try:
            os.environ["KNOW_YOUR_IP_PING_ENABLED"] = "true"
            os.environ["KNOW_YOUR_IP_PING_TIMEOUT"] = "5000"
            os.environ["KNOW_YOUR_IP_GEONAMES_ENABLED"] = "false"

            config = load_from_env()

            assert config["ping"]["enabled"] is True
            assert config["ping"]["timeout"] == 5000
            assert config["geonames"]["enabled"] is False
        finally:
            os.environ.clear()
            os.environ.update(original_env)


class TestConfigUtils:
    """Test configuration utility functions."""

    def test_find_config_file_none_exists(self):
        """Test finding config file when none exists."""
        # This should return None since no config file exists in test environment
        result = find_config_file()
        # Could be None or a valid path if config exists
        assert result is None or isinstance(result, Path)

    def test_create_default_config(self):
        """Test creating default configuration file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "test_config.toml"
            create_default_config(config_path)

            assert config_path.exists()
            content = config_path.read_text()
            assert "[maxmind]" in content
            assert "[geonames]" in content
            assert "enabled = true" in content
