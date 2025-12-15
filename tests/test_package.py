"""Tests for package-level functionality."""

import know_your_ip


class TestPackage:
    """Test package-level functionality."""

    def test_version_exists(self):
        """Test that version attribute exists."""
        assert hasattr(know_your_ip, "__version__")
        assert isinstance(know_your_ip.__version__, str)

    def test_imports(self):
        """Test that main functions can be imported."""
        from know_your_ip import load_config

        assert callable(load_config)

    def test_all_exports(self):
        """Test that all expected functions are exported."""
        expected_exports = [
            "load_config",
            "maxmind_geocode_ip",
            "geonames_timezone",
            "tzwhere_timezone",
            "ipvoid_scan",
            "abuseipdb_web",
            "abuseipdb_api",
            "censys_api",
            "shodan_api",
            "virustotal_api",
            "ping",
            "traceroute",
            "query_ip",
            "apivoid_api",
        ]

        for func_name in expected_exports:
            assert hasattr(know_your_ip, func_name), f"Missing export: {func_name}"
