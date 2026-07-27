"""Tests for package-level surface."""

import know_your_ip


class TestPackage:
    """Package metadata and exports."""

    def test_version_exists(self):
        assert isinstance(know_your_ip.__version__, str)

    def test_public_api_is_importable(self):
        """Everything named in __all__ actually exists."""
        for name in know_your_ip.__all__:
            assert hasattr(know_your_ip, name), f"Missing export: {name}"

    def test_removed_scrapers_are_gone(self):
        """abuseipdb_web and ipvoid_scan scraped pages now behind Cloudflare
        and hCaptcha respectively; AbuseIPDB's terms also prohibit scraping."""
        assert not hasattr(know_your_ip, "abuseipdb_web")
        assert not hasattr(know_your_ip, "ipvoid_scan")

    def test_tzwhere_replaced(self):
        """tzwhere was abandoned in 2017 and breaks on NumPy >= 1.24."""
        assert not hasattr(know_your_ip, "tzwhere_timezone")
        assert hasattr(know_your_ip, "timezone_at")
