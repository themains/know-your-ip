"""Tests for ping output parsing and platform-specific flags."""

from __future__ import annotations

from unittest import mock

import pytest

from know_your_ip.ping import _parse_unix_ping, _parse_windows_ping, quiet_ping
from know_your_ip.traceroute import os_traceroute

UNIX_OUTPUT = """PING 8.8.8.8 (8.8.8.8): 56 data bytes
64 bytes from 8.8.8.8: icmp_seq=0 ttl=116 time=14.123 ms
64 bytes from 8.8.8.8: icmp_seq=1 ttl=116 time=13.456 ms

--- 8.8.8.8 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss
round-trip min/avg/max/stddev = 13.456/13.790/14.123/0.334 ms
"""

UNIX_NO_SUMMARY = """PING 8.8.8.8 (8.8.8.8): 56 data bytes
64 bytes from 8.8.8.8: icmp_seq=0 ttl=116 time=14.5 ms
2 packets transmitted, 1 received, 50% packet loss
"""

WINDOWS_OUTPUT = """Pinging 8.8.8.8 with 32 bytes of data:
Reply from 8.8.8.8: bytes=32 time=14ms TTL=116
Reply from 8.8.8.8: bytes=32 time=13ms TTL=116

Ping statistics for 8.8.8.8:
    Packets: Sent = 2, Received = 2, Lost = 0 (0% loss),
"""


class TestParseUnixPing:
    def test_prefers_summary_line(self):
        parsed = _parse_unix_ping(UNIX_OUTPUT)

        assert parsed is not None
        max_t, min_t, avg_t, loss = parsed

        assert (max_t, min_t, avg_t) == (14.123, 13.456, 13.790)
        assert loss == 0.0

    def test_falls_back_to_individual_times(self):
        parsed = _parse_unix_ping(UNIX_NO_SUMMARY)

        assert parsed is not None
        max_t, min_t, avg_t, loss = parsed

        assert max_t == min_t == avg_t == 14.5
        assert loss == 0.5

    def test_no_replies_returns_none(self):
        assert _parse_unix_ping("100% packet loss") is None


class TestParseWindowsPing:
    def test_extracts_times_and_loss(self):
        parsed = _parse_windows_ping(WINDOWS_OUTPUT)

        assert parsed is not None
        max_t, min_t, avg_t, loss = parsed

        assert (max_t, min_t) == (14.0, 13.0)
        assert avg_t == 13.5
        assert loss == 0.0

    def test_no_replies_returns_none(self):
        assert _parse_windows_ping("Request timed out.") is None


class TestPingFlags:
    """The -W flag means milliseconds on macOS and seconds on Linux.

    Passing seconds on macOS yields a 3ms deadline, so every probe times out.
    """

    def _captured_cmd(self, system: str) -> list[str]:
        with (
            mock.patch("know_your_ip.ping.platform.system", return_value=system),
            mock.patch("know_your_ip.ping.subprocess.run") as run,
        ):
            run.return_value = mock.Mock(returncode=0, stdout=UNIX_OUTPUT, stderr="")
            quiet_ping("8.8.8.8", timeout=3000, count=3)
        return run.call_args[0][0]

    def test_macos_receives_milliseconds(self):
        cmd = self._captured_cmd("Darwin")

        assert cmd[cmd.index("-W") + 1] == "3000"

    def test_linux_receives_seconds(self):
        cmd = self._captured_cmd("Linux")

        assert cmd[cmd.index("-W") + 1] == "3"

    def test_ipv6_uses_ping6(self):
        with (
            mock.patch("know_your_ip.ping.platform.system", return_value="Darwin"),
            mock.patch("know_your_ip.ping.subprocess.run") as run,
        ):
            run.return_value = mock.Mock(returncode=0, stdout=UNIX_OUTPUT, stderr="")
            quiet_ping("2001:4860:4860::8888", ipv6=True)

        assert run.call_args[0][0][0] == "ping6"


class TestTraceroute:
    def test_rejects_non_ip_input(self):
        """An unvalidated value would be passed through as extra arguments."""
        with pytest.raises(ValueError, match="Not a valid IP address"):
            os_traceroute("8.8.8.8 -w 99999")

    def test_uses_traceroute6_for_ipv6(self):
        with mock.patch("know_your_ip.traceroute.subprocess.run") as run:
            run.return_value = mock.Mock(returncode=0, stdout="ok", stderr="")
            os_traceroute("2001:4860:4860::8888")

        assert run.call_args[0][0][0] == "traceroute6"

    def test_passes_end_of_options_separator(self):
        with mock.patch("know_your_ip.traceroute.subprocess.run") as run:
            run.return_value = mock.Mock(returncode=0, stdout="ok", stderr="")
            os_traceroute("8.8.8.8")

        assert "--" in run.call_args[0][0]

    def test_timeout_returns_empty_not_hang(self):
        import subprocess

        with mock.patch(
            "know_your_ip.traceroute.subprocess.run",
            side_effect=subprocess.TimeoutExpired("traceroute", 1),
        ):
            assert os_traceroute("8.8.8.8") == ""
