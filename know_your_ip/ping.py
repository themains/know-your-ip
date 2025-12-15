#!/usr/bin/env python

"""Modern ping implementation using subprocess for cross-platform compatibility.

This module provides ICMP ping functionality using system ping commands,
avoiding the complexity and security requirements of raw sockets.

Example:
    >>> result = quiet_ping("8.8.8.8", timeout=3000, count=3)
    >>> if result:
    ...     max_rtt, min_rtt, avg_rtt, loss = result
    ...     print(f"Average RTT: {avg_rtt:.2f}ms, Loss: {loss*100:.1f}%")
"""

from __future__ import annotations

import logging
import platform
import re
import subprocess
import sys


def quiet_ping(
    hostname: str,
    timeout: int = 3000,
    count: int = 3,
    numDataBytes: int = 64,
    path_finder: bool = False,
    ipv6: bool = False,
) -> tuple[float, float, float, float] | None:
    """Ping a host and return statistics.

    Uses system ping command for reliable cross-platform operation.
    No root privileges required.

    Args:
        hostname: IP address or hostname to ping.
        timeout: Timeout in milliseconds.
        count: Number of ping packets to send.
        numDataBytes: Size of ping data in bytes (legacy parameter, ignored).
        path_finder: Legacy parameter, ignored.
        ipv6: Use IPv6 ping if True.

    Returns:
        Tuple of (max_time, min_time, avg_time, packet_loss_fraction) in milliseconds,
        or None if ping fails completely.

    Example:
        >>> result = quiet_ping("8.8.8.8", timeout=3000, count=3)
        >>> if result:
        ...     max_rtt, min_rtt, avg_rtt, loss = result
        ...     print(f"Ping successful: avg={avg_rtt:.2f}ms")
        >>> result = quiet_ping("nonexistent.invalid")
        >>> print(result)  # None
    """
    try:
        # Determine ping command based on platform
        system = platform.system().lower()

        match system:
            case "windows":
                cmd = ["ping"]
                if ipv6:
                    cmd.append("-6")
                cmd.extend(["-n", str(count), "-w", str(timeout), hostname])

            case "darwin" | "linux" | _:  # macOS, Linux, or other Unix-like
                cmd = ["ping6" if ipv6 else "ping"]
                # Convert timeout from milliseconds to seconds
                timeout_sec = max(1, timeout // 1000)
                cmd.extend(["-c", str(count), "-W", str(timeout_sec), hostname])

        # Execute ping command
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout / 1000 + 10,  # Add buffer to subprocess timeout
        )

        if result.returncode != 0:
            logging.warning(f"Ping to {hostname} failed: {result.stderr.strip()}")
            return None

        # Parse ping output
        return _parse_ping_output(result.stdout, system)

    except subprocess.TimeoutExpired:
        logging.warning(f"Ping to {hostname} timed out")
        return None
    except FileNotFoundError:
        logging.error("Ping command not found on system")
        return None
    except Exception as e:
        logging.error(f"Ping failed: {e}")
        return None


def _parse_ping_output(
    output: str, system: str
) -> tuple[float, float, float, float] | None:
    """Parse ping command output to extract statistics.

    Args:
        output: Raw output from ping command.
        system: Operating system name for parsing logic.

    Returns:
        Tuple of (max_time, min_time, avg_time, packet_loss_fraction)
        or None if parsing fails.
    """
    try:
        if system == "windows":
            return _parse_windows_ping(output)
        else:
            return _parse_unix_ping(output)
    except Exception as e:
        logging.error(f"Failed to parse ping output: {e}")
        return None


def _parse_windows_ping(output: str) -> tuple[float, float, float, float] | None:
    """Parse Windows ping output.

    Example output:
        Pinging 8.8.8.8 with 32 bytes of data:
        Reply from 8.8.8.8: bytes=32 time=14ms TTL=116
        Reply from 8.8.8.8: bytes=32 time=13ms TTL=116

        Ping statistics for 8.8.8.8:
        Packets: Sent = 2, Received = 2, Lost = 0 (0% loss),
    """
    # Extract individual response times
    times = []
    for match in re.finditer(r"time=(\d+)ms", output):
        times.append(float(match.group(1)))

    if not times:
        return None

    # Extract packet loss
    loss_match = re.search(r"Lost = \d+ \((\d+)% loss\)", output)
    packet_loss = float(loss_match.group(1)) / 100 if loss_match else 0.0

    return max(times), min(times), sum(times) / len(times), packet_loss


def _parse_unix_ping(output: str) -> tuple[float, float, float, float] | None:
    """Parse Unix/Linux/macOS ping output.

    Example output:
        PING 8.8.8.8 (8.8.8.8): 56 data bytes
        64 bytes from 8.8.8.8: icmp_seq=0 ttl=116 time=14.123 ms
        64 bytes from 8.8.8.8: icmp_seq=1 ttl=116 time=13.456 ms

        --- 8.8.8.8 ping statistics ---
        2 packets transmitted, 2 received, 0% packet loss
        round-trip min/avg/max/stddev = 13.456/13.790/14.123/0.334 ms
    """
    # Try to extract statistics from summary line first (more reliable)
    stats_match = re.search(
        r"round-trip min/avg/max/\w+ = ([\d.]+)/([\d.]+)/([\d.]+)/[\d.]+ ms", output
    )

    if stats_match:
        min_time = float(stats_match.group(1))
        avg_time = float(stats_match.group(2))
        max_time = float(stats_match.group(3))

        # Extract packet loss
        loss_match = re.search(r"(\d+)% packet loss", output)
        packet_loss = float(loss_match.group(1)) / 100 if loss_match else 0.0

        return max_time, min_time, avg_time, packet_loss

    # Fallback: parse individual response times
    times = []
    for match in re.finditer(r"time=([\d.]+) ms", output):
        times.append(float(match.group(1)))

    if not times:
        return None

    # Extract packet loss
    loss_match = re.search(r"(\d+)% packet loss", output)
    packet_loss = float(loss_match.group(1)) / 100 if loss_match else 0.0

    return max(times), min(times), sum(times) / len(times), packet_loss


def verbose_ping(hostname: str, timeout: int = 3000, count: int = 3) -> int:
    """Verbose ping with output to console.

    Args:
        hostname: IP address or hostname to ping.
        timeout: Timeout in milliseconds.
        count: Number of ping packets to send.

    Returns:
        0 if successful (received packets), 1 if failed.
    """
    result = quiet_ping(hostname, timeout, count)

    if result is None:
        print(f"PING {hostname}: Host unreachable")
        return 1

    max_time, min_time, avg_time, packet_loss = result
    packets_lost = int(packet_loss * count)
    packets_received = count - packets_lost

    print(
        f"PING {hostname}: {count} packets transmitted, {packets_received} received, "
        f"{packet_loss * 100:.1f}% packet loss"
    )

    if packets_received > 0:
        print(
            f"round-trip min/avg/max = {min_time:.3f}/{avg_time:.3f}/{max_time:.3f} ms"
        )
        return 0
    else:
        return 1


if __name__ == "__main__":
    """Simple CLI for testing purposes."""
    if len(sys.argv) != 2:
        print("Usage: python ping.py <hostname>")
        sys.exit(1)

    hostname = sys.argv[1]
    result = verbose_ping(hostname)
    sys.exit(result)
