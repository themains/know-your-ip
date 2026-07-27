#!/usr/bin/env python

"""Cross-platform traceroute using the system command."""

from __future__ import annotations

import ipaddress
import logging
import platform
import subprocess

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 120


def os_traceroute(ip: str, max_hops: int = 30, timeout: int = DEFAULT_TIMEOUT) -> str:
    r"""Trace the network path to an IP address.

    Uses ``tracert`` on Windows and ``traceroute``/``traceroute6`` elsewhere.

    Args:
        ip: Target IP address.
        max_hops: Maximum number of hops to trace.
        timeout: Seconds to wait before giving up on the subprocess.

    Returns:
        The command's stdout, or an empty string if it failed or timed out.

    Raises:
        ValueError: If ``ip`` is not a valid IP address.

    Example:
        >>> os_traceroute("8.8.8.8", max_hops=5)  # doctest: +SKIP
        'traceroute to 8.8.8.8 (8.8.8.8), 5 hops max, 60 byte packets\\n...'
    """
    # Validate before building the command: an unvalidated value would be
    # passed through as further traceroute arguments.
    try:
        address = ipaddress.ip_address(str(ip).strip())
    except ValueError as exc:
        raise ValueError(f"Not a valid IP address: {ip!r}") from exc

    if platform.system().lower() == "windows":
        cmd = ["tracert", "-h", str(max_hops), "-d", str(address)]
    else:
        binary = "traceroute6" if address.version == 6 else "traceroute"
        cmd = [binary, "-m", str(max_hops), "-n", "--", str(address)]

    try:
        # Fixed argv list, no shell; the address is validated above.
        result = subprocess.run(  # noqa: S603
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        logger.warning("traceroute to %s timed out after %ss", address, timeout)
        return ""
    except FileNotFoundError:
        logger.error("%s command not found on this system", cmd[0])
        return ""

    if result.returncode != 0 and not result.stdout:
        logger.warning("traceroute to %s failed: %s", address, result.stderr.strip())
        return ""

    return result.stdout
