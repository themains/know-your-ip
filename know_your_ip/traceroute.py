#!/usr/bin/env python

"""Cross-platform traceroute implementation using system commands.

This module provides network path tracing functionality by calling
the appropriate system traceroute command for each platform.
"""

from __future__ import annotations

import os
import shlex
from subprocess import PIPE, Popen


def os_traceroute(ip: str, max_hops: int = 30) -> bytes:
    """Perform traceroute to an IP address using system commands.

    Uses platform-specific traceroute commands:
    - Windows: tracert
    - Unix/Linux/macOS: traceroute

    Args:
        ip: Target IP address or hostname.
        max_hops: Maximum number of hops to trace (default: 30).

    Returns:
        Raw traceroute output as bytes from the system command.

    Example:
        >>> result = os_traceroute("8.8.8.8", max_hops=15)
        >>> print(result.decode('utf-8'))
        traceroute to 8.8.8.8 (8.8.8.8), 15 hops max, 60 byte packets
        1  192.168.1.1  1.234 ms  1.567 ms  1.890 ms
        ...
    """
    match os.name:
        case "nt":
            cmd = f"tracert -h {max_hops} -d {ip}"
        case "posix":
            cmd = f"traceroute -m {max_hops} -n {ip}"
        case _:
            # Default fallback for other operating systems
            cmd = f"traceroute {ip}"

    p = Popen(shlex.split(cmd), stdout=PIPE, stderr=PIPE)
    out, err = p.communicate()

    return out
