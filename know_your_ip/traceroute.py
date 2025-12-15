#!/usr/bin/env python

from __future__ import annotations

import os
import shlex
from subprocess import PIPE, Popen


def os_traceroute(ip: str, max_hops: int = 30) -> bytes:
    if os.name == 'nt':
        cmd = f'tracert -h {max_hops} -d {ip}'
    elif os.name == 'posix':
        cmd = f'traceroute -m {max_hops} -n {ip}'
    else:
        # FIXME: other OSes.
        cmd = f'traceroute {ip}'

    p = Popen(shlex.split(cmd), stdout=PIPE, stderr=PIPE)
    out, err = p.communicate()

    return out
