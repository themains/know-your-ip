#!/usr/bin/env python

from __future__ import annotations

import array
import logging
import os
import select
import signal
import socket
import struct
import sys
import time
from typing import Any

try:
    from _thread import get_ident
except ImportError:

    def get_ident():
        return 0


"""
    A pure python ping implementation using raw sockets.

    (This is Python 3 port of https://github.com/jedie/python-ping)
    (Tested and working with python 2.7, should work with 2.6+)

    Note that ICMP messages can only be sent from processes running as root
    (in Windows, you must run this script as 'Administrator').

    Derived from ping.c distributed in Linux's netkit. That code is
    copyright (c) 1989 by The Regents of the University of California.
    That code is in turn derived from code written by Mike Muuss of the
    US Army Ballistic Research Laboratory in December, 1983 and
    placed in the public domain. They have my thanks.

    Bugs are naturally mine. I'd be glad to hear about them. There are
    certainly word - size dependencies here.

    Copyright (c) Matthew Dixon Cowles, <http://www.visi.com/~mdc/>.
    Distributable under the terms of the GNU General Public License
    version 2. Provided with no warranties of any sort.

    Original Version from Matthew Dixon Cowles:
      -> ftp://ftp.visi.com/users/mdc/ping.py

    Rewrite by Jens Diemer:
      -> http://www.python-forum.de/post-69122.html#69122

    Rewrite by George Notaras:
      -> http://www.g-loaded.eu/2009/10/30/python-ping/

    Enhancements by Martin Falatic:
      -> http://www.falatic.com/index.php/39/pinging-with-python

    Enhancements and fixes by Georgi Kolev:
      -> http://github.com/jedie/python-ping/

    Bug fix by Andrejs Rozitis:
      -> http://github.com/rozitis/python-ping/

    Bug fix by  Auke Willem Oosterhoff

    Revision history
    ~~~~~~~~~~~~~~~~

    Febriary 4, 2015
    ----------------
    * Fix statistics dump on unexpected exit
    * Fixing a bug where we match the ICMP request as respons
      Fix based on samuel's work https://github.com/samuel/python-ping/commit/745c159dacce6afebb0f82cac8e9ed5bb2189491#diff-0ee81781c0132dc8f743df3a41b71918R128
    * Merging simudream's patch to fix python3 error handeling.

    January 21, 2015
    ----------------
    * Set socket options to allow sending pings to broadcast address
      - Based on Tom Wilkie's patch
        https://github.com/tomwilkie/pyping/commit/7d017b03ee462fae72e2d0ff96a042bcba295564

    August 6, 2014
    --------------
    * Fixing an bug introduced with last changes :S
      - Python on Windows dosn't have socket.inet_ntop
        Adding try/except to handle AttributeError.

    June 28, 2014
    -------------
    * A bit closer to what PIP8 wants

    * Litlle modifications by Auke Willem Oosterhoff:
     - Added support for simultaneous pings on multiple hosts.
     https://bitbucket.org/OrangeTux/python-ping/commits/d4aa720662995a57cf18fa6b8ea689e9d11d26c7/raw/

    * Faster and cleaner checksum creation
      Based on frfra's patch
      https://github.com/alexlouden/python-ping/commit/b9fc3acb2c36ccc895d1f7ba7336b951dc033ce9

    * Changing 'except' calls to work with 2.x and 3.x
      Based on pferate's patch
      https://github.com/pferate/python_ping/commit/4e761ea99582ac1699c7965d149ce16e6b62f0ac

    June 19, 2013
    --------------
    * Added support for IPv6. Taken from implementation of Lars Strand.

    March 19, 2013
    --------------
    * Fixing bug to prevent divide by 0 during run-time.

    January 26, 2012
    ----------------
    * Fixing BUG #4 - competability with python 2.x [tested with 2.7]
      - Packet data building is different for 2.x and 3.x.
        'cose of the string/bytes difference.
    * Fixing BUG #10 - the multiple resolv issue.
      - When pinging domain names insted of hosts (for exmaple google.com)
        you can get different IP every time you try to resolv it, we should
        resolv the host only once and stick to that IP.
    * Fixing BUGs #3 #10 - Doing hostname resolv only once.
    * Fixing BUG #14 - Removing all 'global' stuff.
        - You should not use globul! Its bad for you...and its not thread safe!
    * Fix - forcing the use of different times on linux/windows for
            more accurate mesurments. (time.time - linux/ time.clock - windows)
    * Adding quiet_ping function - This way we'll be able to use this script
        as external lib.
    * Changing default timeout to 3s. (1second is not enought)
    * Switching data syze to packet size. It's easyer for the user to ignore the
        fact that the packet headr is 8b and the datasize 64 will make packet with
        size 72.

    October 12, 2011
    --------------
    Merged updates from the main project
      -> https://github.com/jedie/python-ping

    September 12, 2011
    --------------
    Bugfixes + cleanup by Jens Diemer
    Tested with Ubuntu + Windows 7

    September 6, 2011
    --------------
    Cleanup by Martin Falatic. Restored lost comments and docs. Improved
    functionality: constant time between pings, internal times consistently
    use milliseconds. Clarified annotations (e.g., in the checksum routine).
    Using unsigned data in IP & ICMP header pack/unpack unless otherwise
    necessary. Signal handling. Ping-style output formatting and stats.

    August 3, 2011
    --------------
    Ported to py3k by Zach Ware. Mostly done by 2to3; also minor changes to
    deal with bytes vs. string changes (no more ord() in checksum() because
    >source_string< is actually bytes, added .encode() to data in
    send_one_ping()).  That's about it.

    March 11, 2010
    --------------
    changes by Samuel Stauffer:
    - replaced time.clock with default_timer which is set to
      time.clock on windows and time.time on other systems.

    November 8, 2009
    ----------------
    Improved compatibility with GNU/Linux systems.

    Fixes by:
     * George Notaras -- http://www.g-loaded.eu
    Reported by:
     * Chris Hallman -- http://cdhallman.blogspot.com

    Changes in this release:
     - Re-use time.time() instead of time.clock(). The 2007 implementation
       worked only under Microsoft Windows. Failed on GNU/Linux.
       time.clock() behaves differently under the two OSes[1].

    [1] http://docs.python.org/library/time.html#time.clock

    May 30, 2007
    ------------
    little rewrite by Jens Diemer:
     -  change socket asterisk import to a normal import
     -  replace time.time() with time.clock()
     -  delete "return None" (or change to "return" only)
     -  in checksum() rename "str" to "source_string"

    December 4, 2000
    ----------------
    Changed the struct.pack() calls to pack the checksum and ID as
    unsigned. My thanks to Jerome Poincheval for the fix.

    November 22, 1997
    -----------------
    Initial hack. Doesn't do much, but rather than try to guess
    what features I (or others) will want in the future, I've only
    put in what I need now.

    December 16, 1997
    -----------------
    For some reason, the checksum bytes are in the wrong order when
    this is run under Solaris 2.X for SPARC but it works right under
    Linux x86. Since I don't know just what's wrong, I'll swap the
    bytes always and then do an htons().

    ===========================================================================
    IP header info from RFC791
      -> http://tools.ietf.org/html/rfc791)

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Version|  IHL  |Type of Service|          Total Length         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         Identification        |Flags|      Fragment Offset    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Time to Live |    Protocol   |         Header Checksum       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Source Address                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Destination Address                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Options                    |    Padding    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    ===========================================================================
    ICMP Echo / Echo Reply Message header info from RFC792
      -> http://tools.ietf.org/html/rfc792

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |     Type      |     Code      |          Checksum             |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |           Identifier          |        Sequence Number        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |     Data ...
        +-+-+-+-+-

    ===========================================================================
    ICMP parameter info:
      -> http://www.iana.org/assignments/icmp-parameters/icmp-parameters.xml

    ===========================================================================
    An example of ping's typical output:

    PING heise.de (193.99.144.80): 56 data bytes
    64 bytes from 193.99.144.80: icmp_seq=0 ttl=240 time=127 ms
    64 bytes from 193.99.144.80: icmp_seq=1 ttl=240 time=127 ms
    64 bytes from 193.99.144.80: icmp_seq=2 ttl=240 time=126 ms
    64 bytes from 193.99.144.80: icmp_seq=3 ttl=240 time=126 ms
    64 bytes from 193.99.144.80: icmp_seq=4 ttl=240 time=127 ms

    ----heise.de PING Statistics----
    5 packets transmitted, 5 packets received, 0.0% packet loss
    round-trip (ms)  min/avg/max/med = 126/127/127/127

    ===========================================================================
"""

# =============================================================================#

# Use time.perf_counter() for high-resolution timing on all platforms (Python 3.3+)
default_timer = time.perf_counter

# =============================================================================#
# ICMP parameters

ICMP_ECHOREPLY = 0  # Echo reply (per RFC792)
ICMP_ECHO = 8  # Echo request (per RFC792)
ICMP_ECHO_IPV6 = 128  # Echo request (per RFC4443)
ICMP_ECHO_IPV6_REPLY = 129  # Echo request (per RFC4443)
ICMP_MAX_RECV = 2048  # Max size of incoming buffer

MAX_SLEEP = 1000


class MyStats:
    thisIP = "0.0.0.0"
    pktsSent = 0
    pktsRcvd = 0
    minTime = 999999999
    maxTime = 0
    totTime = 0
    avrgTime = 0
    fracLoss = 1.0


myStats = MyStats  # NOT Used globally anymore.


# =============================================================================#
def checksum(source_string: bytes) -> int:
    """
    A port of the functionality of in_cksum() from ping.c
    Ideally this would act on the string as a series of 16-bit ints (host
    packed), but this works.
    Network data is big-endian, hosts are typically little-endian
    """
    if len(source_string) % 2:
        source_string += "\x00"
    converted = array.array("H", source_string)
    if sys.byteorder == "big":
        converted.bytewap()
    val = sum(converted)

    val &= 0xFFFFFFFF  # Truncate val to 32 bits (a variance from ping.c, which
    # uses signed ints, but overflow is unlikely in ping)

    val = (val >> 16) + (val & 0xFFFF)  # Add high 16 bits to low 16 bits
    val += val >> 16  # Add carry from above (if any)
    answer = ~val & 0xFFFF  # Invert and truncate to 16 bits
    answer = socket.htons(answer)

    return answer


# =============================================================================#
def do_one(
    myStats,
    destIP,
    hostname,
    timeout,
    mySeqNumber,
    numDataBytes,
    quiet=False,
    ipv6=False,
):
    """
    Returns either the delay (in ms) or None on timeout.
    """
    delay = None

    if ipv6:
        try:  # One could use UDP here, but it's obscure
            mySocket = socket.socket(
                socket.AF_INET6, socket.SOCK_RAW, socket.getprotobyname("ipv6-icmp")
            )
            mySocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        # except socket.error
        except OSError as e:
            # etype, evalue, etb = sys.exc_info()
            logging.error(f"failed. (socket error: '{e}')")  # evalue.args[1])
            logging.error("Note that python-ping uses RAW socketsand requiers root rights.")
            raise  # raise the original error
    else:
        try:  # One could use UDP here, but it's obscure
            mySocket = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp")
            )
            mySocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        # except socket.error:
        except OSError as e:
            # etype, evalue, etb = sys.exc_info()
            logging.error(f"failed. (socket error: '{e}')")  # evalue.args[1])
            logging.error("Note that python-ping uses RAW socketsand requires root rights.")
            raise  # raise the original error

    # my_ID = os.getpid() & 0xFFFF
    my_ID = (os.getpid() ^ get_ident()) & 0xFFFF

    sentTime = send_one_ping(mySocket, destIP, my_ID, mySeqNumber, numDataBytes, ipv6)
    if sentTime is None:
        mySocket.close()
        return delay

    myStats.pktsSent += 1

    recvTime, dataSize, iphSrcIP, icmpSeqNumber, iphTTL = receive_one_ping(
        mySocket, my_ID, timeout, ipv6
    )

    mySocket.close()

    if recvTime:
        delay = (recvTime - sentTime) * 1000
        if not quiet:
            if ipv6:
                host_addr = hostname
            else:
                try:
                    host_addr = socket.inet_ntop(
                        socket.AF_INET, struct.pack("!I", iphSrcIP)
                    )
                except AttributeError:
                    # Python on windows dosn't have inet_ntop.
                    host_addr = hostname

            logging.info(
                f"{dataSize} bytes from {host_addr}: icmp_seq={icmpSeqNumber} ttl={iphTTL} time={delay} ms"
            )
        myStats.pktsRcvd += 1
        myStats.totTime += delay
        if myStats.minTime > delay:
            myStats.minTime = delay
        if myStats.maxTime < delay:
            myStats.maxTime = delay
    else:
        delay = None
        if not quiet:
            logging.warning("Request timed out.")

    return delay


# =============================================================================#
def send_one_ping(mySocket: socket.socket, destIP: str, myID: int, mySeqNumber: int, numDataBytes: int, ipv6: bool = False) -> float | None:
    """
    Send one ping to the given >destIP<.
    """
    # destIP  =  socket.gethostbyname(destIP)

    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    # (numDataBytes - 8) - Remove header size from packet size
    myChecksum = 0

    # Make a dummy heder with a 0 checksum.
    if ipv6:
        header = struct.pack("!BbHHh", ICMP_ECHO_IPV6, 0, myChecksum, myID, mySeqNumber)
    else:
        header = struct.pack("!BBHHH", ICMP_ECHO, 0, myChecksum, myID, mySeqNumber)

    padBytes = []
    startVal = 0x42
    # 'cose of the string/byte changes in python 2/3 we have
    # to build the data differnely for different version
    # or it will make packets with unexpected size.
    if sys.version[:1] == "2":
        bytes = struct.calcsize("d")
        data = ((numDataBytes - 8) - bytes) * "Q"
        data = struct.pack("d", default_timer()) + data
    else:
        for i in range(startVal, startVal + (numDataBytes - 8)):
            padBytes += [(i & 0xFF)]  # Keep chars in the 0-255 range
        # data = bytes(padBytes)
        data = bytearray(padBytes)

    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(header + data)  # Checksum is in network order

    # Now that we have the right checksum, we put that in. It's just easier
    # to make up a new header than to stuff it into the dummy.
    if ipv6:
        header = struct.pack("!BbHHh", ICMP_ECHO_IPV6, 0, myChecksum, myID, mySeqNumber)
    else:
        header = struct.pack("!BBHHH", ICMP_ECHO, 0, myChecksum, myID, mySeqNumber)

    packet = header + data

    sendTime = default_timer()

    try:
        mySocket.sendto(packet, (destIP, 1))  # Port number is irrelevant for ICMP
    # except socket.error:
    except OSError as e:
        # etype, evalue, etb = sys.exc_info()
        logging.error(f"General failure ({e})")  # (evalue.args[1]))
        return

    return sendTime


# =============================================================================#
def receive_one_ping(mySocket: socket.socket, myID: int, timeout: int, ipv6: bool = False) -> tuple[float | None, int, int, int, int]:
    """
    Receive the ping from the socket. Timeout = in ms
    """
    timeLeft = timeout / 1000

    while True:  # Loop while waiting for packet or timeout
        startedSelect = default_timer()
        whatReady = select.select([mySocket], [], [], timeLeft)
        howLongInSelect = default_timer() - startedSelect
        if whatReady[0] == []:  # Timeout
            return None, 0, 0, 0, 0

        timeReceived = default_timer()

        recPacket, addr = mySocket.recvfrom(ICMP_MAX_RECV)

        ipHeader = recPacket[:20]
        (
            iphVersion,
            iphTypeOfSvc,
            iphLength,
            iphID,
            iphFlags,
            iphTTL,
            iphProtocol,
            iphChecksum,
            iphSrcIP,
            iphDestIP,
        ) = struct.unpack("!BBHHHBBHII", ipHeader)

        if ipv6:
            icmpHeader = recPacket[0:8]
        else:
            icmpHeader = recPacket[20:28]

        icmpType, icmpCode, icmpChecksum, icmpPacketID, icmpSeqNumber = struct.unpack(
            "!BBHHH", icmpHeader
        )

        # Match only the packets we care about
        if (icmpType != 8) and (icmpPacketID == myID):
            # if icmpPacketID == myID: # Our packet
            dataSize = len(recPacket) - 28
            # print (len(recPacket.encode()))
            return timeReceived, (dataSize + 8), iphSrcIP, icmpSeqNumber, iphTTL

        timeLeft = timeLeft - howLongInSelect
        if timeLeft <= 0:
            return None, 0, 0, 0, 0


# =============================================================================#
def dump_stats(myStats: MyStats) -> None:
    """
    Show stats when pings are done
    """
    logging.info(f"\n----{myStats.thisIP} PYTHON PING Statistics----")

    if myStats.pktsSent > 0:
        myStats.fracLoss = (myStats.pktsSent - myStats.pktsRcvd) / myStats.pktsSent

    logging.info(
        f"{myStats.pktsSent} packets transmitted, {myStats.pktsRcvd} packets received, {100.0 * myStats.fracLoss:.1f}% packet loss"
    )

    if myStats.pktsRcvd > 0:
        logging.info(
            f"round-trip (ms)  min/avg/max = {myStats.minTime:.0f}/{myStats.totTime / myStats.pktsRcvd:.1f}/{myStats.maxTime:.0f}"
        )

    logging.info("")
    return


# =============================================================================#
def signal_handler(signum: int, frame: Any) -> None:
    """
    Handle exit via signals
    """
    dump_stats(myStats)
    logging.warning(f"\n(Terminated with signal {signum})\n")
    sys.exit(0)


# =============================================================================#
def verbose_ping(
    hostname, timeout=3000, count=3, numDataBytes=64, path_finder=False, ipv6=False
):
    """
    Send >count< ping to >destIP< with the given >timeout< and display
    the result.
    """
    signal.signal(signal.SIGINT, signal_handler)  # Handle Ctrl-C
    if hasattr(signal, "SIGBREAK"):
        # Handle Ctrl-Break e.g. under Windows
        signal.signal(signal.SIGBREAK, signal_handler)

    myStats = MyStats()  # Reset the stats

    mySeqNumber = 0  # Starting value

    try:
        if ipv6:
            info = socket.getaddrinfo(hostname, None)[0]
            destIP = info[4][0]
        else:
            destIP = socket.gethostbyname(hostname)
        logging.info(f"\nPYTHON PING {hostname} ({destIP}): {numDataBytes} data bytes")
    except socket.gaierror as e:
        # etype, evalue, etb = sys.exc_info()
        logging.error(
            f"\nPYTHON PING: Unknown host: {hostname} ({e})"
        )  # (hostname, evalue.args[1]))
        return

    myStats.thisIP = destIP

    for _i in range(count):
        delay = do_one(
            myStats, destIP, hostname, timeout, mySeqNumber, numDataBytes, ipv6=ipv6
        )
        if delay is None:
            delay = 0

        mySeqNumber += 1

        # Pause for the remainder of the MAX_SLEEP period (if applicable)
        if MAX_SLEEP > delay:
            time.sleep((MAX_SLEEP - delay) / 1000)

    dump_stats(myStats)
    # 0 if we receive at least one packet
    # 1 if we don't receive any packets
    return not myStats.pktsRcvd


# =============================================================================#
def quiet_ping(
    hostname, timeout=3000, count=3, numDataBytes=64, path_finder=False, ipv6=False
):
    """
    Same as verbose_ping, but the results are returned as tuple
    """
    myStats = MyStats()  # Reset the stats
    mySeqNumber = 0  # Starting value

    try:
        if ipv6:
            info = socket.getaddrinfo(hostname, None)[0]
            destIP = info[4][0]
        else:
            destIP = socket.gethostbyname(hostname)
    except socket.gaierror:
        return False

    myStats.thisIP = destIP

    # This will send packet that we dont care about 0.5 seconds before it starts
    # acrutally pinging. This is needed in big MAN/LAN networks where you sometimes
    # loose the first packet. (while the switches find the way... :/ )
    if path_finder:
        fakeStats = MyStats()
        do_one(
            fakeStats,
            destIP,
            hostname,
            timeout,
            mySeqNumber,
            numDataBytes,
            quiet=True,
            ipv6=ipv6,
        )
        time.sleep(0.5)

    for _i in range(count):
        delay = do_one(
            myStats,
            destIP,
            hostname,
            timeout,
            mySeqNumber,
            numDataBytes,
            quiet=True,
            ipv6=ipv6,
        )

        if delay is None:
            delay = 0

        mySeqNumber += 1

        # Pause for the remainder of the MAX_SLEEP period (if applicable)
        if MAX_SLEEP > delay:
            time.sleep((MAX_SLEEP - delay) / 1000)

    if myStats.pktsSent > 0:
        myStats.fracLoss = (myStats.pktsSent - myStats.pktsRcvd) / myStats.pktsSent
    if myStats.pktsRcvd > 0:
        myStats.avrgTime = myStats.totTime / myStats.pktsRcvd

    # return tuple(max_rtt, min_rtt, avrg_rtt, percent_lost)
    return myStats.maxTime, myStats.minTime, myStats.avrgTime, myStats.fracLoss


# =============================================================================#
if __name__ == "__main__":
    # Simple CLI for testing purposes
    match len(sys.argv):
        case 1:
            # These should work:
            verbose_ping("8.8.8.8")
            verbose_ping("heise.de")
            verbose_ping("google.com")

            # Inconsistent on Windows w/ ActivePython (Python 3.2 resolves correctly
            # to the local host, but 2.7 tries to resolve to the local *gateway*)
            verbose_ping("localhost")

            # Should fail with 'getaddrinfo failed':
            verbose_ping("foobar_url.foobar")

            # Should fail (timeout), but it depends on the local network:
            verbose_ping("192.168.255.254")

            # Should fails with 'The requested address is not valid in its context':
            verbose_ping("0.0.0.0")
        case 2:
            retval = verbose_ping(sys.argv[1])
            sys.exit(retval)
        case _:
            logging.error("Error: call ./ping.py hostname")
