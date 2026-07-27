Background
==========

Notes on what each kind of lookup actually measures, and how much to trust it.

Geolocating an IP
-----------------

There is no direct way to discern the physical location of an IP address.
Locations are inferred from network delay and topology measurements combined
with private and public databases. One family of algorithms starts from a set
of landmarks at known locations, bounds the distance to the last router before
the target using observed latency, intersects those bounds, and takes the
centroid.

Accuracy is uneven and generally unquantified by the providers. Independent
measurement studies consistently find that **country-level** assignment is
reliable — error rates under about 1% across the major providers — while
**city-level** accuracy varies by an order of magnitude, and is dramatically
worse for mobile networks than for fixed ones. Treat country as solid, city as
indicative, and latitude/longitude as a centroid rather than a location.

``maxmind_geocode_ip`` reads the `GeoLite2 City database
<https://dev.maxmind.com/geoip/geolite2-free-geolocation-data>`__ locally.
Anonymous downloads ended in 2019: a free MaxMind account and license key are
now required.

Timezone
--------

Timezone can be derived from coordinates, which means it inherits all the
uncertainty above. Two paths are available:

- ``maxmind_geocode_ip`` already returns ``location.time_zone`` directly from
  the City database. This is free and requires no extra lookup.
- ``timezone_at`` resolves coordinates against timezone polygons offline via
  ``timezonefinder`` (the optional ``timezone`` extra). Useful as an
  independent cross-check.
- ``geonames_timezone`` queries `GeoNames
  <https://www.geonames.org/export/web-services.html>`__ over the network.

Ping and traceroute
-------------------

``ping`` sends ICMP echo requests and reports round-trip time (min, max, mean)
and packet loss. ``traceroute`` maps the routers along the path and the time to
each hop. Both shell out to the system commands and need no special
privileges. Many hosts drop ICMP entirely, so silence is not evidence of
absence.

Exposed services
----------------

- `Censys <https://docs.censys.com/>`__ scans the IPv4 address space and
  reports open ports, protocols, certificates, and ASN. Requires registration;
  the free tier is credit-limited.
- `Shodan <https://shodan.io>`__ indexes internet-connected devices, services,
  and known vulnerabilities. IP lookups require a paid membership — free API
  keys cannot call the host endpoint.

Both report what a scanner observed at some past moment, not what is true now.

Reputation and abuse
--------------------

Many organizations maintain blocklists, and they cite each other, so counting
"detections" across services overstates independence.

- `VirusTotal <https://www.virustotal.com>`__ aggregates verdicts from roughly
  ninety engines and reports ASN, network, RIR, JARM, and a reputation score
  derived from community votes. Note that VirusTotal returns *categories* only
  for domains and URLs, never for IP addresses.
- `AbuseIPDB <https://www.abuseipdb.com>`__ collects user-submitted abuse
  reports with categories such as SSH brute force, port scanning, and web spam.
  ``days`` controls the lookback window, up to the API maximum of 365.
- `APIVoid <https://www.apivoid.com/api/ip-reputation/>`__ reports proxy, VPN,
  Tor, and hosting flags alongside blocklist detections.

An IP appearing on a blocklist says something about the address, which may be
shared, reassigned, or NATed behind thousands of users. It is weak evidence
about any individual.

Query limits
------------

============  =================================  ==========================
Service       Free tier                          Notes
============  =================================  ==========================
GeoNames      10,000/day, 1,000/hour             Must enable the free web service
AbuseIPDB     1,000 checks/day                   Higher on paid plans
VirusTotal    500/day, 4/minute                  An unpublished monthly cap also applies
Censys        100 credits/month                  Platform API
Shodan        None                               IP lookup requires paid membership
APIVoid       None                               30-day trial only
============  =================================  ==========================

API reference
=============

.. automodule:: know_your_ip
   :members:
   :undoc-members:
   :show-inheritance:
