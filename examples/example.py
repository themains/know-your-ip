#!/usr/bin/env python

from pprint import pprint

from know_your_ip import (
    abuseipdb_api,
    abuseipdb_web,
    censys_api,
    geonames_timezone,
    ipvoid_scan,
    load_config,
    maxmind_geocode_ip,
    ping,
    shodan_api,
    traceroute,
    tzwhere_timezone,
    virustotal_api,
)

if __name__ == "__main__":
    # load configuration from file (default: 'know_your_ip.cfg')
    args = load_config()

    # target IP
    ip = "222.186.30.49"

    # Maxmind API
    print("Maxmind...")
    result = maxmind_geocode_ip(args, ip)
    pprint(result)

    # Get lat/long
    lat = result["maxmind.location.latitude"]
    lng = result["maxmind.location.longitude"]

    # Timezone from lat/lng
    print("Geonames...")
    result = geonames_timezone(args, lat, lng)
    pprint(result)

    # Timezone from lat/lng (offline)
    print("Tzwhere...")
    result = tzwhere_timezone(args, lat, lng)
    pprint(result)

    # abuseipdb web search
    print("AbuseIPDB (Web)...")
    result = abuseipdb_web(args, ip)
    pprint(result)

    # abuseipdb API
    print("AbuseIPDB (API)...")
    result = abuseipdb_api(args, ip)
    pprint(result)

    # ipvoid.com
    print("IPvoid...")
    result = ipvoid_scan(args, ip)
    pprint(result)

    # censys API
    print("Census API...")
    result = censys_api(args, ip)
    pprint(result)

    # shodan API
    print("Shodan API...")
    result = shodan_api(args, ip)
    pprint(result)

    # virustotal API
    print("Virustotal API...")
    result = virustotal_api(args, ip)
    pprint(result)

    # ping
    print("Ping...")
    result = ping(args, ip)
    pprint(result)

    # traceroute
    print("Traceroute...")
    result = traceroute(args, ip)
    pprint(result)
