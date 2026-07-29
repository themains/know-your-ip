#!/usr/bin/env python

"""Query one IP address against each service that is enabled in the config.

Copy ``examples/know_your_ip.toml`` to ``know_your_ip.toml`` in the working
directory, add your API keys, and set ``enabled = true`` for the services you
want. Services that are disabled or missing a key are skipped.
"""

from pprint import pprint

from know_your_ip import (
    abuseipdb_api,
    apivoid_api,
    censys_api,
    enrich,
    geonames_timezone,
    load_config,
    maxmind_geocode_ip,
    ping,
    query_ip,
    shodan_api,
    timezone_at,
    traceroute,
    virustotal_api,
)

IP = "8.8.8.8"


def main() -> None:
    """Run each service individually, then run them all together."""
    config = load_config()

    lat = lng = None

    print("\n--- Keyless: classification, reverse DNS, registry ---")
    pprint(query_ip(config, IP, providers=["network", "rdap"]))

    print("\n--- Many addresses at once ---")
    # enrich is the batch entry point: paced to each provider's rate limit,
    # optionally cached, and it returns a manifest describing the run.
    batch = enrich(["8.8.8.8", "1.1.1.1"], config=config, providers=["network"])
    for row in batch:
        print(f"   {row['ip']:<10} {row['network.category']}")
    print(
        "   manifest:",
        batch.manifest["providers"],
        batch.manifest["addresses_enriched"],
    )

    if config.maxmind.enabled:
        print("\n--- MaxMind ---")
        # Enabled by default, but the database needs a free account. Calling
        # the provider directly raises rather than recording an error the way
        # query_ip does, so this example handles it explicitly.
        try:
            result = maxmind_geocode_ip(config, IP)
        except FileNotFoundError as exc:
            print(exc)
            result = {}
        pprint(result)
        lat = result.get("maxmind.location.latitude")
        lng = result.get("maxmind.location.longitude")

    if lat is not None and lng is not None:
        if config.geonames.enabled:
            print("\n--- GeoNames (timezone from lat/lng) ---")
            pprint(geonames_timezone(config, lat, lng))

        if config.timezone.enabled:
            print("\n--- Offline timezone ---")
            pprint(timezone_at(config, lat, lng))

    for label, enabled, fn in [
        ("AbuseIPDB", config.abuseipdb.enabled, abuseipdb_api),
        ("APIVoid", config.apivoid.enabled, apivoid_api),
        ("Censys", config.censys.enabled, censys_api),
        ("Shodan", config.shodan.enabled, shodan_api),
        ("VirusTotal", config.virustotal.enabled, virustotal_api),
    ]:
        if enabled:
            print(f"\n--- {label} ---")
            pprint(fn(config, IP))

    if config.ping.enabled:
        print("\n--- Ping ---")
        pprint(ping(config, IP))

    if config.traceroute.enabled:
        print("\n--- Traceroute ---")
        pprint(traceroute(config, IP))

    # query_ip runs every enabled service and returns the full record.
    print("\n--- query_ip (everything at once) ---")
    pprint(query_ip(config, IP))


if __name__ == "__main__":
    main()
