# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Censys now captures the response it was already paying for. One host request
  returns ~31 KB across seven sections and the parser kept eight fields; it now
  keeps thirty, including:
  - `bgp_prefix` - the announced prefix, i.e. routing data at no extra request.
  - `latitude`/`longitude` and `province`/`postal_code`/`continent` - a second
    independent geolocation, which is what makes cross-source disagreement
    measurable without adding a provider.
  - the `whois` block - network handle, CIDRs, allocation type, organization,
    and abuse contact - cross-checking the `rdap` provider rather than
    duplicating it.
  - `last_scan_time` - when Censys actually observed the services, which is the
    provenance stamp for that section.
  Verified against the live Platform API; tests now replay a captured payload
  rather than a hand-written approximation.
- Two keyless providers, so the package is useful with **no API keys at all**:
  - `network` classifies an address offline (public, private, loopback,
    link-local, multicast, reserved, CGNAT) and resolves its PTR record.
    Knowing which addresses are not globally routable lets a caller skip them
    before spending metered quota - real research data is full of RFC1918.
  - `rdap` queries the responsible registry over RDAP, the IETF successor to
    port-43 WHOIS, routed via IANA's bootstrap registry. Returns the network
    handle and name, allocation and last-changed dates, and an abuse contact.
    Non-routable addresses are reported as such rather than queried.
  Both are on by default. Note that RIRs differ in what they populate: APNIC
  fills the top-level `country`, ARIN does not.
- A provider registry. Each source is described once - its cost, whether it
  needs a key, whether it can answer historically - rather than as another
  `if config.x.enabled:` branch. `--list-providers` shows the table, and
  `--providers a,b` runs a chosen set without editing configuration.
- An `as_of` parameter on `query_ip` and `--as-of` on the command line. No
  provider honors it yet; those that cannot are **skipped with a warning**
  rather than answering a question about 2019 with today's data. The contract
  exists first so every provider added later inherits it.
- An append-only SQLite cache (`--cache`, `--max-age`). Re-running an analysis
  costs no API quota, which is what makes a 500/day free tier usable at
  research sample sizes. Because rows are appended rather than replaced,
  repeated runs over a fixed address list accumulate a panel dataset:
  `Cache.history(ip)` returns the observations in order.
- Cache keys include a fingerprint of the settings that affect the answer, so
  a result fetched with AbuseIPDB's 30-day window cannot satisfy a request for
  365 days.

## [0.3.0] - 2026-07-27

### Added

- A shared HTTP transport (`know_your_ip.http`). One pooled session replaces a
  fresh TCP+TLS connection per lookup; retries use exponential backoff with
  jitter and honor `Retry-After`; and each provider declares its published
  allowance so requests are paced by a token bucket rather than fired until the
  service returns 429. Six concurrent VirusTotal lookups on the free 4/min tier
  now complete in ~30s with no rate-limit errors.
- Failed calls return a value (`<service>.error` or `<service>.status`) instead
  of an empty dict indistinguishable from "nothing found".

### Changed

- `censys.protocols` is split into `censys.transport_protocols` (`tcp`, `udp`,
  `quic` - lowercase, as the API returns them) and `censys.services` (the
  application protocol: `DNS`, `HTTP`). The old name held transport values
  under a label that read like application protocol.
- `censys.ports` is deduplicated and numerically sorted. A host commonly
  exposes one port over several transports, so the previous output could read
  `443|443`; `censys.service_count` keeps the raw total.
- `censys.dns_name_count` replaces any attempt to expand `dns.names`, which
  returns 100 hostnames per host and would add 100 columns to every CSV row.

### Fixed

- The Censys rate limit is documented as an unverified guess. It was carried
  over from the legacy Search API; the Platform API publishes no rate-limit
  headers and meters the free tier as a monthly credit quota instead.

### Changed

- Versions are derived from git tags (hatchling + uv-dynamic-versioning); there
  is no version string to bump.
- Adopted the py-canon fleet standard for CI, docs, and release workflows, and
  the stricter shared ruff/pyright/pydoclint configuration. Docs moved from
  `docs/source/` to `docs/`.
- Every provider now goes through the shared transport, removing about 110
  lines of duplicated retry logic.
- A 429 is retried with backoff rather than abandoned, so a transient rate
  limit recovers instead of surfacing as a failure.

### Fixed

- `query_ip()` returned only fields listed in `[output] columns`, which
  contained no `virustotal.*` or `censys.*` entries. Every documented library
  example raised `KeyError`. It now returns the complete record; column
  selection applies to CSV output only, or explicitly via `select_columns()`.
- MaxMind lookups raised `AttributeError` on any current install. geoip2 5.0
  removed the `raw` attribute from response models. The database is now read
  directly with `maxminddb`, which also drops the `aiohttp` dependency.
- MaxMind `db_path` resolved relative paths against the installed package
  directory, so the documented default `"./db"` pointed inside `site-packages`.
  Relative paths now resolve against the working directory, and the default and
  an explicit `"./db"` resolve identically (previously they did not).
- `tzwhere` raised `ValueError` on NumPy 1.24+ and was abandoned in 2017.
  Replaced by `timezonefinder` behind the optional `timezone` extra.
- Ping always failed on macOS: `-W` is milliseconds there and seconds on Linux,
  so the default became a 3 ms deadline.
- `main()` could loop forever, re-running a failed batch without advancing.
- Four retry loops incremented their counter only on exception, so any non-200
  response burned all five attempts back-to-back with no delay.
- AbuseIPDB read `abuseConfidencePercentage`, which does not exist in API v2;
  the field is `abuseConfidenceScore` and the column was always 0.
- AbuseIPDB categories were read from a non-existent top-level `categories`
  key. They are aggregated from `data.reports[].categories`.
- APIVoid used the v1 endpoint, which passed its announced end of life in
  February 2026. Now uses v2 (POST, `X-API-Key`, flattened response).
- Censys sent Bearer auth to a legacy Search v2 URL built from a base that
  already contained a version, and read the wrong response envelope. Now targets
  the Platform API at `api.platform.censys.io`.
- GeoNames used cleartext HTTP. Switched to `secure.geonames.org`
  (`api.geonames.org` presents a certificate for that name, so plain HTTPS
  fails validation). Quota errors returned inside HTTP 200 are now detected.
- Timezone lookup crashed with an unbound `lat`/`lng` when MaxMind was disabled.
- `traceroute` had no timeout and could hang indefinitely; unvalidated input
  could inject additional traceroute arguments.
- CSV output opened without `newline=""`, producing blank rows on Windows, and
  without a context manager.

### Added

- IP address validation. Invalid input is reported and skipped rather than
  being passed through to URLs and subprocesses.
- IPv6 support in ping (`ping6`) and traceroute (`traceroute6`).
- `select_columns()` for explicit column filtering.
- `--all-columns` to write every collected field, and `--log-file`.
- VirusTotal now also reports `timeout` analysis counts, `continent`, `jarm`,
  `regional_internet_registry`, `tags`, vote totals, and analysis dates.
- Unknown configuration keys and sections are rejected; unrecognized
  `KNOW_YOUR_IP_*` environment variables warn instead of vanishing silently.
- Tests for the service integrations, which previously had none.

### Changed

- Concurrency uses threads rather than processes; the work is I/O-bound and
  process workers re-imported the package and re-pickled the config per task.
- MaxMind database readers are cached per process instead of being reopened for
  every address.
- `shodan` and `timezonefinder` moved to optional extras. `timezonefinder` is
  ~55 MB and publishes wheels only for linux-x86_64.
- Library modules log to their own logger instead of reconfiguring the root
  logger on import and truncating `know_your_ip.log` on every run.
- The example configuration is generated from the models, so it cannot drift
  from them.

### Removed

- `abuseipdb_web()` — scraped a page now behind Cloudflare, using selectors
  from a design that no longer exists. AbuseIPDB's terms prohibit scraping, and
  it duplicated data the API already returns.
- `ipvoid_scan()` — the results page is hCaptcha-gated and contains none of the
  markup the parser expected.
- `tzwhere_timezone()` — replaced by `timezone_at()`.
- The `[ipvoid]` and `[tzwhere]` configuration sections.
