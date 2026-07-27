# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
