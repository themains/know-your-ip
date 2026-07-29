# Test fixtures

## `GeoLite2-City-Test.mmdb`

A small synthetic database from MaxMind's own
[MaxMind-DB](https://github.com/maxmind/MaxMind-DB) repository
(`test-data/GeoLite2-City-Test.mmdb`), Apache-2.0. It contains fabricated
records, not real geolocation data.

It exists so the MaxMind provider is exercised against the genuine binary
format without a licence key or a 60 MB download. Everything else about that
provider was mocked, and a mock would not have caught the record-shape change
that broke it when geoip2 5.0 removed `.raw`.

## `censys_host_8.8.8.8.json`

Captured from the live Censys Platform API. Trimmed: `dns.names` and
`dns.forward_dns` are truncated and TLS certificate blobs replaced, since the
real response is ~31 KB and the parser reads none of that. Field names, nesting,
and value casing are unmodified - the previous hand-written fixture asserted
uppercase transport protocols the API never returns.
