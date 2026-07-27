# Contributing

Thanks for your interest in improving `know_your_ip`.

## Setup

```bash
git clone https://github.com/themains/know-your-ip
cd know-your-ip
uv sync --extra dev --extra test
uv run pre-commit install
```

## Before opening a pull request

```bash
uv run ruff check .
uv run ruff format --check .
uv run pytest --cov=know_your_ip
```

CI runs the same commands on Linux, macOS, and Windows against Python
3.11-3.13.

## Testing against external services

Tests must not make live network calls. Use recorded payloads with
`responses`, as in `tests/test_providers.py`.

This matters more here than in most projects. Several integrations broke
silently — a removed `geoip2` attribute, a renamed AbuseIPDB field, a Censys
API generation change — because nothing exercised them. When you touch a
provider, add a test that pins the specific field names and response shape you
rely on.

If you verify something against a live API, put the captured payload in a test
rather than the credential.

## Adding a service

1. Add a configuration section in `know_your_ip/config.py`, inheriting from
   `_Section` so unknown keys are rejected.
2. Add a `<service>_api(config, ip)` function returning a flat dict whose keys
   are prefixed with `<service>.`.
3. Call it from `query_ip()` behind an `enabled` check.
4. Export it from `know_your_ip/__init__.py`.
5. Add tests covering the success path, a 429, an auth failure, and a
   not-found response.
6. If it needs a heavyweight or platform-limited dependency, make it an
   optional extra and import it lazily.

Note what the service's terms of use permit. Scraping is not acceptable here —
two scrapers were removed for that reason.

## Conduct

Contributors are expected to follow the
[Contributor Code of Conduct](https://contributor-covenant.org/version/1/0/0/).
