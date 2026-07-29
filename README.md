# Know Your IP

[![PyPI version](https://img.shields.io/pypi/v/know_your_ip.svg)](https://pypi.python.org/pypi/know_your_ip)
[![CI](https://github.com/themains/know-your-ip/workflows/CI/badge.svg)](https://github.com/themains/know-your-ip/actions)
[![Downloads](https://static.pepy.tech/badge/know-your-ip)](https://pepy.tech/project/know-your-ip)

**Join a list of IP addresses against everything known about them.**

Built for research: hand it ten thousand addresses and it stays inside every
API's rate limit, never pays for the same lookup twice, doesn't lose a row when
a service goes down, and records enough about the run that you can defend the
numbers in a paper months later.

It does something useful before you sign up for anything.

## Thirty seconds, no account needed

```python
import know_your_ip as kyi

result = kyi.enrich(["66.249.66.1", "199.27.76.249"], providers=["rdap", "ranges"])

for row in result.canonical:
    print(
        row["ip"],
        row.get("registry_handle"),
        row.get("bot_name"),
        row.get("hosting_provider"),
    )
```

```
66.249.66.1 NET-66-249-64-0-1 googlebot None
199.27.76.249 NET-199-27-72-0-1 None fastly
```

One is Google's crawler, the other is Fastly's CDN — no API key, no database
download, no account. Add keys later for reputation and exposure data.

## One column per variable, not one per vendor

Providers spell the same thing differently. Ask five of them about an address
and "country" comes back about fifteen times, meaning three different things:
MaxMind alone returns `country.iso_code`, `country.geoname_id`, and the country
name in ten languages — plus a separate `registered_country`, which is where
the *block* is registered and routinely differs from where the address is used.

`result.canonical` does the reconciliation, and says how much the sources
agreed:

| column | meaning |
|---|---|
| `country_code` | the value sources settled on |
| `country_code.sources` | which providers answered |
| `country_code.agree` | whether they concurred (absent if only one did) |
| `country_code.values` | the distinct answers, when they disagreed |

Disagreement is reported rather than resolved away. Geolocation sources
genuinely differ, and every other tool hides that behind one confident answer.

```python
import know_your_ip as kyi

result = kyi.enrich(["8.8.8.8"], providers=["rdap", "ranges"])
print(result.disagreements)
```

`result.tidy()` gives the same data in long form — one row per address, field,
and source — which is the shape for comparing sources, and for a paper's
appendix.

## Why not just call the APIs yourself?

You can. Thirty lines of `requests` gets you the first hundred addresses. It's
the next ten thousand that hurt, and these are the four things you end up
building:

**Your loop will hit rate limits.** VirusTotal's free tier is four requests a
minute. Here, requests are paced per provider from published limits — six
concurrent lookups on that tier finish in thirty seconds with zero rate errors,
so raising concurrency is safe rather than counterproductive.

**Re-running will cost you a day.** VirusTotal allows 500 lookups daily, so a
5,000-address study is a ten-day job you can't repeat after a reviewer asks a
question. Results cache to disk; the second run costs nothing.

**One bad service will cost you rows.** A timeout mid-loop loses everything
after it. Here a failing provider becomes a value in that row, not an
exception — malformed addresses are skipped, not fatal, and identical failures
are reported once rather than ten thousand times.

**You'll be asked where the numbers came from.** Every run produces a manifest:
package version, which providers ran, a fingerprint of the settings, cache
hits, and per-provider error counts.

And one thing you probably wouldn't build: because results are appended rather
than overwritten, enriching the same list monthly leaves you with a panel
dataset as a side effect.

## What you can find out

Organised by the question, not by the vendor.

| Question | Where it comes from | Needs an account? |
|---|---|---|
| Is this address even routable? | Offline classification — private, loopback, CGNAT, reserved | No |
| What does it call itself? | Reverse DNS | No |
| Who is it registered to, and who do I report abuse to? | RDAP, the registry system that replaced WHOIS | No |
| Where is it? | MaxMind GeoLite2 · Censys | Free database · free tier |
| Has it been reported for abuse? | AbuseIPDB · VirusTotal | Free tiers |
| What is it running, and what's exposed? | Censys · Shodan | Free tier · paid |
| Is it a VPN, proxy, or datacenter? | Published cloud/CDN ranges · APIVoid | No · paid |
| Is it a Tor exit, or a search crawler? | Tor Project · Google and Bing range files | No |
| How does the network reach it? | ping, traceroute | No |

Knowing what *isn't* routable matters more than it sounds: real address data is
full of RFC1918, and spending metered quota to be told `192.168.1.1` is private
is waste.

## Working with batches

```python
import know_your_ip as kyi

result = kyi.enrich_csv(
    "addresses.csv",
    "enriched.csv",
    column="ip",
    cache="cache.sqlite",  # second run costs no quota
    max_workers=10,  # safe: pacing is per provider
)

print(f"{len(result)} rows, errors: {result.errors}")
```

Or from the shell:

```bash
know_your_ip --file addresses.csv --cache cache.sqlite -o enriched.csv
know_your_ip --list-providers      # what's registered and what each costs
```

Into pandas, if you'd rather:

```python
import know_your_ip as kyi

df = kyi.enrich(["8.8.8.8"], providers=["network"]).to_dataframe()
```

## Reproducibility

Every run describes itself:

```python
import json

import know_your_ip as kyi

result = kyi.enrich(["8.8.8.8"], providers=["network"])
print(json.dumps(result.manifest, indent=2)[:200])
```

Save it next to your results and the table can be regenerated and defended.
API keys are deliberately excluded from the fingerprint, so the manifest is
safe to publish.

Asking about the past is honest about what it doesn't know:

```python
from datetime import date

import know_your_ip as kyi

result = kyi.enrich(["8.8.8.8"], as_of=date(2019, 3, 14))
print(result.manifest["providers"])
```

No provider can answer for 2019 yet, so none of them pretends to — you get an
empty provider list rather than today's data wearing a 2019 label. As
historical sources land they'll honour the same contract.

## Install

Python 3.11+.

```bash
pip install know_your_ip
```

The base install is deliberately small — three dependencies, no accounts
needed. Optional extras:

```bash
pip install 'know_your_ip[pandas]'    # to_dataframe()
pip install 'know_your_ip[shodan]'    # Shodan
pip install 'know_your_ip[timezone]'  # offline timezone lookup
```

## Configuration

Keys go in `know_your_ip.toml`, in the working directory or
`~/.config/know-your-ip/config.toml`:

```toml
[abuseipdb]
enabled = true
api_key = "..."
days = 180          # lookback window; API maximum is 365

[virustotal]
enabled = true
api_key = "..."
```

Or as environment variables — `KNOW_YOUR_IP_VIRUSTOTAL_API_KEY` and so on.
Unknown keys and sections are rejected rather than ignored, so a typo fails
loudly instead of silently disabling a provider.

Generate a complete annotated file:

```python
from pathlib import Path

from know_your_ip import create_default_config

create_default_config(Path("know_your_ip.toml"))
```

### Geolocation database

MaxMind needs a free account since 2019. Once you have an account ID and
license key:

```bash
know_your_ip download-db --account-id YOUR_ID --license-key YOUR_KEY
```

It lands where the package looks for it, with no further configuration.
GeoLite2 allows 30 downloads per 24 hours, and its licence requires deleting
outdated copies within 30 days.

## Where to look next

- [`examples/example.ipynb`](https://github.com/themains/know-your-ip/blob/master/examples/example.ipynb) — a walkthrough that runs with no accounts
- [`examples/example.py`](https://github.com/themains/know-your-ip/blob/master/examples/example.py) — each provider, then all together
- [Documentation](https://themains.github.io/know-your-ip/) — full API reference
- [`CONTRIBUTING.md`](https://github.com/themains/know-your-ip/blob/master/CONTRIBUTING.md) — adding a provider

## Command line reference

```
usage: know_your_ip [-h] [-f FILE] [-c CONFIG] [-o OUTPUT] [-n MAX_CONN]
                    [--from FROM_ROW] [--to TO] [--all-columns]
                    [--providers PROVIDERS] [--as-of AS_OF] [--cache [PATH]]
                    [--max-age HOURS] [--list-providers]
                    [--log-file LOG_FILE] [-v] [--no-header]
                    [ip ...]
```

## Citation

If this package contributes to published work, see
[`CITATION.cff`](https://github.com/themains/know-your-ip/blob/master/CITATION.cff).

## Authors

[Suriyan Laohaprapanon](https://github.com/suriyan) and
[Gaurav Sood](https://github.com/soodoku). Released under the
[MIT License](https://opensource.org/licenses/MIT).

---

Intended for legitimate research, security analysis, and network diagnostics.
Respect each service's terms and rate limits.
