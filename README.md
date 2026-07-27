# Know Your IP

[![PyPI version](https://img.shields.io/pypi/v/know_your_ip.svg)](https://pypi.python.org/pypi/know_your_ip)
[![CI](https://github.com/themains/know-your-ip/workflows/CI/badge.svg)](https://github.com/themains/know-your-ip/actions)
[![Downloads](https://static.pepy.tech/badge/know-your-ip)](https://pepy.tech/project/know-your-ip)

Get data on IP addresses: where they are located, whether they have been
reported for abuse, what services they expose, and how the network reaches
them. Point it at a CSV of addresses and get a CSV back.

## Install

**Requires Python 3.11+.**

```bash
pip install know_your_ip
```

The base install is small and has no API-key requirement. Optional services
come as extras:

```bash
pip install 'know_your_ip[shodan]'    # Shodan client
pip install 'know_your_ip[timezone]'  # offline timezone lookup
pip install 'know_your_ip[pandas]'    # DataFrame helpers in the examples
```

## Quick start

### Command line

```bash
# One or more addresses
know_your_ip 8.8.8.8 1.1.1.1

# From a file, 10 at a time
know_your_ip --file input.csv --config know_your_ip.toml -n 10 -o out.csv

# Every field collected, not just the [output] columns
know_your_ip 8.8.8.8 --all-columns
```

Invalid addresses are reported and skipped rather than aborting the run.

### Library

```python
from know_your_ip import KnowYourIPConfig, query_ip

config = KnowYourIPConfig()
config.virustotal.enabled = True
config.virustotal.api_key = "your_api_key"

result = query_ip(config, "8.8.8.8")
print(result["virustotal.reputation"])
```

`query_ip` returns **every** field it collected. The `[output]` column list
only controls what the command line writes to CSV. To apply it yourself:

```python
from know_your_ip import select_columns

select_columns(result, config.output.columns)
```

## Configuration

Configuration is TOML. See [`examples/know_your_ip.toml`](https://github.com/themains/know-your-ip/blob/master/examples/know_your_ip.toml)
for a complete file; generate a fresh one with:

```python
from pathlib import Path
from know_your_ip import create_default_config

create_default_config(Path("know_your_ip.toml"))
```

Files are looked for at `./know_your_ip.toml`, then
`~/.config/know-your-ip/config.toml`, then `~/.know-your-ip.toml`.

```toml
[maxmind]
enabled = true
db_path = "./db"      # relative paths resolve against the working directory

[abuseipdb]
enabled = true
api_key = "your_api_key_here"
days = 180            # lookback window; API maximum is 365

[virustotal]
enabled = true
api_key = "your_api_key_here"

[output]
columns = ["ip", "maxmind.country.names.en", "virustotal.reputation"]
```

Unknown keys and sections are rejected rather than silently ignored, so a typo
fails loudly.

### Environment variables

Any setting can be supplied as `KNOW_YOUR_IP_<SECTION>_<FIELD>`. These override
the configuration file.

```bash
export KNOW_YOUR_IP_VIRUSTOTAL_API_KEY="your_key"
export KNOW_YOUR_IP_VIRUSTOTAL_ENABLED=true
```

Unrecognized `KNOW_YOUR_IP_*` variables produce a warning.

## Services

| Service | Provides | Access |
|---|---|---|
| **MaxMind GeoLite2** | Country, city, lat/long, timezone | Free database; account + license key required to download |
| **VirusTotal** | Reputation, per-engine analysis counts, ASN, JARM | Free tier: 500/day, 4/min |
| **AbuseIPDB** | Abuse confidence, report categories, ISP, usage type | Free tier: 1,000 checks/day |
| **Censys** | Open ports, protocols, ASN, location | Free tier: 100 credits/month |
| **Shodan** | Open ports, services, vulnerabilities | Paid; free keys cannot do IP lookups |
| **APIVoid** | Proxy/VPN/Tor flags, blocklist detections | Paid; 30-day trial only |
| **GeoNames** | Timezone from coordinates | Free tier: 10,000/day, 1,000/hour |
| **Ping / traceroute** | Latency, packet loss, network path | System commands, no privileges needed |

Registration: [VirusTotal](https://www.virustotal.com/gui/join-us) ·
[AbuseIPDB](https://www.abuseipdb.com/register) ·
[Censys](https://platform.censys.io/) ·
[Shodan](https://account.shodan.io/register) ·
[GeoNames](https://www.geonames.org/login) ·
[MaxMind](https://www.maxmind.com/en/geolite2/signup)

### MaxMind database

Anonymous GeoLite2 downloads ended in 2019. Create a free MaxMind account, get
a license key, download `GeoLite2-City.mmdb`, and point `db_path` at the
directory containing it.

## Working with pandas

```python
import pandas as pd
from know_your_ip import load_config, query_ip

config = load_config()
df = pd.read_csv("ips.csv")
results = pd.DataFrame(query_ip(config, ip) for ip in df["ip"])
results.to_csv("enriched.csv", index=False)
```

## Command line reference

```
usage: know_your_ip [-h] [-f FILE] [-c CONFIG] [-o OUTPUT] [-n MAX_CONN]
                    [--from FROM_ROW] [--to TO] [--all-columns]
                    [--log-file LOG_FILE] [-v] [--no-header]
                    [ip ...]

positional arguments:
  ip                    IP address(es) to analyze

options:
  -f, --file FILE       File listing IP addresses
  -c, --config CONFIG   Configuration file (TOML)
  -o, --output OUTPUT   Output CSV file
  -n, --max-conn N      Max concurrent requests
  --from FROM_ROW       From row
  --to TO               To row (0 means all)
  --all-columns         Write every collected field
  --log-file LOG_FILE   Also write logs to this file
  -v, --verbose         Verbose mode
  --no-header           Omit the CSV header row
```

## Requirements

- Python 3.11+
- `traceroute` (Unix) or `tracert` (Windows) for the traceroute feature
- Ping and traceroute use system commands and need no special privileges

Runs on Linux, macOS, and Windows.

## Examples

- [example.py](https://github.com/themains/know-your-ip/blob/master/examples/example.py) — each service, then all of them
- [example.ipynb](https://github.com/themains/know-your-ip/blob/master/examples/example.ipynb) — notebook walkthrough
- [know_your_ip.toml](https://github.com/themains/know-your-ip/blob/master/examples/know_your_ip.toml) — full configuration
- [input.csv](https://github.com/themains/know-your-ip/blob/master/examples/input.csv) / [output.csv](https://github.com/themains/know-your-ip/blob/master/examples/output.csv)

## Documentation

<https://themains.github.io/know-your-ip/>

## Contributing

See [CONTRIBUTING.md](https://github.com/themains/know-your-ip/blob/master/CONTRIBUTING.md). Contributors are expected to follow the
[Contributor Code of Conduct](https://contributor-covenant.org/version/1/0/0/).

## Authors

- [Suriyan Laohaprapanon](https://github.com/suriyan)
- [Gaurav Sood](https://github.com/soodoku)

## License

[MIT](https://opensource.org/licenses/MIT).

---

**Note**: Intended for legitimate security analysis, threat intelligence, and
network research. Respect each service's terms of use and rate limits.
