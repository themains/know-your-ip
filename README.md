# Know Your IP

[![PyPI version](https://img.shields.io/pypi/v/know_your_ip.svg)](https://pypi.python.org/pypi/know_your_ip)
[![CI](https://github.com/themains/know-your-ip/workflows/CI/badge.svg)](https://github.com/themains/know-your-ip/actions)
[![Downloads](https://static.pepy.tech/badge/know-your-ip)](https://pepy.tech/project/know-your-ip)

Get comprehensive data on IP addresses. Learn where they are located (lat/long, country, city, time zone), whether they are flagged as malicious (by [AbuseIPDB](https://www.abuseipdb.com), [VirusTotal](https://www.virustotal.com), [IPVoid](https://ipvoid.com/), etc.), which ports are open and what services are running (via [Shodan](https://shodan.io)), and network diagnostics (ping, traceroute).

## 🚀 What's New in v0.2.0

- **Modern Configuration**: TOML-based config with Pydantic validation
- **VirusTotal API v3**: Latest API with enhanced threat intelligence
- **Embedded Categories**: Self-contained AbuseIPDB category mapping
- **Python 3.11+ Features**: Match/case syntax, union types, type safety
- **Performance Boost**: No file I/O for category lookups
- **Environment Variables**: Configuration via `KNOW_YOUR_IP_*` variables

## Quick Start

### Installation

**Requirements**: Python 3.11+

```bash
pip install know_your_ip
```

### Basic Usage

#### Command Line
```bash
# Analyze single IP
know_your_ip 8.8.8.8

# Analyze from file
know_your_ip --file input.csv --config config.toml
```

#### Python Library
```python
from know_your_ip import KnowYourIPConfig, query_ip

# Load configuration
config = KnowYourIPConfig()
config.virustotal.enabled = True
config.virustotal.api_key = "your_api_key"

# Analyze IP
result = query_ip(config, "8.8.8.8")
print(result['virustotal.reputation'])  # 530
```

## Configuration

### TOML Configuration File

Create `know_your_ip.toml`:

```toml
[maxmind]
enabled = true
db_path = "./db"

[abuseipdb]
enabled = true
api_key = "your_api_key_here"
days = 90

[virustotal]
enabled = true
api_key = "your_api_key_here"

[output]
columns = [
    "ip",
    "maxmind.country.names.en",
    "virustotal.reputation",
    "abuseipdb.categories"
]
```

### Environment Variables

```bash
export KNOW_YOUR_IP_VIRUSTOTAL_API_KEY="your_key"
export KNOW_YOUR_IP_VIRUSTOTAL_ENABLED=true
export KNOW_YOUR_IP_ABUSEIPDB_API_KEY="your_key"
```

### Programmatic Configuration

```python
from know_your_ip import KnowYourIPConfig

config = KnowYourIPConfig()
config.virustotal.api_key = "your_api_key"
config.abuseipdb.enabled = True
config.abuseipdb.days = 30
```

## Supported Services

| Service | Features | API Required |
|---------|----------|--------------|
| **MaxMind** | Geolocation, ASN, ISP | Free database |
| **VirusTotal** | Threat reputation, categories | ✅ Free/Paid |
| **AbuseIPDB** | Abuse reports, categories | ✅ Free/Paid |
| **Shodan** | Open ports, services | ✅ Paid |
| **Censys** | Internet scanning data | ✅ Free/Paid |
| **IPVoid** | Blacklist status | Web scraping |
| **GeoNames** | Timezone data | ✅ Free |
| **Ping/Traceroute** | Network diagnostics | System tools |

### API Registration Links

- [VirusTotal](https://www.virustotal.com/gui/join-us) - 500 requests/day, 4/min free
- [AbuseIPDB](https://www.abuseipdb.com/register) - 1,000 requests/day free
- [Shodan](https://account.shodan.io/register) - Paid service ($69+/month)
- [Censys](https://search.censys.io/register) - 250 requests/month free
- [GeoNames](https://www.geonames.org/login) - 10,000 requests/day, 1,000/hour free

## Advanced Features

### Pandas Integration

```python
import pandas as pd
from know_your_ip import load_config, query_ip

# Load IPs from CSV
df = pd.read_csv('ips.csv')

# Load configuration
config = load_config()

# Analyze all IPs
results = df['ip'].apply(lambda ip: pd.Series(query_ip(config, ip)))
results.to_csv('analysis.csv', index=False)
```

### Custom Analysis

```python
from know_your_ip import maxmind_geocode_ip, virustotal_api

# Get only geolocation
location = maxmind_geocode_ip(config, "8.8.8.8")
print(f"Country: {location['maxmind.country.names.en']}")

# Get only threat intelligence
threat_data = virustotal_api(config, "8.8.8.8")
print(f"Malicious detections: {threat_data['virustotal.malicious']}")
```

### Batch Processing

```bash
# Process large files with concurrency
know_your_ip --file large_ips.csv --max-conn 10 --config config.toml

# Process specific range
know_your_ip --file ips.csv --from 100 --to 200
```

## API Reference

### Core Functions

- `query_ip(config, ip)` - Complete IP analysis
- `load_config(path)` - Load configuration from file
- `maxmind_geocode_ip(config, ip)` - Geolocation data
- `virustotal_api(config, ip)` - VirusTotal threat intel
- `abuseipdb_api(config, ip)` - Abuse reports
- `shodan_api(config, ip)` - Port/service data
- `ping(config, ip)` - Network latency
- `traceroute(config, ip)` - Network path

### Configuration Classes

- `KnowYourIPConfig` - Main configuration
- `MaxMindConfig` - Geolocation settings
- `VirusTotalConfig` - Threat intel settings
- `AbuseIPDBConfig` - Abuse data settings
- `OutputConfig` - Output column configuration

## Command Line Reference

```
usage: know_your_ip [-h] [-f FILE] [-c CONFIG] [-o OUTPUT] [-n MAX_CONN]
                    [--from FROM_ROW] [--to TO] [-v] [--no-header]
                    [ip [ip ...]]

Know Your IP - Comprehensive IP Address Analysis

positional arguments:
  ip                    IP Address(es) to analyze

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  List of IP addresses file
  -c CONFIG, --config CONFIG
                        Configuration file (TOML format)
  -o OUTPUT, --output OUTPUT
                        Output CSV file name
  -n MAX_CONN, --max-conn MAX_CONN
                        Max concurrent connections
  --from FROM_ROW       From row number
  --to TO               To row number
  -v, --verbose         Verbose mode
  --no-header           Output without header
```

## Rate Limits

| Service | Free Tier | Paid Tier |
|---------|-----------|-----------|
| VirusTotal | 500/day, 4/min | Higher limits |
| AbuseIPDB | 1,000/day | 10,000+/day |
| Censys | 250/month, 1 req/2.5s | Higher limits |
| GeoNames | 10,000/day, 1,000/hour | Commercial plans |
| Shodan | No free API | $69+/month |

## Examples

See the [`examples/`](examples/) directory for:
- [example.py](examples/example.py) - Basic usage examples
- [example.ipynb](examples/example.ipynb) - Jupyter notebook tutorial
- [input.csv](examples/input.csv) - Sample input file
- [output.csv](examples/output.csv) - Sample output

## System Requirements

### Dependencies
- Python 3.11+
- System `traceroute` command (Linux) or `tracert` (Windows)
- Raw socket access for ping (requires admin/root privileges)

### Platform Support
- ✅ Linux
- ✅ macOS
- ✅ Windows
- ✅ Docker/containers

## Documentation

For comprehensive documentation, visit: [https://themains.github.io/know-your-ip/](https://themains.github.io/know-your-ip/)

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) and [Code of Conduct](https://contributor-covenant.org/version/1/0/0/).

## License

Released under the [MIT License](https://opensource.org/licenses/MIT).

## Authors

- [Suriyan Laohaprapanon](https://github.com/soodoku)
- [Gaurav Sood](https://github.com/soodoku)

---

**Security Note**: This tool is designed for legitimate security analysis, threat intelligence, and network diagnostics. Please use responsibly and in accordance with applicable laws and service terms of use.
