Know Your IP
--------------

.. image:: https://img.shields.io/pypi/v/know_your_ip.svg
    :target: https://pypi.python.org/pypi/know_your_ip
.. image:: https://readthedocs.org/projects/know_your_ip/badge/?version=latest
    :target: http://know_your_ip.readthedocs.io/en/latest/?badge=latest
    :alt: Documentation Status

Get comprehensive data on IP addresses. Learn where they are located (lat/long,
country, city, time zone), whether they are flagged as malicious (by
`AbuseIPDB <https://www.abuseipdb.com>`__,
`VirusTotal <https://www.virustotal.com>`__,
`IPVoid <https://ipvoid.com/>`__, etc.), which ports are open and what
services are running (via `Shodan <https://shodan.io>`__), and network
diagnostics (ping, traceroute).

If you are curious about potential application of the package, we have a
:download:`presentation <../../presentation/kip.pdf>` on
its use in cybersecurity analysis workflow.

You can use the package in two different ways. You can call it from the shell, or you can
use it as an external library. From the shell, you can run ``know_your_ip``. It takes a csv
with a single column of IP addresses (sample input file: :download:`input.csv <../../examples/input.csv>`),
and a modern TOML configuration file with API keys and output settings,
and appends the requested results to the IP list (sample output file: :download:`output.csv <../../examples/output.csv>`).
This simple setup allows you to mix and match easily.

If you want to use it as an external library, the package also provides that. The function ``query_ip`` uses
the modern Pydantic configuration system and takes an IP address. You can
also get data from specific services. For instance, if you only care about getting the MaxMind data,
use ``maxmind_geocode_ip``. If you would like data from the abuseipdb, call the ``abuseipdb_api`` function, etc.
These functions use the type-safe ``KnowYourIPConfig`` configuration object. For examples of how to use the package,
see :download:`example.py <../../examples/example.py>` or the jupyter notebook
`example.ipynb <https://github.com/themains/know-your-ip/blob/master/examples/example.ipynb>`__.

What's New in v0.2.0
----------------------

The latest version brings significant modernization and improvements:

**Modern Configuration System**
- TOML configuration format with Pydantic v2 validation
- Type-safe configuration with field validators
- Environment variable support (``KNOW_YOUR_IP_*`` prefix)
- Embedded AbuseIPDB category mapping (no external CSV files)

**API Upgrades**
- VirusTotal API v3 with enhanced threat intelligence
- Updated rate limits and improved error handling
- Modern Python 3.11+ features (match/case syntax, union types)

**Performance Improvements**
- Eliminated file I/O operations for category lookups
- Self-contained category dictionary with all 23 AbuseIPDB categories
- Faster startup and reduced dependencies

**Developer Experience**
- Google-style docstrings with comprehensive examples
- Type hints throughout codebase
- Improved error messages and validation

Brief Primer on Functionality
--------------------------------

-  **Geocoding IPs**: There is no simple way to discern the location of
   an IP. The locations are typically inferred from data on delay and
   topology along with information from private and public databases.
   For instance, one algorithm starts with a database of locations of
   various 'landmarks', calculates the maximum distance of the last
   router before IP from the landmarks using Internet speed, and builds
   a boundary within which the router must be present and then takes the
   centroid of it. The accuracy of these inferences is generally
   unknown, but can be fairly \`poor.' For instance, most geolocation
   services place my IP more than 30 miles away from where I am.
   Try http://www.geoipinfo.com/.

   The script provides hook to `Maxmind City Lite
   DB <http://dev.maxmind.com/geoip/geoip2/geolite2/>`__. It expects a
   copy of the database to be in the folder in which the script is run.
   To download the database, go
   `here <http://dev.maxmind.com/geoip/geoip2/geolite2/>`__. The
   function ``maxmind_geocode_ip`` returns city, country, lat/long etc.

-  **Timezone**: In theory, there are 24 time zones. In practice, a few
   more. For instance, countries like India have half-hour offsets.
   Theoretical mappings can be easily created for lat/long data based on
   the 15 degrees longitude span. For practical mappings, one strategy
   is to map (nearest) city to time zone (recall the smallish lists that
   you scroll though on your computer's time/date program.) There are a
   variety of services for getting the timezone, including, but not
   limited to,

   -  `Time and Date <http://www.timeanddate.com/news/time/>`__
   -  `City Time Zone <http://www.citytimezones.info/index.htm>`__
   -  `Edval <http://www.edval.biz/mapping-lat-lng-s-to-timezones>`__
   -  `Geonames <http://www.geonames.org/export/ws-overview.html>`__
   -  `Worldtime.io <http://worldtime.io/>`__
   -  `Twinsun.com <http://www.twinsun.com/tz/tz-link.htm>`__

For its ease, we choose a `Python hook to nodeJS lat/long to
timezone <https://github.com/pegler/>`__. To get the timezone, we first
need to geocode the IP (see above). The function ``tzwhere_timezone`` takes
lat/long and returns timezone.

-  **Ping**: Sends out a ICMP echo request and waits for the reply.
   Measures round-trip time (min, max, and mean), reporting errors and
   packet loss. If there is a timeout, the function produces nothing. If
   there is a reply, it returns::

    packets_sent, packets_received, packets_lost, min_time,
    max_time, avg_time

-  **Traceroute**: Sends a UDP (or ICMP) packet. Builds the path for how
   the request is routed, noting routers and time.

-  **Backgrounder**:

   -  `censys.io <http://censys.io>`__: Performs ZMap and ZGrab scans of
      IPv4 address space. To use censys.io, you must first register.
      Once you register and have the API key, configure it in your TOML file
      or environment variables. The function takes an IP and returns
      asn, timezone, country etc. For a full list, see
      https://censys.io/ipv4/help.

   -  `shodan.io <http://shodan.io>`__: Scans devices connected to the
      Internet for services, open ports etc. You must register to use
      shodan.io. Querying costs money. Once you register and have the
      API key, configure it in your TOML file or environment variables. The script implements
      two API calls: shodan/host/ip and shodan/scan. The function takes
      a list of IPs and returns

-  **Blacklists and Backgrounders**: The number of services that
   maintain blacklists is enormous. Here's a list of some of the
   services: TornevallNET, BlockList\_de, Spamhaus, MyWOT, SpamRATS,
   Malc0de, SpyEye, GoogleSafeBrowsing, ProjectHoneypot, etc. Some of
   the services report results from other services as part of their
   results. In this script, we implement hooks to the following three:

   -  `virustotal.com <http://virustotal.com>`__: A Google company that
      analyzes and tracks suspicious files, URLs, and IPs. You must
      register to use virustotal. Once you register and have the API
      key, configure it in your TOML file or environment variables. The function implements
      the modern VirusTotal API v3 for retrieving IP address reports.

   -  `abuseipdb.com <http://abuseipdb.com>`__: Tracks reports on IPs.
      You must register to use the API. Once you register and have the
      API key, configure it in your TOML file or environment variables. The API
      provides comprehensive abuse data with embedded category mapping
      for improved performance.

   -  `ipvoid.com <http://ipvoid.com>`__: Tracks information on IPs.
      There is no API. We scrape information about IPs including status
      on various blacklist sites.

Query Limits
~~~~~~~~~~~~

+---------------+--------------------+-------------------------------------------------------------------------------------+
| Service       | Query Limits       | More Info                                                                           |
+===============+====================+=====================================================================================+
| GeoNames      | 10K/day, 1K/hour   | `GeoNames Web Services <https://www.geonames.org/export/web-services.html>`__       |
+---------------+--------------------+-------------------------------------------------------------------------------------+
| AbuseIPDB     | 1K/day             | `AbuseIPDB API <https://docs.abuseipdb.com/>`__                                     |
+---------------+--------------------+-------------------------------------------------------------------------------------+
| VirusTotal    | 500/day, 4/min     | `VirusTotal API v3 <https://developers.virustotal.com/reference/ip-info>`__         |
+---------------+--------------------+-------------------------------------------------------------------------------------+
| Censys        | 250/month          | `Censys Search API <https://search.censys.io/api>`__                                |
+---------------+--------------------+-------------------------------------------------------------------------------------+
| Shodan        | Paid plans only    | `Shodan Developer API <https://developer.shodan.io/pricing>`__                      |
+---------------+--------------------+-------------------------------------------------------------------------------------+
| IPVoid        | Web scraping       | No API - scraping only                                                             |
+---------------+--------------------+-------------------------------------------------------------------------------------+

API
----

.. automodule:: know_your_ip
   :members:


Installation
-----------------

**Requirements**: Python 3.11+

The script depends on some system libraries. Currently ``traceroute`` uses
operating system command ``traceroute`` on Linux and ``tracert`` on
Windows.

Ping function is based on a pure python ping implementation using raw
socket and you must have root (on Linux) or Admin (on Windows) privileges to run

::

    # Install package and dependencies
    pip install know_your_ip

    # On Ubuntu Linux (if traceroute command not installed)
    sudo apt-get install traceroute

Getting KYIP Ready For Use
----------------------------

To use the software, you need to configure API keys and optionally download MaxMind databases:

-  **Configuration**: Create a TOML configuration file (default: ``know_your_ip.toml``) with your API keys and settings
-  **MaxMind Database**: For geolocation, download the GeoLite2-City database from
   `MaxMind <https://dev.maxmind.com/geoip/geoip2/geolite2/>`__ and place it in the ``db_path`` directory
-  **Output Columns**: Configure desired output columns in the TOML file's ``[output]`` section
-  **Environment Variables**: Alternatively, use environment variables with the ``KNOW_YOUR_IP_*`` prefix
-  **Python 3.11+**: Ensure you have Python 3.11 or higher installed

Configuration File
------------------------

Most functions make calls to different public REST APIs and hence require an API key and/or username.
You can register to get the API keys at the following URLs:

    * `GeoNames <https://www.geonames.org/login>`__ - Free: 10K requests/day, 1K requests/hour
    * `AbuseIPDB <https://www.abuseipdb.com/register>`__ - Free tier: 1K requests/day
    * `VirusTotal <https://www.virustotal.com/gui/join-us>`__ - Free tier: 500 requests/day, 4 requests/min
    * `Censys <https://search.censys.io/register>`__ - Free tier: 250 requests/month, 1 req/2.5 sec
    * `Shodan <https://account.shodan.io/register>`__ - Paid service starting at $69/month

**TOML Configuration File**

Create a ``know_your_ip.toml`` file with your API keys and settings:

.. code-block:: toml

    # Know Your IP Configuration
    # See https://github.com/themains/know-your-ip for documentation

    [maxmind]
    enabled = true
    db_path = "./db"

    [geonames]
    enabled = false
    # username = "your_username_here"

    [abuseipdb]
    enabled = true
    api_key = "your_api_key_here"
    days = 90

    [virustotal]
    enabled = true
    api_key = "your_api_key_here"

    [shodan]
    enabled = false
    # api_key = "your_api_key_here"

    [output]
    columns = [
        "ip",
        "maxmind.country.names.en",
        "maxmind.location.time_zone",
        "abuseipdb.categories",
        "virustotal.reputation",
        "virustotal.malicious"
    ]

**Environment Variables**

You can also configure via environment variables:

.. code-block:: bash

    export KNOW_YOUR_IP_VIRUSTOTAL_API_KEY="your_key_here"
    export KNOW_YOUR_IP_VIRUSTOTAL_ENABLED=true
    export KNOW_YOUR_IP_ABUSEIPDB_API_KEY="your_key_here"
    export KNOW_YOUR_IP_ABUSEIPDB_ENABLED=true

**Programmatic Configuration**

.. code-block:: python

    from know_your_ip import KnowYourIPConfig

    config = KnowYourIPConfig()
    config.virustotal.enabled = True
    config.virustotal.api_key = "your_api_key"
    config.abuseipdb.enabled = True
    config.abuseipdb.days = 30


Using KYIP
-----------------

From the command line
~~~~~~~~~~~~~~~~~~~~~~~~~

::

    usage: know_your_ip [-h] [-f FILE] [-c CONFIG] [-o OUTPUT] [-n MAX_CONN]
                        [--from FROM_ROW] [--to TO] [-v] [--no-header]
                        [ip [ip ...]]

    Know Your IP

    positional arguments:
    ip                    IP Address(es)

    optional arguments:
    -h, --help            show this help message and exit
    -f FILE, --file FILE  List of IP addresses file
    -c CONFIG, --config CONFIG
                            Configuration file
    -o OUTPUT, --output OUTPUT
                            Output CSV file name
    -n MAX_CONN, --max-conn MAX_CONN
                            Max concurrent connections
    --from FROM_ROW       From row number
    --to TO               To row number
    -v, --verbose         Verbose mode
    --no-header           Output without header at the first row


::

    know_your_ip --file input.csv

As an External Library
~~~~~~~~~~~~~~~~~~~~~~~~~~

Please look at :download:`example.py <../../examples/example.py>` or the jupyter notebook
`example.ipynb <https://github.com/themains/know-your-ip/blob/master/examples/example.ipynb>`__.

As an External Library with Pandas DataFrame
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    import pandas as pd
    from know_your_ip import KnowYourIPConfig, query_ip

    # Load configuration
    config = KnowYourIPConfig()
    config.virustotal.enabled = True
    config.virustotal.api_key = "your_api_key"
    config.abuseipdb.enabled = True
    config.abuseipdb.api_key = "your_api_key"

    # Process DataFrame
    df = pd.read_csv('examples/input.csv', header=None)
    odf = df[0].apply(lambda ip: pd.Series(query_ip(config, ip)))
    odf.to_csv('output.csv', index=False)


Authors
----------

Suriyan Laohaprapanon and Gaurav Sood

The Contributor Code of Conduct
----------------------------------

The project welcomes contributions from everyone! In fact, it depends on
it. To maintain this welcoming atmosphere, and to collaborate in a fun
and productive way, we expect contributors to the project to abide by
the `Contributor Code of
Conduct <http://contributor-covenant.org/version/1/0/0/>`__.

License
---------------

The package is released under the `MIT
License <https://opensource.org/licenses/MIT>`__.
