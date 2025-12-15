Know Your IP
--------------

.. image:: https://img.shields.io/pypi/v/know_your_ip.svg
    :target: https://pypi.python.org/pypi/know_your_ip
.. image:: https://readthedocs.org/projects/know_your_ip/badge/?version=latest
    :target: http://know_your_ip.readthedocs.io/en/latest/?badge=latest
    :alt: Documentation Status

Get data on IP addresses. Learn where they are located (lat/long,
country, city, time zone), whether they are blacklisted or not (by
`abuseipdb <http://http://www.abuseipdb.com>`__,
`virustotal <http://www.virustotal.com>`__,
`ipvoid <http://ipvoid.com/>`__, etc.) and for what (and when they were
blacklisted), which ports are open, and what services are running (via
`shodan <http://shodan.io>`__), and what you get when you ping or issue
a traceroute. 

If you are curious about potential application of the package, we have a
:download:`presentation <../../presentation/kip.pdf>` on 
its use in cybersecurity analysis workflow.

You can use the package in two different ways. You can call it from the shell, or you can
use it as an external library. From the shell, you can run ``know_your_ip``. It takes a csv 
with a single column of IP addresses (sample input file: :download:`input.csv <../../examples/input.csv>`), 
details of the API keys to various services (in :download:`know_your_ip.cfg <../../know_your_ip/know_your_ip.cfg>`) 
and which columns you would like from which service (in :download:`this example columns.txt <../../know_your_ip/columns.txt>`), 
and appends the requested results to the IP list (sample output file: :download:`output.csv <../../examples/output.csv>`). 
This simple setup allows you to mix and match easily. 

If you want to use it as an external library, the package also provides that. The function ``query_ip`` relies
on the same config files as ``know_your_ip`` and takes an IP address. We illustrate its use below. You can 
also get data from specific services. For instance, if you only care about getting the MaxMind data, 
use ``maxmind_geocode_ip``. If you would like data from the abuseipdb, call the ``abuseipdb_api`` function, etc. 
These functions still rely on the global config and columns files. For examples of how to use the package, 
see :download:`example.py <../../examples/example.py>` or the jupyter notebook 
`example.ipynb <https://github.com/themains/know-your-ip/blob/master/examples/example.ipynb>`__.

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
      Once you register and have the API key, put in
      :download:`here <../../know_your_ip/know_your_ip.cfg>`. The function takes an IP and returns
      asn, timezone, country etc. For a full list, see
      https://censys.io/ipv4/help.

   -  `shodan.io <http://shodan.io>`__: Scans devices connected to the
      Internet for services, open ports etc. You must register to use
      shodan.io. Querying costs money. Once you register and have the
      API key, put in :download:`here <../../know_your_ip/know_your_ip.cfg>`. The script implements
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
      key, put in :download:`here <../../know_your_ip/know_your_ip.cfg>`. The function implements
      retrieving IP address reports method.

   -  `abuseipdb.com <http://abuseipdb.com>`__: Tracks reports on IPs.
      You must register to use the API. Once you register and have the
      API key, put in :download:`here <../../know_your_ip/know_your_ip.cfg>`. There is a limit of
      5k pings per month. The function that we implement here is a
      mixture of API and scraping as the API doesn't return details of
      the reports filed.

   -  `ipvoid.com <http://ipvoid.com>`__: Tracks information on IPs.
      There is no API. We scrape information about IPs including status
      on various blacklist sites.

Query Limits
~~~~~~~~~~~~

+---------------+--------------------+-------------------------------------------------------------------------------------+
| Service       | Query Limits       | More Info                                                                           |
+===============+====================+=====================================================================================+
| Censys.io     | 120/5 minutes      | `Censys Acct. <https://censys.io/account>`__                                        |
+---------------+--------------------+-------------------------------------------------------------------------------------+
| Virustotal    | 4/minute           | `Virustotal API Doc. <https://www.virustotal.com/en/documentation/public-api/>`__   |
+---------------+--------------------+-------------------------------------------------------------------------------------+
| AbuseIPDB     | 2500/month         | `AbuseIPDB FAQ <http://www.abuseipdb.com/faq.html>`__                               |
+---------------+--------------------+-------------------------------------------------------------------------------------+
| IPVoid        | \-                 |                                                                                     |
+---------------+--------------------+-------------------------------------------------------------------------------------+
| Shodan        | \-                 |                                                                                     |
+---------------+--------------------+-------------------------------------------------------------------------------------+
| \-----------  | \----------------  | \-----------                                                                        |
+---------------+--------------------+-------------------------------------------------------------------------------------+

API
----

.. automodule:: know_your_ip
   :members:


Installation
-----------------

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

Note: If you use anaconda on Windows, it is best to install Shapely via:

::

    conda install -c scitools shapely 

Getting KYIP Ready For Use
----------------------------

To use the software, you need to take care of three things. You need to fill out
the API keys in the config file, have a copy of MaxMind db if you want to use MaxMind,
and pick out the columns you want in the columns.txt file:

-  In the config file (default: ``know_your_ip.cfg``), the settings grouped by function.
-  For Maxmind API, the script expects a copy of the database to be in
   the folder specify by ``dbpath`` in the config file. To download the
   database, go `here <http://dev.maxmind.com/geoip/geoip2/geolite2/>`__
-  In the columns file (default: ``columns.txt``), there are the data
   columns to be output by the script. We may have more than one columns
   file but only one will be use by setting the ``columns`` variable in
   ``output`` section.

Configuration File
------------------------

Most of functions make calls to different public REST APIs and hence require an API key and/or username.
You can register to get the API keys at the following URLs:

    * `GeoNames <http://www.geonames.org/login>`__
    * `AbuseIPDB <https://www.abuseipdb.com/register>`__
    * `Censys <https://censys.io/register>`__
    * `Shodan <https://account.shodan.io/registe>`__
    * `VirusTotal <https://www.virustotal.com/en/documentation/virustotal-community/>`__

    .. include:: ../../know_your_ip/know_your_ip.cfg
        :literal:

    See :download:`this example know_your_ip.cfg <../../know_your_ip/know_your_ip.cfg>`

    We can also select the data columns which will be outputted to the CSV file in the text file.
    To take out that column from the output file, add ``#`` at the start of line in the text file ``columns.txt``.

    .. include:: ../../know_your_ip/columns.txt
        :literal:

    See :download:`this example columns.txt <../../know_your_ip/columns.txt>`


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
    from know_your_ip import load_config, query_ip

    df = pd.read_csv('examples/input.csv', header=None)

    args = load_config('know_your_ip/know_your_ip.cfg')

    odf = df[0].apply(lambda c: pd.Series(query_ip(args, c)))

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
