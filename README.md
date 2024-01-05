# PyMap

## Purpose

I wanted to build a port scanner in python that supported single ports, multiple ports, and port ranges for both TCP and UDP. Since then, I've added network support, targeted multithreading, cleaned up the code for readability, and added a bunch of features. This is not designed to replace nmap - if you're doing port scanning you should probably be using that rather than this - but if you want something purely python and to learn how to build a port scanner from scratch this can help. 

### Usage:

```
usage: PyMap [-h] [-p PORT] [-m {TCP,UDP}] [-w TIMEOUT] [-v] [-t THREADS] [--tcp-top-1000] [--udp-top-1000] [--tcp-all] [--udp-all] [--web] Address

Scans a target IP or network to identify open ports. Parameters can be provided to modify the scanner profile.

positional arguments:
  Address               The hostname or IP address of the target. Also supports subnet ranges using CIDR notation.

options:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  Default: 80. The Port(s) to scan. Can be comma delimited hyphenated. Use - to scan all ports.
  -m {TCP,UDP}, --mode {TCP,UDP}
                        Default: TCP. The protocol used during the scan (e.g. TCP, UDP.)
  -w TIMEOUT, --wait TIMEOUT
                        Default: 50. The timeout in ms to wait for connections. Increase to improve accuracy, but will slow scan speed.
  -v, --version         Displays the current version of PyMap.
  -t THREADS, --threads THREADS
                        The number of threads to use during the scan. Increase to speed up scans.

Predefined Port Lists:
  Use these options to scan a predefined list of ports.

  --tcp-top-1000        Top 1000 TCP ports.
  --udp-top-1000        Top 1000 UDP ports.
  --tcp-all             All TCP ports.
  --udp-all             All UDP ports.
  --web                 All ports commonly used for web services (80, 443, 8080, 8443).
```

