# PyMap

## Purpose

I wanted to build a port scanner in python that supported single ports, multiple ports, and port ranges for both TCP and UDP. Since then, I've added network support, targeted multithreading, and cleaned up the code to be a bit easier to read. It's not designed to replace nmap, and if you're doing port scanning you should probably be using that rather than this - but if you want to learn how to build a port scanner from scratch this can help.

### Usage:

```
usage: PyMap [-h] [-p PORT] [-m {TCP,UDP}] [-w TIMEOUT] [-v] [-t THREADS] Address

Scans a target IP or network to identify open ports. Parameters can be provided to modify the scanner profile.

positional arguments:
  Address               The hostname or IP address of the target. Also supports subnet ranges using CIDR notation.

options:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  The Port(s) to scan. Can be comma delimited hyphenated.
  -m {TCP,UDP}, --mode {TCP,UDP}
                        The protocol used during the scan (e.g. TCP, UDP.)
  -w TIMEOUT, --wait TIMEOUT
                        The timeout in ms to wait for connections. Increase to slow scans.
  -v, --version         Displays the current version of PyMap.
  -t THREADS, --threads THREADS
                        The number of threads to use during the scan. Increase to speed up scans.
```

