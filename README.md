# PyMap

## Purpose

I wanted to build a port scanner in python that supported single ports, multiple ports, and port ranges for both TCP and UDP. There is a strong chance that this will be expanded to include other features in the future, but there are no guarantees. 

### Usage:

```
PyMap [-h] [-p PORT] [-m {TCP,UDP}] [-w TIMEOUT Address                                                                                                                                                                                                   
Scans a target IP or network to identify open ports. Parameters can be provided to modify the scanner profile.

options:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  The Port(s) to scan. Can be comma delimited hyphenated.
  -m {TCP,UDP}, --mode {TCP,UDP}
                        The protocol used during the scan (e.g. TCP, UDP.)
  -w TIMEOUT, --wait TIMEOUT
                        The timeout in ms to wait for connections. Increase to slow scans.
```

