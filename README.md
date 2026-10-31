# port-scanner

CLI port scanner in Python 3. It performs TCP connect, UDP, and stealth SYN scans over single ports or ranges;
`-sv` adds service/version detection on open TCP ports. The raw-socket scans (`-udp`, `-s`) are Linux-specific,
require root.

**This tool is created for educational purposes only. Only scan networks you own or have explicit
authorization to test.**


## Layout

    port_scanner.py    entry point
    scanner/
        cli.py         pure functions
        packets.py     TCP/IP byte layer
        output.py      terminal + file reporting (-f)
        services.py    service/version identification (-sv)
        scanners/
            tcp_connect.py   full-handshake TCP scan
            udp.py           UDP probe + ICMP error matching
            syn.py           half-open stealth SYN scan (-s, needs root)

## Setup

Python 3.8+:

    python3 port_scanner.py --help

    Usage: port_scanner.py <ip> [options]

    OPTIONS:
        -p      Specify ports (single, multiple comma-separated, or range)
        -tcp    Perform TCP scan
        -udp    Perform UDP scan
        -s      Perform stealth scan
        -f      Save output to file (provide filename after flag)
        -sv     Identify services and versions on open ports

    Example:
    $ python3 port_scanner.py 127.0.0.1 -p 22,80,12345 -tcp -f scan_results.txt
    Scanning 127.0.0.1...
    Port 22: Closed
    Port 80: Closed
    Port 12345: Open
    Result written to file: scan_results.txt

## Service detection (-sv)

`-sv` appends the service and version to open TCP ports:

    Port 22: Open (ssh — 8.9p1)
    Port 80: Open (http)
    Port 443: Open (https — 2.4.52)

Silent services use the port table. TLS ports get a real TLS handshake and an HTTP request where
appropriate; unknown TLS ports report `ssl`. `-udp -sv` is rejected, and `-s -sv` adds a handshake
on open ports.

## Port states

    Open           a service is listening
    Closed         host reachable, nothing listening
    Filtered       a firewall dropped the probe
    Open|Filtered  quiet service and firewall are indistinguishable
