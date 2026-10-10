import ipaddress
from dataclasses import dataclass
from typing import List, Optional, Set

USAGE = """Usage: port_scanner.py <ip> [options]

OPTIONS:
    -p      Specify ports (single, multiple comma-separated, or range)
    -tcp    Perform TCP scan
    -udp    Perform UDP scan
    -s      Perform stealth scan
    -f      Save output to file (provide filename after flag)"""

MIN_PORT = 1
MAX_PORT = 65535

PROTOCOL_FLAGS = {"-tcp": "tcp", "-udp": "udp", "-s": "syn"}
DEFAULT_SCAN_TYPE = "tcp"
HELP_FLAGS = {"--help", "-h"}


class CliError(Exception):
    """Invalid CLI input"""


class ShowHelp(Exception):
    """--help/-h"""


@dataclass(frozen=True)
class Config:
    """scan configuration."""

    target: str
    ports: List[int]
    scan_type: str
    outfile: Optional[str]


def parse_args(argv: List[str]) -> Config:
    """Parse CLI arguments into a Config."""
    if not argv:
        raise CliError("no arguments given")

    target: Optional[str] = None
    port_spec: Optional[str] = None
    outfile: Optional[str] = None
    scan_flags: List[str] = []

    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in HELP_FLAGS:
            raise ShowHelp()
        if arg == "-p":
            if port_spec is not None:
                raise CliError(
                    "duplicate -p flag (combine ports in one spec, e.g. -p 22,80-90)"
                )
            port_spec = _flag_value(argv, i, "-p", "port specification")
            i += 2
            continue
        if arg == "-f":
            if outfile is not None:
                raise CliError("duplicate -f flag (only one output file is supported)")
            outfile = _flag_value(argv, i, "-f", "filename")
            i += 2
            continue
        if arg in PROTOCOL_FLAGS:
            scan_flags.append(arg)
        elif arg.startswith("-"):
            raise CliError(f"unknown option '{arg}'")
        elif target is not None:
            raise CliError(
                f"unexpected extra argument '{arg}' (only one target IP is supported)"
            )
        else:
            target = _validate_target(arg)
        i += 1

    if target is None:
        raise CliError("missing target IP address")
    if len(scan_flags) > 1:
        raise CliError(
            f"conflicting scan types: {' '.join(scan_flags)} "
            "(choose exactly one of -tcp, -udp, -s)"
        )
    scan_type = PROTOCOL_FLAGS[scan_flags[0]] if scan_flags else DEFAULT_SCAN_TYPE
    if port_spec is None:
        raise CliError("no ports specified (use -p, e.g. -p 22,80 or -p 20-25)")
    try:
        ports = parse_ports(port_spec)
    except ValueError as exc:
        raise CliError(f"invalid -p value: {exc}") from None
    return Config(target=target, ports=ports, scan_type=scan_type, outfile=outfile)


def parse_ports(spec: str) -> List[int]:
    """Parse a port into a sorted list of unique port numbers."""
    if not spec.strip():
        raise ValueError("empty port specification")
    ports: Set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            raise ValueError(
                f"empty port entry in '{spec}' (e.g. a trailing or double comma)"
            )
        if "-" in part:
            start_s, _, end_s = part.partition("-")
            start = _port_number(start_s.strip(), spec)
            end = _port_number(end_s.strip(), spec)
            if start > end:
                raise ValueError(
                    f"invalid port range '{part}' (start {start} > end {end})"
                )
            ports.update(range(start, end + 1))
        else:
            ports.add(_port_number(part, spec))
    return sorted(ports)


def _port_number(token: str, spec: str) -> int:
    """Validate one port and return it as an int."""
    if not (token.isascii() and token.isdigit()):
        raise ValueError(f"invalid port '{token}' in '{spec}' (not a number)")
    port = int(token)
    if not MIN_PORT <= port <= MAX_PORT:
        raise ValueError(f"port {port} out of range {MIN_PORT}-{MAX_PORT}")
    return port


def _flag_value(argv: List[str], i: int, flag: str, what: str) -> str:
    if i + 1 >= len(argv):
        raise CliError(f"{flag} requires a {what} after it")
    value = argv[i + 1]
    if not value.strip():
        raise CliError(f"{flag} requires a {what} after it (got an empty value)")
    return value


def _validate_target(raw: str) -> str:
    """Validate an IPv4 target address; raise CliError with a specific message."""
    try:
        ipaddress.IPv4Address(raw)
    except ValueError:
        try:
            ipaddress.IPv6Address(raw)
        except ValueError:
            raise CliError(
                f"invalid target '{raw}': not a valid IPv4 address"
            ) from None
        raise CliError(
            f"invalid target '{raw}': IPv6 is not supported (IPv4 only)"
        ) from None
    return raw
