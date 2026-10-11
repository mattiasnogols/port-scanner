#!/usr/bin/env python3
"""
Exit codes: 0 = success (including --help), 1 = runtime error (needs root),
2 = usage error, 3 = scan type not implemented yet.
"""

import sys
from typing import List, Optional

from scanner.cli import USAGE, CliError, Config, ShowHelp, parse_args
from scanner.scanners import NeedsRootError, syn, tcp_connect, udp

EXIT_OK = 0
EXIT_RUNTIME = 1
EXIT_USAGE = 2
EXIT_UNIMPLEMENTED = 3

SCANNER_MODULES = {"tcp": tcp_connect, "udp": udp, "syn": syn}


def main(argv: Optional[List[str]] = None) -> int:
    """Parse *argv* and run the scan."""
    argv = sys.argv[1:] if argv is None else list(argv)
    try:
        config = parse_args(argv)
    except ShowHelp:
        print(USAGE)
        return EXIT_OK
    except CliError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        print(USAGE, file=sys.stderr)
        return EXIT_USAGE
    return _run(config)


def _run(config: Config) -> int:
    """Sequential execution"""
    module = SCANNER_MODULES.get(config.scan_type)
    if module is None:
        print(f"Error: scan not implemented",
              file=sys.stderr)
        return EXIT_UNIMPLEMENTED
    # stealth scan
    label = " (stealth)" if config.scan_type == "syn" else ""
    print(f"Scanning{label} {config.target}...")
    try:
        for port in config.ports:
            state = module.scan_port(config.target, port)
            print(f"Port {port}: {state}")
    except NeedsRootError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_RUNTIME
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
