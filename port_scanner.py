#!/usr/bin/env python3
"""
Exit codes: 0 = success (including --help), 2 = usage error,
3 = scan type not implemented yet.
"""

import sys
from typing import List, Optional

from scanner.cli import USAGE, CliError, Config, ShowHelp, parse_args
from scanner.scanners import tcp_connect

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_UNIMPLEMENTED = 3

SCANNER_MODULES = {"tcp": tcp_connect}


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
    print(f"Scanning {config.target}...")
    for port in config.ports:
        state = module.scan_port(config.target, port)
        print(f"Port {port}: {state}")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
