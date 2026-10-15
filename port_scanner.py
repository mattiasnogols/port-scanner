#!/usr/bin/env python3
"""Port scanner entry: parse arguments, print results."""

import sys
from typing import List, Optional

from scanner.cli import USAGE, CliError, Config, ShowHelp, parse_args
from scanner.output import OutputError, report
from scanner.scanners import NeedsRootError, syn, tcp_connect, udp

EXIT_OK = 0
EXIT_RUNTIME = 1
EXIT_USAGE = 2
EXIT_UNIMPLEMENTED = 3
EXIT_INTERRUPT = 130

SCANNER_MODULES = {"tcp": tcp_connect, "udp": udp, "syn": syn}


def main(argv: Optional[List[str]] = None) -> int:
    """Parse argv and run the scan."""
    argv = sys.argv[1:] if argv is None else list(argv)
    try:
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
    except KeyboardInterrupt:
        print("\nInterrupted", file=sys.stderr)
        return EXIT_INTERRUPT


def _run(config: Config) -> int:
    """Scan the requested ports, then render everything via output.report.

    Scanning and reporting are separate jobs.
    """
    module = SCANNER_MODULES.get(config.scan_type)
    if module is None:
        # parse_args only for known scan type.
        print("Error: scan not implemented", file=sys.stderr)
        return EXIT_UNIMPLEMENTED
    try:
        results = {port: module.scan_port(config.target, port)
                   for port in config.ports}
        report(config.target, config.scan_type, results, config.outfile)
    except NeedsRootError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_RUNTIME
    except OutputError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_RUNTIME
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
