#!/usr/bin/env python3
"""
Exit codes: 0 = success (including --help), 2 = usage error.
"""

import sys
from typing import List, Optional

from scanner.cli import USAGE, CliError, Config, ShowHelp, parse_args

EXIT_OK = 0
EXIT_USAGE = 2


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
    _run(config)
    return EXIT_OK


def _run(config: Config) -> None:
    """Execute the scan described by config."""
    destination = f", output to {config.outfile}" if config.outfile else ""
    print(
        f"Config OK: {config.scan_type} scan of {config.target}, "
        f"{len(config.ports)} port(s){destination}. "
        "Scanning not yet implemented (see PLAN.md)."
    )


if __name__ == "__main__":
    sys.exit(main())
