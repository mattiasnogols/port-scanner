#!/usr/bin/env python3
"""Port scanner entry: parse arguments, print results."""

import sys
from typing import Dict, List, Optional, Tuple

from scanner import osdetect, packets, parallel, services
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
        if config.os_detection:
            metadata = parallel.scan_ports_with_meta(
                module.scan_port_with_meta, config.target, config.ports)
            results, os_info = _metadata_parts(metadata)
        else:
            results = parallel.scan_ports(module.scan_port, config.target,
                                          config.ports)
            os_info = None
        detected = (services.detect_services(config.target, results)
                    if config.service_detection else None)
        report(config.target, config.scan_type, results, config.outfile,
               detected, os_info)
    except parallel.ScanInterrupted as exc:
        # Ctrl+C mid-scan: render whatever finished
        if not exc.results:
            raise
        if config.os_detection:
            results, os_info = _metadata_parts(exc.results)
            report(config.target, config.scan_type, results, config.outfile,
                   os_info=os_info)
        else:
            report(config.target, config.scan_type, exc.results,
                   config.outfile)
        return EXIT_RUNTIME
    except NeedsRootError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_RUNTIME
    except OutputError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_RUNTIME
    return EXIT_OK


def _metadata_parts(
    metadata: Dict[int, Tuple[str, Optional[packets.TcpReply]]],
) -> Tuple[Dict[int, str], osdetect.OsGuess]:
    """Split {port: (state, reply)} into states + the best OS guess."""
    states = {port: state for port, (state, _) in metadata.items()}
    ordered = sorted(metadata.items())
    pairs = []
    for wanted in ("Open", "Closed"):
        pairs.extend(
            (reply.ttl, reply.window)
            for _, (state, reply) in ordered
            if state == wanted and reply is not None
        )
    return states, osdetect.detect_os(pairs)


if __name__ == "__main__":
    sys.exit(main())
