"""Terminal + file reporting (-f).

Print scan results, JSON output is separate from other scanner capabilities.
"""

import os
from datetime import datetime
from typing import Dict, List, Optional

from scanner.osdetect import OsGuess
from scanner.services import UNKNOWN, ServiceInfo

# The stealth scan is the only tagged in the header
STEALTH_LABEL = " (stealth)"

TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"


class OutputError(Exception):
    """Result file could not be written (permissions, bad path)"""


def scan_header(target: str, scan_type: str) -> str:
    label = STEALTH_LABEL if scan_type == "syn" else ""
    return f"Scanning{label} {target}..."


def result_lines(
    results: Dict[int, str],
    services: Optional[Dict[int, ServiceInfo]] = None,
) -> List[str]:
    """One line per port, sorted; -sv adds a service/version suffix."""
    lines = []
    for port in sorted(results):
        line = f"Port {port}: {results[port]}"
        info = services.get(port) if services else None
        if info is not None and info.service and info.service != UNKNOWN:
            if info.version:
                line += f" ({info.service} — {info.version})"
            else:
                line += f" ({info.service})"
        lines.append(line)
    return lines


def os_line(info: Optional[OsGuess]) -> Optional[str]:
    """The optional -os line."""
    if info is None:
        return None
    if info.ttl is None or info.window is None:
        return f"OS guess: {info.os_guess} (no reply)"
    return (f"OS guess: {info.os_guess} (TTL={info.ttl}, "
            f"window={info.window}, confidence: {info.confidence})")


def format_file_body(lines: List[str], when: Optional[datetime] = None) -> str:
    when = datetime.now() if when is None else when
    header = f"# Scan date: {when.strftime(TIMESTAMP_FORMAT)}"
    return "\n".join([header] + lines) + "\n"


def save_results(name: str, lines: List[str]) -> str:
    # A trailing separator (or . / ..) names a directory, not a file: fail this immediately.
    if name in (".", "..") or name.endswith(os.sep):
        raise OutputError(
            f"cannot write result file '{name}': not a file path"
        )
    body = format_file_body(lines)
    stem, ext = os.path.splitext(name)
    counter = 0
    while True:
        path = name if counter == 0 else f"{stem}{counter}{ext}"
        try:
            with open(path, "x", encoding="utf-8") as fh:
                fh.write(body)
            return path
        except FileExistsError:
            counter += 1  # taken: try the next number
        except OSError as exc:
            raise OutputError(
                f"cannot write result file '{path}': {exc.strerror or exc}"
            ) from None


def report(target: str, scan_type: str, results: Dict[int, str],
           outfile: Optional[str] = None,
           services: Optional[Dict[int, ServiceInfo]] = None,
           os_info: Optional[OsGuess] = None) -> Optional[str]:
    """Render the scan: terminal lines, then the file when -f was given.
       Returns the path written, or None without -f.
    """
    lines = [scan_header(target, scan_type)] + result_lines(results, services)
    guess = os_line(os_info)
    if guess is not None:
        lines.append(guess)
    for line in lines:
        print(line)
    if outfile is None:
        return None
    path = save_results(outfile, lines)
    print(f"Result written to file: {path}")
    return path
