"""Terminal + file reporting (-f).

Print scan results, JSON output is separate from other scanner capabilities.
"""

import os
from datetime import datetime
from typing import Dict, List, Optional

# The stealth scan is the only tagged in the header
STEALTH_LABEL = " (stealth)"

TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"


class OutputError(Exception):
    """Result file could not be written (permissions, bad path)"""


def scan_header(target: str, scan_type: str) -> str:
    label = STEALTH_LABEL if scan_type == "syn" else ""
    return f"Scanning{label} {target}..."


def result_lines(results: Dict[int, str]) -> List[str]:
    return [f"Port {port}: {results[port]}" for port in sorted(results)]


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
           outfile: Optional[str] = None) -> Optional[str]:
    """Render the scan: terminal lines, then the file when -f was given.

       Returns the path written, or None without -f.
    """
    lines = [scan_header(target, scan_type)] + result_lines(results)
    for line in lines:
        print(line)
    if outfile is None:
        return None
    path = save_results(outfile, lines)
    print(f"Result written to file: {path}")
    return path
