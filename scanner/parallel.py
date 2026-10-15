"""Thread-pool scanning: run any scanner's scan_port over many ports."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, Iterable

from scanner.scanners import NeedsRootError

MAX_WORKERS = 100

# one broken worker must never abort the whole scan
FALLBACK_STATE = "Filtered"


class ScanInterrupted(KeyboardInterrupt):
    """Ctrl+C during scan_ports()"""

    def __init__(self, results: Dict[int, str]):
        super().__init__("scan interrupted")
        self.results = results


def scan_ports(
    scan_fn: Callable[..., str],
    ip: str,
    ports: Iterable[int],
    max_workers: int = MAX_WORKERS,
) -> Dict[int, str]:
    """Scan ports on ip with a thread pool; returns {port: state}."""
    port_list = list(ports)
    if not port_list:
        return {}
    # A handful of ports must not spin up 100 idle threads.
    workers = min(max_workers, len(port_list))
    results: Dict[int, str] = {}
    pool = ThreadPoolExecutor(max_workers=workers)
    try:
        futures = {pool.submit(scan_fn, ip, port): port for port in port_list}
        for future in as_completed(futures):
            port = futures[future]
            try:
                results[port] = future.result()
            except NeedsRootError:
                pool.shutdown(wait=False, cancel_futures=True)
                raise
            except Exception:
                # Isolate an unexpected failure
                results[port] = FALLBACK_STATE
    except KeyboardInterrupt:
        pool.shutdown(wait=False, cancel_futures=True)
        raise ScanInterrupted(results) from None
    pool.shutdown()
    return results
