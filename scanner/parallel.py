"""Thread-pool scanning: run any scanner's scan_port over many ports."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, Iterable, Optional, Tuple

from scanner import packets
from scanner.scanners import NeedsRootError

MAX_WORKERS = 100

# one broken worker must never abort the whole scan
FALLBACK_STATE = "Filtered"


ScanMeta = Tuple[str, Optional[packets.TcpReply]]


class ScanInterrupted(KeyboardInterrupt):
    """Ctrl+C during a pooled scan; carries whatever finished."""

    def __init__(self, results: Dict[int, Any]):
        super().__init__("scan interrupted")
        self.results = results


def scan_ports(
    scan_fn: Callable[..., str],
    ip: str,
    ports: Iterable[int],
    max_workers: int = MAX_WORKERS,
) -> Dict[int, str]:
    """Scan ports on ip with a thread pool."""
    return _scan_ports(scan_fn, ip, ports, max_workers, FALLBACK_STATE)


def scan_ports_with_meta(
    scan_fn: Callable[..., ScanMeta],
    ip: str,
    ports: Iterable[int],
    max_workers: int = MAX_WORKERS,
) -> Dict[int, ScanMeta]:
    """Scan with a metadata scanner."""
    return _scan_ports(scan_fn, ip, ports, max_workers,
                       (FALLBACK_STATE, None))


def _scan_ports(
    scan_fn: Callable[..., Any],
    ip: str,
    ports: Iterable[int],
    max_workers: int,
    failure: Any,
) -> Dict[int, Any]:
    """Shared pool: run scan_fn and collect one result per port."""
    port_list = list(ports)
    if not port_list:
        return {}
    # A handful of ports must not spin up 100 idle threads.
    workers = min(max_workers, len(port_list))
    results: Dict[int, Any] = {}
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
                results[port] = failure
    except KeyboardInterrupt:
        pool.shutdown(wait=False, cancel_futures=True)
        raise ScanInterrupted(results) from None
    pool.shutdown()
    return results
