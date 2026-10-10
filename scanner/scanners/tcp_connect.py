"""TCP connect scan (-tcp)

(SYN -> SYN+ACK -> ACK), "noisy"
    handshake completes     -> Open      (something accepted the SYN)
    errno.ECONNREFUSED      -> Closed    (host answered with a RST)
    timeout / other OSError -> Filtered  (silence: a firewall dropped it)

Interface (see scanner/scanners/__init__.py):
"""

import errno
import socket

OPEN = "Open"
CLOSED = "Closed"
FILTERED = "Filtered"

# Per-port timeout in seconds
# Too short and slow-but-open ports look filtered; too long and firewalled ranges take forever.
DEFAULT_TIMEOUT = 1.5


def scan_port(ip: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> str:
    """Return the state: OPEN, CLOSED, or FILTERED. """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        if result == 0:
            return OPEN
        if result == errno.ECONNREFUSED:
            return CLOSED
        return FILTERED
    except OSError:
        return FILTERED
    finally:
        sock.close()
