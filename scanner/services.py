"""Service and version identification for open ports (-sv)."""

import re
import socket
from functools import lru_cache
from typing import Dict, Iterable, NamedTuple, Optional

UNKNOWN = "unknown"
OPEN_STATE = "Open"

# Banner-grab: one short timeout per socket operation.
GRAB_TIMEOUT = 1.0
BANNER_SIZE = 1024

HTTP_PORTS = {80, 8000, 8008, 8080, 8081, 8888}
HTTPS_PORTS = {443, 465, 993, 995, 8443}
HTTP_PROBE = b"GET / HTTP/1.0\r\n\r\n"

# Common TCP services; everything else falls back to /etc/services.
PORT_SERVICES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios",
    143: "imap",
    161: "snmp",
    389: "ldap",
    443: "https",
    445: "smb",
    465: "smtps",
    514: "syslog",
    587: "submission",
    631: "ipp",
    993: "imaps",
    995: "pop3s",
    1433: "ms-sql-s",
    1521: "oracle",
    2049: "nfs",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    5900: "vnc",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
    27017: "mongodb",
}

ETC_SERVICES_PATH = "/etc/services"

# Specific banners first
_BANNER_RULES = (
    (re.compile(r"SSH-[\d.]+-OpenSSH[_-]([0-9][\w.]*)", re.IGNORECASE), "ssh"),
    (re.compile(r"vsftpd[ /]([0-9][\w.]*)", re.IGNORECASE), "ftp"),
    (re.compile(r"proftpd[ /]([0-9][\w.]*)", re.IGNORECASE), "ftp"),
    (re.compile(r"\bexim[ /]([0-9][\w.]*)", re.IGNORECASE), "smtp"),
    (re.compile(r"\bpostfix\b", re.IGNORECASE), "smtp"),
    (re.compile(r"SSH-", re.IGNORECASE), "ssh"),
    (re.compile(r"\bftp\b", re.IGNORECASE), "ftp"),
    (re.compile(r"\b(?:e)?smtp\b", re.IGNORECASE), "smtp"),
)

_HTTP_STATUS = re.compile(r"^HTTP/\d", re.IGNORECASE)
_SERVER_HEADER = re.compile(r"^Server:\s*([^\r\n]+)",
                            re.IGNORECASE | re.MULTILINE)
_SERVER_PRODUCTS = (
    (re.compile(r"apache[/ ]([0-9][\w.]*)", re.IGNORECASE), "http"),
    (re.compile(r"nginx[/ ]([0-9][\w.]*)", re.IGNORECASE), "http"),
    (re.compile(r"microsoft-iis[/ ]([0-9][\w.]*)", re.IGNORECASE), "http"),
)


class ServiceInfo(NamedTuple):
    """Decoded service name and optional version."""
    service: str
    version: Optional[str] = None


def service_name(port: int) -> Optional[str]:
    """Name for a TCP port"""
    name = PORT_SERVICES.get(port)
    if name is not None:
        return name
    return _etc_services().get(port)


def _parse_etc_services(lines: Iterable[str]) -> Dict[int, str]:
    """TCP entries only.

    Comments and blank lines skipped; malformed fields ignored"""
    table: Dict[int, str] = {}
    for line in lines:
        fields = line.split("#", 1)[0].split()
        if len(fields) < 2:
            continue
        port_text, _, proto = fields[1].partition("/")
        if proto != "tcp" or not (port_text.isascii() and port_text.isdigit()):
            continue
        port = int(port_text)
        if 1 <= port <= 65535:
            table.setdefault(port, fields[0])
    return table


@lru_cache(maxsize=1)
def _etc_services() -> Dict[int, str]:
    try:
        with open(ETC_SERVICES_PATH, encoding="utf-8", errors="replace") as fh:
            return _parse_etc_services(fh)
    except OSError:
        return {}


def identify(banner: str) -> ServiceInfo:
    text = banner or ""
    http = _identify_http(text)
    if http is not None:
        return http
    for pattern, service in _BANNER_RULES:
        match = pattern.search(text)
        if match:
            version = match.group(1) if match.groups() else None
            return ServiceInfo(service, version)
    return ServiceInfo(UNKNOWN, None)


def _identify_http(text: str) -> Optional[ServiceInfo]:
    """HTTP status line or Server header -> http + product version."""
    server = _SERVER_HEADER.search(text)
    if server is None:
        if _HTTP_STATUS.match(text):
            return ServiceInfo("http", None)
        return None
    header = server.group(1)
    for pattern, service in _SERVER_PRODUCTS:
        match = pattern.search(header)
        if match:
            return ServiceInfo(service, match.group(1))
    return ServiceInfo("http", None)


def grab_banner(ip: str, port: int,
                timeout: float = GRAB_TIMEOUT) -> Optional[str]:
    """Read a service banner from an open TCP port; None on any failure."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        if sock.connect_ex((ip, port)) != 0:
            return None
        timed_out = False
        try:
            data = sock.recv(BANNER_SIZE)
        except socket.timeout:
            data = b""
            timed_out = True
        if timed_out and port in HTTP_PORTS:
            sock.sendall(HTTP_PROBE)
            data = sock.recv(BANNER_SIZE)
        if not data:
            return None
        return data.decode("utf-8", errors="replace").strip()
    except OSError:
        return None
    finally:
        sock.close()


def detect_services(ip: str, results: Dict[int, str],
                    timeout: float = GRAB_TIMEOUT) -> Dict[int, ServiceInfo]:
    """Identify services on Open ports; never changes a port's state.
    Open ports are usually few, so probes run sequentially.
    """
    found: Dict[int, ServiceInfo] = {}
    for port in sorted(results):
        if results[port] != OPEN_STATE:
            continue
        fallback = None
        try:
            fallback = service_name(port)
            banner = grab_banner(ip, port, timeout)
            info = identify(banner) if banner else ServiceInfo(UNKNOWN, None)
            if info.service == UNKNOWN and fallback:
                info = ServiceInfo(fallback, None)
            found[port] = info
        except Exception:
            found[port] = ServiceInfo(fallback or UNKNOWN, None)
    return found
