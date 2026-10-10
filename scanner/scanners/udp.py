"""UDP scan (-udp)
no handshake, no acknowledgment. ICMP is the only signal:

    ICMP port-unreachable (type 3, code 3) -> Closed
    any UDP reply                          -> Open
    silence within the timeout             -> Open|Filtered

Needs root at runtime"""

import selectors
import socket
import struct
import time
from typing import NamedTuple, Optional

from scanner.scanners import NeedsRootError

OPEN = "Open"
CLOSED = "Closed"
OPEN_FILTERED = "Open|Filtered" 

# UDP is slower than TCP
DEFAULT_TIMEOUT = 2.0

IPPROTO_UDP = 17
ICMP_DEST_UNREACH = 3

# Minimal DNS query for "example.com" (type A): empty may be ignored so a custom reply from port 53
DNS_PROBE = (
    b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"  # id, flags, counts
    b"\x07example\x03com\x00"                            # QNAME
    b"\x00\x01\x00\x01"                                  # QTYPE=A, QCLASS=IN
)

# port 53 payload; everything else empty.
PAYLOADS = {53: DNS_PROBE}


class IcmpPacket(NamedTuple):
    """ICMP type/code, plus any UDP ports quoted by an unreachable."""
    type: int
    code: int
    src_port: Optional[int]
    dst_port: Optional[int]


def parse_icmp(data: bytes) -> IcmpPacket:
    """ValueError if the packet is too short for IP + ICMP headers."""
    if len(data) < 28:  # minimum IPv4 + ICMP header
        raise ValueError(f"packet too short: {len(data)} bytes")
    ihl = (data[0] & 0x0F) * 4
    icmp_at = ihl + 8
    if len(data) < icmp_at:
        raise ValueError(f"truncated ICMP header in {len(data)}-byte packet")

    icmp_type = data[ihl]
    icmp_code = data[ihl + 1]

    src_port = dst_port = None
    if icmp_type == ICMP_DEST_UNREACH and len(data) >= icmp_at + 20:
        # IP header followed by 8+ payload bytes, with the UDP ports in the first 4.
        inner = icmp_at
        udp_at = inner + (data[inner] & 0x0F) * 4
        if data[inner + 9] == IPPROTO_UDP and len(data) >= udp_at + 4:
            src_port, dst_port = struct.unpack_from("!HH", data, udp_at)

    return IcmpPacket(icmp_type, icmp_code, src_port, dst_port)


def scan_port(ip: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> str:
    """Probe UDP port: OPEN, CLOSED, or OPEN_FILTERED.

    Watch two sockets until the deadline: raw ICMP (port-unreachable
    quoting our probe -> Closed) and the UDP probe socket (any reply ->
    Open). Silence -> Open|Filtered. Needs root for the raw socket.
    """
    try:
        icmp = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                             socket.IPPROTO_ICMP)
    except PermissionError as exc:
        raise NeedsRootError("UDP scan requires root (try sudo)") from exc
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sel = selectors.DefaultSelector()
    try:
        try:
            probe.sendto(PAYLOADS.get(port, b""), (ip, port))
        except OSError:
            return OPEN_FILTERED
        src_port = probe.getsockname()[1]
        sel.register(probe, selectors.EVENT_READ)
        sel.register(icmp, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            ready = sel.select(remaining) if remaining > 0 else []
            if not ready:
                return OPEN_FILTERED
            for sock, _ in ready:
                if sock is probe:
                    return OPEN
                if _is_our_port_unreachable(icmp, ip, src_port, port):
                    return CLOSED
    finally:
        sel.close()
        probe.close()
        icmp.close()


def _is_our_port_unreachable(icmp, ip: str, src_port: int, port: int) -> bool:
    """True if the next queued ICMP packet is a port-unreachable (3/3) from
    the target quoting our probe's ports. Raw sockets see all ICMP, so
    peer IP + quoted ports are the match; anything else is ignored."""
    try:
        data, peer = icmp.recvfrom(65535)
    except OSError:
        return False
    if peer[0] != ip:
        return False
    try:
        pkt = parse_icmp(data)
    except ValueError:
        return False
    return (pkt.type == ICMP_DEST_UNREACH and pkt.code == 3
            and (pkt.src_port, pkt.dst_port) == (src_port, port))
