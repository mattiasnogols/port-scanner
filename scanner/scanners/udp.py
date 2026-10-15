"""UDP scan (-udp)

no handshake, no acknowledgment. ICMP is the only signal:

    ICMP port-unreachable (type 3, code 3) -> Closed
    UDP reply from the target              -> Open
    silence within the timeout             -> Open|Filtered (open, or firewall dropped)

Needs root at runtime

Interface (see scanner/scanners/__init__.py):
"""

import selectors
import socket
import struct
import time
from typing import NamedTuple, Optional

from scanner.scanners import NeedsRootError

OPEN = "Open"
CLOSED = "Closed"
OPEN_FILTERED = "Open|Filtered"

# Per-port timeout in seconds
# too short misses slow replies, too long and firewalled ranges take forever.
DEFAULT_TIMEOUT = 2.0

IPPROTO_UDP = 17
ICMP_DEST_UNREACH = 3

# Ports that need a question before they answer;
DNS_PROBE = (
    b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"  # id, flags, counts
    b"\x07example\x03com\x00"                            # QNAME
    b"\x00\x01\x00\x01"                                  # QTYPE=A, QCLASS=IN
)

PAYLOADS = {53: DNS_PROBE}


class IcmpPacket(NamedTuple):
    """Decoded ICMP header: type and code always; ports only when the
    packet is a destination-unreachable quoting a UDP datagram."""
    type: int
    code: int
    src_port: Optional[int]
    dst_port: Optional[int]


def parse_icmp(data: bytes) -> IcmpPacket:
    """type, code, embedded UDP ports out of a raw packet.

    Raises ValueError if the packet is too short for IP + ICMP headers
    or a malformed IP header length.
    """
    if len(data) < 28:  # minimum IPv4 header + ICMP header
        raise ValueError(f"packet too short: {len(data)} bytes")
    ihl = (data[0] & 0x0F) * 4
    if ihl < 20:
        raise ValueError(
            f"invalid IP header length {ihl} in {len(data)}-byte packet"
        )
    icmp_at = ihl + 8
    if len(data) < icmp_at:
        raise ValueError(f"truncated ICMP header in {len(data)}-byte packet")

    icmp_type = data[ihl]
    icmp_code = data[ihl + 1]

    src_port = dst_port = None
    if icmp_type == ICMP_DEST_UNREACH and len(data) >= icmp_at + 20:
        inner = icmp_at
        inner_ihl = (data[inner] & 0x0F) * 4
        udp_at = inner + inner_ihl
        if (inner_ihl >= 20 and data[inner + 9] == IPPROTO_UDP
                and len(data) >= udp_at + 4):
            src_port, dst_port = struct.unpack_from("!HH", data, udp_at)

    return IcmpPacket(icmp_type, icmp_code, src_port, dst_port)


def scan_port(ip: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> str:
    """Probe UDP port: OPEN, CLOSED, or OPEN_FILTERED.

    Watch two sockets until the deadline: raw ICMP (port-unreachable
    quoting our probe -> Closed) and the UDP probe socket (a datagram
    from the target -> Open; ECONNREFUSED -> Closed). Silence ->
    Open|Filtered. Needs root for the raw socket.
    """
    try:
        icmp = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                             socket.IPPROTO_ICMP)
    except PermissionError as exc:
        # Raw sockets are root-only
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
                # Full timeout with no signal
                return OPEN_FILTERED
            for sock, _ in ready:
                if sock is probe:
                    try:
                        _, peer = probe.recvfrom(65535)
                    except ConnectionRefusedError:
                        return CLOSED  # ICMP port-unreachable as socket error
                    except OSError:
                        continue  # wait out the deadline
                    if peer[0] == ip:
                        return OPEN
                elif _is_our_port_unreachable(icmp, ip, src_port, port):
                    return CLOSED
    finally:
        sel.close()
        probe.close()
        icmp.close()


def _is_our_port_unreachable(icmp, ip: str, src_port: int, port: int) -> bool:
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
