"""UDP scan (-udp)
no handshake, no acknowledgment. ICMP is the only signal:

    ICMP port-unreachable (type 3, code 3) -> Closed
    any UDP reply                          -> Open
    silence within the timeout             -> Open|Filtered

Needs root at runtime"""

import struct
from typing import NamedTuple, Optional

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
