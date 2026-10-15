"""TCP segment crafting for the stealth SYN scan (-s); RFC 793, RFC 1071."""

import random
import socket
import struct
from typing import NamedTuple

# TCP flag bits; SYN|ACK = 0x12 is the Open reply
SYN = 0x02
RST = 0x04
ACK = 0x10

IPPROTO_TCP = 6      # IP protocol number
TCP_HEADER_LEN = 20  # no options
DEFAULT_WINDOW = 1024


def checksum(data: bytes) -> int:
    """RFC 1071 Internet checksum"""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:  # fold carries until none remain
        total = (total >> 16) + (total & 0xFFFF)
    return ~total & 0xFFFF


def tcp_checksum(src_ip: str, dst_ip: str, segment: bytes) -> int:
    """Checksum a TCP segment; the pseudo-header binds it to its addresses."""
    # RFC 793 pseudo-header: src IP | dst IP | zero | protocol | TCP length
    pseudo = struct.pack("!4s4sBBH", socket.inet_aton(src_ip),
                         socket.inet_aton(dst_ip), 0, IPPROTO_TCP,
                         len(segment))
    return checksum(pseudo + segment)


def build_tcp_header(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                     seq: int, flags: int, ack: int = 0,
                     window: int = DEFAULT_WINDOW) -> bytes:
    """Craft a 20-byte TCP header, checksum filled in."""
    # Top nibble: header length in 32-bit words; low bits: flags.
    offset_flags = (TCP_HEADER_LEN // 4) << 12 | flags
    header = struct.pack("!HHLLHHHH", src_port, dst_port, seq, ack,
                         offset_flags, window, 0, 0)  # checksum, urgent = 0
    # Computed with the field zero, then spliced in at offset 16.
    cksum = tcp_checksum(src_ip, dst_ip, header)
    return header[:16] + struct.pack("!H", cksum) + header[18:]


def random_source_port() -> int:
    """Random ephemeral port, picked fresh for each probe."""
    return random.randint(40000, 65535)


def random_seq() -> int:
    """Unpredictable initial sequence number (RFC 793)."""
    return random.randint(0, 0xFFFFFFFF)


class TcpReply(NamedTuple):
    """Decoded fields"""
    ttl: int
    window: int
    flags: int


def parse_reply(data: bytes) -> TcpReply:
    """ValueError on truncated data or a malformed IP/TCP header length."""
    if len(data) < 20:
        raise ValueError(f"packet too short: {len(data)} bytes")
    ihl = (data[0] & 0x0F) * 4  # parse IHL
    if ihl < 20:
        raise ValueError(
            f"invalid IP header length {ihl} in {len(data)}-byte packet"
        )
    if len(data) < ihl + 20:
        raise ValueError(f"truncated TCP header in {len(data)}-byte packet")
    ttl = data[8]                             # IP header byte 8
    tcp_offset = (data[ihl + 12] >> 4) * 4    # TCP data offset, 32-bit words
    if tcp_offset < TCP_HEADER_LEN:
        raise ValueError(
            f"invalid TCP data offset {tcp_offset} in {len(data)}-byte packet"
        )
    flags = data[ihl + 13]
    (window,) = struct.unpack_from("!H", data, ihl + 14)
    return TcpReply(ttl, window, flags)
