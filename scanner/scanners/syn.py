"""Stealth SYN scan (-s), a.k.a. half-open scanning.

We craft the SYN ourselves (scanner/packets.py) on a raw socket and never
complete the handshake, so the target's application never sees a connection:

    SYN+ACK reply -> Open      (RST'd away as a courtesy; rarely logged)
    RST reply     -> Closed    (the kernel rejected: nothing listening)
    silence       -> Filtered  (a firewall dropped the SYN)

Needs root at runtime (raw sockets are root-only on Linux).

Interface (see scanner/scanners/__init__.py):
"""

import socket
import struct
import time
from typing import Optional

from scanner import packets
from scanner.scanners import NeedsRootError

OPEN = "Open"
CLOSED = "Closed"
FILTERED = "Filtered"

# Per-port timeout in seconds
# Too short and a slow SYN+ACK looks filtered; too long and firewalled
# ranges take forever.
DEFAULT_TIMEOUT = 1.5

# The reply that means Open: SYN+ACK = 0x12
OPEN_REPLY = packets.SYN | packets.ACK


def scan_port(ip: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> str:
    """Probe ip:port with a hand-crafted SYN: OPEN, CLOSED, or FILTERED."""
    try:
        raw = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                            socket.IPPROTO_TCP)
    except PermissionError as exc:
        # Raw sockets are root-only
        raise NeedsRootError("SYN scan requires root (try sudo)") from exc
    src_port = packets.random_source_port()
    seq = packets.random_seq()
    try:
        try:
            # The kernel builds the IP header (no IP_HDRINCL), but the
            # pseudo-header checksum must carry the source address the
            # kernel will actually route by — hence _local_ip().
            src_ip = _local_ip(ip)
            syn = packets.build_tcp_header(src_ip, ip, src_port, port, seq,
                                           packets.SYN)
            raw.sendto(syn, (ip, 0))
        except OSError:
            # No route, etc: like tcp_connect, a failed send counts as silence
            return FILTERED
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return FILTERED  # full timeout with no answer to our SYN
            raw.settimeout(remaining)
            try:
                data, peer = raw.recvfrom(65535)
            except socket.timeout:
                return FILTERED
            except OSError:
                continue  # transient recv error: wait out the deadline
            reply = _our_reply(data, peer[0], ip, src_port, port)
            if reply is None:
                continue
            if (reply.flags & OPEN_REPLY) == OPEN_REPLY:
                _send_rst(raw, src_ip, ip, src_port, port, seq)
                return OPEN
            if reply.flags & packets.RST:
                return CLOSED
            # Anything else (a bare ACK, say) doesn't answer our SYN:
            # keep waiting.
    finally:
        raw.close()


def _local_ip(ip: str) -> str:
    """Source address the kernel will use to reach *ip*.

    The UDP-connect trick sends nothing: connect() on a datagram socket
    only forces the routing decision, and getsockname() then reveals the
    source address our packets will carry. The pseudo-header checksum
    must be built with exactly that address or the target rejects the SYN.
    """
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect((ip, 9))  # discard port; no packet leaves the machine
        return probe.getsockname()[0]
    finally:
        probe.close()


def _our_reply(data: bytes, peer_ip: str, ip: str, src_port: int,
               port: int) -> Optional[packets.TcpReply]:
    """The parsed reply if *data* answers our probe, else None.

    A raw socket sees every TCP packet the kernel receives, so a packet
    only counts when it comes from the target and its port pair mirrors
    ours exactly (their source = the probed port, their dest = our
    random source port).
    """
    if peer_ip != ip:
        return None
    try:
        reply = packets.parse_reply(data)
    except ValueError:
        return None  # truncated junk: ignore, never fatal
    # Safe to unpack: parse_reply just validated a full IP + 20-byte TCP
    # header. IHL parsed, not assumed — IP options shift the TCP header.
    their_src, their_dst = struct.unpack_from("!HH", data,
                                              (data[0] & 0x0F) * 4)
    if (their_src, their_dst) != (port, src_port):
        return None
    return reply


def _send_rst(raw, src_ip: str, ip: str, src_port: int, port: int,
              seq: int) -> None:
    """Courtesy RST so the target isn't left with a half-open connection.

    seq must equal the SYN+ACK's ack number — our ISN + 1 (mod 2**32) —
    or the target's kernel treats the RST as stale and ignores it. Our
    own kernel usually RSTs first (no socket owns src_port), but sending
    ours keeps the scan polite even where that reply is suppressed.
    """
    rst = packets.build_tcp_header(src_ip, ip, src_port, port,
                                   (seq + 1) & 0xFFFFFFFF, packets.RST)
    try:
        raw.sendto(rst, (ip, 0))
    except OSError:
        pass  # courtesy only — never fail an Open verdict over it
