"""Fast, dependency-free scanning of capture files for IPsec content.

Written as a raw record walker rather than on top of a packet library because the
corpora this audits are tens of gigabytes: constructing a parsed object per packet
would take hours, and every field needed here sits at a fixed offset.

The question it answers is narrow and precise. Does this capture contain
**IKE negotiations** (UDP 500, or UDP 4500 with the non-ESP marker), **ESP**
(IP protocol 50) or **AH** (IP protocol 51)? Those three are what an IPsec analyser
needs, and their absence is what Step 3.5 sets out to demonstrate.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Final

PCAP_MAGIC_LE: Final = b"\xd4\xc3\xb2\xa1"
PCAP_MAGIC_BE: Final = b"\xa1\xb2\xc3\xd4"
PCAP_MAGIC_LE_NS: Final = b"\x4d\x3c\xb2\xa1"
PCAP_MAGIC_BE_NS: Final = b"\xa1\xb2\x3c\x4d"
PCAPNG_MAGIC: Final = b"\x0a\x0d\x0d\x0a"

# Link types this walker understands. Anything else is reported rather than guessed at.
DLT_ETHERNET: Final = 1
DLT_RAW: Final = 101
DLT_LINUX_SLL: Final = 113
DLT_LINUX_SLL2: Final = 276
DLT_NULL: Final = 0

ETHERTYPE_IPV4: Final = 0x0800
ETHERTYPE_IPV6: Final = 0x86DD
ETHERTYPE_VLAN: Final = 0x8100

PROTO_AH: Final = 51
PROTO_ESP: Final = 50
PROTO_UDP: Final = 17

IKE_PORT: Final = 500
NAT_T_PORT: Final = 4500


class UnsupportedCaptureError(ValueError):
    """The file is not a classic pcap this scanner can walk."""


@dataclass
class ScanResult:
    """What one capture file contains, from an IPsec point of view."""

    path: str
    readable: bool = True
    error: str | None = None
    link_type: int | None = None
    total_packets: int = 0
    ipv4_packets: int = 0
    ipv6_packets: int = 0
    esp_packets: int = 0
    ah_packets: int = 0
    ike_udp500_packets: int = 0
    ike_udp4500_packets: int = 0
    esp_over_udp_packets: int = 0
    truncated: bool = False
    notes: list[str] = field(default_factory=list)

    @property
    def ike_packets(self) -> int:
        """Genuine IKE: port 500, plus port 4500 carrying the non-ESP marker."""
        return self.ike_udp500_packets + self.ike_udp4500_packets

    @property
    def ipsec_packets(self) -> int:
        return self.esp_packets + self.ah_packets + self.ike_packets

    @property
    def has_ipsec(self) -> bool:
        return self.ipsec_packets > 0


def _read_global_header(handle: BinaryIO) -> tuple[str, int]:
    magic = handle.read(4)
    if magic == PCAPNG_MAGIC:
        raise UnsupportedCaptureError("pcapng is not walked by this scanner")
    if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_LE_NS):
        endian = "<"
    elif magic in (PCAP_MAGIC_BE, PCAP_MAGIC_BE_NS):
        endian = ">"
    else:
        raise UnsupportedCaptureError(f"not a pcap file (magic {magic!r})")
    rest = handle.read(20)
    if len(rest) < 20:
        raise UnsupportedCaptureError("truncated pcap global header")
    link_type = struct.unpack(f"{endian}I", rest[16:20])[0]
    return endian, int(link_type)


def _records(handle: BinaryIO, endian: str) -> Iterator[bytes]:
    header_format = f"{endian}IIII"
    while True:
        header = handle.read(16)
        if len(header) < 16:
            return
        _ts, _us, incl_len, _orig = struct.unpack(header_format, header)
        if incl_len > 262_144:  # a frame larger than this is a corrupt length field
            return
        data = handle.read(incl_len)
        if len(data) < incl_len:
            return
        yield data


def _strip_link_layer(frame: bytes, link_type: int) -> tuple[int, bytes] | None:
    """Return (ethertype-ish, payload) or None when the frame is not IP."""
    if link_type == DLT_ETHERNET:
        if len(frame) < 14:
            return None
        ethertype = struct.unpack("!H", frame[12:14])[0]
        offset = 14
        # Walk VLAN tags rather than giving up on tagged captures.
        while ethertype == ETHERTYPE_VLAN and len(frame) >= offset + 4:
            ethertype = struct.unpack("!H", frame[offset + 2 : offset + 4])[0]
            offset += 4
        return ethertype, frame[offset:]
    if link_type == DLT_RAW:
        if not frame:
            return None
        version = frame[0] >> 4
        return (ETHERTYPE_IPV4 if version == 4 else ETHERTYPE_IPV6), frame
    if link_type in (DLT_LINUX_SLL, DLT_LINUX_SLL2):
        header_length = 16 if link_type == DLT_LINUX_SLL else 20
        if len(frame) < header_length:
            return None
        protocol_offset = 14 if link_type == DLT_LINUX_SLL else 0
        ethertype = struct.unpack("!H", frame[protocol_offset : protocol_offset + 2])[0]
        return ethertype, frame[header_length:]
    if link_type == DLT_NULL:
        if len(frame) < 4:
            return None
        family = struct.unpack("<I", frame[:4])[0]
        return (ETHERTYPE_IPV4 if family == 2 else ETHERTYPE_IPV6), frame[4:]
    return None


def scan_capture(path: Path, max_packets: int | None = None) -> ScanResult:
    """Count IKE, ESP and AH packets in one capture.

    Never raises for a bad file: an unreadable or truncated capture is reported as
    such, because an audit that dies on one corrupt file cannot survey a corpus.
    """
    result = ScanResult(path=str(path))
    try:
        with path.open("rb") as handle:
            try:
                endian, link_type = _read_global_header(handle)
            except UnsupportedCaptureError as exc:
                result.readable = False
                result.error = str(exc)
                return result
            result.link_type = link_type

            for frame in _records(handle, endian):
                result.total_packets += 1
                if max_packets is not None and result.total_packets > max_packets:
                    result.notes.append(f"stopped after {max_packets} packets")
                    result.truncated = True
                    break
                stripped = _strip_link_layer(frame, link_type)
                if stripped is None:
                    continue
                ethertype, payload = stripped
                if ethertype == ETHERTYPE_IPV4:
                    _classify_ipv4(payload, result)
                elif ethertype == ETHERTYPE_IPV6:
                    _classify_ipv6(payload, result)
    except OSError as exc:
        result.readable = False
        result.error = f"{type(exc).__name__}: {exc}"
    return result


def _classify_ipv4(payload: bytes, result: ScanResult) -> None:
    if len(payload) < 20:
        return
    result.ipv4_packets += 1
    header_length = (payload[0] & 0x0F) * 4
    protocol = payload[9]
    _count_protocol(protocol, payload[header_length:], result)


def _classify_ipv6(payload: bytes, result: ScanResult) -> None:
    if len(payload) < 40:
        return
    result.ipv6_packets += 1
    _count_protocol(payload[6], payload[40:], result)


def _count_protocol(protocol: int, rest: bytes, result: ScanResult) -> None:
    if protocol == PROTO_ESP:
        result.esp_packets += 1
        return
    if protocol == PROTO_AH:
        result.ah_packets += 1
        return
    if protocol != PROTO_UDP or len(rest) < 8:
        return
    source, destination = struct.unpack("!HH", rest[:4])
    if IKE_PORT in (source, destination):
        result.ike_udp500_packets += 1
        return
    if NAT_T_PORT in (source, destination):
        body = rest[8:]
        # On 4500 a four-zero-byte non-ESP marker precedes IKE; anything else is
        # ESP-over-UDP. Counting both as IKE would overstate the finding.
        if body[:4] == b"\x00\x00\x00\x00":
            result.ike_udp4500_packets += 1
        elif body:
            result.esp_over_udp_packets += 1


def count_flows(path: Path) -> set[tuple[str, str, int, int, int]]:
    """Distinct 5-tuples in a capture, direction-normalised.

    Counted here rather than with a packet library because the corpus runs to hundreds
    of captures: a parsed object per packet would take far longer than the sweep that
    produced them. Endpoints are sorted so both directions of a conversation count as
    one flow, which is what a flow-level label describes.
    """
    flows: set[tuple[str, str, int, int, int]] = set()
    try:
        with path.open("rb") as handle:
            try:
                endian, link_type = _read_global_header(handle)
            except UnsupportedCaptureError:
                return flows
            for frame in _records(handle, endian):
                stripped = _strip_link_layer(frame, link_type)
                if stripped is None:
                    continue
                ethertype, payload = stripped
                if ethertype != ETHERTYPE_IPV4 or len(payload) < 20:
                    continue
                header_length = (payload[0] & 0x0F) * 4
                protocol = payload[9]
                source = ".".join(str(b) for b in payload[12:16])
                destination = ".".join(str(b) for b in payload[16:20])
                rest = payload[header_length:]
                sport = dport = 0
                if protocol in (6, 17) and len(rest) >= 4:
                    sport, dport = struct.unpack("!HH", rest[:4])
                elif protocol == PROTO_ESP and len(rest) >= 4:
                    # An ESP SA is identified by its SPI, not by ports.
                    sport = dport = struct.unpack("!I", rest[:4])[0] & 0xFFFF
                endpoints = sorted([(source, sport), (destination, dport)])
                flows.add(
                    (endpoints[0][0], endpoints[1][0], protocol, endpoints[0][1], endpoints[1][1])
                )
    except OSError:
        return flows
    return flows


def find_captures(root: Path) -> list[Path]:
    """Every capture file beneath a directory, in a stable order."""
    if not root.exists():
        return []
    patterns = ("*.pcap", "*.pcapng", "*.cap", "*.dmp")
    found: list[Path] = []
    for pattern in patterns:
        found.extend(root.rglob(pattern))
    return sorted(set(found))
