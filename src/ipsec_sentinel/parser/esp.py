"""ESP parsing: everything an observer can read without a key, and nothing more.

ESP is where the honesty of this project is decided. The payload is encrypted, so a
passive observer gets four things and only four: the SPI naming the security
association, a sequence number, the packet's size, and the time it arrived. There is
no cipher field, no mode field, no algorithm identifier — those were negotiated in the
IKE exchange and are not repeated here.

Everything else this system says about ESP traffic is therefore an **inference** drawn
from sizes and timings, and it carries a calibrated confidence. This module produces
only the facts. It is the boundary between the two lanes, and keeping it narrow is what
makes the inference lane defensible: nothing downstream can be tempted to present a
guess about a cipher as though it had been read off the wire, because the cipher was
never here to read.

The ciphertext itself is deliberately discarded. Nothing in this system can decrypt it,
so retaining it buys nothing and would turn every report into a container for someone
else's encrypted traffic.
"""

from __future__ import annotations

import struct
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from itertools import pairwise
from pathlib import Path
from typing import Final

from ipsec_sentinel.data.pcap_scan import (
    NAT_T_PORT,
    PROTO_ESP,
    PROTO_UDP,
    UnsupportedCaptureError,
    iter_ip_packets,
)
from ipsec_sentinel.models import ESPFlow
from ipsec_sentinel.parser.reader import SafeReader

# On UDP 4500 this four-zero-byte prefix marks IKE; its absence marks ESP.
NON_ESP_MARKER: Final = b"\x00\x00\x00\x00"


class ESPCaptureError(ValueError):
    """The capture cannot be read at all."""


# RFC 4303 section 2: SPI (4 bytes) then Sequence Number (4 bytes).
ESP_HEADER_LENGTH: Final = 8
ESP_SPI_LENGTH: Final = 4

# The sequence number is a 32-bit counter, so it wraps.
SEQUENCE_MODULUS: Final = 1 << 32


@dataclass(frozen=True)
class ESPHeader:
    """The readable part of an ESP packet.

    ``spi`` is eight hex characters — **four** bytes, half the width of the IKE SPI in
    :class:`~ipsec_sentinel.models.IKEExchange`. They identify different things: this
    one names a data security association, that one names a negotiation session.
    Conflating them is not cosmetic. An ESP SPI widened to eight bytes would never
    match its own flow key, and an IKE SPI truncated to four would silently merge two
    distinct negotiations between the same pair of hosts.
    """

    spi: str
    sequence: int
    payload_length: int


def parse_esp_header(data: bytes) -> ESPHeader:
    """Parse an ESP header. The rest of the packet is opaque and is not retained.

    Raises ``TruncatedError`` for fewer than eight bytes. There is no malformed case:
    every 8-byte sequence is a structurally valid ESP header, because both fields are
    fixed-width opaque integers with no reserved values. A zero SPI is invalid by
    RFC 4303, but that is a finding about the traffic, not a parse error, so it is
    left to the assessment layer rather than raised here.
    """
    reader = SafeReader(data)
    spi = reader.read_bytes(ESP_SPI_LENGTH)
    sequence = reader.u32()
    return ESPHeader(
        spi=spi.hex(),
        sequence=sequence,
        payload_length=reader.remaining(),
    )


@dataclass(frozen=True)
class ESPPacket:
    """One ESP packet as observed: who, which SA, which sequence, how big, when."""

    timestamp: datetime
    src_ip: str
    dst_ip: str
    spi: str
    sequence: int
    size: int


@dataclass
class AssembledFlow:
    """One direction of one security association, with its per-packet series.

    The series are kept because Phase 7 computes traffic-shape features from them, and
    a feature computed from a summary statistic cannot be recovered later. They are
    deliberately *not* on the reporting model: a report needs counts and times, not
    ten thousand packet sizes, and putting them there would make every report carry a
    timing side channel of the traffic it describes.
    """

    spi: str
    src_ip: str
    dst_ip: str
    sizes: list[int] = field(default_factory=list)
    sequences: list[int] = field(default_factory=list)
    timestamps: list[datetime] = field(default_factory=list)

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.src_ip, self.dst_ip, self.spi)

    @property
    def packet_count(self) -> int:
        return len(self.sizes)

    @property
    def byte_count(self) -> int:
        return sum(self.sizes)

    @property
    def first_seen(self) -> datetime:
        return min(self.timestamps)

    @property
    def last_seen(self) -> datetime:
        return max(self.timestamps)

    @property
    def reverse_key(self) -> tuple[str, str]:
        """The endpoint pair, direction-normalised, for pairing the two halves of an SA."""
        return tuple(sorted((self.src_ip, self.dst_ip)))  # type: ignore[return-value]

    def to_model(self) -> ESPFlow:
        """The reporting view: counts, times, and the sequence findings.

        The analysis is run here rather than left to the caller so that a reported
        flow can never disagree with its own sequence numbers.
        """
        analysis = analyse_sequence(self)
        return ESPFlow(
            spi=self.spi,
            src_ip=self.src_ip,
            dst_ip=self.dst_ip,
            packet_count=self.packet_count,
            byte_count=self.byte_count,
            first_seen=self.first_seen,
            last_seen=self.last_seen,
            sequence_gaps=analysis.gap_count,
            replay_suspected=analysis.replay_suspected,
        )


def assemble_esp_flows(packets: Iterable[ESPPacket]) -> list[AssembledFlow]:
    """Group ESP packets into flows keyed on (source, destination, SPI).

    **Each direction is a separate flow, and that is correct rather than convenient.**
    An IPsec security association is unidirectional by definition: a tunnel between two
    gateways is two SAs with two different SPIs, negotiated together and rekeyed
    together but otherwise independent. Merging them would average away exactly the
    asymmetry that identifies an application — a video stream is enormous downstream
    and almost silent upstream, and a flow record that hides that is useless to the
    classifier in Phase 7.

    Insertion order is preserved so that flows come back in the order their first
    packet was seen, which makes output stable across runs on the same capture.
    """
    flows: dict[tuple[str, str, str], AssembledFlow] = {}
    for packet in packets:
        key = (packet.src_ip, packet.dst_ip, packet.spi)
        flow = flows.get(key)
        if flow is None:
            flow = AssembledFlow(spi=packet.spi, src_ip=packet.src_ip, dst_ip=packet.dst_ip)
            flows[key] = flow
        flow.sizes.append(packet.size)
        flow.sequences.append(packet.sequence)
        flow.timestamps.append(packet.timestamp)
    return list(flows.values())


def extract_esp_packets(pcap: Path) -> list[ESPPacket]:
    """Every ESP packet in a capture, including ESP encapsulated in UDP for NAT traversal.

    On UDP 4500 an ESP packet has no non-ESP marker — that four-zero-byte prefix is
    what distinguishes IKE there. So the test is the mirror image of the one in the IKE
    ingestion path, and the two must stay consistent: a datagram counted as both, or as
    neither, is a bug in one of them.
    """
    packets: list[ESPPacket] = []
    try:
        for packet in iter_ip_packets(pcap):
            body: bytes | None = None
            if packet.protocol == PROTO_ESP:
                body = packet.payload
            elif packet.protocol == PROTO_UDP and len(packet.payload) >= 8:
                src_port, dst_port = struct.unpack("!HH", packet.payload[:4])
                if NAT_T_PORT in (src_port, dst_port):
                    candidate = packet.payload[8:]
                    if candidate[:4] != NON_ESP_MARKER:
                        body = candidate
            if body is None or len(body) < ESP_HEADER_LENGTH:
                continue
            header = parse_esp_header(body)
            packets.append(
                ESPPacket(
                    timestamp=packet.timestamp,
                    src_ip=packet.src_ip,
                    dst_ip=packet.dst_ip,
                    spi=header.spi,
                    sequence=header.sequence,
                    size=packet.wire_length,
                )
            )
    except (UnsupportedCaptureError, OSError) as exc:
        raise ESPCaptureError(f"{pcap}: {exc}") from exc
    return packets


def flows_from_capture(pcap: Path) -> list[AssembledFlow]:
    """Convenience: capture file straight to assembled flows."""
    return assemble_esp_flows(extract_esp_packets(pcap))


# A backwards jump larger than half the counter space is a wrap, not a reorder. No
# real reordering window is two billion packets wide, and no wrap is smaller.
WRAP_THRESHOLD: Final = 1 << 31


@dataclass(frozen=True)
class SequenceGap:
    """A run of sequence numbers that never arrived."""

    start: int
    end: int

    @property
    def size(self) -> int:
        return self.end - self.start + 1


@dataclass(frozen=True)
class SequenceAnalysis:
    """What the sequence numbers of one flow reveal.

    Three of these findings are about the network and one is about security, and the
    distinction matters when they are reported. Gaps and reorders are ordinary
    behaviour of a lossy path. **Duplicates are not.** ESP sequence numbers are
    assigned by the sender and never repeat within an SA, so the same number arriving
    twice means either the network duplicated a packet or someone replayed it — and a
    passive observer cannot tell which. Hence ``replay_suspected`` rather than
    ``replay_detected``: the evidence is real, the conclusion is not certain, and
    naming it as certainty would be the kind of overclaim this project exists to avoid.
    """

    packet_count: int
    duplicates: int
    reorders: int
    wraps: int
    gaps: tuple[SequenceGap, ...]
    missing_count: int
    highest: int | None = None
    lowest: int | None = None

    @property
    def replay_suspected(self) -> bool:
        return self.duplicates > 0

    @property
    def gap_count(self) -> int:
        return len(self.gaps)

    @property
    def expected_count(self) -> int:
        """How many packets should have arrived across the observed span."""
        if self.highest is None or self.lowest is None:
            return 0
        return self.highest - self.lowest + 1

    @property
    def loss_ratio(self) -> float:
        """Fraction of the observed span that never arrived, in [0, 1]."""
        expected = self.expected_count
        if expected <= 0:
            return 0.0
        return self.missing_count / expected


def _extend_sequences(sequences: Sequence[int]) -> list[int]:
    """Lift 32-bit sequence numbers onto a monotonic axis, counting wraps.

    Without this a rollover from 0xFFFFFFFF to 0 reads as four billion missing
    packets — a flow that ran cleanly for an hour would be reported as catastrophic
    loss. The distinction from a reorder is the size of the backwards jump: a wrap
    crosses half the counter space, a reorder crosses a handful.
    """
    extended: list[int] = []
    epoch = 0
    previous: int | None = None
    for raw in sequences:
        if previous is not None and previous - raw > WRAP_THRESHOLD:
            epoch += 1
        extended.append(raw + epoch * (1 << 32))
        previous = raw
    return extended


def analyse_sequence(flow: AssembledFlow) -> SequenceAnalysis:
    """Analyse one flow's sequence numbers for loss, reordering and replay.

    Takes the assembled flow rather than the reporting model, because the reporting
    model carries the *results* of this analysis (``sequence_gaps``,
    ``replay_suspected``) and not the per-packet series it needs as input.
    """
    if not flow.sequences:
        return SequenceAnalysis(
            packet_count=0, duplicates=0, reorders=0, wraps=0, gaps=(), missing_count=0
        )

    extended = _extend_sequences(flow.sequences)
    wraps = (extended[-1] >> 32) if extended else 0

    seen: set[int] = set()
    duplicates = 0
    reorders = 0
    highest_so_far = extended[0]
    for value in extended:
        if value in seen:
            duplicates += 1
        else:
            seen.add(value)
        if value < highest_so_far:
            reorders += 1
        else:
            highest_so_far = value

    # Gaps are read off the sorted arrivals, never by walking the span between them.
    # The span is a 32-bit counter range: two wraps put four billion values between
    # the lowest and highest sequence, and a loop over that range turns four packets
    # into a 90-second hang. This is the same failure class the parser fuzzing exists
    # to prevent, and it is O(n log n) in packets rather than O(span) here.
    ordered = sorted(seen)
    gaps: list[SequenceGap] = [
        SequenceGap(start=earlier + 1, end=later - 1)
        for earlier, later in pairwise(ordered)
        if later - earlier > 1
    ]
    lowest, highest = ordered[0], ordered[-1]

    return SequenceAnalysis(
        packet_count=len(flow.sequences),
        duplicates=duplicates,
        reorders=reorders,
        wraps=wraps,
        gaps=tuple(gaps),
        missing_count=sum(gap.size for gap in gaps),
        highest=highest,
        lowest=lowest,
    )
