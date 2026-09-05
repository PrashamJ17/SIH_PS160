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

from dataclasses import dataclass
from typing import Final

from ipsec_sentinel.parser.reader import SafeReader

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
