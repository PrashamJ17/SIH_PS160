"""Deterministic IKE parsing.

This is the heart of the product and the reason the whole approach works: the opening
IKE exchange is necessarily in cleartext, because the peers have no shared key yet. So
a passive observer can read exactly which cipher, integrity algorithm, PRF and
Diffie-Hellman group each side offered — without a credential, without touching the
device, without breaking anything.

Nothing here infers. Every value produced by this module is read from a documented
field at a known offset, which is why findings derived from it carry no confidence
score. That distinction is the intellectual centre of the project and it starts here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from ipsec_sentinel.parser.constants import (
    IKE_VERSIONS,
    IKEV1_EXCHANGE_TYPES,
    IKEV2_EXCHANGE_TYPES,
)
from ipsec_sentinel.parser.reader import MalformedError, SafeReader, TruncatedError

IKE_HEADER_LENGTH: Final = 28
IKE_SPI_LENGTH: Final = 8

# RFC 7296 section 3.1.
FLAG_INITIATOR: Final = 0x08
FLAG_VERSION: Final = 0x10
FLAG_RESPONSE: Final = 0x20

IKEV1_AGGRESSIVE_EXCHANGE: Final = 4
VERSION_IKEV1: Final = 0x10
VERSION_IKEV2: Final = 0x20


@dataclass(frozen=True)
class IKEHeader:
    """The fixed 28-byte header at the front of every IKE message."""

    initiator_spi: str
    responder_spi: str
    next_payload: int
    version_major: int
    version_minor: int
    version: str
    unknown_version: bool
    exchange_type: int
    exchange_type_name: str
    flags: int
    message_id: int
    length: int

    @property
    def is_initiator(self) -> bool:
        return bool(self.flags & FLAG_INITIATOR)

    @property
    def is_response(self) -> bool:
        return bool(self.flags & FLAG_RESPONSE)

    @property
    def higher_version_supported(self) -> bool:
        return bool(self.flags & FLAG_VERSION)

    @property
    def is_ikev1(self) -> bool:
        return self.version_major == 1

    @property
    def is_aggressive(self) -> bool:
        """IKEv1 Aggressive Mode.

        Checked against the version as well as the exchange number, because IKEv2
        reuses the low numbers for other things — exchange type 4 there is not
        Aggressive Mode, and reporting it as such would be a false critical finding.
        """
        return self.is_ikev1 and self.exchange_type == IKEV1_AGGRESSIVE_EXCHANGE


def _resolve_version(raw: int) -> tuple[int, int, str, bool]:
    """Split the version byte into its two nibbles and name it."""
    major = (raw >> 4) & 0x0F
    minor = raw & 0x0F
    # Match on the major nibble: 0x21 is still IKEv2, and a minor bump must not make
    # an entire message unparseable.
    for value, name in IKE_VERSIONS.items():
        if (value >> 4) & 0x0F == major:
            return major, minor, name, False
    return major, minor, f"UNKNOWN_VERSION_0x{raw:02x}", True


def _resolve_exchange(exchange_type: int, major: int) -> str:
    """Name an exchange type within its version's number space."""
    table = IKEV1_EXCHANGE_TYPES if major == 1 else IKEV2_EXCHANGE_TYPES
    name = table.get(exchange_type)
    if name is not None:
        return name
    return f"UNKNOWN_EXCHANGE_{exchange_type}"


def parse_ike_header(data: bytes) -> IKEHeader:
    """Parse the fixed IKE header.

    ``TruncatedError`` when there is not enough data, or when the message declares
    more than was supplied. ``MalformedError`` when the declared length is impossible
    — a message cannot be shorter than its own header, and a parser that accepted that
    would go on to compute a negative payload span.
    """
    reader = SafeReader(data)
    initiator_spi = reader.read_bytes(IKE_SPI_LENGTH)
    responder_spi = reader.read_bytes(IKE_SPI_LENGTH)
    next_payload = reader.u8()
    raw_version = reader.u8()
    exchange_type = reader.u8()
    flags = reader.u8()
    message_id = reader.u32()
    length = reader.u32()

    if length < IKE_HEADER_LENGTH:
        raise MalformedError(
            f"declared message length {length} is shorter than the {IKE_HEADER_LENGTH}-byte "
            f"IKE header"
        )
    if length > len(data):
        raise TruncatedError(f"message declares {length} bytes but only {len(data)} were supplied")

    major, minor, version, unknown_version = _resolve_version(raw_version)
    return IKEHeader(
        initiator_spi=initiator_spi.hex(),
        responder_spi=responder_spi.hex(),
        next_payload=next_payload,
        version_major=major,
        version_minor=minor,
        version=version,
        unknown_version=unknown_version,
        exchange_type=exchange_type,
        exchange_type_name=_resolve_exchange(exchange_type, major),
        flags=flags,
        message_id=message_id,
        length=length,
    )
