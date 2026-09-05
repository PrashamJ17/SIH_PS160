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

from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Final

from ipsec_sentinel.models import Transform, TransformType
from ipsec_sentinel.parser.constants import (
    ATTRIBUTE_KEY_LENGTH,
    IKE_VERSIONS,
    IKEV1_EXCHANGE_TYPES,
    IKEV1_PAYLOAD_TYPES,
    IKEV2_EXCHANGE_TYPES,
    IKEV2_PAYLOAD_TYPES,
    TRANSFORM_TYPES,
    resolve_transform_name,
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


# --------------------------------------------------------------------------------
# Payload chain
# --------------------------------------------------------------------------------

GENERIC_PAYLOAD_HEADER_LENGTH: Final = 4
PAYLOAD_NONE: Final = 0
CRITICAL_BIT: Final = 0x80

#: Upper bound on payloads in one message. RFC 7296 imposes no limit, but a real
#: message carries a handful; anything beyond this is a malformed or hostile chain and
#: continuing to follow it is how a parser is turned into a denial-of-service vector.
MAX_PAYLOAD_CHAIN: Final = 64


@dataclass(frozen=True)
class RawPayload:
    """One link of the payload chain, still unparsed.

    ``offset`` is retained because findings cite byte offsets as evidence, and a
    finding that cannot point at where it came from is an assertion rather than proof.
    """

    payload_type: int
    payload_type_name: str
    critical: bool
    length: int
    body: bytes
    offset: int


@dataclass
class PayloadChain:
    """The result of walking a chain: what was read, and what went wrong.

    Iterable, so callers that only want the payloads can treat it as a sequence, while
    the errors remain available. The plan's signature returns a bare iterator, but the
    same step requires malformed links to be *recorded* rather than merely skipped, and
    an iterator has nowhere to record them.
    """

    payloads: list[RawPayload] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    truncated: bool = False

    def __iter__(self) -> Iterator[RawPayload]:
        return iter(self.payloads)

    def __len__(self) -> int:
        return len(self.payloads)

    def of_type(self, payload_type: int) -> list[RawPayload]:
        return [p for p in self.payloads if p.payload_type == payload_type]

    def first_of_type(self, payload_type: int) -> RawPayload | None:
        for candidate in self.payloads:
            if candidate.payload_type == payload_type:
                return candidate
        return None


def walk_payloads(reader: SafeReader, first_type: int, *, ikev1: bool = False) -> PayloadChain:
    """Follow the linked list of payloads to its end, or to the first thing wrong.

    Terminates on every input. Three guards make that true, and each closes a distinct
    way the chain can fail to advance:

    * a payload shorter than its own 4-byte header would leave the cursor where it
      was, looping forever on a zero length;
    * a payload claiming more than remains would read past the message;
    * a chain longer than :data:`MAX_PAYLOAD_CHAIN` is a self-referencing or hostile
      message rather than a real one.

    Nothing raises. Payloads read before a fault are kept, because a truncated tail
    should not cost the proposals already parsed — those are exactly the ones a
    finding may depend on.
    """
    chain = PayloadChain()
    next_type = first_type

    while next_type != PAYLOAD_NONE:
        if len(chain.payloads) >= MAX_PAYLOAD_CHAIN:
            chain.errors.append(
                f"payload chain exceeded {MAX_PAYLOAD_CHAIN} links; stopped following it"
            )
            return chain

        offset = reader.tell_relative()
        try:
            following = reader.u8()
            flags = reader.u8()
            length = reader.u16()
        except TruncatedError as exc:
            chain.errors.append(f"truncated payload header at offset {offset}: {exc}")
            chain.truncated = True
            return chain

        if length < GENERIC_PAYLOAD_HEADER_LENGTH:
            chain.errors.append(
                f"payload at offset {offset} declares length {length}, below the "
                f"{GENERIC_PAYLOAD_HEADER_LENGTH}-byte header; chain cannot advance"
            )
            return chain

        body_length = length - GENERIC_PAYLOAD_HEADER_LENGTH
        try:
            body = reader.read_bytes(body_length)
        except TruncatedError as exc:
            chain.errors.append(f"payload at offset {offset} declares {length} bytes: {exc}")
            chain.truncated = True
            return chain

        chain.payloads.append(
            RawPayload(
                payload_type=next_type,
                payload_type_name=resolve_payload_name(next_type, ikev1=ikev1),
                critical=bool(flags & CRITICAL_BIT),
                length=length,
                body=body,
                offset=offset,
            )
        )
        next_type = following

    return chain


def resolve_payload_name(payload_type: int, *, ikev1: bool = False) -> str:
    """Name a payload type within its version's number space."""
    table = IKEV1_PAYLOAD_TYPES if ikev1 else IKEV2_PAYLOAD_TYPES
    return table.get(payload_type, f"UNKNOWN_PAYLOAD_{payload_type}")


# --------------------------------------------------------------------------------
# Transforms and their attributes
# --------------------------------------------------------------------------------

TRANSFORM_HEADER_LENGTH: Final = 8
ATTRIBUTE_FORMAT_BIT: Final = 0x8000
ATTRIBUTE_TYPE_MASK: Final = 0x7FFF
LAST_SUBSTRUCTURE: Final = 0


@dataclass(frozen=True)
class TransformAttribute:
    """One transform attribute, in either encoding.

    Retained in full even though only key length is currently interpreted: IKEv1
    carries lifetime and authentication method here too, and a finding that cites an
    attribute needs the raw value behind it.
    """

    attr_type: int
    is_tv: bool
    value: int | None = None
    raw: bytes | None = None


@dataclass(frozen=True)
class ParsedTransform:
    """A domain :class:`Transform` plus the structure needed to keep iterating."""

    transform: Transform
    attributes: list[TransformAttribute]
    is_last: bool


def _parse_attributes(reader: SafeReader) -> list[TransformAttribute]:
    """Read every attribute in a transform's remaining bytes.

    Two encodings share the field. The top bit of the first 16-bit word selects them:
    set means the value follows inline in two bytes, clear means a length precedes a
    variable-length value. Reading one as the other silently yields a wrong key length,
    which would turn AES-256 into AES-128 in a compliance report.
    """
    attributes: list[TransformAttribute] = []
    while not reader.at_end():
        header = reader.u16()
        attr_type = header & ATTRIBUTE_TYPE_MASK
        if header & ATTRIBUTE_FORMAT_BIT:
            attributes.append(
                TransformAttribute(attr_type=attr_type, is_tv=True, value=reader.u16())
            )
        else:
            length = reader.u16()
            raw = reader.read_bytes(length)
            attributes.append(TransformAttribute(attr_type=attr_type, is_tv=False, raw=raw))
    return attributes


def _key_length_from(attributes: list[TransformAttribute]) -> int | None:
    """Extract the key-length attribute, or ``None`` if it is absent or unreadable."""
    for attribute in attributes:
        if attribute.attr_type != ATTRIBUTE_KEY_LENGTH:
            continue
        if attribute.is_tv:
            return attribute.value
        # The long form is only meaningful at a width the RFC defines. Anything else
        # is left as None rather than guessed at: an invented key length would be
        # reported as fact by a lane that carries no confidence score.
        if attribute.raw is not None and len(attribute.raw) == 2:
            return int.from_bytes(attribute.raw, "big")
        return None
    return None


def parse_transform(reader: SafeReader) -> ParsedTransform:
    """Parse one transform substructure, including its attributes.

    Attributes are read inside a bounded sub-reader, so an attribute length that
    overruns its transform cannot reach into the next one.
    """
    is_last = reader.u8() == LAST_SUBSTRUCTURE
    reader.u8()  # reserved
    length = reader.u16()
    if length < TRANSFORM_HEADER_LENGTH:
        raise MalformedError(
            f"transform declares length {length}, below the "
            f"{TRANSFORM_HEADER_LENGTH}-byte transform header"
        )
    transform_type = reader.u8()
    reader.u8()  # reserved
    transform_id = reader.u16()

    attribute_reader = reader.sub(length - TRANSFORM_HEADER_LENGTH)
    attributes = _parse_attributes(attribute_reader)

    type_name = TRANSFORM_TYPES.get(transform_type)
    domain_type = TransformType(type_name) if type_name else None
    return ParsedTransform(
        transform=Transform(
            type=domain_type,
            id=transform_id,
            name=resolve_transform_name(
                domain_type if domain_type is not None else transform_type, transform_id
            ),
            key_length=_key_length_from(attributes),
        ),
        attributes=attributes,
        is_last=is_last,
    )
