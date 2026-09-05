"""IKEv1 parsing, and the single highest-value finding this tool makes.

IKEv1 is not IKEv2 with different numbers. It is a different encoding that happens to
share a header:

* Payload types are a separate registry — an SA payload is 1, not 33.
* The SA payload carries a DOI and a Situation before any proposal.
* A phase 1 proposal has no transform-type structure at all. Everything — encryption,
  hash, authentication method, DH group, lifetime — is an SA attribute in the TV/TLV
  encoding, so the IKEv2 transform tables do not merely mislabel IKEv1 values, they
  have no relationship to them.

Reusing the IKEv2 path would therefore not fail loudly. It would report an IKEv1
3DES-CBC proposal (encryption value 5) as ``ENCR_DES_IV32``, which is a plausible
wrong answer in a section of the report that carries no confidence score. Hence a
separate module.

**Aggressive Mode with a pre-shared key is why this module exists.** Aggressive Mode
compresses phase 1 into three messages by sending the identity and the authentication
hash before any shared key exists. With PSK authentication that hash is a function of
the pre-shared key, transmitted in cleartext, and anyone who captured the exchange can
attack it offline at their leisure — no interaction with the gateway, no detection,
no rate limit. Detecting that combination from a passive capture is worth more than
everything else in the parser, and it is deterministic: both halves are read from
documented fields.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

from ipsec_sentinel.parser.constants import (
    IKEV1_ATTR_AUTH_METHOD,
    IKEV1_ATTR_ENCRYPTION,
    IKEV1_ATTR_GROUP,
    IKEV1_ATTR_HASH,
    IKEV1_ATTR_KEY_LENGTH,
    IKEV1_ATTR_LIFE_DURATION,
    IKEV1_ATTR_LIFE_TYPE,
    IKEV1_AUTH_METHOD_PSK,
    PROTOCOL_IDS,
    ikev1_attribute_class_name,
    ikev1_attribute_value_name,
    ikev1_doi_name,
)
from ipsec_sentinel.parser.ike import (
    IKE_HEADER_LENGTH,
    IKEHeader,
    parse_ike_header,
)
from ipsec_sentinel.parser.reader import MalformedError, ParseError, SafeReader

# RFC 2408 section 3.4: proposal and transform payloads carry the generic 4-byte
# payload header (next payload, reserved, length) ahead of their own fields.
GENERIC_PAYLOAD_HEADER_LENGTH: Final = 4

# The DOI and Situation that precede the proposals in an IKEv1 SA payload.
DOI_LENGTH: Final = 4
SITUATION_LENGTH: Final = 4
DOI_IPSEC: Final = 1

ATTRIBUTE_FORMAT_BIT: Final = 0x8000
ATTRIBUTE_TYPE_MASK: Final = 0x7FFF

MAX_PROPOSALS: Final = 64
MAX_TRANSFORMS: Final = 64
MAX_ATTRIBUTES: Final = 256

PAYLOAD_SA: Final = 1


@dataclass(frozen=True)
class IKEv1Attribute:
    """One phase 1 SA attribute.

    Both encodings are retained as read. ``value`` is populated for the inline form and
    for a long form of a width the RFC actually defines; anything else leaves it None
    rather than reinterpreting bytes whose meaning is not specified.
    """

    attr_type: int
    class_name: str
    is_tv: bool
    value: int | None = None
    value_name: str | None = None
    raw: bytes | None = None


@dataclass(frozen=True)
class IKEv1Transform:
    """One phase 1 transform: a transform number, an ID, and its attributes."""

    number: int
    transform_id: int
    attributes: tuple[IKEv1Attribute, ...] = ()

    def attribute(self, attr_type: int) -> IKEv1Attribute | None:
        for attribute in self.attributes:
            if attribute.attr_type == attr_type:
                return attribute
        return None

    def _value(self, attr_type: int) -> int | None:
        attribute = self.attribute(attr_type)
        return attribute.value if attribute is not None else None

    def _name(self, attr_type: int) -> str | None:
        attribute = self.attribute(attr_type)
        return attribute.value_name if attribute is not None else None

    @property
    def encryption(self) -> str | None:
        return self._name(IKEV1_ATTR_ENCRYPTION)

    @property
    def hash_algorithm(self) -> str | None:
        return self._name(IKEV1_ATTR_HASH)

    @property
    def auth_method(self) -> str | None:
        return self._name(IKEV1_ATTR_AUTH_METHOD)

    @property
    def auth_method_id(self) -> int | None:
        return self._value(IKEV1_ATTR_AUTH_METHOD)

    @property
    def dh_group(self) -> int | None:
        return self._value(IKEV1_ATTR_GROUP)

    @property
    def dh_group_name(self) -> str | None:
        return self._name(IKEV1_ATTR_GROUP)

    @property
    def key_length(self) -> int | None:
        return self._value(IKEV1_ATTR_KEY_LENGTH)

    @property
    def life_type(self) -> str | None:
        return self._name(IKEV1_ATTR_LIFE_TYPE)

    @property
    def life_duration(self) -> int | None:
        return self._value(IKEV1_ATTR_LIFE_DURATION)

    @property
    def uses_psk(self) -> bool:
        return self.auth_method_id == IKEV1_AUTH_METHOD_PSK


@dataclass(frozen=True)
class IKEv1Proposal:
    """One phase 1 proposal and every transform offered inside it."""

    number: int
    protocol_id: int
    protocol: str
    spi: str
    transforms: tuple[IKEv1Transform, ...] = ()


@dataclass
class IKEv1SAPayload:
    """An IKEv1 SA payload: DOI, Situation, and the proposals behind them."""

    doi: int = 0
    doi_name: str = ""
    situation: int = 0
    proposals: list[IKEv1Proposal] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def transforms(self) -> list[IKEv1Transform]:
        return [t for proposal in self.proposals for t in proposal.transforms]

    @property
    def uses_psk(self) -> bool:
        """True when any offered transform authenticates with a pre-shared key.

        Any, not all: an attacker picks the weakest offer, so a proposal list that
        includes PSK alongside certificates is a PSK deployment for this purpose.
        """
        return any(transform.uses_psk for transform in self.transforms)


@dataclass(frozen=True)
class IKEv1Exchange:
    """A parsed IKEv1 message and the two facts that decide its severity."""

    header: IKEHeader
    sa: IKEv1SAPayload | None = None
    errors: tuple[str, ...] = ()

    @property
    def is_aggressive(self) -> bool:
        return self.header.is_aggressive

    @property
    def is_main_mode(self) -> bool:
        return self.header.is_ikev1 and self.header.exchange_type == 2

    @property
    def psk_hash_exposed(self) -> bool:
        """Aggressive Mode **and** PSK: the authentication hash is crackable offline.

        Both halves are required. Aggressive Mode with certificates exposes the
        identity but no crackable secret, and PSK in Main Mode is protected by the
        already-established DH shared secret. Only the combination is critical, and
        reporting either half alone as critical would be a false positive in the
        deterministic lane — where findings carry no confidence score and are read as
        fact.
        """
        return self.is_aggressive and self.sa is not None and self.sa.uses_psk


def parse_ikev1_attributes(reader: SafeReader) -> list[IKEv1Attribute]:
    """Read every SA attribute in the reader's remaining bytes.

    The top bit of the first 16-bit word selects the encoding: set means the value
    follows inline, clear means a length precedes a variable-length value. In IKEv1
    this matters more than in IKEv2, because the entire proposal lives here — reading
    one form as the other does not corrupt one field, it corrupts all of them.
    """
    attributes: list[IKEv1Attribute] = []
    while not reader.at_end() and len(attributes) < MAX_ATTRIBUTES:
        header = reader.u16()
        attr_type = header & ATTRIBUTE_TYPE_MASK
        class_name = ikev1_attribute_class_name(attr_type)

        if header & ATTRIBUTE_FORMAT_BIT:
            value = reader.u16()
            attributes.append(
                IKEv1Attribute(
                    attr_type=attr_type,
                    class_name=class_name,
                    is_tv=True,
                    value=value,
                    value_name=ikev1_attribute_value_name(attr_type, value),
                )
            )
            continue

        length = reader.u16()
        raw = reader.read_bytes(length)
        # Lifetime duration is routinely sent as a 4-byte long form, and key length as
        # a 2-byte one. Wider or odd widths are left uninterpreted rather than guessed.
        long_value = int.from_bytes(raw, "big") if 0 < len(raw) <= 4 else None
        attributes.append(
            IKEv1Attribute(
                attr_type=attr_type,
                class_name=class_name,
                is_tv=False,
                value=long_value,
                value_name=(
                    ikev1_attribute_value_name(attr_type, long_value)
                    if long_value is not None
                    else None
                ),
                raw=raw,
            )
        )
    return attributes


def parse_ikev1_transform(reader: SafeReader) -> tuple[IKEv1Transform, int]:
    """Parse one transform payload, returning it and its next-payload type.

    The transform's own length bounds a sub-reader, so an attribute length that
    overruns the transform cannot reach into the transform that follows it.
    """
    next_payload = reader.u8()
    reader.u8()  # RESERVED
    length = reader.u16()
    if length < GENERIC_PAYLOAD_HEADER_LENGTH:
        raise MalformedError(f"IKEv1 transform length {length} is shorter than its own header")
    body = reader.sub(length - GENERIC_PAYLOAD_HEADER_LENGTH)

    number = body.u8()
    transform_id = body.u8()
    body.u16()  # RESERVED2

    return (
        IKEv1Transform(
            number=number,
            transform_id=transform_id,
            attributes=tuple(parse_ikev1_attributes(body)),
        ),
        next_payload,
    )


def parse_ikev1_proposal(reader: SafeReader) -> tuple[IKEv1Proposal, int, list[str]]:
    """Parse one proposal payload and every transform inside it."""
    next_payload = reader.u8()
    reader.u8()  # RESERVED
    length = reader.u16()
    if length < GENERIC_PAYLOAD_HEADER_LENGTH:
        raise MalformedError(f"IKEv1 proposal length {length} is shorter than its own header")
    body = reader.sub(length - GENERIC_PAYLOAD_HEADER_LENGTH)

    number = body.u8()
    protocol_id = body.u8()
    spi_size = body.u8()
    transform_count = body.u8()
    spi = body.read_bytes(spi_size)

    errors: list[str] = []
    transforms: list[IKEv1Transform] = []
    # The declared count is a hint, not a bound: a lying count must not be able to
    # drive the loop, so the reader's own extent decides when to stop.
    while not body.at_end() and len(transforms) < MAX_TRANSFORMS:
        try:
            transform, _ = parse_ikev1_transform(body)
        except ParseError as exc:
            errors.append(str(exc))
            break
        transforms.append(transform)

    if transform_count != len(transforms):
        errors.append(
            f"proposal {number} declared {transform_count} transforms but "
            f"{len(transforms)} were present"
        )

    return (
        IKEv1Proposal(
            number=number,
            protocol_id=protocol_id,
            protocol=PROTOCOL_IDS.get(protocol_id, f"UNKNOWN_PROTOCOL_{protocol_id}"),
            spi=spi.hex(),
            transforms=tuple(transforms),
        ),
        next_payload,
        errors,
    )


def parse_ikev1_sa_payload(reader: SafeReader) -> IKEv1SAPayload:
    """Parse an IKEv1 SA payload body: DOI and Situation, then the proposals.

    The Situation field exists only for the IPSEC DOI. Consuming it unconditionally
    would shift every proposal four bytes to the left for any other DOI, and the
    resulting garbage would parse — proposals are self-describing enough to produce
    plausible nonsense rather than an error.
    """
    payload = IKEv1SAPayload()
    payload.doi = reader.u32()
    payload.doi_name = ikev1_doi_name(payload.doi)
    if payload.doi == DOI_IPSEC:
        payload.situation = reader.u32()

    while not reader.at_end() and len(payload.proposals) < MAX_PROPOSALS:
        try:
            proposal, next_payload, errors = parse_ikev1_proposal(reader)
        except ParseError as exc:
            payload.errors.append(str(exc))
            break
        payload.proposals.append(proposal)
        payload.errors.extend(errors)
        if next_payload == 0:
            break
    return payload


def parse_ikev1_exchange(data: bytes) -> IKEv1Exchange:
    """Parse an IKEv1 message far enough to decide whether the PSK hash is exposed.

    Payloads after the SA are walked but not decoded here; the SA payload carries the
    authentication method, which together with the exchange type is everything the
    critical finding needs.
    """
    header = parse_ike_header(data, tolerate_truncation=True)
    reader = SafeReader(data, start=IKE_HEADER_LENGTH, end=min(header.length, len(data)))

    errors: list[str] = []
    if header.truncated:
        errors.append(
            f"message declares {header.length} bytes but only {len(data)} were "
            f"captured; parsing the payloads that arrived"
        )
    sa: IKEv1SAPayload | None = None
    next_payload = header.next_payload
    seen = 0

    while next_payload != 0 and not reader.at_end() and seen < MAX_PROPOSALS:
        seen += 1
        try:
            following = reader.u8()
            reader.u8()  # RESERVED
            length = reader.u16()
            if length < GENERIC_PAYLOAD_HEADER_LENGTH:
                raise MalformedError(
                    f"IKEv1 payload length {length} is shorter than its own header"
                )
            body = reader.sub(length - GENERIC_PAYLOAD_HEADER_LENGTH)
        except ParseError as exc:
            errors.append(str(exc))
            break

        if next_payload == PAYLOAD_SA and sa is None:
            try:
                sa = parse_ikev1_sa_payload(body)
            except ParseError as exc:
                errors.append(str(exc))
            else:
                errors.extend(sa.errors)

        next_payload = following

    return IKEv1Exchange(header=header, sa=sa, errors=tuple(errors))
