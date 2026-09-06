"""One entry point for a whole IKE message, whichever version it is.

Callers should not have to know that IKEv1 and IKEv2 need different parsers, and more
importantly they should not have to remember that a message from a capture is hostile
input. Everything below is total: for any sequence of bytes at all, this module returns
a result or raises one of the parser's own two errors. It never raises anything else,
never loops without bound, and never takes long. Step 4.9 fuzzes exactly that promise,
because a security tool that can be crashed by the traffic it inspects is a liability
rather than a defence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

from ipsec_sentinel.models import Proposal, Transform, TransformType
from ipsec_sentinel.parser.constants import (
    IKEV1_ATTR_ENCRYPTION,
    IKEV1_ATTR_HASH,
    groups_for_ke_length,
)
from ipsec_sentinel.parser.ike import (
    IKE_HEADER_LENGTH,
    IKEHeader,
    parse_ike_header,
    parse_ke_payload,
    parse_notify_payload,
    parse_sa_payload,
    parse_vendor_id_payload,
    walk_payloads,
)
from ipsec_sentinel.parser.ikev1 import IKEv1Transform, parse_ikev1_exchange
from ipsec_sentinel.parser.reader import ParseError, SafeReader

PAYLOAD_SA_V2: Final = 33
PAYLOAD_KE_V2: Final = 34
PAYLOAD_NOTIFY_V2: Final = 41
PAYLOAD_VENDOR_ID_V2: Final = 43

# Byte 17 of an IKE message is the version, high nibble major.
VERSION_OFFSET: Final = 17


@dataclass
class ParsedMessage:
    """Everything read from one IKE message, plus whatever could not be read.

    ``errors`` is part of the result rather than an exception because a partly
    readable message is still evidence. A capture with a snaplen cut, a vendor's
    non-conforming payload, a deliberately malformed probe — each of those yields
    real facts alongside a recorded complaint, and discarding the facts to signal the
    complaint would lose the more useful half.
    """

    header: IKEHeader
    proposals: list[Proposal] = field(default_factory=list)
    ke_group_from_length: int | None = None
    auth_methods: list[str] = field(default_factory=list)
    vendor_ids: list[str] = field(default_factory=list)
    notifies: list[str] = field(default_factory=list)
    psk_hash_exposed: bool = False
    errors: list[str] = field(default_factory=list)

    @property
    def is_aggressive(self) -> bool:
        return self.header.is_aggressive

    @property
    def is_ikev1(self) -> bool:
        return self.header.is_ikev1


def group_from_ke_length(length: int) -> int | None:
    """The DH group a KE length implies, but only when it implies exactly one.

    768-bit MODP and 384-bit ECP both produce 96 bytes. Returning either would be a
    coin flip presented as a parsed fact, so an ambiguous length yields nothing.
    """
    candidates = groups_for_ke_length(length)
    return candidates[0] if len(candidates) == 1 else None


def _attribute_id(transform: IKEv1Transform, attr_type: int) -> int:
    """The numeric value of an attribute, or 0 when absent or uninterpretable.

    Zero is not valid in any of these registries, so it reads as "no ID" rather than
    as a real algorithm.
    """
    attribute = transform.attribute(attr_type)
    if attribute is None or attribute.value is None:
        return 0
    return attribute.value


def project_v1_transform(transform: IKEv1Transform) -> list[Transform]:
    """Normalise an IKEv1 phase 1 transform onto the shared transform model.

    IKEv1 has no transform-type structure — the whole proposal is a bag of SA
    attributes — so this projects those attributes onto the IKEv2-shaped model the
    rest of the system speaks. Nothing is inferred: each entry comes from an attribute
    that was present, and an absent attribute produces no entry.
    """
    projected: list[Transform] = []
    if transform.encryption is not None:
        projected.append(
            Transform(
                type=TransformType.ENCR,
                id=_attribute_id(transform, IKEV1_ATTR_ENCRYPTION),
                name=transform.encryption,
                key_length=transform.key_length,
            )
        )
    if transform.hash_algorithm is not None:
        projected.append(
            Transform(
                type=TransformType.INTEG,
                id=_attribute_id(transform, IKEV1_ATTR_HASH),
                name=transform.hash_algorithm,
            )
        )
    if transform.dh_group is not None:
        projected.append(
            Transform(
                type=TransformType.DH,
                id=transform.dh_group,
                name=transform.dh_group_name or str(transform.dh_group),
            )
        )
    return projected


def _parse_v1(data: bytes) -> ParsedMessage:
    parsed = parse_ikev1_exchange(data)
    proposals: list[Proposal] = []
    if parsed.sa is not None:
        for proposal in parsed.sa.proposals:
            for transform in proposal.transforms:
                proposals.append(
                    Proposal(
                        number=proposal.number,
                        protocol=proposal.protocol,
                        transforms=project_v1_transform(transform),
                    )
                )
    auth_methods: list[str] = []
    if parsed.sa is not None:
        for transform in parsed.sa.transforms:
            method = transform.auth_method
            if method is not None and method not in auth_methods:
                auth_methods.append(method)

    return ParsedMessage(
        header=parsed.header,
        proposals=proposals,
        auth_methods=auth_methods,
        psk_hash_exposed=parsed.psk_hash_exposed,
        errors=list(parsed.errors),
    )


def _parse_v2(data: bytes) -> ParsedMessage:
    header = parse_ike_header(data, tolerate_truncation=True)
    chain = walk_payloads(
        SafeReader(data, start=IKE_HEADER_LENGTH, end=min(header.length, len(data))),
        header.next_payload,
    )
    message = ParsedMessage(header=header, errors=list(chain.errors))
    if header.truncated:
        message.errors.append(
            f"message declares {header.length} bytes but only {len(data)} were captured"
        )

    for payload in chain:
        try:
            if payload.payload_type == PAYLOAD_SA_V2:
                sa = parse_sa_payload(SafeReader(payload.body))
                message.proposals.extend(sa.proposals)
                message.errors.extend(sa.errors)
            elif payload.payload_type == PAYLOAD_KE_V2:
                ke = parse_ke_payload(SafeReader(payload.body))
                message.ke_group_from_length = group_from_ke_length(ke.public_value_length)
            elif payload.payload_type == PAYLOAD_NOTIFY_V2:
                message.notifies.append(parse_notify_payload(SafeReader(payload.body)).notify_name)
            elif payload.payload_type == PAYLOAD_VENDOR_ID_V2:
                message.vendor_ids.append(
                    parse_vendor_id_payload(SafeReader(payload.body)).vendor_id
                )
        except ParseError as exc:
            # One unreadable payload must not discard the exchange around it.
            message.errors.append(str(exc))
    return message


def parse_ike_message(data: bytes) -> ParsedMessage:
    """Parse an IKE message of either version.

    Raises ``TruncatedError`` when there is not even a header, and ``MalformedError``
    when the header is impossible. Every other defect below the header is recorded on
    the result rather than raised, because the readable part of a broken message is
    still evidence.
    """
    header = parse_ike_header(data, tolerate_truncation=True)
    return _parse_v1(data) if header.is_ikev1 else _parse_v2(data)
