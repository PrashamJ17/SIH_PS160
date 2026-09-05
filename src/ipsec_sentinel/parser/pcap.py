"""From a capture file to a list of :class:`IKEExchange` objects.

This is where the parser meets real input, and it is the layer at which one specific
bug keeps appearing in IPsec tooling. UDP 500 carries IKE directly. UDP 4500 carries
*either* IKE or ESP, distinguished only by a four-byte non-ESP marker of zeros in
front of the IKE message. Handing an ESP-over-UDP datagram to the IKE parser produces
a header whose fields are ciphertext — an SPI, a version, an exchange type, all read
from random bytes. Occasionally that garbage passes validation, and the result is a
fabricated negotiation reported as fact in the deterministic lane.

So the marker is checked before anything else, and the test suite asserts on the
negative case as much as the positive one.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Final

from ipsec_sentinel.data.pcap_scan import (
    IKE_PORT,
    NAT_T_PORT,
    UnsupportedCaptureError,
    iter_udp_datagrams,
)
from ipsec_sentinel.models import IKEExchange, Proposal, Transform, TransformType
from ipsec_sentinel.parser.constants import (
    IKEV1_ATTR_ENCRYPTION,
    IKEV1_ATTR_HASH,
    groups_for_ke_length,
)
from ipsec_sentinel.parser.ike import (
    IKE_HEADER_LENGTH,
    parse_ike_header,
    parse_ke_payload,
    parse_notify_payload,
    parse_sa_payload,
    parse_vendor_id_payload,
    walk_payloads,
)
from ipsec_sentinel.parser.ikev1 import IKEv1Transform, parse_ikev1_exchange
from ipsec_sentinel.parser.reader import ParseError, SafeReader

NON_ESP_MARKER: Final = b"\x00\x00\x00\x00"

# Byte 17 of an IKE message is the version, high nibble major. Read directly rather
# than by parsing the header twice, since the two versions need different parsers.
VERSION_OFFSET: Final = 17

PAYLOAD_SA_V2: Final = 33
PAYLOAD_KE_V2: Final = 34
PAYLOAD_NOTIFY_V2: Final = 41
PAYLOAD_VENDOR_ID_V2: Final = 43


class CaptureError(ValueError):
    """The capture cannot be read at all."""


@dataclass(frozen=True)
class IKEDatagram:
    """A UDP datagram carrying an IKE message, with the marker already stripped."""

    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    payload: bytes
    nat_traversal: bool


def is_ike_datagram(port_pair: tuple[int, int], payload: bytes) -> bool:
    """Whether this UDP payload is IKE rather than ESP-over-UDP.

    On 500 the answer is yes by port. On 4500 it is yes only with the non-ESP marker:
    a datagram whose first four bytes are anything else is ESP, whose leading field is
    a security parameter index that cannot be zero.
    """
    source, destination = port_pair
    if IKE_PORT in (source, destination):
        return True
    if NAT_T_PORT in (source, destination):
        return payload[:4] == NON_ESP_MARKER
    return False


def iter_ike_datagrams(pcap: Path) -> Iterator[IKEDatagram]:
    """Yield every datagram in the capture that actually carries IKE.

    The guard wraps the iteration, not the call: :func:`iter_udp_datagrams` is a
    generator, so it opens nothing until first advanced and a missing file would
    otherwise surface as a bare ``FileNotFoundError`` from inside the loop.
    """
    try:
        for datagram in iter_udp_datagrams(pcap):
            ports = (datagram.src_port, datagram.dst_port)
            if not is_ike_datagram(ports, datagram.payload):
                continue
            nat = NAT_T_PORT in ports and IKE_PORT not in ports
            body = datagram.payload[4:] if nat else datagram.payload
            if len(body) < IKE_HEADER_LENGTH:
                continue
            yield IKEDatagram(
                timestamp=datagram.timestamp,
                src_ip=datagram.src_ip,
                dst_ip=datagram.dst_ip,
                src_port=datagram.src_port,
                dst_port=datagram.dst_port,
                payload=body,
                nat_traversal=nat,
            )
    except (UnsupportedCaptureError, OSError) as exc:
        raise CaptureError(f"{pcap}: {exc}") from exc


def _group_from_ke_length(length: int) -> int | None:
    """The DH group a KE length implies, but only when it implies exactly one.

    768-bit MODP and 384-bit ECP both produce 96 bytes. Returning either would be a
    coin flip presented as a parsed fact, so an ambiguous length yields nothing.
    """
    candidates = groups_for_ke_length(length)
    return candidates[0] if len(candidates) == 1 else None


def _attribute_id(transform: IKEv1Transform, attr_type: int) -> int:
    """The numeric value of an attribute, or 0 when it is absent or uninterpretable.

    Zero is not a valid value in any of these registries, so it reads as "no ID" in
    the projected transform rather than as a real algorithm.
    """
    attribute = transform.attribute(attr_type)
    if attribute is None or attribute.value is None:
        return 0
    return attribute.value


def _v1_transforms(transform: IKEv1Transform) -> list[Transform]:
    """Normalise an IKEv1 phase 1 transform into the shared transform model.

    IKEv1 has no transform-type structure — the whole proposal is a bag of SA
    attributes — so this projects those attributes onto the IKEv2-shaped model the
    rest of the system speaks. Nothing is inferred: each entry below comes from an
    attribute that was present, and an absent attribute produces no entry.
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


def _exchange_from_v1(datagram: IKEDatagram) -> IKEExchange | None:
    parsed = parse_ikev1_exchange(datagram.payload)
    proposals: list[Proposal] = []
    if parsed.sa is not None:
        for proposal in parsed.sa.proposals:
            for transform in proposal.transforms:
                proposals.append(
                    Proposal(
                        number=proposal.number,
                        protocol=proposal.protocol,
                        transforms=_v1_transforms(transform),
                    )
                )
    return IKEExchange(
        initiator_spi=parsed.header.initiator_spi,
        responder_spi=parsed.header.responder_spi,
        version=parsed.header.version,
        exchange_type=parsed.header.exchange_type_name,
        is_aggressive=parsed.is_aggressive,
        proposals_offered=proposals,
        timestamp=datagram.timestamp,
        src_ip=datagram.src_ip,
        dst_ip=datagram.dst_ip,
    )


def _exchange_from_v2(datagram: IKEDatagram) -> IKEExchange | None:
    header = parse_ike_header(datagram.payload, tolerate_truncation=True)
    chain = walk_payloads(
        SafeReader(
            datagram.payload,
            start=IKE_HEADER_LENGTH,
            end=min(header.length, len(datagram.payload)),
        ),
        header.next_payload,
    )

    proposals: list[Proposal] = []
    ke_group: int | None = None
    vendor_ids: list[str] = []
    notifies: list[str] = []

    for payload in chain:
        try:
            if payload.payload_type == PAYLOAD_SA_V2:
                proposals.extend(parse_sa_payload(SafeReader(payload.body)).proposals)
            elif payload.payload_type == PAYLOAD_KE_V2:
                parsed_ke = parse_ke_payload(SafeReader(payload.body))
                ke_group = _group_from_ke_length(parsed_ke.public_value_length)
            elif payload.payload_type == PAYLOAD_NOTIFY_V2:
                notifies.append(parse_notify_payload(SafeReader(payload.body)).notify_name)
            elif payload.payload_type == PAYLOAD_VENDOR_ID_V2:
                vendor_ids.append(parse_vendor_id_payload(SafeReader(payload.body)).vendor_id)
        except ParseError:
            # One unreadable payload must not discard the exchange around it. The
            # chain walker has already recorded what went wrong.
            continue

    return IKEExchange(
        initiator_spi=header.initiator_spi,
        responder_spi=header.responder_spi,
        version=header.version,
        exchange_type=header.exchange_type_name,
        is_aggressive=header.is_aggressive,
        proposals_offered=proposals,
        ke_group_from_length=ke_group,
        vendor_ids=vendor_ids,
        notifies=notifies,
        timestamp=datagram.timestamp,
        src_ip=datagram.src_ip,
        dst_ip=datagram.dst_ip,
    )


def extract_ike_exchanges(pcap: Path) -> list[IKEExchange]:
    """Every IKE message in the capture, parsed.

    One message, one :class:`IKEExchange` — correlating the initiator's offer with the
    responder's choice is a later step, and doing it here would mean guessing at
    pairings before the data supports it.

    A message the parser cannot read is skipped rather than raising: a capture is
    hostile input, and one malformed datagram must not cost the analyst the other
    thousand. A file that cannot be read *at all* does raise, because that is a
    different question and the analyst needs to be told.
    """
    exchanges: list[IKEExchange] = []
    for datagram in iter_ike_datagrams(pcap):
        try:
            exchange = (
                _exchange_from_v1(datagram)
                if datagram.payload[VERSION_OFFSET] >> 4 == 1
                else _exchange_from_v2(datagram)
            )
        except ParseError:
            continue
        if exchange is not None:
            exchanges.append(exchange)
    return exchanges
