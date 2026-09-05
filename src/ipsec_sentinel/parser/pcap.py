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
from ipsec_sentinel.models import IKEExchange
from ipsec_sentinel.parser.ike import IKE_HEADER_LENGTH
from ipsec_sentinel.parser.message import parse_ike_message
from ipsec_sentinel.parser.reader import ParseError

NON_ESP_MARKER: Final = b"\x00\x00\x00\x00"


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


def _exchange_from(datagram: IKEDatagram) -> IKEExchange:
    """Build the domain model from a parsed message plus the datagram's addressing."""
    message = parse_ike_message(datagram.payload)
    return IKEExchange(
        initiator_spi=message.header.initiator_spi,
        responder_spi=message.header.responder_spi,
        version=message.header.version,
        exchange_type=message.header.exchange_type_name,
        is_aggressive=message.is_aggressive,
        proposals_offered=message.proposals,
        ke_group_from_length=message.ke_group_from_length,
        vendor_ids=message.vendor_ids,
        notifies=message.notifies,
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
            exchanges.append(_exchange_from(datagram))
        except ParseError:
            continue
    return exchanges
