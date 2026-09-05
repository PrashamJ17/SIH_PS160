"""Synthetic IKE packet builders for tests (build plan Step 0.8).

These construct byte-exact IKE messages from first principles, so the parser can be
tested long before the testbed produces a real capture — and so hostile, malformed and
edge-case inputs can be produced deliberately rather than hoped for.

Wire formats follow RFC 7296 (IKEv2) and RFC 2409 / RFC 2408 (IKEv1, ISAKMP). Every
length field is computed from the actual bytes emitted, never hard-coded, so a builder
cannot silently drift out of agreement with what it claims to build.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Final

from ipsec_sentinel.models import Proposal, TransformType
from ipsec_sentinel.parser.constants import ATTRIBUTE_KEY_LENGTH, TRANSFORM_TYPES

IKE_HEADER_LENGTH: Final = 28
GENERIC_PAYLOAD_HEADER_LENGTH: Final = 4
PROPOSAL_HEADER_LENGTH: Final = 8
TRANSFORM_HEADER_LENGTH: Final = 8
TV_ATTRIBUTE_LENGTH: Final = 4

# "Last Substruc" values (RFC 7296 sections 3.3.1 and 3.3.2).
LAST_SUBSTRUCTURE: Final = 0
MORE_PROPOSALS: Final = 2
MORE_TRANSFORMS: Final = 3

# IKEv2 payload type numbers.
PAYLOAD_NONE: Final = 0
PAYLOAD_SA: Final = 33
PAYLOAD_KE: Final = 34
PAYLOAD_NONCE: Final = 40

# IKEv1 payload type numbers differ from IKEv2 and need their own table.
V1_PAYLOAD_NONE: Final = 0
V1_PAYLOAD_SA: Final = 1
V1_PAYLOAD_KE: Final = 4
V1_PAYLOAD_ID: Final = 5
V1_PAYLOAD_NONCE: Final = 10

# IKEv1 SA attribute types (RFC 2409 appendix A).
V1_ATTR_ENCRYPTION: Final = 1
V1_ATTR_HASH: Final = 2
V1_ATTR_AUTH_METHOD: Final = 3
V1_ATTR_GROUP: Final = 4
V1_ATTR_LIFE_TYPE: Final = 11
V1_ATTR_LIFE_DURATION: Final = 12
V1_ATTR_KEY_LENGTH: Final = 14
V1_AUTH_PRE_SHARED_KEY: Final = 1
V1_AUTH_RSA_SIGNATURES: Final = 3

VERSION_IKEV1: Final = 0x10
VERSION_IKEV2: Final = 0x20

EXCHANGE_IKE_SA_INIT: Final = 34
EXCHANGE_V1_MAIN: Final = 2
EXCHANGE_V1_AGGRESSIVE: Final = 4

PROTOCOL_IKE: Final = 1

# Public-value sizes, so KE payloads are the length their group implies.
_KE_LENGTH_BY_GROUP: Final[dict[int, int]] = {
    1: 96,
    2: 128,
    5: 192,
    14: 256,
    15: 384,
    16: 512,
    19: 64,
    20: 96,
    21: 132,
    31: 32,
}

_TRANSFORM_TYPE_IDS: Final[dict[str, int]] = {n: i for i, n in TRANSFORM_TYPES.items()}


def build_ike_header(
    i_spi: bytes = b"\x11" * 8,
    r_spi: bytes = b"\x00" * 8,
    next_payload: int = PAYLOAD_SA,
    version: int = VERSION_IKEV2,
    exchange_type: int = EXCHANGE_IKE_SA_INIT,
    flags: int = 0x08,
    message_id: int = 0,
    length: int | None = None,
) -> bytes:
    """Build the fixed 28-byte IKE header.

    ``length`` defaults to the header length alone; callers building a full message
    pass the total. It is left settable so tests can produce a deliberately wrong
    length field.
    """
    return (
        i_spi
        + r_spi
        + struct.pack(
            "!BBBBII",
            next_payload,
            version,
            exchange_type,
            flags,
            message_id,
            IKE_HEADER_LENGTH if length is None else length,
        )
    )


def build_key_length_attribute(key_length: int) -> bytes:
    """Key-length attribute in TV form: AF bit set, type 14, 2-byte value."""
    return struct.pack("!HH", 0x8000 | ATTRIBUTE_KEY_LENGTH, key_length)


def build_tlv_attribute(attr_type: int, value: bytes) -> bytes:
    """Attribute in TLV form: AF bit clear, then an explicit length."""
    return struct.pack("!HH", attr_type & 0x7FFF, len(value)) + value


def build_transform(
    t_type: int,
    t_id: int,
    key_length: int | None = None,
    is_last: bool = False,
    attributes: bytes = b"",
) -> bytes:
    """Build one transform substructure, with an optional key-length attribute."""
    attrs = attributes
    if key_length is not None:
        attrs = build_key_length_attribute(key_length) + attrs
    total = TRANSFORM_HEADER_LENGTH + len(attrs)
    header = struct.pack(
        "!BBHBBH",
        LAST_SUBSTRUCTURE if is_last else MORE_TRANSFORMS,
        0,
        total,
        t_type,
        0,
        t_id,
    )
    return header + attrs


def build_proposal(
    number: int,
    protocol: int,
    transforms: list[bytes],
    is_last: bool = False,
    spi: bytes = b"",
) -> bytes:
    """Build one proposal substructure wrapping the given transforms."""
    body = b"".join(transforms)
    total = PROPOSAL_HEADER_LENGTH + len(spi) + len(body)
    header = struct.pack(
        "!BBHBBBB",
        LAST_SUBSTRUCTURE if is_last else MORE_PROPOSALS,
        0,
        total,
        number,
        protocol,
        len(spi),
        len(transforms),
    )
    return header + spi + body


def _generic_payload(next_payload: int, body: bytes, critical: bool = False) -> bytes:
    """Wrap a payload body in the 4-byte generic payload header."""
    total = GENERIC_PAYLOAD_HEADER_LENGTH + len(body)
    return struct.pack("!BBH", next_payload, 0x80 if critical else 0, total) + body


def build_sa_payload(proposals: list[bytes], next_payload: int = PAYLOAD_NONE) -> bytes:
    """Build an IKEv2 SA payload carrying the given proposal substructures."""
    return _generic_payload(next_payload, b"".join(proposals))


def build_ke_payload(
    dh_group: int,
    key_data: bytes | None = None,
    next_payload: int = PAYLOAD_NONE,
) -> bytes:
    """Build a KE payload whose public value is the length the group implies."""
    if key_data is None:
        key_data = b"\xab" * _KE_LENGTH_BY_GROUP.get(dh_group, 256)
    return _generic_payload(next_payload, struct.pack("!HH", dh_group, 0) + key_data)


def build_nonce_payload(length: int = 32, next_payload: int = PAYLOAD_NONE) -> bytes:
    """Build a nonce payload of the requested data length."""
    return _generic_payload(next_payload, bytes(range(256))[:length] * (length // 256 + 1))


def _finalise(header_args: dict[str, object], payloads: bytes) -> bytes:
    """Emit a header whose length field matches the real total, plus the payloads."""
    total = IKE_HEADER_LENGTH + len(payloads)
    return build_ike_header(length=total, **header_args) + payloads  # type: ignore[arg-type]


def transforms_for(proposal: Proposal) -> list[bytes]:
    """Encode a domain :class:`Proposal`'s transforms as wire substructures."""
    encoded: list[bytes] = []
    for index, transform in enumerate(proposal.transforms):
        encoded.append(
            build_transform(
                t_type=_TRANSFORM_TYPE_IDS[transform.type.value],
                t_id=transform.id,
                key_length=transform.key_length,
                is_last=index == len(proposal.transforms) - 1,
            )
        )
    return encoded


def build_ike_sa_init(proposals: list[Proposal]) -> bytes:
    """Build a full, valid IKE_SA_INIT message from domain proposals.

    The DH group of the first proposal's DH transform drives the KE payload, so the
    KE length corroborates the declared group rather than contradicting it.
    """
    wire_proposals = [
        build_proposal(
            number=p.number,
            protocol=PROTOCOL_IKE,
            transforms=transforms_for(p),
            is_last=index == len(proposals) - 1,
        )
        for index, p in enumerate(proposals)
    ]
    dh_group = 14
    for p in proposals:
        for t in p.transforms:
            if t.type is TransformType.DH:
                dh_group = t.id
                break
        break

    payloads = (
        build_sa_payload(wire_proposals, next_payload=PAYLOAD_KE)
        + build_ke_payload(dh_group, next_payload=PAYLOAD_NONCE)
        + build_nonce_payload(next_payload=PAYLOAD_NONE)
    )
    return _finalise(
        {
            "next_payload": PAYLOAD_SA,
            "version": VERSION_IKEV2,
            "exchange_type": EXCHANGE_IKE_SA_INIT,
        },
        payloads,
    )


def _weak_proposal() -> Proposal:
    from ipsec_sentinel.models import Transform

    return Proposal(
        number=1,
        protocol="IKE",
        transforms=[
            Transform(type=TransformType.ENCR, id=3, name="ENCR_3DES"),
            Transform(type=TransformType.PRF, id=1, name="PRF_HMAC_MD5"),
            Transform(type=TransformType.INTEG, id=1, name="AUTH_HMAC_MD5_96"),
            Transform(type=TransformType.DH, id=2, name="1024-bit MODP"),
        ],
    )


def _strong_proposal() -> Proposal:
    from ipsec_sentinel.models import Transform

    return Proposal(
        number=1,
        protocol="IKE",
        transforms=[
            Transform(type=TransformType.ENCR, id=20, name="ENCR_AES_GCM_16", key_length=256),
            Transform(type=TransformType.PRF, id=6, name="PRF_HMAC_SHA2_384"),
            Transform(type=TransformType.DH, id=20, name="384-bit ECP"),
        ],
    )


def build_weak_ike_sa_init() -> bytes:
    """3DES + MD5 + DH group 2 — the canonical bad configuration."""
    return build_ike_sa_init([_weak_proposal()])


def build_strong_ike_sa_init() -> bytes:
    """AES-GCM-256 + SHA2-384 PRF + DH group 20."""
    return build_ike_sa_init([_strong_proposal()])


def build_multi_proposal_ike_sa_init() -> bytes:
    """A menu offering strong first and 3DES as a fallback.

    Auditing only the accepted proposal would miss the 3DES fallback entirely, which
    is the whole reason the parser keeps every offered proposal.
    """
    weak = _weak_proposal()
    return build_ike_sa_init(
        [_strong_proposal(), Proposal(number=2, protocol="IKE", transforms=weak.transforms)]
    )


def build_v1_attribute(attr_type: int, value: int) -> bytes:
    """IKEv1 basic (TV) SA attribute."""
    return struct.pack("!HH", 0x8000 | attr_type, value)


def build_ikev1_aggressive(
    encryption: int = 5,
    hash_alg: int = 1,
    group: int = 2,
    auth_method: int = V1_AUTH_PRE_SHARED_KEY,
    exchange_type: int = EXCHANGE_V1_AGGRESSIVE,
    life_type: int | None = None,
    life_duration: int | None = None,
    key_length: int | None = None,
    doi: int = 1,
) -> bytes:
    """IKEv1 Aggressive Mode with PSK authentication.

    Defaults are 3DES (5) + MD5 (1) + group 2 + PSK: the configuration whose correct
    finding is not "weak" but "assume this pre-shared key is already compromised",
    because Aggressive Mode puts a crackable PSK hash on the wire.

    An IKEv1 SA payload carries a DOI and Situation before its proposals, and its
    proposal and transform substructures are themselves ISAKMP payloads, so this
    cannot reuse the IKEv2 builders.
    """
    attributes = (
        build_v1_attribute(V1_ATTR_ENCRYPTION, encryption)
        + build_v1_attribute(V1_ATTR_HASH, hash_alg)
        + build_v1_attribute(V1_ATTR_AUTH_METHOD, auth_method)
        + build_v1_attribute(V1_ATTR_GROUP, group)
    )
    if key_length is not None:
        attributes += build_v1_attribute(V1_ATTR_KEY_LENGTH, key_length)
    if life_type is not None:
        attributes += build_v1_attribute(V1_ATTR_LIFE_TYPE, life_type)
    if life_duration is not None:
        # Lifetime duration is conventionally the long (TLV) form, 4 bytes.
        attributes += struct.pack("!HH", V1_ATTR_LIFE_DURATION, 4) + struct.pack(
            "!I", life_duration
        )
    # IKEv1 transform payload: header, transform #, transform-id, 2 reserved bytes.
    transform = struct.pack("!BBHBBH", 0, 0, 8 + len(attributes), 1, 1, 0) + attributes
    # IKEv1 proposal payload: header, proposal #, protocol, SPI size, # transforms.
    proposal = struct.pack("!BBHBBBB", 0, 0, 8 + len(transform), 1, PROTOCOL_IKE, 0, 1) + transform
    # IKEv1 SA payload: header, DOI, then Situation for the IPsec DOI only.
    sa_body = (struct.pack("!II", doi, 1) if doi == 1 else struct.pack("!I", doi)) + proposal
    sa_payload = _generic_payload(V1_PAYLOAD_KE, sa_body)

    ke_payload = _generic_payload(V1_PAYLOAD_NONCE, b"\xcd" * _KE_LENGTH_BY_GROUP.get(group, 128))
    nonce_payload = _generic_payload(V1_PAYLOAD_ID, b"\xef" * 32)
    # Identity payload — exposed in cleartext by Aggressive Mode, unlike Main Mode.
    id_body = struct.pack("!BBH", 1, 0, 0) + bytes([203, 0, 113, 1])
    id_payload = _generic_payload(V1_PAYLOAD_NONE, id_body)

    payloads = sa_payload + ke_payload + nonce_payload + id_payload
    return _finalise(
        {
            "next_payload": V1_PAYLOAD_SA,
            "version": VERSION_IKEV1,
            "exchange_type": exchange_type,
            "flags": 0x00,
        },
        payloads,
    )


def build_ikev1_main_mode(auth_method: int = V1_AUTH_PRE_SHARED_KEY, **kwargs: int) -> bytes:
    """IKEv1 Main Mode (exchange type 2).

    Structurally identical to Aggressive Mode at the SA payload; the difference that
    matters is the exchange type, because Main Mode completes the DH exchange before
    any authentication payload is sent. PSK here is not a crackable-hash finding.
    """
    return build_ikev1_aggressive(auth_method=auth_method, exchange_type=EXCHANGE_V1_MAIN, **kwargs)


# ---------------------------------------------------------------------------
# Capture-file construction
#
# Written by hand rather than with a packet library: the tests below assert on how the
# ingestion layer treats malformed and adversarial captures, and a library that
# normalises its output cannot produce those.
# ---------------------------------------------------------------------------

PCAP_MAGIC_US: Final = b"\xd4\xc3\xb2\xa1"
PCAP_MAGIC_NS: Final = b"\x4d\x3c\xb2\xa1"
DLT_ETHERNET: Final = 1
IKE_PORT: Final = 500
NAT_T_PORT: Final = 4500


def build_udp_frame(
    payload: bytes,
    src_ip: str = "192.0.2.1",
    dst_ip: str = "192.0.2.2",
    src_port: int = IKE_PORT,
    dst_port: int = IKE_PORT,
) -> bytes:
    """An Ethernet + IPv4 + UDP frame carrying ``payload``."""
    udp = struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0) + payload
    total = 20 + len(udp)
    ipv4 = (
        struct.pack("!BBHHHBBH", 0x45, 0, total, 0, 0, 64, 17, 0)
        + bytes(int(part) for part in src_ip.split("."))
        + bytes(int(part) for part in dst_ip.split("."))
    )
    ethernet = b"\x02" * 6 + b"\x03" * 6 + struct.pack("!H", 0x0800)
    return ethernet + ipv4 + udp


def build_pcap(
    frames: list[bytes], nanosecond: bool = False, base_time: int = 1_700_000_000
) -> bytes:
    """A classic pcap file containing ``frames``, one record each."""
    magic = PCAP_MAGIC_NS if nanosecond else PCAP_MAGIC_US
    out = magic + struct.pack("<HHiIII", 2, 4, 0, 0, 262_144, DLT_ETHERNET)
    for index, frame in enumerate(frames):
        out += struct.pack("<IIII", base_time + index, 0, len(frame), len(frame))
        out += frame
    return out


def write_pcap(path: Path, frames: list[bytes], **kwargs: object) -> Path:
    """Write ``frames`` to ``path`` as a pcap and return the path."""
    path.write_bytes(build_pcap(frames, **kwargs))  # type: ignore[arg-type]
    return path


def build_esp_over_udp_frame(spi: int = 0xDEADBEEF) -> bytes:
    """ESP on port 4500 — no non-ESP marker, so the first four bytes are the SPI.

    An SPI cannot be zero, which is precisely what makes the marker unambiguous.
    """
    body = struct.pack("!II", spi, 1) + b"\xa5" * 64
    return build_udp_frame(body, src_port=NAT_T_PORT, dst_port=NAT_T_PORT)


def build_natt_ike_frame(message: bytes) -> bytes:
    """IKE on port 4500, behind the four-byte non-ESP marker."""
    return build_udp_frame(b"\x00\x00\x00\x00" + message, src_port=NAT_T_PORT, dst_port=NAT_T_PORT)
