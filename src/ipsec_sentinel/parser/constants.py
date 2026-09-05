"""IANA protocol constants and the resolvers that turn numbers into names.

Pure data with almost no logic — but an error here is invisible and corrupts every
finding downstream. A mis-mapped transform ID turns a critical finding into a clean
bill of health, so every table is tested exhaustively and every resolver is total:
an unrecognised value yields an ``UNKNOWN_*`` marker and never raises.

Sources: RFC 7296 (IKEv2), RFC 2409 (IKEv1), RFC 8221/8247 (algorithm requirements)
and the IANA "Internet Key Exchange Version 2 (IKEv2) Parameters" registry.
"""

from __future__ import annotations

import warnings
from typing import Final, NamedTuple

from ipsec_sentinel.models import TransformType

IKE_VERSIONS: Final[dict[int, str]] = {0x10: "IKEv1", 0x20: "IKEv2"}

IKEV2_EXCHANGE_TYPES: Final[dict[int, str]] = {
    34: "IKE_SA_INIT",
    35: "IKE_AUTH",
    36: "CREATE_CHILD_SA",
    37: "INFORMATIONAL",
}

IKEV1_EXCHANGE_TYPES: Final[dict[int, str]] = {
    0: "NONE",
    1: "Base",
    2: "Identity Protection (Main Mode)",
    3: "Authentication Only",
    4: "Aggressive Mode",
    5: "Informational",
    32: "Quick Mode",
}

IKEV2_PAYLOAD_TYPES: Final[dict[int, str]] = {
    33: "SA",
    34: "KE",
    35: "IDi",
    36: "IDr",
    37: "CERT",
    38: "CERTREQ",
    39: "AUTH",
    40: "Ni/Nr",
    41: "N",
    42: "D",
    43: "V",
    44: "TSi",
    45: "TSr",
    46: "SK",
    47: "CP",
}

# IKEv1 numbers its payloads differently from IKEv2 (RFC 2408 section 3.1). Using the
# IKEv2 table on an IKEv1 message would name an SA payload "UNKNOWN_PAYLOAD_1" and a
# Vendor ID "UNKNOWN_PAYLOAD_13" — silently losing the two payloads that matter most.
IKEV1_PAYLOAD_TYPES: Final[dict[int, str]] = {
    0: "NONE",
    1: "SA",
    2: "Proposal",
    3: "Transform",
    4: "KE",
    5: "ID",
    6: "CERT",
    7: "CERTREQ",
    8: "HASH",
    9: "SIG",
    10: "NONCE",
    11: "N",
    12: "D",
    13: "V",
    130: "NAT-D",
    131: "NAT-OA",
}

TRANSFORM_TYPES: Final[dict[int, str]] = {1: "ENCR", 2: "PRF", 3: "INTEG", 4: "DH", 5: "ESN"}

ENCR_ALGORITHMS: Final[dict[int, str]] = {
    1: "ENCR_DES_IV64",
    2: "ENCR_DES",
    3: "ENCR_3DES",
    5: "ENCR_RC5",
    6: "ENCR_IDEA",
    7: "ENCR_CAST",
    8: "ENCR_BLOWFISH",
    11: "ENCR_NULL",
    12: "ENCR_AES_CBC",
    13: "ENCR_AES_CTR",
    14: "ENCR_AES_CCM_8",
    15: "ENCR_AES_CCM_12",
    16: "ENCR_AES_CCM_16",
    18: "ENCR_AES_GCM_8",
    19: "ENCR_AES_GCM_12",
    20: "ENCR_AES_GCM_16",
    23: "ENCR_CAMELLIA_CBC",
    28: "ENCR_CHACHA20_POLY1305",
}

INTEG_ALGORITHMS: Final[dict[int, str]] = {
    0: "NONE",
    1: "AUTH_HMAC_MD5_96",
    2: "AUTH_HMAC_SHA1_96",
    5: "AUTH_AES_XCBC_96",
    12: "AUTH_HMAC_SHA2_256_128",
    13: "AUTH_HMAC_SHA2_384_192",
    14: "AUTH_HMAC_SHA2_512_256",
}

PRF_ALGORITHMS: Final[dict[int, str]] = {
    1: "PRF_HMAC_MD5",
    2: "PRF_HMAC_SHA1",
    4: "PRF_AES128_XCBC",
    5: "PRF_HMAC_SHA2_256",
    6: "PRF_HMAC_SHA2_384",
    7: "PRF_HMAC_SHA2_512",
}

# Protocol IDs inside an SA proposal (RFC 7296 section 3.3.1).
PROTOCOL_IDS: Final[dict[int, str]] = {1: "IKE", 2: "AH", 3: "ESP"}

ESN_VALUES: Final[dict[int, str]] = {
    0: "No Extended Sequence Numbers",
    1: "Extended Sequence Numbers",
}

# group -> (human name, strength in bits). For MODP the bits are the modulus size;
# for ECP they are the curve's field size, which is why 384-bit ECP (group 20) is far
# stronger than 1024-bit MODP (group 2) despite the smaller number.
DH_GROUPS: Final[dict[int, tuple[str, int]]] = {
    1: ("768-bit MODP", 768),
    2: ("1024-bit MODP", 1024),
    5: ("1536-bit MODP", 1536),
    14: ("2048-bit MODP", 2048),
    15: ("3072-bit MODP", 3072),
    16: ("4096-bit MODP", 4096),
    19: ("256-bit ECP", 256),
    20: ("384-bit ECP", 384),
    21: ("521-bit ECP", 521),
    31: ("Curve25519", 256),
}

# Length in bytes of the KE payload's public value -> the DH groups that produce it.
#
# MODP public values are one modulus (bits / 8). ECP public values are an uncompressed
# point, x||y, so twice the field size in bytes.
#
# The mapping is deliberately one-to-MANY: 768-bit MODP (group 1) and 384-bit ECP
# (group 20) both yield 96 bytes. Length therefore can never *determine* the group —
# it is only a consistency check on the group named in the transform. See
# :func:`check_ke_length`.
KE_LENGTH_TO_GROUP: Final[dict[int, tuple[int, ...]]] = {
    32: (31,),  # Curve25519
    64: (19,),  # 256-bit ECP: 2 x 32
    96: (1, 20),  # 768-bit MODP *and* 384-bit ECP (2 x 48) — the documented collision
    128: (2,),  # 1024-bit MODP
    132: (21,),  # 521-bit ECP: 2 x 66
    192: (5,),  # 1536-bit MODP
    256: (14,),  # 2048-bit MODP
    384: (15,),  # 3072-bit MODP
    512: (16,),  # 4096-bit MODP
}

# IKE attribute type carrying the key length. This attribute is the only thing that
# separates AES-128 from AES-256: both are transform ID 12.
ATTRIBUTE_KEY_LENGTH: Final = 14

NOTIFY_TYPES: Final[dict[int, str]] = {
    14: "NO_PROPOSAL_CHOSEN",
    17: "INVALID_KE_PAYLOAD",
    16388: "USE_TRANSPORT_MODE",
    16389: "HTTP_CERT_LOOKUP_SUPPORTED",
    16390: "NAT_DETECTION_SOURCE_IP",
    16391: "NAT_DETECTION_DESTINATION_IP",
    16395: "COOKIE",
    16406: "REDIRECT",
}

_ALGORITHM_TABLES: Final[dict[str, dict[int, str]]] = {
    TransformType.ENCR.value: ENCR_ALGORITHMS,
    TransformType.PRF.value: PRF_ALGORITHMS,
    TransformType.INTEG.value: INTEG_ALGORITHMS,
    TransformType.ESN.value: ESN_VALUES,
}


class KELengthWarning(UserWarning):
    """The KE payload length does not confirm the declared DH group.

    A warning rather than an exception: a length disagreement is intelligence about a
    peer, not a reason to abandon parsing a capture.
    """


class KELengthCheck(NamedTuple):
    """Result of cross-checking a KE payload length against the declared DH group."""

    declared_group: int
    observed_length: int
    candidate_groups: tuple[int, ...]
    consistent: bool
    ambiguous: bool
    message: str | None


def resolve_transform_name(transform_type: TransformType | int, transform_id: int) -> str:
    """Resolve a (transform type, transform ID) pair to its IANA name.

    Total by construction: an unrecognised type or ID yields an ``UNKNOWN_*`` marker
    rather than raising, because a parser must never abort on a value it has not seen.
    """
    if isinstance(transform_type, TransformType):
        type_name: str | None = transform_type.value
    else:
        type_name = TRANSFORM_TYPES.get(transform_type)
    if type_name is None:
        return f"UNKNOWN_TRANSFORM_TYPE_{transform_type}_{transform_id}"

    if type_name == TransformType.DH.value:
        return dh_group_name(transform_id)

    table = _ALGORITHM_TABLES.get(type_name, {})
    return table.get(transform_id, f"UNKNOWN_{type_name}_{transform_id}")


def dh_group_name(group: int) -> str:
    """Human-readable name for a DH group, or an ``UNKNOWN_DH_*`` marker."""
    entry = DH_GROUPS.get(group)
    return entry[0] if entry else f"UNKNOWN_DH_{group}"


def dh_group_bits(group: int) -> int | None:
    """Strength of a DH group in bits, or ``None`` if the group is unknown."""
    entry = DH_GROUPS.get(group)
    return entry[1] if entry else None


def groups_for_ke_length(length: int) -> tuple[int, ...]:
    """DH groups that produce a KE public value of ``length`` bytes.

    Returns an empty tuple for an unrecognised length, and more than one group where
    lengths collide (96 bytes is both group 1 and group 20).
    """
    return KE_LENGTH_TO_GROUP.get(length, ())


def check_ke_length(declared_group: int, observed_length: int) -> KELengthCheck:
    """Cross-check an observed KE payload length against the declared DH group.

    The transform's declared group always wins; this only reports whether the observed
    length corroborates it. Any doubt is raised as a :class:`KELengthWarning`, never as
    an exception, and both values are retained on the result either way.
    """
    candidates = groups_for_ke_length(observed_length)

    if not candidates:
        message = (
            f"KE payload length {observed_length} bytes is unrecognised; cannot corroborate "
            f"declared DH group {declared_group} ({dh_group_name(declared_group)})"
        )
        warnings.warn(message, KELengthWarning, stacklevel=2)
        return KELengthCheck(declared_group, observed_length, (), False, False, message)

    if declared_group not in candidates:
        message = (
            f"KE payload length mismatch: {observed_length} bytes implies DH group(s) "
            f"{list(candidates)}, but the transform declared group {declared_group} "
            f"({dh_group_name(declared_group)}); keeping the declared group"
        )
        warnings.warn(message, KELengthWarning, stacklevel=2)
        return KELengthCheck(declared_group, observed_length, candidates, False, False, message)

    if len(candidates) > 1:
        message = (
            f"KE payload length {observed_length} bytes is ambiguous between DH groups "
            f"{list(candidates)}; using the declared group {declared_group} "
            f"({dh_group_name(declared_group)})"
        )
        warnings.warn(message, KELengthWarning, stacklevel=2)
        return KELengthCheck(declared_group, observed_length, candidates, True, True, message)

    return KELengthCheck(declared_group, observed_length, candidates, True, False, None)


def notify_type_name(notify_type: int) -> str:
    """Resolve an IKEv2 notify message type to its IANA name.

    Total by construction: an unrecognised type yields ``UNKNOWN_NOTIFY_<n>`` rather
    than raising. Types 1-16383 are errors, 16384 and above are status notifications;
    a capture full of unknown error types is itself a finding, so they are kept.
    """
    return NOTIFY_TYPES.get(notify_type, f"UNKNOWN_NOTIFY_{notify_type}")


def notify_protocol_name(protocol_id: int) -> str:
    """Resolve the protocol ID in a notify payload.

    Zero is legal and means the notification is not specific to a single SA
    (RFC 7296 section 3.10), so it is named rather than treated as absent.
    """
    if protocol_id == 0:
        return "NONE"
    return PROTOCOL_IDS.get(protocol_id, f"UNKNOWN_PROTOCOL_{protocol_id}")


# ---------------------------------------------------------------------------
# IKEv1 (RFC 2407/2408/2409)
#
# IKEv1 encodes a phase 1 proposal entirely as SA attributes, so none of the IKEv2
# transform-type tables apply. The attribute classes and their value spaces are
# separate registries and are kept separate here — resolving an IKEv1 encryption value
# through the IKEv2 table would report 3DES-CBC (value 5) as ENCR_DES_IV32.
# ---------------------------------------------------------------------------

IKEV1_DOI: Final[dict[int, str]] = {0: "ISAKMP", 1: "IPSEC"}

IKEV1_ATTRIBUTE_CLASSES: Final[dict[int, str]] = {
    1: "Encryption Algorithm",
    2: "Hash Algorithm",
    3: "Authentication Method",
    4: "Group Description",
    5: "Group Type",
    6: "Group Prime/Irreducible Polynomial",
    7: "Group Generator One",
    8: "Group Generator Two",
    9: "Group Curve A",
    10: "Group Curve B",
    11: "Life Type",
    12: "Life Duration",
    13: "PRF",
    14: "Key Length",
    15: "Field Size",
    16: "Group Order",
}

IKEV1_ATTR_ENCRYPTION: Final = 1
IKEV1_ATTR_HASH: Final = 2
IKEV1_ATTR_AUTH_METHOD: Final = 3
IKEV1_ATTR_GROUP: Final = 4
IKEV1_ATTR_LIFE_TYPE: Final = 11
IKEV1_ATTR_LIFE_DURATION: Final = 12
IKEV1_ATTR_KEY_LENGTH: Final = 14

IKEV1_ENCRYPTION_ALGORITHMS: Final[dict[int, str]] = {
    1: "DES_CBC",
    2: "IDEA_CBC",
    3: "BLOWFISH_CBC",
    4: "RC5_R16_B64_CBC",
    5: "3DES_CBC",
    6: "CAST_CBC",
    7: "AES_CBC",
    8: "CAMELLIA_CBC",
}

IKEV1_HASH_ALGORITHMS: Final[dict[int, str]] = {
    1: "MD5",
    2: "SHA",
    3: "TIGER",
    4: "SHA2_256",
    5: "SHA2_384",
    6: "SHA2_512",
}

# Value 1 is the one that matters. Aggressive Mode sends the identity and the hash
# before a shared key exists, so with PSK the hash is offline-crackable by anyone who
# captured the exchange. That combination is the highest-value finding this tool makes.
IKEV1_AUTH_METHOD_PSK: Final = 1

IKEV1_AUTH_METHODS: Final[dict[int, str]] = {
    1: "PRE_SHARED_KEY",
    2: "DSS_SIGNATURES",
    3: "RSA_SIGNATURES",
    4: "ENCRYPTION_WITH_RSA",
    5: "REVISED_ENCRYPTION_WITH_RSA",
    64221: "HYBRID_INIT_RSA",
    64222: "HYBRID_RESP_RSA",
    65001: "XAUTH_INIT_PRESHARED",
    65002: "XAUTH_RESP_PRESHARED",
    65003: "XAUTH_INIT_RSA",
    65004: "XAUTH_RESP_RSA",
}

IKEV1_LIFE_TYPES: Final[dict[int, str]] = {1: "seconds", 2: "kilobytes"}

_IKEV1_VALUE_TABLES: Final[dict[int, dict[int, str]]] = {
    IKEV1_ATTR_ENCRYPTION: IKEV1_ENCRYPTION_ALGORITHMS,
    IKEV1_ATTR_HASH: IKEV1_HASH_ALGORITHMS,
    IKEV1_ATTR_AUTH_METHOD: IKEV1_AUTH_METHODS,
    IKEV1_ATTR_LIFE_TYPE: IKEV1_LIFE_TYPES,
}


def ikev1_doi_name(doi: int) -> str:
    return IKEV1_DOI.get(doi, f"UNKNOWN_DOI_{doi}")


def ikev1_attribute_class_name(attr_type: int) -> str:
    """Name an IKEv1 SA attribute class, total by construction."""
    return IKEV1_ATTRIBUTE_CLASSES.get(attr_type, f"UNKNOWN_ATTRIBUTE_{attr_type}")


def ikev1_attribute_value_name(attr_type: int, value: int) -> str | None:
    """Name an IKEv1 attribute's value within its own class.

    Returns ``None`` for classes whose values are numbers rather than enumerations
    (key length, lifetime duration) — inventing a name for those would be a fiction.
    The DH group is deliberately routed through :func:`dh_group_name`, which is shared
    with IKEv2 because the group registry genuinely is shared.
    """
    if attr_type == IKEV1_ATTR_GROUP:
        return dh_group_name(value)
    table = _IKEV1_VALUE_TABLES.get(attr_type)
    if table is None:
        return None
    return table.get(value, f"UNKNOWN_{ikev1_attribute_class_name(attr_type)}_{value}")
