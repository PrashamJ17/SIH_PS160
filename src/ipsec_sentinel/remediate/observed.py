"""Reconstruct a configuration from what was observed on the wire.

The remediation lane hardens a :class:`TunnelConfig` — the same structure the testbed
generates from. Everything upstream of it produces an :class:`IKEExchange`, which is what
a capture yields. This module is the join, and it is the piece that lets a change package
be produced from a real capture rather than only from a config the operator already had.

The mapping is keyed on **transform IDs**, not names. A name is a rendering choice that
either side can change; the IANA number is the wire's own identity for the algorithm and
is what the two ends actually agreed on.

Anything that cannot be mapped returns ``None`` with a reason rather than a partial
config. A configuration built from a proposal that was only half understood would be
hardened, rendered, and handed to an operator to apply — and the parts that were guessed
would be indistinguishable from the parts that were read.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from ipsec_sentinel.models import IKEExchange, Proposal, TransformType
from ipsec_sentinel.remediate.config import TunnelConfig, is_aead

# IKEv1 and IKEv2 number their algorithms in **separate registries**, and the overlap is
# actively misleading: value 7 is CAST in IKEv2 and AES in IKEv1, value 5 is 3DES in
# IKEv1 and DES-IV32 in IKEv2. Reading an IKEv1 proposal through the IKEv2 table does not
# fail — it silently yields a different, plausible algorithm, and the change package
# built from it would correct a configuration the device does not have. The parser keeps
# the two registries apart for the same reason; so does this module.
ENCRYPTION_BY_ID: Final[dict[int, str]] = {
    3: "3des",
    11: "null",
    12: "aes",  # key length decides aes128 / aes256
    # RFC 8221 permits GCM with an 8-, 12- or 16-octet ICV, and all three are deployed.
    # Only 16 was mapped at first, so a device reporting either of the others failed
    # reconstruction with "no configuration equivalent" — found by asserting the
    # device-state mapping and the wire mapping agree.
    18: "aes_gcm8",
    19: "aes_gcm12",
    20: "aes_gcm16",
}
AES_CBC_BY_KEY_LENGTH: Final[dict[int, str]] = {128: "aes128", 192: "aes192", 256: "aes256"}
AES_GCM_BY_KEY_LENGTH: Final[dict[str, dict[int, str]]] = {
    "aes_gcm8": {128: "aes128gcm8", 192: "aes192gcm8", 256: "aes256gcm8"},
    "aes_gcm12": {128: "aes128gcm12", 192: "aes192gcm12", 256: "aes256gcm12"},
    "aes_gcm16": {128: "aes128gcm16", 192: "aes192gcm16", 256: "aes256gcm16"},
}

# IKEv1 phase 1, RFC 2409 appendix A. Encryption is attribute class 1.
IKEV1_ENCRYPTION_BY_ID: Final[dict[int, str]] = {
    1: "des",
    2: "idea",
    3: "blowfish",
    4: "rc5",
    5: "3des",
    6: "cast",
    7: "aes",  # key length decides aes128 / aes256, as in IKEv2
    8: "camellia",
}

# IKEv1 has one hash algorithm serving as both integrity and PRF (attribute class 2),
# which is why the reconstructed PRF follows the hash rather than being assumed.
IKEV1_HASH_BY_ID: Final[dict[int, tuple[str, str]]] = {
    1: ("md5", "prfmd5"),
    2: ("sha1", "prfsha1"),
    4: ("sha256", "prfsha256"),
    5: ("sha384", "prfsha384"),
    6: ("sha512", "prfsha512"),
}

INTEGRITY_BY_ID: Final[dict[int, str]] = {
    1: "md5",
    2: "sha1",
    12: "sha256",
    13: "sha384",
    14: "sha512",
}
PRF_BY_ID: Final[dict[int, str]] = {
    1: "prfmd5",
    2: "prfsha1",
    5: "prfsha256",
    6: "prfsha384",
    7: "prfsha512",
}
DH_BY_ID: Final[dict[int, str]] = {
    1: "modp768",
    2: "modp1024",
    5: "modp1536",
    14: "modp2048",
    15: "modp3072",
    16: "modp4096",
    19: "ecp256",
    20: "ecp384",
    21: "ecp521",
    31: "curve25519",
}

# Lifetimes are local policy and are not on the wire for IKEv2 (RFC 7296 removed them
# from the SA payload). Reconstruction uses the testbed's own defaults so the rules that
# read them are not handed a fabricated number that looks observed.
ASSUMED_IKE_LIFETIME_S: Final = 14400
ASSUMED_CHILD_LIFETIME_S: Final = 3600


@dataclass(frozen=True)
class Reconstruction:
    """A configuration recovered from a negotiation, and what had to be assumed."""

    config: TunnelConfig | None
    assumptions: tuple[str, ...] = ()
    reason: str | None = None
    """Why no configuration could be built, when ``config`` is ``None``."""

    @property
    def ok(self) -> bool:
        return self.config is not None


def _encryption(
    transform_id: int, key_length: int | None, *, ikev1: bool
) -> tuple[str | None, str | None]:
    table = IKEV1_ENCRYPTION_BY_ID if ikev1 else ENCRYPTION_BY_ID
    name = table.get(transform_id)
    if name is None:
        version = "IKEv1" if ikev1 else "IKEv2"
        return None, (
            f"{version} encryption transform {transform_id} has no configuration equivalent"
        )
    if name == "aes":
        if key_length is None:
            return None, "AES was negotiated without a key length attribute"
        resolved = AES_CBC_BY_KEY_LENGTH.get(key_length)
        if resolved is None:
            return None, f"no configuration name for {key_length}-bit AES-CBC"
        return resolved, None
    if name.startswith("aes_gcm"):
        if key_length is None:
            return None, "AES-GCM was negotiated without a key length attribute"
        resolved = AES_GCM_BY_KEY_LENGTH[name].get(key_length)
        if resolved is None:
            icv = name.removeprefix("aes_gcm")
            return None, f"no configuration name for {key_length}-bit AES-GCM-{icv}"
        return resolved, None
    return name, None


def config_from_proposal(
    proposal: Proposal,
    *,
    ike_version: str,
    aggressive: bool = False,
    mode: str = "tunnel",
    ip_version: int = 4,
) -> Reconstruction:
    """Recover a configuration from one accepted or offered proposal."""
    by_type: dict[str, tuple[int, int | None]] = {}
    for transform in proposal.transforms:
        if transform.type is not None:
            by_type[transform.type.value] = (transform.id, transform.key_length)

    if TransformType.ENCR.value not in by_type:
        return Reconstruction(None, reason="the proposal carries no encryption transform")
    if TransformType.DH.value not in by_type:
        return Reconstruction(None, reason="the proposal carries no key exchange transform")

    ikev1 = ike_version.lower() in ("ikev1", "1")
    encryption, problem = _encryption(*by_type[TransformType.ENCR.value], ikev1=ikev1)
    if encryption is None:
        return Reconstruction(None, reason=problem)

    dh_id = by_type[TransformType.DH.value][0]
    dh_group = DH_BY_ID.get(dh_id)
    if dh_group is None:
        return Reconstruction(None, reason=f"DH group {dh_id} has no configuration equivalent")

    # Asked of the configuration model rather than guessed from the name. A suffix test
    # for "gcm16" silently excluded GCM-8 and GCM-12, so those were treated as non-AEAD
    # and refused for want of an integrity transform they are not supposed to have.
    aead = is_aead(encryption)
    integrity: str | None = None
    if not aead:
        if TransformType.INTEG.value not in by_type:
            return Reconstruction(
                None,
                reason=(
                    f"{encryption} is not an AEAD cipher and the proposal carries no "
                    f"integrity transform, so the configuration cannot be reconstructed"
                ),
            )
        integ_id = by_type[TransformType.INTEG.value][0]
        integrity = (
            IKEV1_HASH_BY_ID.get(integ_id, (None, None))[0]
            if ikev1
            else INTEGRITY_BY_ID.get(integ_id)
        )
        if integrity is None:
            version = "IKEv1" if ikev1 else "IKEv2"
            return Reconstruction(
                None,
                reason=(
                    f"{version} integrity transform {integ_id} has no configuration equivalent"
                ),
            )

    assumptions: list[str] = []
    prf_entry = by_type.get(TransformType.PRF.value)
    if prf_entry is None and ikev1 and TransformType.INTEG.value in by_type:
        # IKEv1 carries one hash attribute; the parser files it as INTEG.
        prf_entry = by_type[TransformType.INTEG.value]
    if prf_entry is None:
        prf = "prfsha256"
        assumptions.append(
            "no PRF transform was observed; assumed prfsha256, which does not affect the "
            "findings this package addresses"
        )
    elif ikev1:
        # IKEv1 has no separate PRF: the hash algorithm serves both roles (RFC 2409
        # section 5), so the PRF follows the integrity choice rather than being assumed.
        resolved_prf = IKEV1_HASH_BY_ID.get(prf_entry[0], (None, None))[1]
        if resolved_prf is None:
            return Reconstruction(
                None, reason=f"IKEv1 hash {prf_entry[0]} has no configuration equivalent"
            )
        prf = resolved_prf
    else:
        resolved_prf = PRF_BY_ID.get(prf_entry[0])
        if resolved_prf is None:
            return Reconstruction(
                None, reason=f"PRF transform {prf_entry[0]} has no configuration equivalent"
            )
        prf = resolved_prf

    assumptions.append(
        "SA lifetimes are local policy and IKEv2 does not carry them on the wire; the "
        "testbed defaults are used and the lifetime rules should be read from the "
        "operator's configuration instead"
    )
    # PFS and the child group are negotiated in an encrypted exchange, so a passive
    # observer cannot see them. Assumed present rather than absent: assuming absent
    # would make the generator "enable PFS" on every tunnel, including those that
    # already have it, which is a change an operator would rightly refuse.
    assumptions.append(
        "perfect forward secrecy and the child key exchange group are negotiated inside "
        "an encrypted exchange and were not observed; PFS is assumed enabled and the "
        "child group assumed to match the IKE group"
    )

    try:
        config = TunnelConfig(
            ike_version="ikev1" if ikev1 else "ikev2",
            encryption=encryption,
            integrity=integrity,
            prf=prf,
            dh_group=dh_group,
            pfs=True,
            child_dh_group=None,
            mode=mode,  # type: ignore[arg-type]
            ip_version=ip_version,  # type: ignore[arg-type]
            ike_lifetime_s=ASSUMED_IKE_LIFETIME_S,
            child_lifetime_s=ASSUMED_CHILD_LIFETIME_S,
            aggressive=aggressive,
        )
    except ValueError as exc:
        return Reconstruction(None, reason=f"the observed combination is not a valid config: {exc}")
    return Reconstruction(config, tuple(assumptions))


def config_from_exchange(exchange: IKEExchange, mode: str = "tunnel") -> Reconstruction:
    """Recover a configuration from a negotiation.

    Reads the **first offered** proposal, which is the peer's own preference and the one
    a remediation should correct. An accepted proposal reflects what the two ends had in
    common on that occasion; the offer is what this peer is willing to accept generally,
    and that is the thing worth changing.
    """
    if not exchange.proposals_offered:
        return Reconstruction(None, reason="the negotiation carries no proposal to read")
    ip_version = 6 if ":" in exchange.src_ip else 4
    return config_from_proposal(
        exchange.proposals_offered[0],
        ike_version=exchange.version,
        aggressive=exchange.is_aggressive,
        mode=mode,
        ip_version=ip_version,
    )
