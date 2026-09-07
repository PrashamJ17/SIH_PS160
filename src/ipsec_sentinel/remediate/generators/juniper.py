"""Juniper SRX ``security ike`` / ``security ipsec`` generator.

Junos names algorithms in full — ``aes-256-gcm``, ``hmac-sha-256-128``, ``group19`` — and
splits the proposal across an IKE proposal, an IKE policy, an IPsec proposal and an
IPsec policy. Emitting set-format commands rather than the curly-brace form, because
that is what an operator pastes into a session.

**Syntax-validated, not deployment-tested.** No SRX exists in this testbed.
"""

from __future__ import annotations

from typing import Final

from ipsec_sentinel.remediate.config import TunnelConfig, is_aead
from ipsec_sentinel.remediate.generators.base import (
    DeploymentStatus,
    status_banner,
    translate,
)

VENDOR: Final = "Juniper SRX"
FILENAME: Final = "juniper-srx.set"
STATUS: Final = DeploymentStatus.SYNTAX_VALIDATED
COMMENT: Final = "#"

ENCRYPTION: Final[dict[str, str]] = {
    "aes256gcm16": "aes-256-gcm",
    "aes128gcm16": "aes-128-gcm",
    "aes256": "aes-256-cbc",
    "aes128": "aes-128-cbc",
    "3des": "3des-cbc",
}

INTEGRITY: Final[dict[str, str]] = {
    "sha256": "hmac-sha-256-128",
    "sha384": "hmac-sha-384-192",
    "sha1": "hmac-sha1-96",
    "md5": "hmac-md5-96",
}

DH_GROUP: Final[dict[str, str]] = {
    "modp1024": "group2",
    "modp1536": "group5",
    "modp2048": "group14",
    "ecp256": "group19",
    "ecp384": "group20",
}

# Junos has no Curve25519 group in the IKE proposal hierarchy.
UNSUPPORTED: Final[dict[str, str]] = {
    "curve25519": "ecp384 (group20), which Junos does implement",
}


def render(config: TunnelConfig, role: str = "left") -> str:
    if role not in ("left", "right"):
        raise ValueError(f"role must be 'left' or 'right', got {role!r}")

    encryption = translate(ENCRYPTION, config.encryption, "encryption", VENDOR)
    group = translate(
        DH_GROUP, config.dh_group, "DH group", VENDOR, UNSUPPORTED.get(config.dh_group)
    )
    peer = "<PEER_ADDRESS>" if role == "left" else "<LOCAL_ADDRESS>"
    version = "v2-only" if config.ike_version == "ikev2" else "v1-only"

    ike = [
        "set security ike proposal SENTINEL-IKE authentication-method pre-shared-keys",
        f"set security ike proposal SENTINEL-IKE dh-group {group}",
        f"set security ike proposal SENTINEL-IKE encryption-algorithm {encryption}",
        f"set security ike proposal SENTINEL-IKE lifetime-seconds {config.ike_lifetime_s}",
    ]
    ipsec = [
        "set security ipsec proposal SENTINEL-ESP protocol esp",
        f"set security ipsec proposal SENTINEL-ESP encryption-algorithm {encryption}",
        f"set security ipsec proposal SENTINEL-ESP lifetime-seconds {config.child_lifetime_s}",
    ]
    if not is_aead(config.encryption):
        integrity = translate(INTEGRITY, config.integrity or "", "integrity", VENDOR)
        ike.insert(
            3,
            f"set security ike proposal SENTINEL-IKE authentication-algorithm {integrity}",
        )
        ipsec.insert(
            2,
            f"set security ipsec proposal SENTINEL-ESP authentication-algorithm {integrity}",
        )

    if config.pfs:
        child = config.effective_child_dh_group or config.dh_group
        child_group = translate(DH_GROUP, child, "DH group", VENDOR, UNSUPPORTED.get(child))
        pfs = (
            "set security ipsec policy SENTINEL-IPSEC-POL "
            f"perfect-forward-secrecy keys {child_group}"
        )
    else:
        pfs = f"{COMMENT} perfect forward secrecy is NOT configured on this policy"

    return "\n".join(
        [
            status_banner(VENDOR, STATUS, COMMENT),
            COMMENT,
            *ike,
            "set security ike policy SENTINEL-IKE-POL proposals SENTINEL-IKE",
            "set security ike gateway SENTINEL-GW ike-policy SENTINEL-IKE-POL",
            f"set security ike gateway SENTINEL-GW address {peer}",
            f"set security ike gateway SENTINEL-GW version {version}",
            COMMENT,
            *ipsec,
            "set security ipsec policy SENTINEL-IPSEC-POL proposals SENTINEL-ESP",
            pfs,
            "set security ipsec vpn SENTINEL-VPN ike gateway SENTINEL-GW",
            "set security ipsec vpn SENTINEL-VPN ike ipsec-policy SENTINEL-IPSEC-POL",
            COMMENT,
            f"{COMMENT} The pre-shared key is configured separately. This tool stores",
            f"{COMMENT} and emits no credentials.",
            "",
        ]
    )
