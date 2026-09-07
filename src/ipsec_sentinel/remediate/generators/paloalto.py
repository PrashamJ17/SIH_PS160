"""Palo Alto PAN-OS IKE and IPsec crypto profile generator.

PAN-OS uses set-format commands under ``network ike``, naming algorithms in full and
Diffie-Hellman groups as ``group19``.

**Syntax-validated, not deployment-tested.** No PAN-OS device exists in this testbed.
"""

from __future__ import annotations

from typing import Final

from ipsec_sentinel.remediate.config import TunnelConfig, is_aead
from ipsec_sentinel.remediate.generators.base import (
    DeploymentStatus,
    status_banner,
    translate,
)

VENDOR: Final = "Palo Alto PAN-OS"
FILENAME: Final = "paloalto-ipsec.set"
STATUS: Final = DeploymentStatus.SYNTAX_VALIDATED
COMMENT: Final = "#"

ENCRYPTION: Final[dict[str, str]] = {
    "aes256gcm16": "aes-256-gcm",
    "aes128gcm16": "aes-128-gcm",
    "aes256": "aes-256-cbc",
    "aes128": "aes-128-cbc",
    "3des": "3des",
}

INTEGRITY: Final[dict[str, str]] = {
    "sha256": "sha256",
    "sha384": "sha384",
    "sha1": "sha1",
    "md5": "md5",
}

DH_GROUP: Final[dict[str, str]] = {
    "modp1024": "group2",
    "modp1536": "group5",
    "modp2048": "group14",
    "ecp256": "group19",
    "ecp384": "group20",
}

# PAN-OS exposes groups 1-21 in its crypto profiles; Curve25519 is not among them.
UNSUPPORTED: Final[dict[str, str]] = {
    "curve25519": "ecp384 (group20), which PAN-OS does implement",
}


def render(config: TunnelConfig, role: str = "left") -> str:
    if role not in ("left", "right"):
        raise ValueError(f"role must be 'left' or 'right', got {role!r}")

    encryption = translate(ENCRYPTION, config.encryption, "encryption", VENDOR)
    group = translate(
        DH_GROUP, config.dh_group, "DH group", VENDOR, UNSUPPORTED.get(config.dh_group)
    )
    peer = "<PEER_ADDRESS>" if role == "left" else "<LOCAL_ADDRESS>"
    version = "ikev2" if config.ike_version == "ikev2" else "ikev1"

    ike = "set network ike crypto-profiles ike-crypto-profiles SENTINEL-IKE"
    esp = "set network ike crypto-profiles ipsec-crypto-profiles SENTINEL-ESP"

    ike_lines = [
        f"{ike} dh-group {group}",
        f"{ike} encryption {encryption}",
        f"{ike} lifetime seconds {config.ike_lifetime_s}",
    ]
    esp_lines = [
        f"{esp} esp encryption {encryption}",
        f"{esp} lifetime seconds {config.child_lifetime_s}",
    ]
    if not is_aead(config.encryption):
        integrity = translate(INTEGRITY, config.integrity or "", "integrity", VENDOR)
        ike_lines.insert(2, f"{ike} hash {integrity}")
        esp_lines.insert(1, f"{esp} esp authentication {integrity}")

    if config.pfs:
        child = translate(
            DH_GROUP,
            config.effective_child_dh_group or config.dh_group,
            "DH group",
            VENDOR,
            UNSUPPORTED.get(config.effective_child_dh_group or config.dh_group),
        )
        pfs_line = (
            f"set network ike crypto-profiles ipsec-crypto-profiles SENTINEL-ESP dh-group {child}"
        )
    else:
        pfs_line = f"{COMMENT} perfect forward secrecy is NOT configured on this profile"

    return "\n".join(
        [
            status_banner(VENDOR, STATUS, COMMENT),
            COMMENT,
            *ike_lines,
            COMMENT,
            *esp_lines,
            pfs_line,
            COMMENT,
            f"set network ike gateway SENTINEL-GW protocol version {version}",
            f"set network ike gateway SENTINEL-GW peer-address ip {peer}",
            "set network ike gateway SENTINEL-GW protocol ikev2 ike-crypto-profile SENTINEL-IKE",
            COMMENT,
            f"{COMMENT} The pre-shared key is configured separately. This tool stores",
            f"{COMMENT} and emits no credentials.",
            "",
        ]
    )
