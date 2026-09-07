"""Cisco IOS / IOS-XE ``crypto ikev2`` generator.

Cisco splits what strongSwan writes as one proposal string across several named objects:
a ``crypto ikev2 proposal`` for the IKE SA, an ``ipsec transform-set`` for ESP, and a
profile binding them. That structure is why a naive one-line translation produces
something a device rejects.

**Syntax-validated, not deployment-tested.** No Cisco device exists in this testbed. The
grammar below follows the published IOS-XE configuration guide and the generated file
says, in its own header, that it has never been loaded.
"""

from __future__ import annotations

from typing import Final

from ipsec_sentinel.remediate.config import TunnelConfig, is_aead
from ipsec_sentinel.remediate.generators.base import (
    DeploymentStatus,
    status_banner,
    translate,
)

VENDOR: Final = "Cisco IOS-XE"
FILENAME: Final = "cisco-ikev2.cfg"
STATUS: Final = DeploymentStatus.SYNTAX_VALIDATED
COMMENT: Final = "!"

ENCRYPTION: Final[dict[str, str]] = {
    "aes256gcm16": "aes-gcm-256",
    "aes128gcm16": "aes-gcm-128",
    "aes256": "aes-cbc-256",
    "aes128": "aes-cbc-128",
    "3des": "3des",
}

INTEGRITY: Final[dict[str, str]] = {
    "sha256": "sha256",
    "sha384": "sha384",
    "sha1": "sha1",
    "md5": "md5",
}

PRF: Final[dict[str, str]] = {
    "prfsha256": "sha256",
    "prfsha384": "sha384",
    "prfsha1": "sha1",
    "prfmd5": "md5",
}

# IOS-XE group numbers. Curve25519 (IANA group 31) is deliberately absent: IOS-XE
# does not implement it, and its group 21 is 521-bit ECP — a different curve.
# Mapping one onto the other emits a configuration that loads cleanly and
# negotiates something the assessment never asked for.
DH_GROUP: Final[dict[str, str]] = {
    "modp1024": "2",
    "modp1536": "5",
    "modp2048": "14",
    "ecp256": "19",
    "ecp384": "20",
}

# Canonical algorithms this vendor genuinely cannot express, and what to use
# instead. Declared so a coverage test can tell a deliberate gap from an
# unfinished table.
UNSUPPORTED: Final[dict[str, str]] = {
    "curve25519": "ecp384 (group 20), which IOS-XE does implement",
}

# IOS transform-set names for ESP.
ESP_ENCRYPTION: Final[dict[str, str]] = {
    "aes256gcm16": "esp-gcm 256",
    "aes128gcm16": "esp-gcm 128",
    "aes256": "esp-aes 256",
    "aes128": "esp-aes 128",
    "3des": "esp-3des",
}

ESP_INTEGRITY: Final[dict[str, str]] = {
    "sha256": "esp-sha256-hmac",
    "sha384": "esp-sha384-hmac",
    "sha1": "esp-sha-hmac",
    "md5": "esp-md5-hmac",
}


def render(config: TunnelConfig, role: str = "left") -> str:
    """Render an IOS-XE configuration fragment for one end."""
    if role not in ("left", "right"):
        raise ValueError(f"role must be 'left' or 'right', got {role!r}")

    encryption = translate(ENCRYPTION, config.encryption, "encryption", VENDOR)
    prf = translate(PRF, config.prf, "PRF", VENDOR)
    group = translate(
        DH_GROUP,
        config.dh_group,
        "DH group",
        VENDOR,
        UNSUPPORTED.get(config.dh_group),
    )
    esp_encryption = translate(ESP_ENCRYPTION, config.encryption, "ESP encryption", VENDOR)

    proposal = ["crypto ikev2 proposal SENTINEL-PROPOSAL", f" encryption {encryption}"]
    if not is_aead(config.encryption):
        integrity = translate(INTEGRITY, config.integrity or "", "integrity", VENDOR)
        proposal.append(f" integrity {integrity}")
    proposal.append(f" prf {prf}")
    proposal.append(f" group {group}")

    transform = f"crypto ipsec transform-set SENTINEL-TS {esp_encryption}"
    if not is_aead(config.encryption):
        transform += " " + translate(ESP_INTEGRITY, config.integrity or "", "ESP integrity", VENDOR)

    peer = "<PEER_ADDRESS>" if role == "left" else "<LOCAL_ADDRESS>"
    pfs_line = (
        " set pfs group"
        + translate(
            DH_GROUP,
            config.effective_child_dh_group or config.dh_group,
            "DH group",
            VENDOR,
            UNSUPPORTED.get(config.effective_child_dh_group or config.dh_group),
        )
        if config.pfs
        else " ! perfect forward secrecy is NOT enabled on this profile"
    )

    return "\n".join(
        [
            status_banner(VENDOR, STATUS, COMMENT),
            COMMENT,
            *proposal,
            COMMENT,
            "crypto ikev2 policy SENTINEL-POLICY",
            " proposal SENTINEL-PROPOSAL",
            COMMENT,
            transform,
            f" mode {config.mode}",
            COMMENT,
            "crypto ikev2 profile SENTINEL-PROFILE",
            f" match identity remote address {peer}",
            " authentication remote pre-share",
            " authentication local pre-share",
            f" lifetime {config.ike_lifetime_s}",
            COMMENT,
            "crypto ipsec profile SENTINEL-IPSEC",
            " set transform-set SENTINEL-TS",
            " set ikev2-profile SENTINEL-PROFILE",
            f" set security-association lifetime seconds {config.child_lifetime_s}",
            pfs_line,
            COMMENT,
            f"{COMMENT} Keys are configured separately with `crypto ikev2 keyring`.",
            f"{COMMENT} This tool stores and emits no credentials.",
            "",
        ]
    )
