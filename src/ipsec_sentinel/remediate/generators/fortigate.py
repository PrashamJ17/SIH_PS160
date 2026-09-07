"""FortiGate ``config vpn ipsec phase1-interface`` generator.

FortiOS expresses a proposal as a single space-separated list of ``cipher-hash`` pairs
and names Diffie-Hellman groups as bare numbers on a ``set dhgrp`` line.

**Syntax-validated, not deployment-tested.** No FortiGate exists in this testbed.
"""

from __future__ import annotations

from typing import Final

from ipsec_sentinel.remediate.config import TunnelConfig, is_aead
from ipsec_sentinel.remediate.generators.base import (
    DeploymentStatus,
    status_banner,
    translate,
)

VENDOR: Final = "FortiGate"
FILENAME: Final = "fortigate-ipsec.cfg"
STATUS: Final = DeploymentStatus.SYNTAX_VALIDATED
COMMENT: Final = "#"

ENCRYPTION: Final[dict[str, str]] = {
    "aes256gcm16": "aes256gcm",
    "aes128gcm16": "aes128gcm",
    "aes256": "aes256",
    "aes128": "aes128",
    "3des": "3des",
}

INTEGRITY: Final[dict[str, str]] = {
    "sha256": "sha256",
    "sha384": "sha384",
    "sha1": "sha1",
    "md5": "md5",
}

# FortiOS dhgrp numbers. 31 is Curve25519, supported from FortiOS 6.2.
DH_GROUP: Final[dict[str, str]] = {
    "modp1024": "2",
    "modp1536": "5",
    "modp2048": "14",
    "ecp256": "19",
    "ecp384": "20",
    "curve25519": "31",
}

UNSUPPORTED: Final[dict[str, str]] = {}


def proposal(config: TunnelConfig) -> str:
    """FortiOS proposal: ``cipher-hash`` pairs. AEAD ciphers carry no hash term."""
    encryption = translate(ENCRYPTION, config.encryption, "encryption", VENDOR)
    if is_aead(config.encryption):
        return encryption
    integrity = translate(INTEGRITY, config.integrity or "", "integrity", VENDOR)
    return f"{encryption}-{integrity}"


def render(config: TunnelConfig, role: str = "left") -> str:
    if role not in ("left", "right"):
        raise ValueError(f"role must be 'left' or 'right', got {role!r}")

    group = translate(DH_GROUP, config.dh_group, "DH group", VENDOR)
    child_group = translate(
        DH_GROUP, config.effective_child_dh_group or config.dh_group, "DH group", VENDOR
    )
    peer = "<PEER_ADDRESS>" if role == "left" else "<LOCAL_ADDRESS>"
    version = "2" if config.ike_version == "ikev2" else "1"

    phase2 = [
        "config vpn ipsec phase2-interface",
        '    edit "SENTINEL-P2"',
        '        set phase1name "SENTINEL-P1"',
        f"        set proposal {proposal(config)}",
        f"        set keylifeseconds {config.child_lifetime_s}",
    ]
    phase2.append(f"        set dhgrp {child_group}" if config.pfs else "        set pfs disable")
    phase2 += ["    next", "end"]

    return "\n".join(
        [
            status_banner(VENDOR, STATUS, COMMENT),
            COMMENT,
            "config vpn ipsec phase1-interface",
            '    edit "SENTINEL-P1"',
            "        set type static",
            f"        set remote-gw {peer}",
            f"        set ike-version {version}",
            f"        set proposal {proposal(config)}",
            f"        set dhgrp {group}",
            f"        set keylife {config.ike_lifetime_s}",
            "        set psksecret <CONFIGURE-OUT-OF-BAND>",
            "    next",
            "end",
            COMMENT,
            *phase2,
            COMMENT,
            f"{COMMENT} The pre-shared key is a placeholder. This tool stores no",
            f"{COMMENT} credentials and emits none.",
            "",
        ]
    )
