"""Libreswan ``ipsec.conf`` generator.

Libreswan shares strongSwan's IKE lineage but not its syntax: proposals live on
``ike=`` and ``esp=`` lines, algorithms use underscore-separated names, and Diffie-Hellman
groups are written ``dh14`` rather than ``modp2048``.

**Syntax-validated, not deployment-tested.** The testbed runs strongSwan only. Adding a
Libreswan container would make this live-testable and is the obvious next step, but
until that exists this generator's output has never been loaded onto Libreswan and the
emitted file says so in its header.
"""

from __future__ import annotations

from typing import Final

from ipsec_sentinel.remediate.generators.base import (
    DeploymentStatus,
    status_banner,
    translate,
)
from testbed.orchestrate.config_gen import TunnelConfig, is_aead

VENDOR: Final = "Libreswan"
FILENAME: Final = "ipsec.conf"
STATUS: Final = DeploymentStatus.SYNTAX_VALIDATED

ENCRYPTION: Final[dict[str, str]] = {
    "aes256gcm16": "aes_gcm256",
    "aes128gcm16": "aes_gcm128",
    "aes256": "aes256",
    "aes128": "aes128",
    "3des": "3des",
}

INTEGRITY: Final[dict[str, str]] = {
    "sha256": "sha2_256",
    "sha384": "sha2_384",
    "sha1": "sha1",
    "md5": "md5",
}

DH_GROUP: Final[dict[str, str]] = {
    "modp1024": "dh2",
    "modp1536": "dh5",
    "modp2048": "dh14",
    "ecp256": "dh19",
    "ecp384": "dh20",
    "curve25519": "dh31",
}


# Libreswan implements the whole canonical space, so it has no declared gaps.
UNSUPPORTED: Final[dict[str, str]] = {}


def proposal(config: TunnelConfig) -> str:
    """The ``ike=`` proposal: ``encryption-integrity;dhgroup``.

    AEAD ciphers carry integrity internally, so the integrity term is omitted — including
    it is not merely redundant, Libreswan rejects the combination.
    """
    encryption = translate(ENCRYPTION, config.encryption, "encryption", VENDOR)
    group = translate(DH_GROUP, config.dh_group, "DH group", VENDOR)
    if is_aead(config.encryption):
        return f"{encryption};{group}"
    integrity = translate(INTEGRITY, config.integrity or "", "integrity", VENDOR)
    return f"{encryption}-{integrity};{group}"


def esp_proposal(config: TunnelConfig) -> str:
    """The ``esp=`` proposal. Carries a DH group only when PFS is on."""
    encryption = translate(ENCRYPTION, config.encryption, "encryption", VENDOR)
    parts = encryption
    if not is_aead(config.encryption):
        integrity = translate(INTEGRITY, config.integrity or "", "integrity", VENDOR)
        parts = f"{encryption}-{integrity}"
    child = config.effective_child_dh_group
    if child is None:
        return parts
    return f"{parts};{translate(DH_GROUP, child, 'DH group', VENDOR)}"


def render(config: TunnelConfig, role: str = "left") -> str:
    """Render a complete ``ipsec.conf`` for one end.

    Addresses and subnets are emitted as placeholders. The tool observes a tunnel's
    endpoints on the wire but not its routing intent, and inventing a subnet an
    operator did not ask for is how a remediation takes down traffic it was never
    meant to touch.

    No ``secrets`` are emitted. Libreswan reads them from ``ipsec.secrets``, and this
    tool stores no credentials anywhere.
    """
    if role not in ("left", "right"):
        raise ValueError(f"role must be 'left' or 'right', got {role!r}")

    # The two documents must mirror each other. Libreswan's `left` is conventionally
    # "this side", so the subnets swap between the two files — a change package whose
    # two halves are byte-identical has not described a site-to-site tunnel, it has
    # described one end twice.
    if role == "left":
        local_subnet, peer_subnet = "<LOCAL_SUBNET>", "<PEER_SUBNET>"
        peer_address = "<PEER_ADDRESS>"
    else:
        local_subnet, peer_subnet = "<PEER_SUBNET>", "<LOCAL_SUBNET>"
        peer_address = "<LOCAL_ADDRESS>"
    keyexchange = "ikev2" if config.ike_version == "ikev2" else "ikev1"
    pfs = "yes" if config.pfs else "no"

    return "\n".join(
        [
            status_banner(VENDOR, STATUS),
            "",
            "config setup",
            "    protostack=netkey",
            "",
            "conn sentinel-remediated",
            f"    keyexchange={keyexchange}",
            f"    type={config.mode}",
            f"    ike={proposal(config)}",
            f"    esp={esp_proposal(config)}",
            f"    pfs={pfs}",
            f"    ikelifetime={config.ike_lifetime_s}s",
            f"    salifetime={config.child_lifetime_s}s",
            "    left=%defaultroute",
            f"    leftsubnet={local_subnet}",
            f"    right={peer_address}",
            f"    rightsubnet={peer_subnet}",
            "    authby=secret",
            "    auto=start",
            "    # Credentials live in ipsec.secrets and are never written by this tool.",
            "",
        ]
    )
