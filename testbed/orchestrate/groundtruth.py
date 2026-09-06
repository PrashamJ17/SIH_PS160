"""Read back what was actually negotiated, not what was proposed.

This is the most important correctness step in the dataset pipeline. A label taken
from the config file records an *intent*; peers negotiate, and what they settle on is
not always what was asked for. Training on intent rather than reality produces a
corpus whose labels are quietly wrong, and no amount of downstream care recovers from
that.

So every label comes from two independent observations of reality — the daemon's view
via ``swanctl --list-sas`` and the kernel's via ``ip xfrm state`` — and the manifest
records explicitly whether they matched the intent.

**No key material is ever extracted.** ``ip xfrm state`` prints session keys inline;
the parsers here read the algorithm name and ICV length and discard the key bytes
without ever placing them in a returned object.
"""

from __future__ import annotations

from typing import Any, Final

from pydantic import BaseModel, Field

# Promoted to the product at Step 10.4b: reading a device's own state stopped being a
# harness concern when it became a way to close the passive lane's rekey blind spot.
# Imported rather than duplicated, so the corpus's ground truth and the product's
# collector cannot drift apart — if the parser gains a field, both get it.
from ipsec_sentinel.collect import (
    NAT_T_PORT,
    KernelSA,
    NegotiatedChild,
    NegotiatedIKE,
    parse_list_sas,
    parse_xfrm_state,
)
from testbed.orchestrate.config_gen import TunnelConfig
from testbed.orchestrate.dockerutil import exec_in_container

__all__ = [
    "NAT_T_PORT",
    "KernelSA",
    "NegotiatedChild",
    "NegotiatedIKE",
    "parse_list_sas",
    "parse_xfrm_state",
]


def harvest_swanctl(container: str) -> tuple[NegotiatedIKE, NegotiatedChild | None]:
    """Ask the daemon what it actually negotiated."""
    return parse_list_sas(exec_in_container(container, "swanctl", "--list-sas"))


def harvest_xfrm_state(container: str) -> list[KernelSA]:
    """Ask the kernel which SAs are actually installed."""
    return parse_xfrm_state(exec_in_container(container, "ip", "xfrm", "state"))


class Manifest(BaseModel):
    """Intent and reality side by side, with an explicit verdict on whether they agree.

    Harness-only: the corpus needs it, the product does not. The *parsers* moved to
    ``ipsec_sentinel.collect`` at Step 10.4b because reading a device's own state became
    a product capability; this record of what a sweep cell intended did not.
    """

    capture_id: str
    config_id: str
    intent: dict[str, Any]
    negotiated_ike: NegotiatedIKE | None = None
    negotiated_child: NegotiatedChild | None = None
    kernel_sas: list[KernelSA] = Field(default_factory=list)
    negotiation_matched_intent: bool = False
    mismatches: list[str] = Field(default_factory=list)
    capture_meta: dict[str, Any] = Field(default_factory=dict)


# Map strongSwan config tokens to the names the daemon reports back.
_ENCRYPTION_ALIASES: Final[dict[str, tuple[str, int | None]]] = {
    "aes128gcm16": ("AES_GCM_16", 128),
    "aes192gcm16": ("AES_GCM_16", 192),
    "aes256gcm16": ("AES_GCM_16", 256),
    "aes128": ("AES_CBC", 128),
    "aes192": ("AES_CBC", 192),
    "aes256": ("AES_CBC", 256),
    "3des": ("3DES_CBC", None),
    "des": ("DES_CBC", None),
}
_DH_ALIASES: Final[dict[str, str]] = {
    "modp1024": "MODP_1024",
    "modp1536": "MODP_1536",
    "modp2048": "MODP_2048",
    "modp3072": "MODP_3072",
    "modp4096": "MODP_4096",
    "ecp256": "ECP_256",
    "ecp384": "ECP_384",
    "ecp521": "ECP_521",
    "curve25519": "CURVE_25519",
}


def compare_intent(
    cfg: TunnelConfig, ike: NegotiatedIKE, child: NegotiatedChild | None
) -> list[str]:
    """List the ways reality departed from intent. Empty means they agree."""
    mismatches: list[str] = []
    if not ike.established:
        mismatches.append("IKE SA was not established")
    expected_version = "IKEv1" if cfg.ike_version == "ikev1" else "IKEv2"
    if ike.ike_version is not None and ike.ike_version != expected_version:
        mismatches.append(f"ike_version: intended {expected_version}, negotiated {ike.ike_version}")

    expected_enc, expected_len = _ENCRYPTION_ALIASES.get(cfg.encryption, (None, None))
    if expected_enc is not None and ike.encryption is not None and ike.encryption != expected_enc:
        mismatches.append(f"encryption: intended {expected_enc}, negotiated {ike.encryption}")
    if (
        expected_len is not None
        and ike.encryption_keylen is not None
        and ike.encryption_keylen != expected_len
    ):
        mismatches.append(
            f"key length: intended {expected_len}, negotiated {ike.encryption_keylen}"
        )

    expected_dh = _DH_ALIASES.get(cfg.dh_group)
    if expected_dh is not None and ike.dh_group is not None and ike.dh_group != expected_dh:
        mismatches.append(f"dh_group: intended {expected_dh}, negotiated {ike.dh_group}")

    if child is None:
        mismatches.append("no child SA was installed")
    else:
        if not child.installed:
            mismatches.append("child SA was not installed")
        if child.mode is not None and child.mode != cfg.mode:
            mismatches.append(f"mode: intended {cfg.mode}, negotiated {child.mode}")
    return mismatches


def build_manifest(
    cfg: TunnelConfig,
    swanctl: tuple[NegotiatedIKE, NegotiatedChild | None],
    xfrm: list[KernelSA],
    capture_meta: dict[str, Any] | None = None,
    capture_id: str | None = None,
) -> Manifest:
    """Merge intent and reality into the label manifest.

    ``negotiation_matched_intent`` is the field every downstream consumer must respect:
    a cell where it is False has labels that describe something other than what was
    captured, and training on it would poison the corpus.
    """
    ike, child = swanctl
    mismatches = compare_intent(cfg, ike, child)
    return Manifest(
        capture_id=capture_id or f"run_{cfg.config_id()}",
        config_id=cfg.config_id(),
        intent={
            "ike_version": cfg.ike_version,
            "encryption": cfg.encryption,
            "integrity": cfg.integrity,
            "prf": cfg.prf,
            "dh_group": cfg.dh_group,
            "pfs": cfg.pfs,
            "child_dh_group": cfg.effective_child_dh_group,
            "mode": cfg.mode,
            "ip_version": cfg.ip_version,
            "ike_lifetime_s": cfg.ike_lifetime_s,
            "child_lifetime_s": cfg.child_lifetime_s,
            "aggressive": cfg.aggressive,
        },
        negotiated_ike=ike,
        negotiated_child=child,
        kernel_sas=xfrm,
        negotiation_matched_intent=not mismatches,
        mismatches=mismatches,
        capture_meta=capture_meta or {},
    )
