"""Generate a corrected strongSwan configuration from an assessment.

The output is a document. Nothing here connects to anything: the tool writes the
configuration and a human applies it, which is why the remediation lane imports no
transport that could reach a device.

**The generator hardens rather than replaces.** It carries every setting the operator
already chose — mode, IP version, IKE version, lifetimes — and changes only what a
finding actually names. A remediation that rewrites a working configuration into the
generator's own preferences is not remediation; it is a migration, and it will be
rejected by the person who has to justify the change.

**Both ends are always emitted.** A proposal is a negotiation, so a change applied to
one peer does not degrade the tunnel — it stops it establishing, and the drop arrives at
the next rekey rather than immediately.

The upgrade table is deliberately conservative. 3DES becomes AES-256-GCM rather than
AES-128-CBC, because a remediation an operator has to repeat in two years is a
remediation that will not be done at all; but a configuration already using AES-128 is
left alone unless a baseline demands otherwise, since "not the strongest available" is
not a finding.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from typing import Final

from ipsec_sentinel.remediate.models import (
    BlastRadius,
    ChangePackage,
    ChangeRisk,
    ChangeStep,
    ConfigRole,
    DeviceConfig,
)
from testbed.orchestrate.config_gen import TunnelConfig, render_swanctl_conf

VENDOR: Final = "strongswan"

# What a broken or deprecated algorithm becomes. Conservative by design: the
# replacement must be strong enough that this remediation is not repeated.
ENCRYPTION_UPGRADES: Final[dict[str, str]] = {
    "des": "aes256gcm16",
    "3des": "aes256gcm16",
    "null": "aes256gcm16",
}

INTEGRITY_UPGRADES: Final[dict[str, str]] = {
    "md5": "sha256",
    "sha1": "sha256",
}


# The PRF is upgraded independently of the cipher. Replacing 3DES with AES-GCM while
# leaving prfmd5 in the proposal produces a configuration that looks corrected and is
# still keying from a broken hash — and because AEAD suppresses the integrity
# transform, the PRF becomes the only place MD5 would still appear.
PRF_UPGRADES: Final[dict[str, str]] = {
    "prfmd5": "prfsha256",
    "prfsha1": "prfsha256",
}
# Groups below 112-bit strength. Replaced with curve25519 under IKEv2 and modp2048
# under IKEv1, which has no standardised Curve25519 support.
WEAK_DH_GROUPS: Final[frozenset[str]] = frozenset({"modp768", "modp1024", "modp1536"})
DH_REPLACEMENT_IKEV2: Final = "curve25519"
DH_REPLACEMENT_IKEV1: Final = "modp2048"

MAX_IKE_LIFETIME_S: Final = 24 * 60 * 60
MAX_CHILD_LIFETIME_S: Final = 8 * 60 * 60

# Findings this generator knows how to act on. A finding outside this set is reported
# as unaddressed rather than silently dropped: a change package that claims to fix
# something it did not touch is worse than one that admits the gap.
ADDRESSABLE: Final[frozenset[str]] = frozenset(
    {
        "CRY-01",
        "CRY-02",
        "CRY-03",
        "CRY-04",
        "CRY-05",
        "CRY-06",
        "CRY-07",
        "CRY-09",
        "CRY-11",
        "CRY-12",
        "IKE-01",
        "IKE-02",
        "IKE-03",
        "PFS-01",
        "SA-01",
        "SA-02",
    }
)


class GenerationError(ValueError):
    """A corrected configuration could not be produced."""


def harden(config: TunnelConfig) -> tuple[TunnelConfig, list[str]]:
    """Return a corrected configuration and a plain-language list of what changed.

    Changes only what is genuinely weak. A setting that is merely not the strongest
    available is left alone, because "you could use a bigger number" is not a finding
    and an operator asked to justify a change needs a reason with a name.
    """
    changes: list[str] = []
    updated = config

    if updated.encryption in ENCRYPTION_UPGRADES:
        target = ENCRYPTION_UPGRADES[updated.encryption]
        changes.append(f"encryption {updated.encryption} -> {target}")
        # AEAD carries its own integrity, so a separate transform becomes invalid.
        updated = replace(updated, encryption=target, integrity=None)
    elif updated.integrity in INTEGRITY_UPGRADES:
        target = INTEGRITY_UPGRADES[updated.integrity]
        changes.append(f"integrity {updated.integrity} -> {target}")
        updated = replace(updated, integrity=target)

    if updated.prf in PRF_UPGRADES:
        target = PRF_UPGRADES[updated.prf]
        changes.append(f"PRF {updated.prf} -> {target}")
        updated = replace(updated, prf=target)

    # IKEv1 first: it decides which DH replacement is legal.
    if updated.ike_version == "ikev1":
        changes.append("IKE version ikev1 -> ikev2")
        if updated.aggressive:
            changes.append("aggressive mode disabled (it has no IKEv2 equivalent)")
        updated = replace(updated, ike_version="ikev2", aggressive=False)

    if updated.dh_group in WEAK_DH_GROUPS:
        target = DH_REPLACEMENT_IKEV2 if updated.ike_version == "ikev2" else DH_REPLACEMENT_IKEV1
        changes.append(f"Diffie-Hellman group {updated.dh_group} -> {target}")
        updated = replace(updated, dh_group=target)

    if not updated.pfs:
        changes.append("perfect forward secrecy enabled")
        updated = replace(updated, pfs=True)

    if updated.child_dh_group in WEAK_DH_GROUPS:
        changes.append(f"child DH group {updated.child_dh_group} -> {updated.dh_group}")
        updated = replace(updated, child_dh_group=updated.dh_group)

    if updated.ike_lifetime_s > MAX_IKE_LIFETIME_S:
        changes.append(f"IKE SA lifetime {updated.ike_lifetime_s}s -> {MAX_IKE_LIFETIME_S}s")
        updated = replace(updated, ike_lifetime_s=MAX_IKE_LIFETIME_S)

    if updated.child_lifetime_s > MAX_CHILD_LIFETIME_S:
        changes.append(f"child SA lifetime {updated.child_lifetime_s}s -> {MAX_CHILD_LIFETIME_S}s")
        updated = replace(updated, child_lifetime_s=MAX_CHILD_LIFETIME_S)

    return updated, changes


def _steps(aggressive_psk: bool) -> list[ChangeStep]:
    """The ordered, zero-downtime sequence.

    The peer is staged first and the local end second, so that at no point is the local
    end offering something the peer will refuse. The reverse order leaves a window in
    which the tunnel cannot re-establish.
    """
    steps = [
        ChangeStep(
            order=1,
            role=ConfigRole.PEER,
            description="Stage the corrected configuration on the peer",
            action="Write the new swanctl.conf and run `swanctl --load-all`",
            expected_disruption_s=0,
        ),
        ChangeStep(
            order=2,
            role=ConfigRole.LOCAL,
            description="Stage the corrected configuration locally",
            action="Write the new swanctl.conf and run `swanctl --load-all`",
            expected_disruption_s=0,
        ),
        ChangeStep(
            order=3,
            role=ConfigRole.LOCAL,
            description="Rekey the tunnel onto the new proposal",
            action="`swanctl --initiate --child <name>` after terminating the old SA",
            expected_disruption_s=5,
        ),
    ]
    if aggressive_psk:
        steps.insert(
            0,
            ChangeStep(
                order=1,
                role=ConfigRole.PEER,
                description=(
                    "Rotate the pre-shared key before anything else. Aggressive Mode "
                    "has already exposed a crackable hash of the current one, so "
                    "reusing it carries the compromise forward"
                ),
                action="Generate a new PSK out of band and stage it on both ends",
                reversible=False,
                expected_disruption_s=0,
            ),
        )
        steps = [replace_order(step, index + 1) for index, step in enumerate(steps)]
    return steps


def replace_order(step: ChangeStep, order: int) -> ChangeStep:
    return step.model_copy(update={"order": order})


def generate_change_package(
    tunnel_id: str,
    config: TunnelConfig,
    findings_addressed: list[str],
    local_hint: str = "local gateway",
    peer_hint: str = "peer gateway",
) -> ChangePackage:
    """Produce a both-ends change package correcting ``config``."""
    if not findings_addressed:
        raise GenerationError(
            "a change package must name the findings it addresses; one that changes "
            "settings for no stated reason cannot be reviewed"
        )
    corrected, changes = harden(config)
    if not changes:
        raise GenerationError(
            f"{tunnel_id}: nothing to correct in this configuration. Generating an "
            f"empty change package would ask an operator to take a risk for no benefit."
        )

    aggressive_psk = config.aggressive and config.ike_version == "ikev1"
    unaddressed = sorted(set(findings_addressed) - ADDRESSABLE)

    notes = [f"Change: {c}" for c in changes]
    if unaddressed:
        notes.append(
            "NOT addressed by this package: "
            + ", ".join(unaddressed)
            + " — these need a change this generator cannot make."
        )

    return ChangePackage(
        tunnel_id=tunnel_id,
        findings_addressed=findings_addressed,
        local_config=DeviceConfig(
            role=ConfigRole.LOCAL,
            vendor=VENDOR,
            device_hint=local_hint,
            filename="swanctl.conf",
            content=render_swanctl_conf(corrected, "left"),
            notes=list(notes),
        ),
        peer_config=DeviceConfig(
            role=ConfigRole.PEER,
            vendor=VENDOR,
            device_hint=peer_hint,
            filename="swanctl.conf",
            content=render_swanctl_conf(corrected, "right"),
            notes=list(notes),
        ),
        sequence=_steps(aggressive_psk),
        verification=[
            "`swanctl --list-sas` reports the child SA as INSTALLED on both ends",
            f"the negotiated proposal reads {corrected.proposal_string()}",
            f"the ESP proposal reads {corrected.esp_proposal_string()}",
            "traffic passes end to end after the rekey",
        ],
        rollback=[
            "Restore the previous swanctl.conf on both ends from backup",
            "Run `swanctl --load-all` on both ends",
            "Re-initiate the tunnel and confirm the old SA installs",
        ],
        blast_radius=BlastRadius(
            risk=ChangeRisk.SINGLE_TUNNEL,
            tunnels_affected=1,
            peers_requiring_coordination=[peer_hint],
            estimated_disruption_s=5,
            notes=[
                "The peer must be changed in the same window. A proposal changed at one "
                "end only does not degrade — it stops the tunnel establishing at the "
                "next rekey.",
            ],
        ),
        requires_maintenance_window=aggressive_psk,
        generated_at=datetime.now(UTC),
    )
