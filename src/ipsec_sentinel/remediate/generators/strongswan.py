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

from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime
from typing import Final

from ipsec_sentinel.models import TunnelAssessment
from ipsec_sentinel.parser.constants import dh_security_bits
from ipsec_sentinel.remediate.blast import assess_blast_radius
from ipsec_sentinel.remediate.generators.base import DeploymentStatus, status_banner
from ipsec_sentinel.remediate.models import (
    ChangePackage,
    ChangeStep,
    ConfigRole,
    DeviceConfig,
)
from ipsec_sentinel.remediate.sequence import build_sequence
from testbed.orchestrate.config_gen import Role, TunnelConfig, render_swanctl_conf

VENDOR: Final = "strongswan"
COMMENT: Final = "#"

# The one vendor whose generated form has actually been loaded onto a live instance.
# Declared here rather than left implicit so it goes through the same mechanism as the
# five that have not: a status nobody declares is a status nobody can check, and the M8
# gate is what noticed this one was missing.
STATUS: Final = DeploymentStatus.LIVE_TESTED

# strongSwan names the groups; the security-strength table is keyed by IANA group
# number. Mapped here rather than duplicating the strengths, so the generator and the
# assessment cannot drift apart about which group is stronger.
DH_GROUP_NUMBERS: Final[dict[str, int]] = {
    "modp1024": 2,
    "modp1536": 5,
    "modp2048": 14,
    "modp3072": 15,
    "modp4096": 16,
    "ecp256": 19,
    "ecp384": 20,
    "ecp521": 21,
    "curve25519": 31,
}

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
        # The generated configuration offers exactly one proposal, so every weaker
        # alternative is gone by construction — which is what IKE-04 asks for.
        "IKE-04",
        "PFS-01",
        "PFS-02",
        "SA-01",
        "SA-02",
    }
)


class GenerationError(ValueError):
    """A corrected configuration could not be produced."""


def _dh_strength(name: str | None) -> int | None:
    """Security strength of a strongSwan DH group name, or ``None`` if unrecognised.

    ``None`` rather than a default, for the same reason the parser refuses to guess:
    an unknown group defaulted low invents a finding, and defaulted high hides one.
    """
    number = DH_GROUP_NUMBERS.get(name or "")
    return dh_security_bits(number) if number is not None else None


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

    # PFS-02: a child group that is merely *weaker than the IKE group* need not be weak
    # in absolute terms — modp2048 under ecp384, say — so the branch above does not
    # reach it. The weaker of the two sets the effective strength, which makes the
    # stronger one wasted. Compared on security bits rather than parameter size,
    # because 256-bit ECP is stronger than 2048-bit MODP and comparing the numbers
    # printed in the names gets that backwards.
    child_group = updated.effective_child_dh_group
    ike_bits = _dh_strength(updated.dh_group)
    child_bits = _dh_strength(child_group)
    if ike_bits is not None and child_bits is not None and child_bits < ike_bits:
        changes.append(
            f"child DH group {child_group} -> {updated.dh_group} "
            f"({child_bits}-bit strength was below the IKE group's {ike_bits})"
        )
        updated = replace(updated, child_dh_group=updated.dh_group)

    if updated.ike_lifetime_s > MAX_IKE_LIFETIME_S:
        changes.append(f"IKE SA lifetime {updated.ike_lifetime_s}s -> {MAX_IKE_LIFETIME_S}s")
        updated = replace(updated, ike_lifetime_s=MAX_IKE_LIFETIME_S)

    if updated.child_lifetime_s > MAX_CHILD_LIFETIME_S:
        changes.append(f"child SA lifetime {updated.child_lifetime_s}s -> {MAX_CHILD_LIFETIME_S}s")
        updated = replace(updated, child_lifetime_s=MAX_CHILD_LIFETIME_S)

    return updated, changes


def _steps(current: TunnelConfig, target: TunnelConfig, aggressive_psk: bool) -> list[ChangeStep]:
    """The change sequence: four steps, plus PSK rotation where one is compromised.

    Delegates to :func:`build_sequence`, which is verified to keep a common proposal on
    both ends at every intermediate state — including the half-applied ones. An earlier
    version of this function staged each end and then rekeyed, which reads as safe and
    is not: between the two stages the ends offer disjoint proposals.
    """
    steps = build_sequence(current.proposal_string(), target.proposal_string())

    if not aggressive_psk:
        return steps

    # Aggressive Mode with a PSK has already put a crackable hash on the wire, so the
    # key is compromised before the change begins. Rotating it after the crypto
    # transition would carry the compromise across; it goes first.
    rotation = ChangeStep(
        order=1,
        role=ConfigRole.BOTH,
        description=(
            "Rotate the pre-shared key before anything else. Aggressive Mode has "
            "already exposed a crackable hash of the current key, so reusing it "
            "carries the compromise forward into the corrected tunnel."
        ),
        action="Generate a new PSK out of band and install it on both peers.",
        reversible=False,
        expected_disruption_s=0,
    )
    return [rotation, *(step.model_copy(update={"order": step.order + 1}) for step in steps)]


def render(config: TunnelConfig, role: str = "left") -> str:
    """Render one end's ``swanctl.conf``, with the provenance banner on top.

    The same shape as every other vendor's ``render``, so a caller does not have to
    know which one it is holding. The banner matters most on the vendor that *is*
    live-tested: without it the strongest claim in the set would be the only one the
    document does not make.
    """
    if role not in ("left", "right"):
        raise ValueError(f"role must be 'left' or 'right', got {role!r}")
    end: Role = "left" if role == "left" else "right"
    banner = status_banner(VENDOR, STATUS, COMMENT)
    return f"{banner}\n\n{render_swanctl_conf(config, end)}"


def _unobserved(tunnel_id: str, local_hint: str, peer_hint: str) -> TunnelAssessment:
    """A tunnel about which nothing was observed.

    Carries no ESP flows and no inference, so every estimate derived from it comes back
    as "not enough evidence" rather than as a favourable answer. The score and grade are
    required by the model and are not read by the blast assessment.
    """
    return TunnelAssessment(
        tunnel_id=tunnel_id,
        endpoints=(local_hint, peer_hint),
        esp_flows=[],
        score=0,
        grade="F",
    )


def generate_change_package(
    tunnel_id: str,
    config: TunnelConfig,
    findings_addressed: list[str],
    local_hint: str = "local gateway",
    peer_hint: str = "peer gateway",
    *,
    observed: TunnelAssessment | None = None,
    sibling_tunnels: Sequence[str] = (),
) -> ChangePackage:
    """Produce a both-ends change package correcting ``config``.

    ``observed`` supplies what the capture saw of this tunnel, which is what decides
    the blast radius and whether the change needs scheduling. Without it the package
    still generates, but it says plainly that the timing advice rests on no observation
    rather than quietly reporting a tunnel as safe to change now.
    """
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

    steps = _steps(config, corrected, aggressive_psk)
    blast = assess_blast_radius(
        observed or _unobserved(tunnel_id, local_hint, peer_hint),
        # A pre-shared key rotation interrupts the tunnel by construction, so it needs
        # a window however quiet the tunnel looks.
        disruptive_change=aggressive_psk,
        sibling_tunnels=sibling_tunnels,
        estimated_disruption_s=sum(step.expected_disruption_s for step in steps),
    )
    if observed is None:
        blast.radius.notes.insert(
            0,
            "No traffic observation was supplied for this tunnel, so the timing advice "
            "below rests on nothing measured. Treat it as a floor, not a verdict.",
        )
    notes.extend(f"Blast radius: {reason}" for reason in blast.reasons)

    return ChangePackage(
        tunnel_id=tunnel_id,
        findings_addressed=findings_addressed,
        local_config=DeviceConfig(
            role=ConfigRole.LOCAL,
            vendor=VENDOR,
            device_hint=local_hint,
            filename="swanctl.conf",
            content=render(corrected, "left"),
            notes=list(notes),
        ),
        peer_config=DeviceConfig(
            role=ConfigRole.PEER,
            vendor=VENDOR,
            device_hint=peer_hint,
            filename="swanctl.conf",
            content=render(corrected, "right"),
            notes=list(notes),
        ),
        sequence=steps,
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
        blast_radius=blast.radius,
        requires_maintenance_window=blast.requires_maintenance_window,
        generated_at=datetime.now(UTC),
    )
