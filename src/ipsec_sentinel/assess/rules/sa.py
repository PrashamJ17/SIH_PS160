"""Forward secrecy and SA lifetime rules, PFS-01 to SA-04.

This file is where the project's central discipline costs something, so it is worth
stating plainly what it can and cannot see.

**A passive observer cannot see most of what these rules assess.** Perfect forward
secrecy is negotiated in IKEv1 Quick Mode or IKEv2 CREATE_CHILD_SA, and both are
encrypted. Anti-replay and the replay window are local settings that never appear on
the wire in any form. Child SA lifetimes are phase 2 and equally invisible. IKEv2 does
not even negotiate the IKE SA lifetime — RFC 7296 removed it from the SA payload, so
each peer keeps its own and never announces it.

Exactly one of these is genuinely readable from a capture: **IKEv1 phase 1 lifetime**,
which is a cleartext SA attribute. This corpus carries 31,680 s and 95,040 s, and the
second is over the 24-hour threshold — a real finding, read from the wire.

For the rest there were three options: infer them from side channels and present the
guess as fact; emit them with a confidence and move them to the inferred lane; or take
the facts from the operator. The third is chosen here. A rule whose input was not
supplied returns ``None`` — silence, not a default. A report asserting "PFS is
disabled" because nobody said otherwise would be worse than no report at all, because
an operator would act on it.

Every finding below is therefore still deterministic: read from the wire, or read from
a document the operator provided. The evidence always names which, so a reader can tell
them apart without trusting the tool.

SA-03 is the one hybrid. It fires on operator configuration, and *also* on a purely
observable trigger the build plan names: duplicate ESP sequence numbers that the
tunnel carried on regardless. That is an observation, not a conclusion, and the
evidence says so — a passive observer cannot distinguish a peer with anti-replay
disabled from a network that duplicated a packet.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ipsec_sentinel.assess.framework import DEFAULT_BASELINE
from ipsec_sentinel.models import Finding, Severity, TransformType
from ipsec_sentinel.parser.correlate import Tunnel
from ipsec_sentinel.parser.esp import analyse_sequence

IKE_LIFETIME_LIMIT_S = 24 * 60 * 60
CHILD_LIFETIME_LIMIT_S = 8 * 60 * 60
MINIMUM_REPLAY_WINDOW = 64

WIRE_SOURCE = "read from the IKE handshake"


@dataclass(frozen=True)
class SARule:
    """A rule over forward secrecy or SA lifetime settings."""

    id: str
    title: str
    severity: Severity
    standard_ref: str
    remediation_hint: str
    attack_technique: str | None = None
    baselines: list[str] = field(default_factory=lambda: [DEFAULT_BASELINE])

    def evaluate(self, tunnel: Tunnel) -> Finding | None:  # pragma: no cover - overridden
        raise NotImplementedError

    def _finding(self, evidence: str) -> Finding:
        return Finding(
            rule_id=self.id,
            title=self.title,
            severity=self.severity,
            evidence=evidence,
            standard_ref=self.standard_ref,
            attack_technique=self.attack_technique,
            remediation_hint=self.remediation_hint,
        )


def _hours(seconds: int) -> str:
    return f"{seconds} s ({seconds / 3600:.1f} h)"


@dataclass(frozen=True)
class PFSDisabled(SARule):
    def evaluate(self, tunnel: Tunnel) -> Finding | None:
        config = tunnel.config
        if config is None or config.pfs_enabled is None:
            # Not observable from a capture and not supplied. Silence is the only
            # honest output; a default would be an assertion nobody made.
            return None
        if config.pfs_enabled:
            return None
        return self._finding(
            f"perfect forward secrecy is disabled, per {config.source}. Without it, "
            f"compromise of the IKE SA key exposes every child SA derived from it, "
            f"including traffic already captured"
        )


@dataclass(frozen=True)
class ChildGroupWeakerThanIKE(SARule):
    def evaluate(self, tunnel: Tunnel) -> Finding | None:
        config = tunnel.config
        if config is None or config.child_dh_group is None or tunnel.ike is None:
            return None
        ike_groups = [
            transform.id
            for proposal in tunnel.ike.proposals_offered
            for transform in proposal.transforms
            if transform.type == TransformType.DH
        ]
        if not ike_groups:
            return None
        strongest_ike = max(ike_groups)
        if config.child_dh_group >= strongest_ike:
            return None
        return self._finding(
            f"the child SA uses Diffie-Hellman group {config.child_dh_group} "
            f"({config.source}) while the IKE SA negotiated group {strongest_ike} "
            f"({WIRE_SOURCE}). The weaker group sets the effective strength of the "
            f"rekey, so the stronger IKE group buys nothing"
        )


@dataclass(frozen=True)
class IKELifetimeTooLong(SARule):
    def evaluate(self, tunnel: Tunnel) -> Finding | None:
        wire = tunnel.ike.ike_lifetime_seconds if tunnel.ike else None
        supplied = tunnel.config.ike_lifetime_seconds if tunnel.config else None

        if wire is not None and wire > IKE_LIFETIME_LIMIT_S:
            return self._finding(
                f"the IKE SA lifetime is {_hours(wire)}, over the {_hours(IKE_LIFETIME_LIMIT_S)} "
                f"limit ({WIRE_SOURCE} as an IKEv1 phase 1 SA attribute)"
            )
        if supplied is not None and supplied > IKE_LIFETIME_LIMIT_S:
            source = tunnel.config.source if tunnel.config else "configuration"
            return self._finding(
                f"the IKE SA lifetime is {_hours(supplied)}, over the "
                f"{_hours(IKE_LIFETIME_LIMIT_S)} limit, per {source}"
            )
        return None


@dataclass(frozen=True)
class ChildLifetimeTooLong(SARule):
    def evaluate(self, tunnel: Tunnel) -> Finding | None:
        config = tunnel.config
        if config is None or config.child_lifetime_seconds is None:
            return None
        if config.child_lifetime_seconds <= CHILD_LIFETIME_LIMIT_S:
            return None
        return self._finding(
            f"the child SA lifetime is {_hours(config.child_lifetime_seconds)}, over "
            f"the {_hours(CHILD_LIFETIME_LIMIT_S)} limit, per {config.source}"
        )


@dataclass(frozen=True)
class AntiReplayDisabled(SARule):
    def evaluate(self, tunnel: Tunnel) -> Finding | None:
        config = tunnel.config
        if config is not None and config.anti_replay_enabled is False:
            return self._finding(
                f"anti-replay is disabled, per {config.source}. An attacker who "
                f"captures an ESP packet can resend it and the peer will accept it"
            )

        # The observable trigger. Duplicates are a fact; the cause is not.
        duplicated = [
            (flow, analysis)
            for flow in tunnel.flows
            if (analysis := analyse_sequence(flow)).duplicates > 0
        ]
        if not duplicated:
            return None
        total = sum(analysis.duplicates for _flow, analysis in duplicated)
        flow = duplicated[0][0]
        return self._finding(
            f"{total} duplicate ESP sequence number(s) were observed across "
            f"{len(duplicated)} flow(s), first on SPI {flow.spi} "
            f"({flow.src_ip} -> {flow.dst_ip}), and the tunnel carried on. That is "
            f"consistent with anti-replay being disabled, but a passive observer "
            f"cannot distinguish it from network duplication — confirm against the "
            f"device configuration before acting"
        )


@dataclass(frozen=True)
class ReplayWindowTooSmall(SARule):
    def evaluate(self, tunnel: Tunnel) -> Finding | None:
        config = tunnel.config
        if config is None or config.replay_window is None:
            return None
        if config.replay_window >= MINIMUM_REPLAY_WINDOW:
            return None
        if config.anti_replay_enabled is False:
            # The window is irrelevant when the check is off, and reporting both
            # would imply two fixes where there is one.
            return None
        return self._finding(
            f"the anti-replay window is {config.replay_window} packets, below the "
            f"recommended {MINIMUM_REPLAY_WINDOW}, per {config.source}. On a path that "
            f"reorders, a window this small drops legitimate packets"
        )


PFS_01 = PFSDisabled(
    id="PFS-01",
    title="Perfect forward secrecy disabled",
    severity=Severity.HIGH,
    standard_ref="NIST SP 800-77 Rev. 1 section 5.1; RFC 7296 section 1.3.1",
    attack_technique="T1040",
    remediation_hint=(
        "Enable PFS on the child SA so each rekey performs a fresh Diffie-Hellman "
        "exchange. Without it, one compromised IKE key decrypts every child SA "
        "derived from it, including traffic captured months ago."
    ),
)

PFS_02 = ChildGroupWeakerThanIKE(
    id="PFS-02",
    title="Child SA Diffie-Hellman group weaker than the IKE SA group",
    severity=Severity.MEDIUM,
    standard_ref="NIST SP 800-77 Rev. 1 section 5.1",
    remediation_hint=(
        "Raise the child SA group to match the IKE SA group. The weaker of the two "
        "sets the effective strength, so the stronger one is wasted."
    ),
)

SA_01 = IKELifetimeTooLong(
    id="SA-01",
    title="IKE SA lifetime longer than 24 hours",
    severity=Severity.MEDIUM,
    standard_ref="NIST SP 800-77 Rev. 1 section 5.1",
    remediation_hint=(
        "Reduce the IKE SA lifetime to 24 hours or less. A long-lived SA widens the "
        "window in which a compromised key remains useful."
    ),
)

SA_02 = ChildLifetimeTooLong(
    id="SA-02",
    title="Child SA lifetime longer than 8 hours",
    severity=Severity.LOW,
    standard_ref="NIST SP 800-77 Rev. 1 section 5.1",
    remediation_hint=(
        "Reduce the child SA lifetime to 8 hours or less so that key material rotates "
        "more often and less traffic sits under any one key."
    ),
)

SA_03 = AntiReplayDisabled(
    id="SA-03",
    title="Anti-replay protection disabled or not enforced",
    severity=Severity.MEDIUM,
    standard_ref="RFC 4303 section 3.4.3",
    attack_technique="T1550",
    remediation_hint=(
        "Enable anti-replay on the SA. If it is already enabled, investigate the "
        "duplicate sequence numbers — they are either network duplication or an "
        "actual replay attempt, and the two need different responses."
    ),
)

SA_04 = ReplayWindowTooSmall(
    id="SA-04",
    title="Anti-replay window smaller than 64 packets",
    severity=Severity.LOW,
    standard_ref="RFC 4303 section 3.4.3",
    remediation_hint=(
        "Increase the anti-replay window to at least 64 packets. A smaller window "
        "drops legitimate traffic on any path that reorders."
    ),
)

SA_RULES: list[SARule] = [PFS_01, PFS_02, SA_01, SA_02, SA_03, SA_04]
