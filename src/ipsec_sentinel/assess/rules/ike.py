"""IKE configuration rules, IKE-01 to IKE-04.

IKE-03 is the finding this whole project is arranged around, and it is worth being
precise about why it is Critical rather than High.

IKEv1 Aggressive Mode compresses phase 1 into three messages by sending the identity
and the authentication hash before any shared secret exists. With pre-shared key
authentication that hash is a function of the PSK, transmitted in cleartext. Anyone who
captured the exchange can attack it offline, at their own pace, with no further contact
with the gateway — no failed login, no rate limit, no log entry, nothing to detect. By
the time the capture exists, the PSK is not "at risk"; it is a secret held by whoever
holds the packets.

That is why IKE-03 supersedes IKE-02. A report showing both a High "Aggressive Mode"
and a Critical "Aggressive Mode with PSK" invites an operator to treat them as two
problems and fix the cheaper one. There is one problem, and the fix is to rotate the key
and disable the mode.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ipsec_sentinel.assess.framework import DEFAULT_BASELINE
from ipsec_sentinel.assess.rules.crypto import weaknesses_in
from ipsec_sentinel.models import Finding, Severity
from ipsec_sentinel.parser.correlate import Tunnel

PSK_METHOD = "PRE_SHARED_KEY"

# The exact wording the build plan requires on IKE-03. Kept as a constant because it is
# the sentence an operator acts on, and a paraphrase would soften it.
PSK_EXPOSURE_STATEMENT = (
    "The pre-shared key hash is exposed to any passive observer and can be cracked "
    "offline. Treat this PSK as compromised."
)


@dataclass(frozen=True)
class IKERule:
    """A rule over the negotiation as a whole rather than a single proposal."""

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


def _uses_psk(tunnel: Tunnel) -> bool:
    """Whether any captured message offered pre-shared key authentication.

    Any, not all: a peer offering PSK alongside certificates will accept PSK, and the
    weakest method it accepts is the one that matters.
    """
    if tunnel.negotiation is None:
        return False
    return any(PSK_METHOD in message.auth_methods for message in tunnel.negotiation.messages)


@dataclass(frozen=True)
class IKEv1InUse(IKERule):
    def evaluate(self, tunnel: Tunnel) -> Finding | None:
        if tunnel.ike is None or tunnel.ike.version != "IKEv1":
            return None
        return self._finding(
            f"the negotiation used {tunnel.ike.version} "
            f"({tunnel.ike.exchange_type}) between {tunnel.endpoints[0]} and "
            f"{tunnel.endpoints[1]}"
        )


@dataclass(frozen=True)
class AggressiveMode(IKERule):
    def evaluate(self, tunnel: Tunnel) -> Finding | None:
        if tunnel.ike is None or not tunnel.ike.is_aggressive:
            return None
        # Superseded by IKE-03 when a PSK is in use: one problem, one finding.
        if _uses_psk(tunnel):
            return None
        return self._finding(
            "IKEv1 Aggressive Mode was used, which sends the peer identity in "
            "cleartext before any shared secret exists"
        )


@dataclass(frozen=True)
class AggressiveModeWithPSK(IKERule):
    def evaluate(self, tunnel: Tunnel) -> Finding | None:
        if tunnel.ike is None or not tunnel.ike.is_aggressive:
            return None
        if not _uses_psk(tunnel):
            return None
        return self._finding(
            f"IKEv1 Aggressive Mode with pre-shared key authentication between "
            f"{tunnel.endpoints[0]} and {tunnel.endpoints[1]}. "
            f"{PSK_EXPOSURE_STATEMENT}"
        )


@dataclass(frozen=True)
class WeakProposalOffered(IKERule):
    def evaluate(self, tunnel: Tunnel) -> Finding | None:
        if tunnel.ike is None or tunnel.negotiation is None:
            return None
        proposals = tunnel.ike.proposals_offered
        if len(proposals) < 2:
            # With one proposal there is nothing to downgrade *to*; the CRY rules
            # already report whatever is wrong with it.
            return None

        described: list[str] = []
        for index, proposal in enumerate(proposals, start=1):
            if tunnel.negotiation.was_accepted(proposal):
                continue
            weak = weaknesses_in(proposal)
            if weak:
                described.append(f"proposal {index} of {len(proposals)} offers {', '.join(weak)}")
        if not described:
            return None
        return self._finding(
            "a weaker proposal than the one selected was advertised and would be "
            "accepted from a peer that offers nothing else: " + "; ".join(described)
        )


IKE_01 = IKEv1InUse(
    id="IKE-01",
    title="IKEv1 in use",
    severity=Severity.MEDIUM,
    standard_ref="RFC 8247 section 2.4; RFC 9395 deprecates IKEv1",
    remediation_hint=(
        "Migrate this tunnel to IKEv2. IKEv1 was deprecated by RFC 9395 and lacks "
        "IKEv2's built-in DoS protection, MOBIKE and cleaner rekeying."
    ),
)

IKE_02 = AggressiveMode(
    id="IKE-02",
    title="IKEv1 Aggressive Mode in use",
    severity=Severity.HIGH,
    standard_ref="RFC 2409 section 5.4; NIST SP 800-77 Rev. 1 section 5.1",
    attack_technique="T1040",
    remediation_hint=(
        "Disable Aggressive Mode and use Main Mode, which completes the "
        "Diffie-Hellman exchange before any identity is sent."
    ),
)

IKE_03 = AggressiveModeWithPSK(
    id="IKE-03",
    title="IKEv1 Aggressive Mode with pre-shared key authentication",
    severity=Severity.CRITICAL,
    standard_ref="RFC 2409 section 5.4; NIST SP 800-77 Rev. 1 section 5.1",
    attack_technique="T1110.002",
    remediation_hint=(
        "Rotate the pre-shared key immediately and disable Aggressive Mode. Rotating "
        "without disabling the mode only restarts the clock, since the next handshake "
        "exposes the new key the same way. Prefer certificate authentication, or "
        "IKEv2 where the authentication payload is encrypted."
    ),
)

IKE_04 = WeakProposalOffered(
    id="IKE-04",
    title="A weaker proposal was offered but not selected",
    severity=Severity.MEDIUM,
    standard_ref="NIST SP 800-77 Rev. 1 section 5.1",
    # T1562.010 was revoked in the 2026-04 ATT&CK release; T1689 is the live
    # replacement. A finding citing a revoked technique renders as a dead link.
    attack_technique="T1689",
    remediation_hint=(
        "Remove the weaker proposals from the configuration. What a gateway advertises "
        "is what it will accept, and a peer offering only the weak option will get it."
    ),
)

IKE_RULES: list[IKERule] = [IKE_01, IKE_02, IKE_03, IKE_04]
