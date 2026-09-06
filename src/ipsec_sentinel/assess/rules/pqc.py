"""Post-quantum readiness grading.

The threat this grades is not hypothetical and not in the future: it is
**harvest now, decrypt later**. An adversary who records IPsec traffic today and stores
it needs no quantum computer today. Classical Diffie-Hellman, of any group size, is
broken by Shor's algorithm whenever a cryptographically relevant quantum computer
arrives, and the ciphertext recorded this morning is still on their disk when it does.

That inverts the usual urgency calculation. For most vulnerabilities, exposure begins
when the attack becomes practical. Here, exposure began the day the traffic was
captured, and no amount of later remediation reaches back to protect it. A tunnel
carrying data with a ten-year confidentiality requirement over classical DH is already
failing that requirement — today, measurably, whatever happens next.

Four grades, from RFC 9370 (hybrid key exchange) and RFC 8784 (post-quantum PSK):

* ``READY`` — a post-quantum KEM is negotiated, in an additional key exchange or the
  DH slot itself. Recorded traffic is not retroactively decryptable.
* ``TRANSITIONAL`` — RFC 8784 post-quantum PSK. Not a post-quantum key exchange, but
  it does defeat harvest-now-decrypt-later for peers that already share a secret out
  of band.
* ``AT_RISK`` — classical key exchange only. Recorded traffic is decryptable in
  retrospect once the hardware exists.
* ``EXPOSED`` — classical only *and* forward secrecy off, so a single key compromise
  reaches every child SA derived from it, not merely one rekey interval.

**A note on what cannot be seen.** ``EXPOSED`` requires knowing that PFS is disabled,
and PFS is negotiated inside encrypted exchanges (see the SA rules). When the operator
has not supplied it, this module grades ``AT_RISK`` and says in the rationale that
``EXPOSED`` cannot be excluded. Grading down on missing information rather than up is
the conservative direction: it under-claims severity rather than manufacturing it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final

from ipsec_sentinel.assess.framework import DEFAULT_BASELINE
from ipsec_sentinel.models import Finding, Severity, Transform, TransformType
from ipsec_sentinel.parser.constants import POST_QUANTUM_GROUPS
from ipsec_sentinel.parser.correlate import Tunnel

NOTIFY_USE_PPK: Final = "USE_PPK"


class PQCGrade(StrEnum):
    """Post-quantum readiness, worst first.

    Ordered by :attr:`rank` rather than by declaration, so a caller can compare grades
    without depending on enum ordering, and so the ordering is a tested property
    rather than an accident of how the class happens to be written.
    """

    EXPOSED = "exposed"
    AT_RISK = "at_risk"
    TRANSITIONAL = "transitional"
    READY = "ready"

    @property
    def rank(self) -> int:
        return _GRADE_RANK[self]

    def __lt__(self, other: object) -> bool:
        """Order by rank, worst first, so ``sorted()`` puts EXPOSED at the top.

        Defined explicitly rather than left to StrEnum, whose inherited string
        comparison would order these alphabetically — at_risk, exposed, ready,
        transitional — which is meaningless and, worse, plausible-looking.
        """
        if not isinstance(other, PQCGrade):
            return NotImplemented
        return self.rank < other.rank


_GRADE_RANK: Final[dict[PQCGrade, int]] = {
    PQCGrade.EXPOSED: 0,
    PQCGrade.AT_RISK: 1,
    PQCGrade.TRANSITIONAL: 2,
    PQCGrade.READY: 3,
}


@dataclass(frozen=True)
class PQCAssessment:
    """A grade and the reasoning behind it."""

    grade: PQCGrade
    rationale: str
    post_quantum_groups: tuple[str, ...] = ()
    classical_groups: tuple[str, ...] = ()
    pfs_known: bool = False


def _key_exchange_transforms(tunnel: Tunnel) -> list[Transform]:
    """Every transform that establishes key material, classical or otherwise."""
    if tunnel.ike is None:
        return []
    return [
        transform
        for proposal in tunnel.ike.proposals_offered
        for transform in proposal.transforms
        if transform.type is not None
        and (transform.type == TransformType.DH or transform.type.is_additional_key_exchange)
    ]


def uses_post_quantum_psk(tunnel: Tunnel) -> bool:
    """Whether RFC 8784 post-quantum PSK was signalled by either peer."""
    if tunnel.negotiation is None:
        return False
    return any(NOTIFY_USE_PPK in message.notifies for message in tunnel.negotiation.messages)


def grade_pqc(tunnel: Tunnel) -> PQCAssessment:
    """Grade one tunnel's exposure to harvest-now-decrypt-later."""
    transforms = _key_exchange_transforms(tunnel)
    post_quantum = tuple(
        transform.name for transform in transforms if transform.id in POST_QUANTUM_GROUPS
    )
    classical = tuple(
        transform.name for transform in transforms if transform.id not in POST_QUANTUM_GROUPS
    )

    if post_quantum:
        return PQCAssessment(
            grade=PQCGrade.READY,
            rationale=(
                f"a post-quantum key exchange is negotiated ({', '.join(post_quantum)}), "
                f"so traffic recorded now is not decryptable in retrospect"
            ),
            post_quantum_groups=post_quantum,
            classical_groups=classical,
            pfs_known=True,
        )

    if uses_post_quantum_psk(tunnel):
        return PQCAssessment(
            grade=PQCGrade.TRANSITIONAL,
            rationale=(
                "an RFC 8784 post-quantum pre-shared key is in use. The key exchange "
                "is still classical, but the PPK is mixed into key derivation, so "
                "recorded traffic is not decryptable by breaking the exchange alone"
            ),
            classical_groups=classical,
            pfs_known=True,
        )

    if not transforms:
        return PQCAssessment(
            grade=PQCGrade.AT_RISK,
            rationale=(
                "no key exchange transform was observed, so post-quantum readiness "
                "cannot be established. Graded AT_RISK because classical key exchange "
                "is overwhelmingly the default and assuming otherwise would overstate "
                "this tunnel's safety"
            ),
        )

    pfs_enabled = tunnel.config.pfs_enabled if tunnel.config else None
    if pfs_enabled is False:
        return PQCAssessment(
            grade=PQCGrade.EXPOSED,
            rationale=(
                f"classical key exchange only ({', '.join(classical)}) with forward "
                f"secrecy disabled. Traffic recorded today is decryptable in retrospect, "
                f"and one compromised IKE key reaches every child SA derived from it "
                f"rather than a single rekey interval"
            ),
            classical_groups=classical,
            pfs_known=True,
        )

    if pfs_enabled is None:
        return PQCAssessment(
            grade=PQCGrade.AT_RISK,
            rationale=(
                f"classical key exchange only ({', '.join(classical)}), so traffic "
                f"recorded today is decryptable in retrospect once the hardware exists. "
                f"The forward secrecy setting was not supplied and is not visible to a "
                f"passive observer, so EXPOSED cannot be excluded — supply it to "
                f"resolve this"
            ),
            classical_groups=classical,
            pfs_known=False,
        )

    return PQCAssessment(
        grade=PQCGrade.AT_RISK,
        rationale=(
            f"classical key exchange only ({', '.join(classical)}) with forward secrecy "
            f"enabled. Traffic recorded today is still decryptable in retrospect once "
            f"the hardware exists; forward secrecy limits the blast radius of a single "
            f"key, it does not survive the exchange itself being broken"
        ),
        classical_groups=classical,
        pfs_known=True,
    )


@dataclass(frozen=True)
class PQCRule:
    """Emits a finding for tunnels that are not post-quantum ready."""

    id: str = "PQC-01"
    title: str = "Not resistant to harvest-now-decrypt-later"
    severity: Severity = Severity.MEDIUM
    standard_ref: str = "RFC 9370; RFC 8784; NIST FIPS 203"
    attack_technique: str | None = "T1040"
    baselines: list[str] = field(default_factory=lambda: [DEFAULT_BASELINE])
    remediation_hint: str = (
        "Enable a hybrid post-quantum key exchange (RFC 9370 additional key exchange "
        "with ML-KEM), or an RFC 8784 post-quantum pre-shared key where the peers "
        "already share a secret. Prioritise tunnels carrying data whose "
        "confidentiality must outlast the arrival of quantum hardware — remediation "
        "later does not protect traffic recorded today."
    )

    def evaluate(self, tunnel: Tunnel) -> Finding | None:
        if tunnel.ike is None:
            return None
        assessment = grade_pqc(tunnel)
        if assessment.grade in (PQCGrade.READY, PQCGrade.TRANSITIONAL):
            return None
        severity = Severity.HIGH if assessment.grade is PQCGrade.EXPOSED else self.severity
        return Finding(
            rule_id=self.id,
            title=f"{self.title} ({assessment.grade.value})",
            severity=severity,
            evidence=assessment.rationale,
            standard_ref=self.standard_ref,
            attack_technique=self.attack_technique,
            remediation_hint=self.remediation_hint,
        )


PQC_01 = PQCRule()
PQC_RULES: list[PQCRule] = [PQC_01]
