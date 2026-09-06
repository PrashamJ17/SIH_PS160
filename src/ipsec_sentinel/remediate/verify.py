"""Close the remediation loop from observed evidence.

A change package is a document. Whether the change was made, made correctly, and made
at both ends is a question only the wire can answer, and it answers it the next time the
peers negotiate. This module reads that negotiation and decides whether the findings the
package addressed can be closed.

The plan describes three outcomes — verified, failed, pending. There is a fourth, and it
is the one that matters most, because it is the state the Step 8.4 sequence deliberately
passes through:

    After step 2 the tunnel is running on the target proposal **and still offering the
    old one**. The negotiation looks exactly like success.

Closing the finding there would be wrong. A gateway that advertises 3DES will accept
3DES from a peer that offers only that, so the downgrade path is open however strong the
proposal currently in use. :attr:`VerificationStatus.PARTIAL` names that state, keeps the
finding open, and says what remains — which is precisely step 3 of the sequence. Reading
`proposal_accepted` alone and calling it verified would silently sign off a tunnel that
is still downgradeable, and it would do so on the evidence of a change that half worked.

One correction is worth recording, because it would have shipped silently. The first
version read ``IKEExchange.proposal_accepted``. Nothing in the parser ever populated
that field — it was always ``None``, so in production this module would have returned
``PENDING`` for every tunnel forever, and the unit tests passed only because they set
the field by hand. The field has been removed. What was agreed is a property of the
*negotiation*: the offer list is in the initiator's opening message and the chosen
proposal in the responder's reply, and
:class:`~ipsec_sentinel.parser.correlate.Negotiation` already knew how to read both.

Nothing here writes to a device. It reads exchanges that a capture already contains.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Final

from pydantic import BaseModel, Field, model_validator

from ipsec_sentinel.models import IKEExchange, Proposal
from ipsec_sentinel.parser.correlate import Negotiation, group_negotiations

TransformKey = tuple[str, str, int | None]


class VerificationStatus(StrEnum):
    """What the wire says about a change that was supposed to have been made."""

    VERIFIED = "verified"
    """A new negotiation selected the target and the superseded proposal is gone."""

    PARTIAL = "partial"
    """The target is in use, but a superseded proposal is still being offered."""

    FAILED = "failed"
    """A new negotiation happened and did not select the target."""

    PENDING = "pending"
    """No new negotiation has been observed yet. Absence of evidence."""


class VerificationResult(BaseModel):
    """The verdict on one tunnel's remediation, with the evidence behind it."""

    tunnel_id: str = Field(min_length=1)
    status: VerificationStatus
    observed_at: datetime | None = None
    findings_closed: list[str] = Field(default_factory=list)
    findings_still_open: list[str] = Field(default_factory=list)
    residual_offers: list[str] = Field(default_factory=list)
    evidence: str = Field(min_length=1)
    overdue: bool = False
    negotiations_considered: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def _only_a_verified_change_closes_anything(self) -> VerificationResult:
        """The guard on the one mistake this module exists to prevent.

        Every non-verified status leaves every finding open. A partial change reads as
        success on the accepted proposal alone, and closing on that would sign off a
        tunnel that is still downgradeable.
        """
        if self.status is not VerificationStatus.VERIFIED and self.findings_closed:
            raise ValueError(
                f"status {self.status.value!r} closed "
                f"{self.findings_closed}; only a verified change closes a finding"
            )
        overlap = set(self.findings_closed) & set(self.findings_still_open)
        if overlap:
            raise ValueError(f"findings both closed and open: {sorted(overlap)}")
        return self

    @property
    def verified(self) -> bool:
        """The plan's field name. True only for a fully verified change."""
        return self.status is VerificationStatus.VERIFIED

    def summary(self) -> str:
        return f"{self.tunnel_id}: {self.status.value} — {self.evidence}"


def transform_keys(proposal: Proposal) -> frozenset[TransformKey]:
    """A comparable identity for a proposal's algorithm choices.

    Keyed on type, name and key length together: AES-128 and AES-256 are the same
    transform ID and differ only in an attribute, so a comparison that dropped the key
    length would report a 128-bit tunnel as matching a 256-bit target.
    """
    return frozenset(
        (
            transform.type.value if transform.type is not None else f"unknown:{transform.id}",
            transform.name,
            transform.key_length,
        )
        for transform in proposal.transforms
    )


def matches(observed: Proposal, expected: Proposal) -> bool:
    """Whether ``observed`` provides exactly what ``expected`` asks for.

    Compared over the transform *types* the target names, so an observed proposal
    carrying an extra type the target is silent about (ESN, say) still matches, while
    every type the target does name must agree exactly.
    """
    wanted = transform_keys(expected)
    if not wanted:
        return False
    types = {key[0] for key in wanted}
    return {key for key in transform_keys(observed) if key[0] in types} == wanted


def describe(proposal: Proposal) -> str:
    """A short human rendering, for evidence strings."""
    parts = [
        f"{transform.name}-{transform.key_length}" if transform.key_length else transform.name
        for transform in proposal.transforms
    ]
    return "/".join(parts) if parts else "(no transforms)"


NO_NEW_EXCHANGE: Final = (
    "No new negotiation has been observed since the change was applied, so there is "
    "nothing yet to verify against. This is not evidence the change failed."
)


def verify_remediation(
    tunnel_id: str,
    expected: Proposal,
    new_exchanges: Sequence[IKEExchange],
    *,
    findings_addressed: Sequence[str] = (),
    superseded: Sequence[Proposal] = (),
    changed_at: datetime | None = None,
    sa_lifetime_s: int | None = None,
    now: datetime | None = None,
) -> VerificationResult:
    """Decide whether the next negotiation shows the remediation took effect.

    ``new_exchanges`` are negotiations observed after the change. When ``changed_at`` is
    given they are filtered by it, because an exchange from before the change describes
    the state the change was meant to correct and would otherwise be read as a failure.

    ``superseded`` names the proposals the change was supposed to remove. Leaving it
    empty means no removal is asserted, and the residual-offer check is skipped — stated
    in the evidence rather than passed over silently.
    """
    findings = list(findings_addressed)
    # Grouped into negotiations first. The parser yields one IKEExchange per *message*,
    # and a single IKEv2 setup is at least four of them; the offer list lives in the
    # initiator's opening message and the agreed proposal in the responder's reply, so
    # no individual message answers the question on its own.
    considered = [
        negotiation
        for negotiation in group_negotiations(list(new_exchanges))
        if changed_at is None or negotiation.started_at >= changed_at
    ]
    considered.sort(key=lambda negotiation: negotiation.started_at)

    def result(
        status: VerificationStatus,
        evidence: str,
        *,
        observed_at: datetime | None = None,
        residual: Sequence[str] = (),
        overdue: bool = False,
    ) -> VerificationResult:
        closed = findings if status is VerificationStatus.VERIFIED else []
        return VerificationResult(
            tunnel_id=tunnel_id,
            status=status,
            observed_at=observed_at,
            findings_closed=list(closed),
            findings_still_open=[] if closed else findings,
            residual_offers=list(residual),
            evidence=evidence,
            overdue=overdue,
            negotiations_considered=len(considered),
        )

    if not considered:
        return result(
            VerificationStatus.PENDING,
            NO_NEW_EXCHANGE + _deadline_note(changed_at, sa_lifetime_s, now),
            overdue=_is_overdue(changed_at, sa_lifetime_s, now),
        )

    latest: Negotiation = considered[-1]
    accepted = latest.accepted_proposal
    if accepted is None:
        return result(
            VerificationStatus.PENDING,
            (
                f"{len(considered)} negotiation(s) observed, but the responder's reply "
                f"was not captured, so what was agreed is unknown. Capture both "
                f"directions to verify."
            ),
            observed_at=latest.started_at,
            overdue=_is_overdue(changed_at, sa_lifetime_s, now),
        )

    if not matches(accepted, expected):
        return result(
            VerificationStatus.FAILED,
            (
                f"the negotiation at {latest.started_at.isoformat()} selected "
                f"{describe(accepted)}, not the target {describe(expected)}. The "
                f"finding stays open."
            ),
            observed_at=latest.started_at,
        )

    residual = [
        describe(offered)
        for offered in latest.representative.proposals_offered
        if any(matches(offered, gone) for gone in superseded)
    ]
    if residual:
        return result(
            VerificationStatus.PARTIAL,
            (
                f"the negotiation at {latest.started_at.isoformat()} selected the target "
                f"{describe(expected)}, but {', '.join(residual)} is still offered. A "
                f"peer that offers only the weaker proposal will still be accepted, so "
                f"the downgrade path is open and the finding stays open with it. "
                f"Complete the removal step."
            ),
            observed_at=latest.started_at,
            residual=residual,
        )

    removal = (
        "and no superseded proposal remains on offer"
        if superseded
        else "no superseded proposal was named, so residual offers were not checked"
    )
    return result(
        VerificationStatus.VERIFIED,
        (
            f"the negotiation at {latest.started_at.isoformat()} selected the target "
            f"{describe(expected)} {removal}."
        ),
        observed_at=latest.started_at,
    )


def _deadline(changed_at: datetime | None, sa_lifetime_s: int | None) -> datetime | None:
    if changed_at is None or sa_lifetime_s is None:
        return None
    return changed_at + timedelta(seconds=sa_lifetime_s)


def _is_overdue(
    changed_at: datetime | None, sa_lifetime_s: int | None, now: datetime | None
) -> bool:
    deadline = _deadline(changed_at, sa_lifetime_s)
    return deadline is not None and now is not None and now > deadline


def _deadline_note(
    changed_at: datetime | None, sa_lifetime_s: int | None, now: datetime | None
) -> str:
    deadline = _deadline(changed_at, sa_lifetime_s)
    if deadline is None:
        return ""
    if now is not None and now > deadline:
        return (
            f" The SA lifetime of {sa_lifetime_s}s has elapsed and a rekey should have "
            f"happened by {deadline.isoformat()}; that it has not is itself worth "
            f"investigating."
        )
    return f" A rekey is expected by {deadline.isoformat()}."
