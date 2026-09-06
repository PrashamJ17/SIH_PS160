"""Tests for automatic fix verification (build plan Step 8.6).

The plan's three cases are :class:`TestThePlansCriteria`. The rest guard the way this
can be wrong in the dangerous direction — closing a finding on evidence that only looks
like success. Every path that is not fully verified must leave the finding open, and a
model validator enforces that independently of the logic that chose the status.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from itertools import count

import pytest
from pydantic import ValidationError

from ipsec_sentinel.models import IKEExchange, Proposal, Transform, TransformType
from ipsec_sentinel.remediate.verify import (
    VerificationResult,
    VerificationStatus,
    describe,
    matches,
    transform_keys,
    verify_remediation,
)

CHANGED_AT = datetime(2026, 5, 1, 10, 0, tzinfo=UTC)
FINDINGS = ["CRY-02", "CRY-06"]


def proposal(
    encr: str = "AES_CBC",
    key_length: int | None = 256,
    integ: str = "HMAC_SHA2_256_128",
    dh: str = "CURVE_25519",
    *,
    number: int = 1,
    esn: bool = False,
) -> Proposal:
    transforms = [
        Transform(type=TransformType.ENCR, id=12, name=encr, key_length=key_length),
        Transform(type=TransformType.INTEG, id=12, name=integ),
        Transform(type=TransformType.DH, id=31, name=dh),
    ]
    if esn:
        transforms.append(Transform(type=TransformType.ESN, id=0, name="NO_ESN"))
    return Proposal(number=number, protocol="IKE", transforms=transforms)


WEAK = proposal(encr="3DES", key_length=None, integ="HMAC_MD5_96", dh="MODP_1024")
TARGET = proposal()


ZERO_SPI = "00" * 8
_next_spi = count(1)


def exchange(
    accepted: Proposal | None = TARGET,
    offered: list[Proposal] | None = None,
    *,
    at: datetime = CHANGED_AT + timedelta(minutes=5),
) -> list[IKEExchange]:
    """One negotiation, as the parser actually delivers it: a message per direction.

    ``extract_ike_exchanges`` yields one :class:`IKEExchange` per IKE *message*, and
    ``IKEExchange.proposal_accepted`` is never populated by the parser. The offer list
    lives in the initiator's opening message and the agreed proposal in the responder's
    reply, so a helper that set both on one object would be testing against something
    the wire never produces — which is exactly how the first version of this module came
    to depend on a field that is always ``None``.

    ``accepted=None`` models a capture that missed the responder's reply.
    """
    initiator_spi = f"{next(_next_spi):016x}"
    offers = offered if offered is not None else ([accepted] if accepted is not None else [])
    messages = [
        IKEExchange(
            initiator_spi=initiator_spi,
            responder_spi=ZERO_SPI,
            version="IKEv2",
            exchange_type="IKE_SA_INIT",
            proposals_offered=offers,
            timestamp=at,
            src_ip="203.0.113.1",
            dst_ip="198.51.100.1",
        )
    ]
    if accepted is not None:
        messages.append(
            IKEExchange(
                initiator_spi=initiator_spi,
                responder_spi="2222222222222222",
                version="IKEv2",
                exchange_type="IKE_SA_INIT",
                proposals_offered=[accepted],
                timestamp=at + timedelta(milliseconds=2),
                src_ip="198.51.100.1",
                dst_ip="203.0.113.1",
            )
        )
    return messages


class TestThePlansCriteria:
    def test_a_new_exchange_matching_the_target_verifies_and_closes(self) -> None:
        result = verify_remediation("t1", TARGET, exchange(), findings_addressed=FINDINGS)
        assert result.status is VerificationStatus.VERIFIED
        assert result.verified is True
        assert result.findings_closed == FINDINGS
        assert result.findings_still_open == []

    def test_a_new_exchange_still_weak_fails_and_the_finding_stays_open(self) -> None:
        result = verify_remediation(
            "t1", TARGET, exchange(accepted=WEAK), findings_addressed=FINDINGS
        )
        assert result.status is VerificationStatus.FAILED
        assert result.verified is False
        assert result.findings_closed == []
        assert result.findings_still_open == FINDINGS
        assert "3DES" in result.evidence

    def test_no_new_exchange_is_pending(self) -> None:
        result = verify_remediation("t1", TARGET, [], findings_addressed=FINDINGS)
        assert result.status is VerificationStatus.PENDING
        assert result.findings_still_open == FINDINGS
        assert "not evidence the change failed" in result.evidence


class TestThePartialCase:
    """The state Step 8.4's sequence passes through between steps 2 and 3."""

    def test_the_target_in_use_with_the_old_one_still_offered_is_not_verified(self) -> None:
        result = verify_remediation(
            "t1",
            TARGET,
            exchange(accepted=TARGET, offered=[TARGET, WEAK]),
            findings_addressed=FINDINGS,
            superseded=[WEAK],
        )
        assert result.status is VerificationStatus.PARTIAL
        assert result.findings_closed == []
        assert result.findings_still_open == FINDINGS

    def test_it_says_what_remains_and_why_it_matters(self) -> None:
        result = verify_remediation(
            "t1",
            TARGET,
            exchange(accepted=TARGET, offered=[TARGET, WEAK]),
            superseded=[WEAK],
        )
        assert result.residual_offers == [describe(WEAK)]
        assert "downgrade path is open" in result.evidence
        assert "Complete the removal step" in result.evidence

    def test_removing_the_old_offer_completes_the_verification(self) -> None:
        """Step 3 of the sequence, seen from the wire."""
        result = verify_remediation(
            "t1",
            TARGET,
            exchange(accepted=TARGET, offered=[TARGET]),
            findings_addressed=FINDINGS,
            superseded=[WEAK],
        )
        assert result.status is VerificationStatus.VERIFIED
        assert result.findings_closed == FINDINGS

    def test_an_unrelated_extra_offer_is_not_a_residual(self) -> None:
        """Only proposals the change undertook to remove count against it."""
        other = proposal(encr="AES_GCM_16", key_length=256, integ="NONE", dh="ECP_384")
        result = verify_remediation(
            "t1",
            TARGET,
            exchange(accepted=TARGET, offered=[TARGET, other]),
            superseded=[WEAK],
        )
        assert result.status is VerificationStatus.VERIFIED

    def test_naming_nothing_to_remove_is_stated_rather_than_passed_over(self) -> None:
        result = verify_remediation("t1", TARGET, exchange(offered=[TARGET, WEAK]))
        assert result.status is VerificationStatus.VERIFIED
        assert "residual offers were not checked" in result.evidence


class TestOnlyAVerifiedChangeCloses:
    def test_the_model_refuses_to_close_on_a_partial_status(self) -> None:
        """Enforced in the model, so a future caller cannot route around the logic."""
        with pytest.raises(ValidationError, match="only a verified change closes"):
            VerificationResult(
                tunnel_id="t1",
                status=VerificationStatus.PARTIAL,
                findings_closed=["CRY-02"],
                evidence="x",
            )

    @pytest.mark.parametrize(
        "status",
        [VerificationStatus.FAILED, VerificationStatus.PENDING, VerificationStatus.PARTIAL],
    )
    def test_no_unverified_status_may_close_anything(self, status: VerificationStatus) -> None:
        with pytest.raises(ValidationError, match="only a verified change closes"):
            VerificationResult(tunnel_id="t1", status=status, findings_closed=["X"], evidence="x")

    def test_a_finding_cannot_be_both_closed_and_open(self) -> None:
        with pytest.raises(ValidationError, match="both closed and open"):
            VerificationResult(
                tunnel_id="t1",
                status=VerificationStatus.VERIFIED,
                findings_closed=["CRY-02"],
                findings_still_open=["CRY-02"],
                evidence="x",
            )


class TestWhatCountsAsANewExchange:
    def test_an_exchange_from_before_the_change_is_not_evidence(self) -> None:
        """It describes the state the change was meant to correct."""
        stale = exchange(accepted=WEAK, at=CHANGED_AT - timedelta(hours=1))
        result = verify_remediation(
            "t1", TARGET, stale, findings_addressed=FINDINGS, changed_at=CHANGED_AT
        )
        assert result.status is VerificationStatus.PENDING
        assert result.negotiations_considered == 0

    def test_the_most_recent_exchange_decides(self) -> None:
        """A tunnel that failed and was then fixed is fixed."""
        result = verify_remediation(
            "t1",
            TARGET,
            [
                *exchange(accepted=TARGET, at=CHANGED_AT + timedelta(minutes=9)),
                *exchange(accepted=WEAK, at=CHANGED_AT + timedelta(minutes=1)),
            ],
            findings_addressed=FINDINGS,
            changed_at=CHANGED_AT,
        )
        assert result.status is VerificationStatus.VERIFIED
        assert result.observed_at == CHANGED_AT + timedelta(minutes=9)
        assert result.negotiations_considered == 2

    def test_an_exchange_with_no_accepted_proposal_is_pending_not_failed(self) -> None:
        """Half a capture cannot say what was agreed."""
        result = verify_remediation(
            "t1", TARGET, exchange(accepted=None, offered=[TARGET]), findings_addressed=FINDINGS
        )
        assert result.status is VerificationStatus.PENDING
        assert "responder's reply was not captured" in result.evidence


class TestTheRekeyDeadline:
    def test_a_rekey_that_has_not_happened_yet_is_simply_pending(self) -> None:
        result = verify_remediation(
            "t1",
            TARGET,
            [],
            changed_at=CHANGED_AT,
            sa_lifetime_s=3600,
            now=CHANGED_AT + timedelta(minutes=10),
        )
        assert result.status is VerificationStatus.PENDING
        assert result.overdue is False
        assert "A rekey is expected by" in result.evidence

    def test_a_rekey_that_should_have_happened_is_flagged(self) -> None:
        result = verify_remediation(
            "t1",
            TARGET,
            [],
            changed_at=CHANGED_AT,
            sa_lifetime_s=3600,
            now=CHANGED_AT + timedelta(hours=4),
        )
        assert result.status is VerificationStatus.PENDING
        assert result.overdue is True
        assert "should have happened" in result.evidence

    def test_without_a_lifetime_no_deadline_is_invented(self) -> None:
        result = verify_remediation("t1", TARGET, [], changed_at=CHANGED_AT)
        assert result.overdue is False
        assert "expected by" not in result.evidence


class TestProposalMatching:
    def test_key_length_is_part_of_the_identity(self) -> None:
        """AES-128 and AES-256 are the same transform ID and differ by an attribute.

        A comparison that dropped the key length would report a 128-bit tunnel as
        matching a 256-bit target — the exact mistake the parser was built to avoid.
        """
        assert matches(proposal(key_length=128), proposal(key_length=256)) is False
        assert matches(proposal(key_length=256), proposal(key_length=256)) is True

    def test_a_transform_type_the_target_is_silent_about_does_not_block_a_match(self) -> None:
        assert matches(proposal(esn=True), TARGET) is True

    def test_a_missing_transform_blocks_a_match(self) -> None:
        stripped = Proposal(
            number=1,
            protocol="IKE",
            transforms=[Transform(type=TransformType.ENCR, id=12, name="AES_CBC", key_length=256)],
        )
        assert matches(stripped, TARGET) is False

    def test_an_empty_target_matches_nothing(self) -> None:
        """Otherwise a target that failed to parse would verify every tunnel."""
        empty = Proposal(number=1, protocol="IKE", transforms=[])
        assert matches(TARGET, empty) is False
        assert matches(empty, empty) is False

    def test_an_unrecognised_transform_still_participates(self) -> None:
        unknown = Proposal(
            number=1, protocol="IKE", transforms=[Transform(type=None, id=99, name="?")]
        )
        assert transform_keys(unknown) == frozenset({("unknown:99", "?", None)})

    def test_describe_renders_key_lengths(self) -> None:
        assert describe(TARGET) == "AES_CBC-256/HMAC_SHA2_256_128/CURVE_25519"
        assert describe(Proposal(number=1, protocol="IKE", transforms=[])) == "(no transforms)"
