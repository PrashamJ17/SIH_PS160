"""Tests for post-quantum readiness grading (build plan Step 6.5)."""

from __future__ import annotations

import itertools
from datetime import UTC, datetime

import pytest

from ipsec_sentinel.assess.rules.pqc import (
    PQC_01,
    PQCGrade,
    grade_pqc,
    uses_post_quantum_psk,
)
from ipsec_sentinel.models import (
    IKEExchange,
    ObservedConfig,
    Proposal,
    Severity,
    Transform,
    TransformType,
)
from ipsec_sentinel.parser.correlate import Tunnel, correlate

BASE = datetime(2026, 9, 6, 12, 0, 0, tzinfo=UTC)

AES_GCM = Transform(type=TransformType.ENCR, id=20, name="ENCR_AES_GCM_16", key_length=256)
ECP256 = Transform(type=TransformType.DH, id=19, name="256-bit ECP")
MODP2048 = Transform(type=TransformType.DH, id=14, name="2048-bit MODP")
MLKEM768_ADDKE = Transform(type=TransformType.ADDKE1, id=36, name="ML-KEM-768")
MLKEM1024_DH = Transform(type=TransformType.DH, id=37, name="ML-KEM-1024")


def build(
    transforms: list[Transform],
    pfs: bool | None = None,
    notifies: list[str] | None = None,
) -> Tunnel:
    exchange = IKEExchange(
        initiator_spi="11" * 8,
        responder_spi="00" * 8,
        version="IKEv2",
        exchange_type="IKE_SA_INIT",
        proposals_offered=[Proposal(number=1, protocol="IKE", transforms=transforms)],
        notifies=notifies or [],
        timestamp=BASE,
        src_ip="192.0.2.1",
        dst_ip="192.0.2.2",
    )
    tunnel = correlate([exchange], [])[0]
    if pfs is not None:
        tunnel.config = ObservedConfig(pfs_enabled=pfs)
    return tunnel


class TestReady:
    def test_an_ml_kem_additional_key_exchange_is_ready(self) -> None:
        assessment = grade_pqc(build([AES_GCM, ECP256, MLKEM768_ADDKE]))
        assert assessment.grade is PQCGrade.READY
        assert "ML-KEM-768" in assessment.rationale

    def test_ml_kem_in_the_dh_slot_is_ready(self) -> None:
        assert grade_pqc(build([AES_GCM, MLKEM1024_DH])).grade is PQCGrade.READY

    def test_ready_records_both_group_families(self) -> None:
        """A hybrid keeps the classical group deliberately; both belong in evidence."""
        assessment = grade_pqc(build([AES_GCM, ECP256, MLKEM768_ADDKE]))
        assert assessment.post_quantum_groups == ("ML-KEM-768",)
        assert assessment.classical_groups == ("256-bit ECP",)

    def test_pfs_does_not_downgrade_a_ready_tunnel(self) -> None:
        """A post-quantum exchange is not retroactively breakable either way."""
        assert grade_pqc(build([MLKEM768_ADDKE], pfs=False)).grade is PQCGrade.READY


class TestTransitional:
    def test_a_post_quantum_psk_is_transitional(self) -> None:
        assessment = grade_pqc(build([AES_GCM, ECP256], notifies=["USE_PPK"]))
        assert assessment.grade is PQCGrade.TRANSITIONAL
        assert "RFC 8784" in assessment.rationale

    def test_the_notify_is_detected_on_the_negotiation(self) -> None:
        assert uses_post_quantum_psk(build([ECP256], notifies=["USE_PPK"])) is True
        assert uses_post_quantum_psk(build([ECP256])) is False

    def test_an_unrelated_notify_does_not_count(self) -> None:
        tunnel = build([AES_GCM, ECP256], notifies=["NAT_DETECTION_SOURCE_IP"])
        assert grade_pqc(tunnel).grade is PQCGrade.AT_RISK

    def test_a_real_key_exchange_outranks_a_psk(self) -> None:
        tunnel = build([AES_GCM, ECP256, MLKEM768_ADDKE], notifies=["USE_PPK"])
        assert grade_pqc(tunnel).grade is PQCGrade.READY


class TestAtRiskAndExposed:
    def test_classical_with_pfs_enabled_is_at_risk(self) -> None:
        assessment = grade_pqc(build([AES_GCM, ECP256], pfs=True))
        assert assessment.grade is PQCGrade.AT_RISK
        assert assessment.pfs_known is True

    def test_classical_with_pfs_disabled_is_exposed(self) -> None:
        assessment = grade_pqc(build([AES_GCM, ECP256], pfs=False))
        assert assessment.grade is PQCGrade.EXPOSED
        assert "forward secrecy disabled" in assessment.rationale

    def test_a_large_classical_group_is_still_at_risk(self) -> None:
        """Shor's algorithm does not care how large the modulus is."""
        assert grade_pqc(build([AES_GCM, MODP2048], pfs=True)).grade is PQCGrade.AT_RISK

    def test_unknown_pfs_grades_at_risk_and_says_exposed_is_not_excluded(self) -> None:
        """Grading down on missing information under-claims rather than invents."""
        assessment = grade_pqc(build([AES_GCM, ECP256]))
        assert assessment.grade is PQCGrade.AT_RISK
        assert assessment.pfs_known is False
        assert "EXPOSED cannot be excluded" in assessment.rationale

    def test_pfs_does_not_rescue_a_classical_exchange(self) -> None:
        assessment = grade_pqc(build([AES_GCM, ECP256], pfs=True))
        assert "does not survive the exchange itself being broken" in assessment.rationale

    def test_no_key_exchange_transform_grades_at_risk(self) -> None:
        assessment = grade_pqc(build([AES_GCM]))
        assert assessment.grade is PQCGrade.AT_RISK
        assert "cannot be established" in assessment.rationale


ORDER = [PQCGrade.EXPOSED, PQCGrade.AT_RISK, PQCGrade.TRANSITIONAL, PQCGrade.READY]


class TestGradeOrdering:
    """The ordering must be total and stable, not an accident of declaration order."""

    def test_ranks_are_distinct_and_ordered(self) -> None:
        ranks = [grade.rank for grade in ORDER]
        assert ranks == sorted(ranks)
        assert len(set(ranks)) == len(ORDER)

    def test_every_grade_has_a_rank(self) -> None:
        assert {grade.rank for grade in PQCGrade} == {0, 1, 2, 3}

    def test_comparison_orders_worst_first(self) -> None:
        assert PQCGrade.EXPOSED < PQCGrade.AT_RISK
        assert PQCGrade.AT_RISK < PQCGrade.READY

    def test_the_ordering_is_total(self) -> None:
        for left, right in itertools.combinations(ORDER, 2):
            assert (left < right) != (right < left)

    def test_sorting_is_stable_and_puts_the_worst_first(self) -> None:
        assert sorted([PQCGrade.READY, PQCGrade.EXPOSED, PQCGrade.AT_RISK]) == [
            PQCGrade.EXPOSED,
            PQCGrade.AT_RISK,
            PQCGrade.READY,
        ]

    def test_comparison_with_a_non_grade_is_not_implemented(self) -> None:
        with pytest.raises(TypeError):
            _ = PQCGrade.READY < 3  # type: ignore[operator]


class TestPQCRule:
    def test_it_fires_on_a_classical_tunnel(self) -> None:
        finding = PQC_01.evaluate(build([AES_GCM, ECP256], pfs=True))
        assert finding is not None
        assert finding.severity is Severity.MEDIUM
        assert finding.confidence is None

    def test_exposed_is_escalated_to_high(self) -> None:
        finding = PQC_01.evaluate(build([AES_GCM, ECP256], pfs=False))
        assert finding is not None
        assert finding.severity is Severity.HIGH

    def test_it_is_silent_on_a_ready_tunnel(self) -> None:
        assert PQC_01.evaluate(build([AES_GCM, MLKEM768_ADDKE])) is None

    def test_it_is_silent_on_a_transitional_tunnel(self) -> None:
        assert PQC_01.evaluate(build([AES_GCM, ECP256], notifies=["USE_PPK"])) is None

    def test_the_title_names_the_grade(self) -> None:
        finding = PQC_01.evaluate(build([AES_GCM, ECP256], pfs=False))
        assert finding is not None
        assert "exposed" in finding.title

    def test_it_is_silent_on_an_orphan_tunnel(self) -> None:
        assert PQC_01.evaluate(Tunnel(tunnel_id="x", endpoints=("a", "b"))) is None

    def test_the_remediation_says_later_fixes_do_not_reach_recorded_traffic(self) -> None:
        assert "does not protect traffic recorded today" in PQC_01.remediation_hint
