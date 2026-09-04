"""Tests for the core domain models (build plan Step 0.6).

The invariant under test throughout: **facts are parsed, estimates are inferred.**
`Finding.confidence is None` marks a deterministic, parsed fact; a non-None confidence
marks an inference. Nothing in the codebase may blur the two.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from ipsec_sentinel.models import (
    Confidence,
    ESPFlow,
    Finding,
    IKEExchange,
    Proposal,
    Severity,
    Transform,
    TransformType,
    TunnelAssessment,
    sort_findings,
)

TS = datetime(2026, 9, 5, 12, 30, tzinfo=UTC)


def make_finding(rule_id: str = "CRY-02", **kw: object) -> Finding:
    base: dict[str, object] = {
        "rule_id": rule_id,
        "title": "Diffie-Hellman group 2 (1024-bit MODP)",
        "severity": Severity.CRITICAL,
        "evidence": "Proposal 1 of 3 offered DH group 2",
        "standard_ref": "RFC 8247 §4",
        "remediation_hint": "Use group 19, 20 or 31",
    }
    base.update(kw)
    return Finding(**base)  # type: ignore[arg-type]


class TestSeverityOrdering:
    def test_critical_ranks_first(self) -> None:
        assert Severity.CRITICAL.rank == 0

    def test_rank_is_strictly_increasing_by_decreasing_urgency(self) -> None:
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        ranks = [s.rank for s in order]
        assert ranks == sorted(ranks)
        assert len(set(ranks)) == len(ranks)

    def test_sort_findings_puts_critical_first(self) -> None:
        findings = [
            make_finding("SA-02", severity=Severity.LOW),
            make_finding("CRY-05", severity=Severity.CRITICAL),
            make_finding("PFS-01", severity=Severity.HIGH),
            make_finding("CFG-01", severity=Severity.INFO),
            make_finding("SA-01", severity=Severity.MEDIUM),
        ]
        assert [f.severity for f in sort_findings(findings)] == [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]

    def test_sort_is_stable_within_a_severity(self) -> None:
        findings = [make_finding("CRY-01"), make_finding("CRY-02"), make_finding("CRY-04")]
        assert [f.rule_id for f in sort_findings(findings)] == ["CRY-01", "CRY-02", "CRY-04"]

    def test_sort_does_not_mutate_the_input(self) -> None:
        findings = [make_finding("SA-02", severity=Severity.LOW), make_finding("CRY-05")]
        before = list(findings)
        sort_findings(findings)
        assert findings == before

    def test_severity_is_a_string_enum(self) -> None:
        assert Severity.INFO.value == "informational"
        assert Severity("critical") is Severity.CRITICAL


class TestConfidence:
    @pytest.mark.parametrize("value", [0.0, 0.5, 1.0])
    def test_accepts_values_inside_the_unit_interval(self, value: float) -> None:
        assert Confidence(value=value, method="isotonic").value == value

    @pytest.mark.parametrize("value", [-0.01, 1.01, 2.0, -1.0])
    def test_rejects_values_outside_the_unit_interval(self, value: float) -> None:
        with pytest.raises(ValidationError):
            Confidence(value=value, method="isotonic")

    def test_method_is_required(self) -> None:
        """An estimate without a stated method is not auditable."""
        with pytest.raises(ValidationError):
            Confidence(value=0.8)  # type: ignore[call-arg]

    def test_abstained_defaults_to_false(self) -> None:
        assert Confidence(value=0.8, method="rf").abstained is False


class TestFindingDeterminism:
    def test_finding_without_confidence_is_deterministic(self) -> None:
        assert make_finding().is_deterministic is True

    def test_finding_with_confidence_is_not_deterministic(self) -> None:
        f = make_finding(confidence=Confidence(value=0.81, method="isolation_forest"))
        assert f.is_deterministic is False

    def test_confidence_defaults_to_none(self) -> None:
        """Rule-engine findings must be deterministic unless they opt in."""
        assert make_finding().confidence is None

    def test_is_deterministic_is_exactly_the_confidence_is_none_test(self) -> None:
        for conf in (None, Confidence(value=0.0, method="m"), Confidence(value=1.0, method="m")):
            assert make_finding(confidence=conf).is_deterministic is (conf is None)


class TestInferencePairing:
    """An inference without a confidence is a category error; so is the reverse."""

    def _assessment(self, **kw: object) -> TunnelAssessment:
        base: dict[str, object] = {
            "tunnel_id": "t-001",
            "endpoints": ("203.0.113.1", "198.51.100.1"),
            "ike": None,
            "esp_flows": [],
            "findings": [],
            "score": 100,
            "grade": "A",
        }
        base.update(kw)
        return TunnelAssessment(**base)  # type: ignore[arg-type]

    def test_inferred_mode_requires_a_confidence(self) -> None:
        with pytest.raises(ValidationError, match="inferred_mode"):
            self._assessment(inferred_mode="tunnel")

    def test_inferred_mode_confidence_requires_a_value(self) -> None:
        with pytest.raises(ValidationError, match="inferred_mode"):
            self._assessment(inferred_mode_confidence=Confidence(value=0.9, method="rf"))

    def test_inferred_traffic_requires_a_confidence(self) -> None:
        with pytest.raises(ValidationError, match="inferred_traffic"):
            self._assessment(inferred_traffic="voip")

    def test_inferred_traffic_confidence_requires_a_value(self) -> None:
        with pytest.raises(ValidationError, match="inferred_traffic"):
            self._assessment(inferred_traffic_confidence=Confidence(value=0.9, method="rf"))

    def test_both_set_together_is_valid(self) -> None:
        a = self._assessment(
            inferred_mode="tunnel",
            inferred_mode_confidence=Confidence(value=0.88, method="rf"),
            inferred_traffic="voip",
            inferred_traffic_confidence=Confidence(value=0.81, method="rf"),
        )
        assert a.inferred_mode == "tunnel"

    def test_neither_set_is_valid(self) -> None:
        assert self._assessment().inferred_mode is None


class TestScoreAndGrade:
    def _assessment(self, **kw: object) -> TunnelAssessment:
        base: dict[str, object] = {
            "tunnel_id": "t-001",
            "endpoints": ("203.0.113.1", "198.51.100.1"),
            "ike": None,
            "esp_flows": [],
            "findings": [],
            "score": 100,
            "grade": "A",
        }
        base.update(kw)
        return TunnelAssessment(**base)  # type: ignore[arg-type]

    @pytest.mark.parametrize("score", [-1, 101, 1000])
    def test_score_must_be_within_zero_to_one_hundred(self, score: int) -> None:
        with pytest.raises(ValidationError):
            self._assessment(score=score)

    @pytest.mark.parametrize("grade", ["A", "B", "C", "D", "F"])
    def test_valid_grades_accepted(self, grade: str) -> None:
        assert self._assessment(grade=grade).grade == grade

    @pytest.mark.parametrize("grade", ["G", "AA", "a", "", "1"])
    def test_invalid_grades_rejected(self, grade: str) -> None:
        with pytest.raises(ValidationError):
            self._assessment(grade=grade)


class TestRoundTrip:
    def _exchange(self) -> IKEExchange:
        weak = Proposal(
            number=1,
            protocol="IKE",
            transforms=[
                Transform(type=TransformType.ENCR, id=3, name="ENCR_3DES"),
                Transform(type=TransformType.INTEG, id=1, name="AUTH_HMAC_MD5_96"),
                Transform(type=TransformType.DH, id=2, name="1024-bit MODP"),
            ],
        )
        strong = Proposal(
            number=2,
            protocol="IKE",
            transforms=[
                Transform(type=TransformType.ENCR, id=20, name="ENCR_AES_GCM_16", key_length=256),
                Transform(type=TransformType.DH, id=20, name="384-bit ECP"),
            ],
        )
        return IKEExchange(
            initiator_spi="1122334455667788",
            responder_spi="99aabbccddeeff00",
            version="IKEv1",
            exchange_type="Aggressive Mode",
            is_aggressive=True,
            proposals_offered=[weak, strong],
            proposal_accepted=weak,
            ke_group_from_length=2,
            vendor_ids=["4f45"],
            notifies=["NAT_DETECTION_SOURCE_IP"],
            timestamp=TS,
            src_ip="203.0.113.1",
            dst_ip="198.51.100.1",
        )

    def _assessment(self) -> TunnelAssessment:
        return TunnelAssessment(
            tunnel_id="t-001",
            endpoints=("203.0.113.1", "198.51.100.1"),
            ike=self._exchange(),
            esp_flows=[
                ESPFlow(
                    spi="a1b2c3d4",
                    src_ip="203.0.113.1",
                    dst_ip="198.51.100.1",
                    packet_count=4096,
                    byte_count=5_242_880,
                    first_seen=TS,
                    last_seen=TS,
                    sequence_gaps=3,
                    replay_suspected=False,
                )
            ],
            findings=[
                make_finding(),
                make_finding(
                    "CFG-01",
                    severity=Severity.INFO,
                    confidence=Confidence(value=0.73, method="isolation_forest"),
                ),
            ],
            score=23,
            grade="F",
            inferred_mode="tunnel",
            inferred_mode_confidence=Confidence(value=0.88, method="rf"),
            inferred_traffic="voip",
            inferred_traffic_confidence=Confidence(value=0.81, method="rf", abstained=False),
        )

    def test_assessment_round_trips_through_json_unchanged(self) -> None:
        original = self._assessment()
        restored = TunnelAssessment.model_validate_json(original.model_dump_json())
        assert restored == original

    def test_round_trip_preserves_the_deterministic_split(self) -> None:
        """The parsed/inferred distinction must survive serialisation."""
        restored = TunnelAssessment.model_validate_json(self._assessment().model_dump_json())
        assert [f.is_deterministic for f in restored.findings] == [True, False]

    def test_json_is_actually_valid_json(self) -> None:
        payload = json.loads(self._assessment().model_dump_json())
        assert payload["grade"] == "F"
        assert payload["findings"][0]["confidence"] is None
        assert payload["findings"][1]["confidence"]["value"] == 0.73

    def test_exchange_round_trips(self) -> None:
        original = self._exchange()
        assert IKEExchange.model_validate_json(original.model_dump_json()) == original

    def test_all_offered_proposals_survive_round_trip(self) -> None:
        """Auditing every offered proposal is the point; none may be dropped."""
        restored = IKEExchange.model_validate_json(self._exchange().model_dump_json())
        assert len(restored.proposals_offered) == 2
        assert [p.number for p in restored.proposals_offered] == [1, 2]


class TestTransform:
    def test_key_length_defaults_to_none(self) -> None:
        assert Transform(type=TransformType.ENCR, id=3, name="ENCR_3DES").key_length is None

    def test_key_length_distinguishes_aes_128_from_aes_256(self) -> None:
        """Same transform ID, different attribute — the reason we parse to attribute level."""
        aes128 = Transform(type=TransformType.ENCR, id=12, name="ENCR_AES_CBC", key_length=128)
        aes256 = Transform(type=TransformType.ENCR, id=12, name="ENCR_AES_CBC", key_length=256)
        assert aes128 != aes256

    def test_transform_type_values(self) -> None:
        assert {t.value for t in TransformType} == {"ENCR", "PRF", "INTEG", "DH", "ESN"}


class TestESPFlow:
    def test_esp_spi_is_distinct_from_ike_spi_width(self) -> None:
        """4-byte ESP SPI vs 8-byte IKE SPI — conflating them is a classic bug."""
        flow = ESPFlow(
            spi="a1b2c3d4",
            src_ip="203.0.113.1",
            dst_ip="198.51.100.1",
            packet_count=1,
            byte_count=100,
            first_seen=TS,
            last_seen=TS,
            sequence_gaps=0,
            replay_suspected=False,
        )
        assert len(flow.spi) == 8
