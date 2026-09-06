"""Tests for scoring and grading (build plan Step 6.7)."""

from __future__ import annotations

import itertools

import pytest

from ipsec_sentinel.assess.scoring import (
    GRADE_THRESHOLDS,
    SEVERITY_WEIGHTS,
    EstateScore,
    grade_for,
    penalty_for,
    score_estate,
    score_tunnel,
)
from ipsec_sentinel.models import Finding, Severity, TunnelAssessment


def finding(severity: Severity, rule_id: str = "TST-01") -> Finding:
    return Finding(
        rule_id=rule_id,
        title="stub",
        severity=severity,
        evidence="stub evidence",
        standard_ref="stub",
        remediation_hint="stub",
    )


def assessment(tunnel_id: str, score: int, grade: str) -> TunnelAssessment:
    return TunnelAssessment(
        tunnel_id=tunnel_id,
        endpoints=("192.0.2.1", "192.0.2.2"),
        score=score,
        grade=grade,
    )


class TestPlanCases:
    """The exact cases the build plan names."""

    def test_no_findings_scores_100_grade_a(self) -> None:
        assert score_tunnel([]) == (100, "A")

    def test_one_critical_scores_60_grade_d(self) -> None:
        assert score_tunnel([finding(Severity.CRITICAL)]) == (60, "D")

    def test_three_criticals_floor_at_zero_grade_f(self) -> None:
        assert score_tunnel([finding(Severity.CRITICAL)] * 3) == (0, "F")

    def test_estate_score_of_one_tunnel_equals_that_tunnel(self) -> None:
        estate = score_estate([assessment("t1", 60, "D")])
        assert estate.score == 60
        assert estate.grade == "D"


class TestMonotonicity:
    def test_adding_a_finding_never_increases_the_score(self) -> None:
        """A score must not improve because the tool looked harder."""
        findings: list[Finding] = []
        previous = 100
        for severity in itertools.islice(itertools.cycle(Severity), 12):
            findings.append(finding(severity))
            current, _ = score_tunnel(findings)
            assert current <= previous
            previous = current

    def test_a_worse_severity_never_scores_higher(self) -> None:
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        scores = [score_tunnel([finding(s)])[0] for s in order]
        assert scores == sorted(scores, reverse=True)

    def test_the_score_never_goes_below_zero(self) -> None:
        assert score_tunnel([finding(Severity.CRITICAL)] * 50)[0] == 0

    def test_the_score_never_exceeds_one_hundred(self) -> None:
        assert score_tunnel([])[0] == 100


class TestWeights:
    def test_the_documented_weights_are_the_implemented_ones(self) -> None:
        """docs/SCORING.md states these; a drift between them is a lie in the report."""
        assert SEVERITY_WEIGHTS == {
            Severity.CRITICAL: 40,
            Severity.HIGH: 20,
            Severity.MEDIUM: 8,
            Severity.LOW: 3,
            Severity.INFO: 0,
        }

    def test_informational_findings_cost_nothing(self) -> None:
        assert score_tunnel([finding(Severity.INFO)] * 20) == (100, "A")

    def test_five_highs_outweigh_one_critical(self) -> None:
        """Intended: five serious weaknesses are worse than one critical one."""
        five_highs = penalty_for([finding(Severity.HIGH)] * 5)
        one_critical = penalty_for([finding(Severity.CRITICAL)])
        assert five_highs > one_critical

    def test_each_level_is_worth_more_than_the_one_below(self) -> None:
        weights = [
            SEVERITY_WEIGHTS[s]
            for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
        ]
        assert weights == sorted(weights, reverse=True)
        assert len(set(weights)) == len(weights)

    def test_every_severity_has_a_weight(self) -> None:
        for severity in Severity:
            assert severity in SEVERITY_WEIGHTS


class TestGrades:
    @pytest.mark.parametrize(
        ("score", "expected"),
        [
            (100, "A"),
            (90, "A"),
            (89, "B"),
            (80, "B"),
            (79, "C"),
            (70, "C"),
            (69, "D"),
            (60, "D"),
            (59, "F"),
            (0, "F"),
        ],
    )
    def test_grade_boundaries(self, score: int, expected: str) -> None:
        assert grade_for(score) == expected

    def test_the_bands_are_contiguous_and_descending(self) -> None:
        thresholds = [t for t, _ in GRADE_THRESHOLDS]
        assert thresholds == sorted(thresholds, reverse=True)
        assert thresholds[-1] == 0, "every score must map to a grade"

    def test_one_critical_is_failing_but_not_the_worst(self) -> None:
        """The distinction the weighting exists to preserve."""
        one, _ = score_tunnel([finding(Severity.CRITICAL)])
        three, _ = score_tunnel([finding(Severity.CRITICAL)] * 3)
        assert one > three
        assert grade_for(one) != grade_for(three)


class TestEstateScoring:
    def test_an_empty_estate_scores_100(self) -> None:
        estate = score_estate([])
        assert estate.score == 100
        assert estate.tunnel_count == 0

    def test_the_unweighted_estate_is_the_mean(self) -> None:
        estate = score_estate([assessment("a", 100, "A"), assessment("b", 60, "D")])
        assert estate.score == 80

    def test_the_distribution_is_carried_alongside_the_mean(self) -> None:
        """Forty healthy tunnels and one catastrophe average to a comfortable number."""
        tunnels = [assessment(f"t{i}", 100, "A") for i in range(40)]
        tunnels.append(assessment("bad", 0, "F"))
        estate = score_estate(tunnels)
        assert estate.score > 90, "the mean hides it"
        assert estate.distribution["F"] == 1, "the distribution does not"
        assert estate.worst_score == 0
        assert estate.worst_tunnel_id == "bad"

    def test_the_best_score_is_carried_too(self) -> None:
        estate = score_estate([assessment("a", 100, "A"), assessment("b", 20, "F")])
        assert estate.best_score == 100

    def test_failing_count_covers_d_and_f(self) -> None:
        estate = score_estate(
            [assessment("a", 100, "A"), assessment("b", 60, "D"), assessment("c", 0, "F")]
        )
        assert estate.failing_count == 2

    def test_criticality_weights_the_mean(self) -> None:
        tunnels = [assessment("critical", 0, "F"), assessment("spare", 100, "A")]
        unweighted = score_estate(tunnels)
        weighted = score_estate(tunnels, criticality={"critical": 9.0, "spare": 1.0})
        assert unweighted.score == 50
        assert weighted.score == 10
        assert weighted.weighted is True

    def test_an_unsupplied_criticality_defaults_to_one(self) -> None:
        """The operator's judgement, not the tool's guess."""
        tunnels = [assessment("a", 0, "F"), assessment("b", 100, "A")]
        assert score_estate(tunnels, criticality={"a": 1.0}).score == 50

    def test_all_zero_weights_fall_back_to_the_plain_mean(self) -> None:
        """Expressing no preference is not a request for a division by zero."""
        tunnels = [assessment("a", 0, "F"), assessment("b", 100, "A")]
        estate = score_estate(tunnels, criticality={"a": 0.0, "b": 0.0})
        assert estate.score == 50
        assert estate.weighted is False

    def test_a_negative_weight_is_clamped_rather_than_inverting_the_result(self) -> None:
        tunnels = [assessment("a", 0, "F"), assessment("b", 100, "A")]
        estate = score_estate(tunnels, criticality={"a": -5.0, "b": 1.0})
        assert estate.score == 100

    def test_the_estate_score_stays_within_range(self) -> None:
        tunnels = [assessment(f"t{i}", s, "A") for i, s in enumerate((0, 100, 50))]
        estate = score_estate(tunnels)
        assert 0 <= estate.score <= 100

    def test_the_result_is_a_dataclass_a_report_can_render(self) -> None:
        assert isinstance(score_estate([assessment("a", 100, "A")]), EstateScore)
