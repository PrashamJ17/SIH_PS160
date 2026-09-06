"""Tests for the threat matrix (build plan Step 9.4).

The plan's three criteria, plus the checks that keep the matrix honest: a technique the
table does not know is passed through rather than renamed, findings with no technique
are named rather than dropped, and every CVE in the catalogue carries the scope note
that says what its published record actually covers.
"""

from __future__ import annotations

import re

import pytest

from ipsec_sentinel.assess.rules import default_registry
from ipsec_sentinel.models import Confidence, Finding, Severity, TunnelAssessment
from ipsec_sentinel.report.threat_matrix import (
    ATTACK_TECHNIQUES,
    CVE_CATALOGUE,
    EXCLUDED_CVES,
    build_threat_matrix,
    cves_for,
    technique_name,
    worst_severity,
)


def finding(
    rule_id: str = "CRY-05",
    technique: str | None = "T1600.001",
    severity: Severity = Severity.CRITICAL,
    *,
    inferred: bool = False,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=f"{rule_id} fired",
        severity=severity,
        evidence="e",
        standard_ref="r",
        attack_technique=technique,
        remediation_hint="h",
        confidence=Confidence(value=0.8, method="m") if inferred else None,
    )


def tunnel(tunnel_id: str = "t-001", findings: list[Finding] | None = None) -> TunnelAssessment:
    return TunnelAssessment(
        tunnel_id=tunnel_id,
        endpoints=("203.0.113.1", "198.51.100.1"),
        findings=findings if findings is not None else [],
        score=30,
        grade="D",
    )


class TestThePlansCriteria:
    def test_rows_match_distinct_techniques(self) -> None:
        matrix = build_threat_matrix(
            [
                tunnel(
                    "t-001",
                    [
                        finding("CRY-05", "T1600.001"),
                        finding("CRY-02", "T1600.001"),
                        finding("PFS-01", "T1040", Severity.HIGH),
                    ],
                )
            ]
        )
        assert len(matrix) == 2
        assert matrix.techniques == ["T1040", "T1600.001"]

    def test_a_tunnel_with_no_findings_appears_in_no_row(self) -> None:
        matrix = build_threat_matrix([tunnel("t-good", []), tunnel("t-bad", [finding()])])
        named = {tid for row in matrix.rows for tid in row.tunnel_ids}
        assert named == {"t-bad"}

    def test_cve_entries_carry_the_id_and_the_score(self) -> None:
        matrix = build_threat_matrix([tunnel("t-001", [finding("CRY-05", "T1600.001")])])
        row = matrix.rows[0]
        assert row.cves
        assert row.cves[0].cve_id == "CVE-2016-2183"
        assert row.cves[0].cvss_score == 7.5
        assert row.worst_cvss == 7.5


class TestRowContents:
    def test_a_row_names_every_affected_tunnel(self) -> None:
        matrix = build_threat_matrix(
            [
                tunnel("t-001", [finding("CRY-05")]),
                tunnel("t-002", [finding("CRY-05")]),
                tunnel("t-003", [finding("PFS-01", "T1040", Severity.HIGH)]),
            ]
        )
        weaken = next(r for r in matrix.rows if r.technique == "T1600.001")
        assert weaken.tunnel_ids == ["t-001", "t-002"]

    def test_a_row_names_every_contributing_rule(self) -> None:
        matrix = build_threat_matrix(
            [tunnel("t-001", [finding("CRY-05"), finding("CRY-02"), finding("CRY-06")])]
        )
        assert matrix.rows[0].rule_ids == ["CRY-02", "CRY-05", "CRY-06"]

    def test_the_worst_contributing_severity_sets_the_row(self) -> None:
        """Averaging would let a pile of low findings dilute a critical one."""
        matrix = build_threat_matrix(
            [
                tunnel(
                    "t-001",
                    [
                        finding("CRY-05", "T1600.001", Severity.CRITICAL),
                        finding("CRY-02", "T1600.001", Severity.LOW),
                        finding("CRY-06", "T1600.001", Severity.LOW),
                    ],
                )
            ]
        )
        assert matrix.rows[0].severity is Severity.CRITICAL

    def test_rows_are_ordered_worst_first(self) -> None:
        matrix = build_threat_matrix(
            [
                tunnel(
                    "t-001",
                    [
                        finding("OPS-01", "T1592.002", Severity.LOW),
                        finding("CRY-05", "T1600.001", Severity.CRITICAL),
                        finding("PFS-01", "T1040", Severity.HIGH),
                    ],
                )
            ]
        )
        assert [row.severity for row in matrix.rows] == [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.LOW,
        ]

    def test_a_tunnel_is_not_listed_twice_in_one_row(self) -> None:
        matrix = build_threat_matrix([tunnel("t-001", [finding("CRY-05"), finding("CRY-02")])])
        assert matrix.rows[0].tunnel_ids == ["t-001"]

    def test_a_cve_is_not_repeated_when_two_rules_cite_it(self) -> None:
        matrix = build_threat_matrix(
            [tunnel("t-001", [finding("CRY-05", "T1600.001"), finding("CRY-08", "T1600.001")])]
        )
        assert [cve.cve_id for cve in matrix.rows[0].cves] == ["CVE-2016-2183"]

    def test_a_technique_with_no_catalogued_cve_carries_none(self) -> None:
        matrix = build_threat_matrix([tunnel("t-001", [finding("PFS-01", "T1040", Severity.HIGH)])])
        assert matrix.rows[0].cves == []
        assert matrix.rows[0].worst_cvss is None


class TestTheSectionSplitSurvivesTheMatrix:
    def test_a_row_from_parsed_findings_only_is_not_marked_inferred(self) -> None:
        matrix = build_threat_matrix([tunnel("t-001", [finding("CRY-05")])])
        assert matrix.rows[0].includes_inferred is False

    def test_a_row_resting_partly_on_an_estimate_says_so(self) -> None:
        """Otherwise it reads as though it rests entirely on the wire."""
        matrix = build_threat_matrix(
            [
                tunnel(
                    "t-001",
                    [finding("CRY-05"), finding("ANOM-01", "T1600.001", inferred=True)],
                )
            ]
        )
        assert matrix.rows[0].includes_inferred is True

    def test_a_row_from_inferred_findings_only_says_so(self) -> None:
        matrix = build_threat_matrix(
            [tunnel("t-001", [finding("ANOM-01", "T1040", inferred=True)])]
        )
        assert matrix.rows[0].includes_inferred is True


class TestUncategorisedFindings:
    def test_a_finding_with_no_technique_is_named_not_dropped(self) -> None:
        matrix = build_threat_matrix([tunnel("t-001", [finding("SA-01", None, Severity.MEDIUM)])])
        assert len(matrix) == 0
        assert matrix.uncategorised_rules == ["SA-01"]

    def test_they_are_reported_once_each(self) -> None:
        matrix = build_threat_matrix(
            [
                tunnel("t-001", [finding("SA-01", None), finding("SA-02", None)]),
                tunnel("t-002", [finding("SA-01", None)]),
            ]
        )
        assert matrix.uncategorised_rules == ["SA-01", "SA-02"]

    def test_a_matrix_can_hold_both_kinds(self) -> None:
        matrix = build_threat_matrix([tunnel("t-001", [finding("CRY-05"), finding("SA-01", None)])])
        assert len(matrix) == 1
        assert matrix.uncategorised_rules == ["SA-01"]


class TestTechniqueNames:
    def test_every_technique_the_rules_cite_has_a_name(self) -> None:
        """A rule citing a technique the table does not know would print a bare ID."""
        cited = {
            rule.attack_technique
            for rule in default_registry().rules
            if rule.attack_technique is not None
        }
        missing = sorted(cited - set(ATTACK_TECHNIQUES))
        assert not missing, f"no name for {missing}"

    def test_an_unknown_technique_is_passed_through_not_renamed(self) -> None:
        assert technique_name("T9999") == "T9999"

    def test_the_names_are_the_published_ones(self) -> None:
        assert ATTACK_TECHNIQUES["T1040"] == "Network Sniffing"
        assert ATTACK_TECHNIQUES["T1689"] == "Downgrade Attack"

    def test_every_identifier_is_well_formed(self) -> None:
        for technique in ATTACK_TECHNIQUES:
            assert re.fullmatch(r"T\d{4}(\.\d{3})?", technique), technique


class TestTheCVECatalogue:
    def test_every_entry_names_a_real_rule(self) -> None:
        known = {rule.id for rule in default_registry().rules}
        unknown = sorted(set(CVE_CATALOGUE) - known)
        assert not unknown, f"catalogue entries for rules that do not exist: {unknown}"

    def test_every_reference_carries_a_scope_note(self) -> None:
        """Relevance is the part that goes wrong, so it has to be written down."""
        for references in CVE_CATALOGUE.values():
            for cve in references:
                assert cve.scope_note.strip()
                assert cve.source.startswith("https://nvd.nist.gov/")

    def test_every_score_is_in_range_and_paired_with_a_vector(self) -> None:
        for references in CVE_CATALOGUE.values():
            for cve in references:
                assert 0.0 <= cve.cvss_score <= 10.0
                assert cve.cvss_vector.startswith("CVSS:3")

    def test_the_id_and_the_score_cannot_be_separated(self) -> None:
        """They are one object, so a score without its CVE is unrepresentable."""
        from pydantic import ValidationError

        from ipsec_sentinel.report.models import CVEReference

        with pytest.raises(ValidationError):
            CVEReference(
                cve_id="not-a-cve",
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N",
                summary="s",
                scope_note="n",
                source="https://nvd.nist.gov/x",
            )

    def test_logjam_is_excluded_with_its_reason(self) -> None:
        """A CVE about TLS attached to an IPsec finding is misinformation with a citation."""
        assert "CVE-2015-4000" in EXCLUDED_CVES
        assert "TLS" in EXCLUDED_CVES["CVE-2015-4000"]
        assert not any(
            cve.cve_id == "CVE-2015-4000"
            for references in CVE_CATALOGUE.values()
            for cve in references
        )

    def test_cves_for_an_unmapped_rule_is_empty(self) -> None:
        assert cves_for("SA-04") == ()


class TestAnEmptyMatrix:
    def test_no_assessments_produces_an_empty_matrix(self) -> None:
        matrix = build_threat_matrix([])
        assert len(matrix) == 0
        assert matrix.techniques == []
        assert matrix.uncategorised_rules == []
        assert worst_severity(matrix) is None

    def test_a_sound_estate_produces_an_empty_matrix(self) -> None:
        matrix = build_threat_matrix([tunnel("t-001", []), tunnel("t-002", [])])
        assert len(matrix) == 0
