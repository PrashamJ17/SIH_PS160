"""Tests for the report builder (build plan Step 9.2).

The plan asks for three things: findings routed correctly, summary counts matching the
section contents, and an empty assessment producing a valid empty report. The routing
test is the one that matters, so it is checked from both directions — nothing
deterministic reaches Section B, and nothing with a confidence reaches Section A — and
the attribution that makes a flattened finding usable is checked too.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime

import pytest

from ipsec_sentinel.assess.inventory import Inventory, InventoryEntry, InventoryStatus, KnownTunnel
from ipsec_sentinel.models import Confidence, Finding, Severity, TunnelAssessment
from ipsec_sentinel.report.build import build_report, headline, route
from ipsec_sentinel.report.models import Report

NOW = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)


def parsed(rule_id: str = "CRY-05", severity: Severity = Severity.CRITICAL) -> Finding:
    return Finding(
        rule_id=rule_id,
        title="3DES negotiated",
        severity=severity,
        evidence="the responder selected ENCR_3DES",
        standard_ref="RFC 8221 section 5",
        remediation_hint="Move to AES-GCM.",
    )


def inferred(rule_id: str = "ANOM-01", severity: Severity = Severity.MEDIUM) -> Finding:
    return Finding(
        rule_id=rule_id,
        title="Traffic shape unlike the rest of the estate",
        severity=severity,
        evidence="isolation forest score",
        standard_ref="n/a",
        remediation_hint="Confirm with the tunnel's owner.",
        confidence=Confidence(value=0.71, method="isolation_forest"),
    )


def assessment(
    tunnel_id: str = "t-001",
    findings: list[Finding] | None = None,
    score: int = 30,
    grade: str = "D",
) -> TunnelAssessment:
    return TunnelAssessment(
        tunnel_id=tunnel_id,
        endpoints=("203.0.113.1", "198.51.100.1"),
        findings=findings or [],
        score=score,
        grade=grade,
    )


def build(
    assessments: list[TunnelAssessment] | None = None,
    inventory: Inventory | None = None,
) -> Report:
    return build_report(
        assessments if assessments is not None else [],
        inventory if inventory is not None else Inventory(),
        "nist_800_77r1",
        source="capture_outer.pcap",
        generated_at=NOW,
    )


class TestRouting:
    def test_a_deterministic_finding_goes_to_section_a(self) -> None:
        report = build([assessment(findings=[parsed()])])
        assert [f.rule_id for f in report.section_a_verified] == ["CRY-05"]
        assert report.section_b_inferred == []

    def test_an_inferred_finding_goes_to_section_b(self) -> None:
        report = build([assessment(findings=[inferred()])])
        assert [f.rule_id for f in report.section_b_inferred] == ["ANOM-01"]
        assert report.section_a_verified == []

    def test_a_mixed_assessment_is_split(self) -> None:
        report = build([assessment(findings=[parsed(), inferred()])])
        assert len(report.section_a_verified) == 1
        assert len(report.section_b_inferred) == 1

    def test_nothing_in_section_a_carries_a_confidence(self) -> None:
        report = build(
            [
                assessment("t-001", [parsed("CRY-05"), inferred("ANOM-01")]),
                assessment("t-002", [parsed("IKE-01"), inferred("ANOM-02")]),
            ]
        )
        assert all(f.confidence is None for f in report.section_a_verified)

    def test_everything_in_section_b_carries_a_confidence(self) -> None:
        report = build(
            [
                assessment("t-001", [parsed("CRY-05"), inferred("ANOM-01")]),
                assessment("t-002", [parsed("IKE-01"), inferred("ANOM-02")]),
            ]
        )
        assert all(f.confidence is not None for f in report.section_b_inferred)

    def test_no_finding_is_lost_or_duplicated(self) -> None:
        findings = [parsed("CRY-05"), parsed("IKE-01"), inferred("ANOM-01")]
        report = build([assessment(findings=findings)])
        assert len(report.all_findings) == len(findings)
        assert {f.rule_id for f in report.all_findings} == {f.rule_id for f in findings}

    def test_route_is_the_single_place_the_decision_is_made(self) -> None:
        verified, inferred_findings = route([parsed(), inferred()])
        assert [f.rule_id for f in verified] == ["CRY-05"]
        assert [f.rule_id for f in inferred_findings] == ["ANOM-01"]

    def test_the_same_rule_on_two_tunnels_appears_twice(self) -> None:
        """Deduplicating would hide that a second tunnel has the same problem."""
        report = build([assessment("t-001", [parsed()]), assessment("t-002", [parsed()])])
        assert len(report.section_a_verified) == 2
        assert {f.tunnel_id for f in report.section_a_verified} == {"t-001", "t-002"}


class TestAttribution:
    def test_each_flattened_finding_names_its_tunnel(self) -> None:
        report = build([assessment("t-042", [parsed(), inferred()])])
        assert all(f.tunnel_id == "t-042" for f in report.all_findings)

    def test_an_existing_attribution_is_not_overwritten(self) -> None:
        """A caller who already attributed a finding knows something the builder does not."""
        pre = parsed().model_copy(update={"tunnel_id": "upstream"})
        report = build([assessment("t-042", [pre])])
        assert report.section_a_verified[0].tunnel_id == "upstream"

    def test_a_rule_produced_finding_starts_unattributed(self) -> None:
        assert parsed().tunnel_id is None


class TestTheExecutiveSummary:
    def test_the_counts_match_the_sections(self) -> None:
        report = build([assessment("t-001", [parsed(), parsed("IKE-01"), inferred()])])
        assert report.executive.verified_findings == len(report.section_a_verified) == 2
        assert report.executive.inferred_findings == len(report.section_b_inferred) == 1

    def test_the_severity_counts_match_the_findings(self) -> None:
        report = build(
            [
                assessment(
                    "t-001",
                    [
                        parsed("CRY-05", Severity.CRITICAL),
                        parsed("IKE-01", Severity.HIGH),
                        parsed("SA-01", Severity.HIGH),
                    ],
                )
            ]
        )
        assert report.executive.findings_by_severity[Severity.CRITICAL] == 1
        assert report.executive.findings_by_severity[Severity.HIGH] == 2
        assert report.executive.critical_count == 1

    def test_the_undocumented_count_comes_from_the_inventory(self) -> None:
        inventory = Inventory(
            documented_list_supplied=True,
            entries=[
                InventoryEntry(
                    tunnel_id="t-001",
                    endpoints=("203.0.113.1", "198.51.100.1"),
                    status=InventoryStatus.UNDOCUMENTED,
                )
            ],
            unobserved=[KnownTunnel(endpoints=("a", "b"))],
        )
        report = build([assessment()], inventory)
        assert report.executive.tunnels_undocumented == 1

    def test_the_builder_cannot_produce_a_mismatch(self) -> None:
        """The model validates this too; the builder should never reach that check."""
        report = build([assessment("t-001", [parsed(), inferred()])])
        assert Report.model_validate(report.model_dump()) == report


class TestTheHeadline:
    def test_an_empty_capture_says_so_plainly(self) -> None:
        text = build().executive.headline
        assert "No IPsec tunnels were found" in text
        assert "Check that the capture was taken" in text

    def test_a_critical_finding_leads_the_headline(self) -> None:
        text = build([assessment("t-001", [parsed()])]).executive.headline
        assert "no longer considered safe" in text
        assert "1 tunnel of the 1 tunnel" in text or "1 tunnel" in text

    def test_it_counts_affected_tunnels_not_findings(self) -> None:
        """Three findings on one tunnel is one tunnel to fix, not three."""
        text = build(
            [assessment("t-001", [parsed("CRY-05"), parsed("CRY-02"), parsed("CRY-06")])]
        ).executive.headline
        assert "1 tunnel of the" in text

    def test_a_clean_estate_points_at_the_exposure_section(self) -> None:
        text = build([assessment("t-001", [], score=100, grade="A")]).executive.headline
        assert "meet the selected baseline in full" in text
        assert "who is talking to whom" in text

    def test_a_high_severity_estate_does_not_claim_a_crisis(self) -> None:
        text = build([assessment("t-001", [parsed("IKE-01", Severity.HIGH)])]).executive.headline
        assert "No immediate crises" in text

    def test_the_headline_avoids_algorithm_names(self) -> None:
        """The M9 criterion is that a non-technical reader understands it."""
        text = build([assessment("t-001", [parsed()])]).executive.headline
        for jargon in ("3DES", "AES", "Diffie", "IKEv", "SHA", "ESP", "SPI"):
            assert jargon not in text, f"{jargon!r} in the executive headline"

    def test_it_is_one_sentence_a_reader_can_act_on(self) -> None:
        text = headline([assessment()], Counter(), 100, "A")
        assert text.endswith(".")
        assert len(text) < 400


class TestKeyPoints:
    def test_an_absent_documented_list_is_stated(self) -> None:
        points = " ".join(build([assessment()]).executive.key_points)
        assert "No documented tunnel list was supplied" in points

    def test_a_matching_documented_list_is_stated(self) -> None:
        inventory = Inventory(
            documented_list_supplied=True,
            entries=[
                InventoryEntry(
                    tunnel_id="t-001",
                    endpoints=("203.0.113.1", "198.51.100.1"),
                    status=InventoryStatus.DOCUMENTED,
                )
            ],
        )
        points = " ".join(build([assessment()], inventory).executive.key_points)
        assert "Every observed tunnel appears on the documented list" in points

    def test_undocumented_tunnels_are_called_out(self) -> None:
        inventory = Inventory(
            documented_list_supplied=True,
            entries=[
                InventoryEntry(
                    tunnel_id="t-001",
                    endpoints=("203.0.113.1", "198.51.100.1"),
                    status=InventoryStatus.UNDOCUMENTED,
                )
            ],
        )
        points = " ".join(build([assessment()], inventory).executive.key_points)
        assert "nobody is maintaining" in points

    def test_the_two_sections_are_explained_to_the_reader(self) -> None:
        points = " ".join(build([assessment("t-001", [parsed(), inferred()])]).executive.key_points)
        assert "read directly from the negotiation" in points
        assert "stated confidence" in points

    def test_an_unassessable_tunnel_is_explained(self) -> None:
        inventory = Inventory(
            entries=[
                InventoryEntry(
                    tunnel_id="t-001",
                    endpoints=("203.0.113.1", "198.51.100.1"),
                    status=InventoryStatus.UNKNOWN,
                    orphan=True,
                )
            ]
        )
        points = " ".join(build([assessment()], inventory).executive.key_points)
        assert "Capture across a rekey" in points


class TestAnEmptyReport:
    def test_no_assessments_produces_a_valid_report(self) -> None:
        report = build()
        assert report.is_empty is True
        assert report.executive.tunnels_assessed == 0
        assert report.all_findings == []

    def test_an_empty_estate_is_not_graded_as_a_failure(self) -> None:
        """Nothing observed is not the same as everything broken."""
        report = build()
        assert report.executive.estate_grade == "A"
        assert report.executive.estate_score == 100

    def test_the_absent_sections_are_empty_rather_than_invented(self) -> None:
        report = build()
        assert len(report.metadata_exposure) == 0
        assert len(report.threat_matrix) == 0
        assert report.pqc.entries == []
        assert report.remediation == []

    def test_it_round_trips(self) -> None:
        report = build()
        assert Report.model_validate_json(report.model_dump_json()) == report


class TestMetadata:
    def test_the_source_and_baseline_are_recorded(self) -> None:
        report = build([assessment()])
        assert report.metadata.source == "capture_outer.pcap"
        assert report.metadata.baseline == "nist_800_77r1"

    def test_the_build_identity_is_recorded(self) -> None:
        report = build([assessment()])
        assert report.metadata.tool_version
        assert "revision unknown" in report.metadata.provenance or report.metadata.git_sha

    def test_the_timestamp_is_the_one_supplied(self) -> None:
        assert build([assessment()]).metadata.generated_at == NOW

    def test_a_generated_at_defaults_to_now(self) -> None:
        report = build_report([], Inventory(), "nist_800_77r1", source="s")
        assert report.metadata.generated_at.tzinfo is not None


@pytest.mark.parametrize("count", [0, 1, 2, 5])
def test_the_estate_score_reflects_the_assessments(count: int) -> None:
    assessments = [assessment(f"t-{i:03d}", score=40, grade="D") for i in range(count)]
    report = build(assessments)
    assert report.executive.tunnels_assessed == count
    assert report.executive.estate_score == (100 if count == 0 else 40)


class TestTheSectionsAreBuiltIn:
    """A caller must not be able to produce a report that quietly omits a section."""

    def test_the_exposure_section_is_populated_without_being_asked_for(self) -> None:
        from datetime import timedelta

        from ipsec_sentinel.models import ESPFlow

        assessed = TunnelAssessment(
            tunnel_id="t-001",
            endpoints=("203.0.113.1", "198.51.100.1"),
            esp_flows=[
                ESPFlow(
                    spi="aabbccdd",
                    src_ip="203.0.113.1",
                    dst_ip="198.51.100.1",
                    packet_count=10,
                    byte_count=1000,
                    first_seen=NOW,
                    last_seen=NOW + timedelta(minutes=5),
                )
            ],
            score=100,
            grade="A",
        )
        report = build([assessed])
        assert len(report.metadata_exposure) == 1
        assert report.metadata_exposure.entries[0].total_bytes == 1000

    def test_a_clean_tunnel_still_reaches_the_exposure_section(self) -> None:
        report = build([assessment("t-001", [], score=100, grade="A")])
        assert [e.tunnel_id for e in report.metadata_exposure.entries] == ["t-001"]

    def test_the_threat_matrix_is_populated_without_being_asked_for(self) -> None:
        with_technique = Finding(
            rule_id="CRY-05",
            title="3DES negotiated",
            severity=Severity.CRITICAL,
            evidence="e",
            standard_ref="r",
            attack_technique="T1600.001",
            remediation_hint="h",
        )
        report = build([assessment("t-001", [with_technique])])
        assert report.threat_matrix.techniques == ["T1600.001"]
        assert report.threat_matrix.rows[0].tunnel_ids == ["t-001"]

    def test_an_explicit_section_overrides_the_computed_one(self) -> None:
        """A caller with per-packet timestamps has a better source than flow summaries."""
        from ipsec_sentinel.report.models import MetadataExposure

        report = build_report(
            [assessment("t-001", [])],
            Inventory(),
            "nist_800_77r1",
            source="s",
            generated_at=NOW,
            metadata_exposure=MetadataExposure(entries=[]),
        )
        assert len(report.metadata_exposure) == 0

    def test_pqc_stays_the_callers_responsibility(self) -> None:
        """Post-quantum grading reads the negotiation, which an assessment does not carry."""
        report = build([assessment("t-001", [])])
        assert report.pqc.entries == []

    def test_a_full_report_still_round_trips(self) -> None:
        report = build([assessment("t-001", [parsed(), inferred()])])
        assert Report.model_validate_json(report.model_dump_json()) == report


class TestAFalsyModelIsNotAMissingOne:
    """Several report models define ``__len__``, so an empty one is falsy.

    ``inventory or Inventory()`` therefore replaces a real inventory with a blank one
    whenever it happens to have no observed entries — and the case where that happens is
    exactly the interesting one: a documented tunnel list where nothing was seen. Every
    default here is chosen with ``is not None``.
    """

    def test_an_inventory_with_no_entries_is_falsy(self) -> None:
        """The property that makes the bug possible, pinned so it is not a surprise."""
        assert bool(Inventory()) is False
        only_unobserved = Inventory(
            documented_list_supplied=True,
            unobserved=[KnownTunnel(endpoints=("10.0.0.1", "10.0.0.2"), name="branch-7")],
        )
        assert bool(only_unobserved) is False
        assert only_unobserved.unobserved

    def test_documented_tunnels_that_were_never_seen_survive_into_the_report(self) -> None:
        inventory = Inventory(
            documented_list_supplied=True,
            unobserved=[KnownTunnel(endpoints=("10.0.0.1", "10.0.0.2"), name="branch-7")],
        )
        report = build([], inventory)
        assert [k.name for k in report.inventory.unobserved] == ["branch-7"]

    def test_an_explicitly_empty_section_is_not_replaced(self) -> None:
        from ipsec_sentinel.report.models import PQCSummary

        report = build_report(
            [],
            Inventory(),
            "nist_800_77r1",
            source="s",
            generated_at=NOW,
            pqc=PQCSummary(note="deliberately empty for this run"),
        )
        assert report.pqc.note == "deliberately empty for this run"
