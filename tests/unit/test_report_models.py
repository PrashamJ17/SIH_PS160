"""Tests for the report model (build plan Step 9.1).

The Section A / Section B separation is the intellectual centre of the product, so it
gets more than the plan's three tests. In particular it is checked under ``python -O``:
the plan sketches the validator with ``assert``, and an assertion is removed by the
optimiser — which would delete the central guarantee in the deployments most likely to
enable it, and delete it silently.
"""

from __future__ import annotations

import subprocess
import sys
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from ipsec_sentinel.assess.inventory import Inventory, InventoryEntry, InventoryStatus
from ipsec_sentinel.assess.rules.pqc import PQCGrade
from ipsec_sentinel.models import Confidence, Finding, Severity
from ipsec_sentinel.report.models import (
    SCHEMA_VERSION,
    CVEReference,
    ExecutiveSummary,
    ExposureEntry,
    MetadataExposure,
    PQCEntry,
    PQCSummary,
    Report,
    ReportMetadata,
    ThreatMatrix,
    ThreatMatrixRow,
)

NOW = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)


def parsed_finding(rule_id: str = "CRY-05", severity: Severity = Severity.CRITICAL) -> Finding:
    return Finding(
        rule_id=rule_id,
        title="3DES negotiated",
        severity=severity,
        evidence="the responder selected ENCR_3DES",
        standard_ref="RFC 8221 section 5",
        remediation_hint="Move to AES-GCM.",
    )


def inferred_finding(rule_id: str = "ML-01", severity: Severity = Severity.MEDIUM) -> Finding:
    return Finding(
        rule_id=rule_id,
        title="Traffic inferred as VoIP",
        severity=severity,
        evidence="packet size and timing distribution",
        standard_ref="n/a",
        remediation_hint="Confirm with the tunnel's owner.",
        confidence=Confidence(value=0.82, method="calibrated_xgboost"),
    )


def metadata() -> ReportMetadata:
    return ReportMetadata(
        source="capture_outer.pcap",
        generated_at=NOW,
        baseline="nist_800_77r1",
        tool_version="0.1.0",
        git_sha="abc1234",
        working_tree_dirty=False,
    )


def summary(
    verified: int = 0,
    inferred: int = 0,
    by_severity: dict[Severity, int] | None = None,
) -> ExecutiveSummary:
    return ExecutiveSummary(
        estate_score=42,
        estate_grade="D",
        tunnels_assessed=1,
        tunnels_undocumented=0,
        verified_findings=verified,
        inferred_findings=inferred,
        findings_by_severity=by_severity or {},
        headline="One tunnel is using cryptography that is no longer considered safe.",
    )


def report(
    section_a: list[Finding] | None = None,
    section_b: list[Finding] | None = None,
    **kwargs: object,
) -> Report:
    a, b = section_a or [], section_b or []
    counts: dict[Severity, int] = {}
    for finding in [*a, *b]:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return Report(
        metadata=metadata(),
        executive=summary(len(a), len(b), counts),
        inventory=Inventory(),
        section_a_verified=a,
        section_b_inferred=b,
        **kwargs,  # type: ignore[arg-type]
    )


class TestTheSeparation:
    def test_a_finding_with_confidence_cannot_go_in_section_a(self) -> None:
        with pytest.raises(ValidationError, match="Section A is for parsed facts"):
            report(section_a=[inferred_finding()])

    def test_a_deterministic_finding_cannot_go_in_section_b(self) -> None:
        with pytest.raises(ValidationError, match="Section B is for inferences"):
            report(section_b=[parsed_finding()])

    def test_the_error_names_the_offending_findings(self) -> None:
        with pytest.raises(ValidationError, match="CRY-05"):
            report(section_b=[parsed_finding("CRY-05")])

    def test_a_correctly_sorted_report_is_accepted(self) -> None:
        built = report(section_a=[parsed_finding()], section_b=[inferred_finding()])
        assert len(built.section_a_verified) == 1
        assert len(built.section_b_inferred) == 1
        assert len(built.all_findings) == 2

    def test_every_section_a_finding_is_deterministic(self) -> None:
        built = report(section_a=[parsed_finding("CRY-05"), parsed_finding("IKE-01")])
        assert all(f.is_deterministic for f in built.section_a_verified)

    def test_the_validator_survives_python_dash_o(self) -> None:
        """The plan sketches this with ``assert``, which ``-O`` removes.

        Run in a subprocess with optimisation on, because the guarantee has to hold in
        the deployment that enables it — and would fail silently there, leaving a
        report that still looks correct.
        """
        script = (
            "import sys;"
            "from datetime import UTC, datetime;"
            "from pydantic import ValidationError;"
            "from ipsec_sentinel.assess.inventory import Inventory;"
            "from ipsec_sentinel.models import Confidence, Finding, Severity;"
            "from ipsec_sentinel.report.models import ExecutiveSummary, Report, ReportMetadata;"
            "f=Finding(rule_id='X',title='t',severity=Severity.LOW,evidence='e',"
            "standard_ref='r',remediation_hint='h',"
            "confidence=Confidence(value=0.5,method='m'));"
            "m=ReportMetadata(source='s',generated_at=datetime.now(UTC),baseline='b',"
            "tool_version='0');"
            "e=ExecutiveSummary(estate_score=1,estate_grade='A',tunnels_assessed=0,"
            "tunnels_undocumented=0,verified_findings=1,inferred_findings=0,"
            "findings_by_severity={Severity.LOW:1},headline='h');"
            "\ntry:\n"
            "    Report(metadata=m,executive=e,inventory=Inventory(),section_a_verified=[f])\n"
            "except ValidationError:\n"
            "    print('REFUSED')\n"
            "else:\n"
            "    print('ACCEPTED')\n"
        )
        result = subprocess.run(
            [sys.executable, "-O", "-c", script],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        assert result.returncode == 0, result.stderr[-500:]
        assert result.stdout.strip() == "REFUSED", (
            f"under -O the separation was not enforced: {result.stdout!r}"
        )


class TestTheSummaryMatchesTheBody:
    def test_a_miscounted_verified_total_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="verified findings, but Section A"):
            Report(
                metadata=metadata(),
                executive=summary(verified=5, by_severity={Severity.CRITICAL: 1}),
                inventory=Inventory(),
                section_a_verified=[parsed_finding()],
            )

    def test_a_miscounted_inferred_total_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="inferred findings, but Section B"):
            Report(
                metadata=metadata(),
                executive=summary(inferred=0, by_severity={Severity.MEDIUM: 1}),
                inventory=Inventory(),
                section_b_inferred=[inferred_finding()],
            )

    def test_mismatched_severity_counts_are_refused(self) -> None:
        with pytest.raises(ValidationError, match="severity counts"):
            Report(
                metadata=metadata(),
                executive=summary(verified=1, by_severity={Severity.LOW: 1}),
                inventory=Inventory(),
                section_a_verified=[parsed_finding(severity=Severity.CRITICAL)],
            )

    def test_zero_entries_do_not_have_to_be_declared(self) -> None:
        """``{CRITICAL: 0}`` and an absent key say the same thing."""
        Report(
            metadata=metadata(),
            executive=ExecutiveSummary(
                estate_score=100,
                estate_grade="A",
                tunnels_assessed=0,
                tunnels_undocumented=0,
                verified_findings=0,
                inferred_findings=0,
                findings_by_severity={Severity.CRITICAL: 0},
                headline="Nothing was found.",
            ),
            inventory=Inventory(),
        )


class TestRoundTrip:
    def test_a_report_round_trips_through_json_unchanged(self) -> None:
        built = report(section_a=[parsed_finding()], section_b=[inferred_finding()])
        assert Report.model_validate_json(built.model_dump_json()) == built

    def test_a_fully_populated_report_round_trips(self) -> None:
        built = report(
            section_a=[parsed_finding()],
            section_b=[inferred_finding()],
            metadata_exposure=MetadataExposure(
                entries=[
                    ExposureEntry(
                        tunnel_id="t1",
                        endpoints=("203.0.113.1", "198.51.100.1"),
                        total_bytes=1024,
                        total_packets=8,
                        session_count=2,
                        active_hours=[9, 10, 11],
                        first_seen=NOW,
                        last_seen=NOW,
                        inferred_traffic="voip",
                        inferred_traffic_confidence=Confidence(value=0.9, method="m"),
                    )
                ]
            ),
            threat_matrix=ThreatMatrix(
                rows=[
                    ThreatMatrixRow(
                        technique="T1040",
                        technique_name="Network Sniffing",
                        severity=Severity.HIGH,
                        tunnel_ids=["t1"],
                        rule_ids=["CRY-05"],
                        cves=[
                            CVEReference(
                                cve_id="CVE-2016-2183",
                                cvss_score=7.5,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                summary="Birthday attacks on 64-bit block ciphers.",
                                scope_note="The record names IPsec alongside TLS and SSH.",
                                source="https://nvd.nist.gov/vuln/detail/CVE-2016-2183",
                            )
                        ],
                    )
                ]
            ),
            pqc=PQCSummary(
                entries=[
                    PQCEntry(tunnel_id="t1", grade=PQCGrade.EXPOSED, rationale="classical only")
                ]
            ),
        )
        restored = Report.model_validate_json(built.model_dump_json())
        assert restored == built
        assert restored.pqc.worst_grade is PQCGrade.EXPOSED
        assert restored.threat_matrix.techniques == ["T1040"]
        assert restored.threat_matrix.rows[0].cves[0].cve_id == "CVE-2016-2183"
        assert restored.threat_matrix.rows[0].worst_cvss == 7.5

    def test_the_schema_version_travels_with_the_report(self) -> None:
        built = report()
        assert built.metadata.schema_version == SCHEMA_VERSION
        assert f'"schema_version":"{SCHEMA_VERSION}"' in built.model_dump_json()

    def test_an_empty_report_is_valid(self) -> None:
        built = report()
        assert built.is_empty is True
        assert Report.model_validate_json(built.model_dump_json()) == built


class TestProvenance:
    def test_a_clean_checkout_reads_as_its_sha(self) -> None:
        assert metadata().provenance == "0.1.0 (abc1234)"

    def test_a_dirty_checkout_says_so(self) -> None:
        dirty = metadata().model_copy(update={"working_tree_dirty": True})
        assert dirty.provenance == "0.1.0 (abc1234-dirty)"

    def test_an_unknown_revision_is_stated_not_omitted(self) -> None:
        unknown = metadata().model_copy(update={"git_sha": None})
        assert "revision unknown" in unknown.provenance

    def test_a_report_must_name_its_source_and_baseline(self) -> None:
        for field in ("source", "baseline"):
            with pytest.raises(ValidationError):
                ReportMetadata(
                    **{
                        **metadata().model_dump(),
                        field: "",
                    }
                )


class TestExposureEntries:
    def test_an_inference_without_a_confidence_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="both be present or both absent"):
            ExposureEntry(
                tunnel_id="t1",
                endpoints=("a", "b"),
                total_bytes=0,
                total_packets=0,
                session_count=0,
                inferred_traffic="voip",
            )

    def test_a_confidence_without_an_inference_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="both be present or both absent"):
            ExposureEntry(
                tunnel_id="t1",
                endpoints=("a", "b"),
                total_bytes=0,
                total_packets=0,
                session_count=0,
                inferred_traffic_confidence=Confidence(value=0.5, method="m"),
            )

    def test_an_entry_with_neither_is_fine(self) -> None:
        """A tunnel the classifier abstained on still appears in the exposure section."""
        entry = ExposureEntry(
            tunnel_id="t1",
            endpoints=("a", "b"),
            total_bytes=10,
            total_packets=1,
            session_count=1,
        )
        assert entry.inferred_traffic is None

    def test_an_impossible_hour_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="hours of the day"):
            ExposureEntry(
                tunnel_id="t1",
                endpoints=("a", "b"),
                total_bytes=0,
                total_packets=0,
                session_count=0,
                active_hours=[9, 24],
            )

    def test_the_section_explains_why_a_good_tunnel_is_listed(self) -> None:
        note = MetadataExposure().note
        assert "regardless of how well it is configured" in note


class TestThreatMatrixRows:
    def test_a_score_cannot_exist_without_its_cve(self) -> None:
        """Not validated — unrepresentable.

        An earlier version carried ``cve_id`` and ``cvss_score`` as two optional fields
        on the row and validated that they appeared together. They are one object now,
        so the invalid state cannot be constructed at all.
        """
        assert "cvss_score" not in ThreatMatrixRow.model_fields
        assert "cve_id" not in ThreatMatrixRow.model_fields
        assert set(CVEReference.model_fields) >= {"cve_id", "cvss_score", "source"}

    def test_a_reference_needs_a_well_formed_cve_id(self) -> None:
        with pytest.raises(ValidationError):
            CVEReference(
                cve_id="CVE-not-a-number",
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N",
                summary="s",
                scope_note="n",
                source="https://nvd.nist.gov/x",
            )

    def test_a_reference_must_say_what_it_covers(self) -> None:
        """Relevance is the part that goes wrong, so the scope note is not optional."""
        with pytest.raises(ValidationError):
            CVEReference(
                cve_id="CVE-2016-2183",
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N",
                summary="s",
                scope_note="",
                source="https://nvd.nist.gov/x",
            )

    def test_a_row_must_name_at_least_one_tunnel_and_rule(self) -> None:
        for field in ("tunnel_ids", "rule_ids"):
            with pytest.raises(ValidationError):
                ThreatMatrixRow(
                    **{
                        "technique": "T1040",
                        "technique_name": "Network Sniffing",
                        "severity": Severity.HIGH,
                        "tunnel_ids": ["t1"],
                        "rule_ids": ["CRY-05"],
                        field: [],
                    }
                )

    def test_an_out_of_range_cvss_score_is_refused(self) -> None:
        with pytest.raises(ValidationError):
            CVEReference(
                cve_id="CVE-2016-2183",
                cvss_score=11.0,
                cvss_vector="CVSS:3.1/AV:N",
                summary="s",
                scope_note="n",
                source="https://nvd.nist.gov/x",
            )


class TestPQCSummary:
    def test_the_worst_grade_is_the_least_ready_one(self) -> None:
        pqc = PQCSummary(
            entries=[
                PQCEntry(tunnel_id="a", grade=PQCGrade.READY, rationale="ML-KEM present"),
                PQCEntry(tunnel_id="b", grade=PQCGrade.EXPOSED, rationale="classical only"),
                PQCEntry(tunnel_id="c", grade=PQCGrade.AT_RISK, rationale="no PPK"),
            ]
        )
        assert pqc.worst_grade is PQCGrade.EXPOSED
        assert pqc.count(PQCGrade.READY) == 1

    def test_an_empty_summary_has_no_worst_grade(self) -> None:
        assert PQCSummary().worst_grade is None

    def test_the_note_explains_harvest_now_decrypt_later(self) -> None:
        assert "decrypted later" in PQCSummary().note


class TestInventoryIsCarriedIntact:
    def test_an_undocumented_tunnel_survives_the_round_trip(self) -> None:
        inventory = Inventory(
            documented_list_supplied=True,
            entries=[
                InventoryEntry(
                    tunnel_id="t1",
                    endpoints=("203.0.113.1", "198.51.100.1"),
                    status=InventoryStatus.UNDOCUMENTED,
                )
            ],
        )
        built = Report(metadata=metadata(), executive=summary(), inventory=inventory)
        restored = Report.model_validate_json(built.model_dump_json())
        assert len(restored.inventory.undocumented) == 1
        assert restored == built


class TestUnknownFieldsAreRefused:
    """Pydantic ignores unknown fields by default, and that default is wrong here.

    A report loaded from a future schema would silently drop what it did not recognise
    while still validating — data loss that looks like success. It is also how a test
    that sets a renamed field keeps passing while testing nothing, which is what
    happened to the CVE fields when they moved onto ``CVEReference``.
    """

    def test_a_report_with_an_unknown_field_is_refused(self) -> None:
        payload = report().model_dump()
        payload["invented_section"] = {"anything": True}
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            Report.model_validate(payload)

    def test_a_renamed_field_cannot_be_set_silently(self) -> None:
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            ThreatMatrixRow(
                technique="T1040",
                technique_name="Network Sniffing",
                severity=Severity.HIGH,
                tunnel_ids=["t1"],
                rule_ids=["CRY-05"],
                cve_id="CVE-2016-2183",
            )

    def test_the_metadata_refuses_unknown_fields_too(self) -> None:
        payload = metadata().model_dump()
        payload["author"] = "someone"
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            ReportMetadata.model_validate(payload)

    def test_a_valid_report_still_round_trips(self) -> None:
        built = report(section_a=[parsed_finding()], section_b=[inferred_finding()])
        assert Report.model_validate_json(built.model_dump_json()) == built
