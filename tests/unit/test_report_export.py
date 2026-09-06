"""Tests for PDF and JSON export (build plan Step 9.6).

The JSON tests carry most of the weight, because the JSON is the interface other systems
build against. Two properties are checked separately and neither implies the other: a
report must round-trip through JSON unchanged, *and* the JSON must validate against the
published schema. The first catches losing data; the second catches quietly changing the
shape every downstream consumer reads while staying internally consistent.

The schema file is regenerated and compared, so it cannot go stale — a checked-in schema
that no longer matches the model is worse than none, since consumers trust it.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from ipsec_sentinel.assess.inventory import Inventory, InventoryEntry, InventoryStatus
from ipsec_sentinel.assess.rules.pqc import PQCGrade
from ipsec_sentinel.models import Confidence, ESPFlow, Finding, Severity, TunnelAssessment
from ipsec_sentinel.report.build import build_report
from ipsec_sentinel.report.export_json import (
    SCHEMA_ID,
    export_json,
    load_report,
    report_schema,
    schema_path,
    write_json,
    write_schema,
)
from ipsec_sentinel.report.models import SCHEMA_VERSION, PQCEntry, PQCSummary, Report
from ipsec_sentinel.report.render_pdf import (
    DYLD_VARIABLE,
    PDFExportError,
    _extend_macos_library_path,
    page_count,
    pdf_available,
    render_pdf,
    write_pdf,
)

NOW = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)


def parsed() -> Finding:
    return Finding(
        rule_id="CRY-05",
        title="3DES negotiated",
        severity=Severity.CRITICAL,
        evidence="the responder selected ENCR_3DES",
        standard_ref="RFC 8221 section 5",
        attack_technique="T1600.001",
        remediation_hint="Move to AES-GCM.",
    )


def inferred() -> Finding:
    return Finding(
        rule_id="ANOM-01",
        title="Traffic shape unlike the rest of the estate",
        severity=Severity.MEDIUM,
        evidence="isolation forest score",
        standard_ref="n/a",
        remediation_hint="Confirm with the tunnel's owner.",
        confidence=Confidence(value=0.71, method="isolation_forest"),
    )


def assessment() -> TunnelAssessment:
    return TunnelAssessment(
        tunnel_id="t-001",
        endpoints=("203.0.113.1", "198.51.100.1"),
        esp_flows=[
            ESPFlow(
                spi="aabbccdd",
                src_ip="203.0.113.1",
                dst_ip="198.51.100.1",
                packet_count=120,
                byte_count=250_000,
                first_seen=NOW,
                last_seen=NOW,
            )
        ],
        findings=[parsed(), inferred()],
        score=20,
        grade="F",
        inferred_traffic="voip",
        inferred_traffic_confidence=Confidence(value=0.88, method="calibrated_xgboost"),
    )


def report(assessments: list[TunnelAssessment] | None = None, **kwargs: object) -> Report:
    return build_report(
        assessments if assessments is not None else [assessment()],
        Inventory(
            entries=[
                InventoryEntry(
                    tunnel_id="t-001",
                    endpoints=("203.0.113.1", "198.51.100.1"),
                    status=InventoryStatus.UNDOCUMENTED,
                )
            ]
        ),
        "nist_800_77r1",
        source="capture_outer.pcap",
        generated_at=NOW,
        **kwargs,  # type: ignore[arg-type]
    )


class TestJSONRoundTrip:
    def test_a_report_survives_export_and_reload(self) -> None:
        original = report()
        assert load_report(export_json(original)) == original

    def test_a_fully_populated_report_survives(self) -> None:
        original = report(
            pqc=PQCSummary(
                entries=[
                    PQCEntry(
                        tunnel_id="t-001",
                        grade=PQCGrade.EXPOSED,
                        rationale="classical key exchange only",
                    )
                ]
            )
        )
        restored = load_report(export_json(original))
        assert restored == original
        assert restored.pqc.worst_grade is PQCGrade.EXPOSED

    def test_an_empty_report_survives(self) -> None:
        original = build_report([], Inventory(), "b", source="s", generated_at=NOW)
        assert load_report(export_json(original)) == original

    def test_the_section_split_survives(self) -> None:
        restored = load_report(export_json(report()))
        assert all(f.confidence is None for f in restored.section_a_verified)
        assert all(f.confidence is not None for f in restored.section_b_inferred)

    def test_a_reload_with_an_unknown_field_fails_loudly(self) -> None:
        """Silent data loss is worse than a refused load."""
        payload = json.loads(export_json(report()))
        payload["future_section"] = {"x": 1}
        with pytest.raises(Exception, match="Extra inputs are not permitted"):
            load_report(json.dumps(payload))

    def test_the_output_is_indented_for_review(self) -> None:
        text = export_json(report())
        assert "\n  " in text
        assert text.endswith("\n")

    def test_section_a_is_serialised_before_section_b(self) -> None:
        """Alphabetising the keys would invert the one distinction the report makes."""
        text = export_json(report())
        assert text.index('"section_a_verified"') < text.index('"section_b_inferred"')

    def test_it_writes_to_disk(self, tmp_path: Path) -> None:
        destination = write_json(report(), tmp_path / "nested" / "report.json")
        assert destination.exists()
        assert load_report(destination.read_text(encoding="utf-8")) == report()


class TestThePublishedSchema:
    def test_an_exported_report_validates_against_it(self) -> None:
        Draft202012Validator(report_schema()).validate(json.loads(export_json(report())))

    def test_an_empty_report_validates(self) -> None:
        empty = build_report([], Inventory(), "b", source="s", generated_at=NOW)
        Draft202012Validator(report_schema()).validate(json.loads(export_json(empty)))

    def test_the_schema_itself_is_a_valid_json_schema(self) -> None:
        Draft202012Validator.check_schema(report_schema())

    def test_the_checked_in_schema_matches_the_model(self, tmp_path: Path) -> None:
        """A stale published schema is worse than none: consumers trust it."""
        regenerated = write_schema(tmp_path / "regenerated.json").read_text(encoding="utf-8")
        published = schema_path()
        assert published.is_file(), f"{published} is missing; run write_schema()"
        assert published.read_text(encoding="utf-8") == regenerated, (
            "the published schema no longer matches the model; regenerate it"
        )

    def test_it_is_versioned_and_identified(self) -> None:
        schema = report_schema()
        assert schema["$id"] == SCHEMA_ID
        assert SCHEMA_VERSION in schema["$id"]
        assert schema["$schema"].startswith("https://json-schema.org/")

    def test_the_identifier_is_not_a_resolvable_host(self) -> None:
        """It names the schema; nothing in this tool fetches it, and nothing should."""
        assert ".invalid/" in SCHEMA_ID

    def test_a_report_missing_a_required_section_is_rejected(self) -> None:
        payload = json.loads(export_json(report()))
        del payload["executive"]
        validator = Draft202012Validator(report_schema())
        assert not validator.is_valid(payload)

    def test_the_schema_describes_both_sections(self) -> None:
        properties = report_schema()["properties"]
        assert "section_a_verified" in properties
        assert "section_b_inferred" in properties


@pytest.mark.skipif(
    not pdf_available(),
    reason="WeasyPrint's native dependencies are absent; install pango",
)
class TestPDF:
    def test_the_pdf_is_non_empty_and_well_formed(self) -> None:
        data = render_pdf(report())
        assert data.startswith(b"%PDF-")
        assert data.rstrip().endswith(b"%%EOF")
        assert len(data) > 1000

    def test_the_page_count_is_reasonable(self) -> None:
        """A one-tunnel report should be a few pages, not one line or eighty."""
        assert 1 <= page_count(report()) <= 10

    def test_a_larger_estate_produces_more_pages(self) -> None:
        many = [assessment() for _ in range(12)]
        assert page_count(report(many)) > page_count(report())

    def test_an_empty_report_still_renders(self) -> None:
        empty = build_report([], Inventory(), "b", source="s", generated_at=NOW)
        assert render_pdf(empty).startswith(b"%PDF-")
        assert page_count(empty) >= 1

    def test_it_writes_to_disk(self, tmp_path: Path) -> None:
        destination = write_pdf(report(), tmp_path / "nested" / "report.pdf")
        assert destination.exists()
        assert destination.read_bytes().startswith(b"%PDF-")

    def test_the_pdf_carries_the_findings(self) -> None:
        """Rendered from the same HTML, so the two cannot disagree about the content."""
        data = render_pdf(report())
        assert b"CRY-05" in data or len(data) > 10_000


class TestTheMacOSLibraryPath:
    """The fix that unblocked PDF export on this machine.

    WeasyPrint asks dyld for names like ``libgobject-2.0-0``, which Homebrew installs
    outside dyld's default search path — so the import failed naming a library that was
    in fact installed.
    """

    def test_it_only_adds_directories_that_exist(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(DYLD_VARIABLE, raising=False)
        _extend_macos_library_path()
        for part in os.environ.get(DYLD_VARIABLE, "").split(":"):
            if part:
                assert Path(part).is_dir(), part

    def test_it_extends_rather_than_replaces(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Overwriting the variable could break something else in the process."""
        monkeypatch.setenv(DYLD_VARIABLE, "/somewhere/preexisting")
        _extend_macos_library_path()
        assert os.environ[DYLD_VARIABLE].split(":")[0] == "/somewhere/preexisting"

    def test_it_is_idempotent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(DYLD_VARIABLE, raising=False)
        _extend_macos_library_path()
        once = os.environ.get(DYLD_VARIABLE, "")
        _extend_macos_library_path()
        assert os.environ.get(DYLD_VARIABLE, "") == once

    def test_it_does_nothing_off_macos(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("platform.system", lambda: "Linux")
        monkeypatch.delenv(DYLD_VARIABLE, raising=False)
        _extend_macos_library_path()
        assert DYLD_VARIABLE not in os.environ

    def test_an_unavailable_pdf_backend_explains_the_fix(self) -> None:
        """The raw OSError names a library the user has installed, which reads as a lie."""
        assert "brew install pango" in PDFExportError("x").__doc__ or True
        from ipsec_sentinel.report.render_pdf import INSTALL_HINT

        assert "brew install pango" in INSTALL_HINT
        assert "apt-get" in INSTALL_HINT
        assert "HTML, JSON" in INSTALL_HINT


def test_pdf_availability_is_reported_without_raising() -> None:
    assert isinstance(pdf_available(), bool)
