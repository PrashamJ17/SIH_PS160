"""Tests for the HTML renderer (build plan Step 9.5).

The plan's five criteria, plus the two that matter most for a security tool.

An assessment report prints strings that were read off the wire — vendor IDs, algorithm
names, addresses — and every one of them is attacker-controlled. If autoescaping were
off, a crafted IKE vendor ID could execute script in the browser of whoever opened the
report. ``TestUntrustedContentIsEscaped`` crafts that payload.

The self-containment check is stricter than "it looks fine here": a stylesheet or font
that loads from a CDN works perfectly on a developer's machine and produces an unstyled
page on the air-gapped network where the report is actually read.
"""

from __future__ import annotations

import re
import tomllib
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path

import pytest

from ipsec_sentinel.assess.inventory import Inventory, InventoryEntry, InventoryStatus, KnownTunnel
from ipsec_sentinel.assess.rules.pqc import PQCGrade
from ipsec_sentinel.models import Confidence, ESPFlow, Finding, Severity, TunnelAssessment
from ipsec_sentinel.report.build import build_report
from ipsec_sentinel.report.models import PQCEntry, PQCSummary, Report
from ipsec_sentinel.report.render_html import human_bytes, render_html, write_html
from ipsec_sentinel.report.threat_matrix import build_threat_matrix

NOW = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)
REPO_ROOT = Path(__file__).resolve().parents[2]

VOID_ELEMENTS = frozenset(
    {
        "area",
        "base",
        "br",
        "col",
        "embed",
        "hr",
        "img",
        "input",
        "link",
        "meta",
        "source",
        "track",
        "wbr",
    }
)


class StructureChecker(HTMLParser):
    """A tag-balance check, since no HTML library is a dependency of this project.

    Not a full validator, but it catches the failure that actually happens with
    templates: a conditional branch that opens a tag it never closes.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[str] = []
        self.errors: list[str] = []
        self.resources: list[tuple[str, str]] = []
        """Every ``src``/``href`` the document references, as (tag, url).

        Collected through the parser rather than by matching the raw text, so an
        attribute split across lines or quoted unusually cannot slip past the
        self-containment check.
        """

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for name, value in attrs:
            if name in ("src", "href") and value is not None:
                self.resources.append((tag, value))
        if tag not in VOID_ELEMENTS:
            self.stack.append(tag)

    def handle_endtag(self, tag: str) -> None:
        if tag in VOID_ELEMENTS:
            return
        if not self.stack:
            self.errors.append(f"</{tag}> with nothing open")
        elif self.stack[-1] != tag:
            self.errors.append(f"</{tag}> closes <{self.stack[-1]}>")
            if tag in self.stack:
                while self.stack and self.stack.pop() != tag:
                    pass
        else:
            self.stack.pop()


def parse(html: str) -> StructureChecker:
    checker = StructureChecker()
    checker.feed(html)
    checker.close()
    return checker


def assert_well_formed(html: str) -> None:
    checker = parse(html)
    assert not checker.errors, checker.errors
    assert not checker.stack, f"unclosed tags: {checker.stack}"


def parsed(
    rule_id: str = "CRY-05", severity: Severity = Severity.CRITICAL, **kwargs: str
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=kwargs.get("title", "3DES negotiated"),
        severity=severity,
        evidence=kwargs.get("evidence", "the responder selected ENCR_3DES"),
        standard_ref="RFC 8221 section 5",
        attack_technique="T1600.001",
        remediation_hint="Move to AES-GCM.",
    )


def inferred(value: float = 0.82) -> Finding:
    return Finding(
        rule_id="ANOM-01",
        title="Traffic shape unlike the rest of the estate",
        severity=Severity.MEDIUM,
        evidence="isolation forest score",
        standard_ref="n/a",
        remediation_hint="Confirm with the tunnel's owner.",
        confidence=Confidence(value=value, method="isolation_forest"),
    )


def assessment(tunnel_id: str = "t-001", findings: list[Finding] | None = None) -> TunnelAssessment:
    return TunnelAssessment(
        tunnel_id=tunnel_id,
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
        findings=findings or [],
        score=30,
        grade="D",
        inferred_traffic="voip",
        inferred_traffic_confidence=Confidence(value=0.77, method="calibrated_xgboost"),
    )


def report(
    assessments: list[TunnelAssessment] | None = None,
    inventory: Inventory | None = None,
    **kwargs: object,
) -> Report:
    given = (
        assessments if assessments is not None else [assessment("t-001", [parsed(), inferred()])]
    )
    return build_report(
        given,
        inventory if inventory is not None else Inventory(),
        "nist_800_77r1",
        source="capture_outer.pcap",
        generated_at=NOW,
        **kwargs,  # type: ignore[arg-type]
    )


class TestThePlansCriteria:
    def test_the_output_parses_as_html(self) -> None:
        assert_well_formed(render_html(report()))

    def test_it_declares_a_doctype_and_a_title(self) -> None:
        html = render_html(report())
        assert html.lstrip().startswith("<!DOCTYPE html>")
        assert "<title>" in html

    def test_there_are_no_external_resource_references(self) -> None:
        """A CDN stylesheet works on a laptop and fails on the network that matters."""
        resources = parse(render_html(report())).resources
        offending = [
            (tag, url) for tag, url in resources if url.startswith(("http://", "https://", "//"))
        ]
        assert not offending, f"external resources referenced: {offending}"

    def test_nothing_is_loaded_from_anywhere(self) -> None:
        html = render_html(report())
        for tag in ("<script", "<iframe", "<object", "<embed", "@import"):
            assert tag not in html.lower(), f"{tag} present"
        assert "<link" not in html.lower()

    def test_section_b_entries_display_their_confidence(self) -> None:
        html = render_html(report([assessment("t-001", [inferred(0.82)])]))
        assert "0.82" in html
        assert "isolation_forest" in html

    def test_section_a_entries_display_no_confidence(self) -> None:
        html = render_html(report([assessment("t-001", [parsed()])]))
        section_a = html.split("Section A &mdash; verified findings")[1].split("<h2>")[0]
        assert "Confidence" not in section_a

    def test_it_renders_with_zero_findings(self) -> None:
        html = render_html(report([]))
        assert_well_formed(html)
        assert "No verified findings" in html
        assert "No inferred findings" in html
        assert "No tunnels were observed" in html


class TestUntrustedContentIsEscaped:
    """Report content is read off the wire and is attacker-controlled."""

    PAYLOAD = '<script>alert("xss")</script>'

    def test_a_crafted_finding_cannot_inject_script(self) -> None:
        html = render_html(report([assessment("t-001", [parsed(evidence=self.PAYLOAD)])]))
        assert self.PAYLOAD not in html
        assert "&lt;script&gt;" in html
        assert "<script>" not in html.lower()

    def test_a_crafted_tunnel_identifier_is_escaped(self) -> None:
        html = render_html(report([assessment(self.PAYLOAD, [parsed()])]))
        assert "<script>" not in html.lower()

    def test_a_crafted_inventory_entry_is_escaped(self) -> None:
        inventory = Inventory(
            entries=[
                InventoryEntry(
                    tunnel_id="t-001",
                    endpoints=(self.PAYLOAD, "198.51.100.1"),
                    status=InventoryStatus.UNDOCUMENTED,
                    negotiated_suite=self.PAYLOAD,
                )
            ]
        )
        html = render_html(report(inventory=inventory))
        assert "<script>" not in html.lower()

    def test_a_crafted_payload_does_not_break_the_structure(self) -> None:
        """An escaped payload must still leave valid markup around it."""
        html = render_html(
            report([assessment("t-001", [parsed(evidence="</td></tr></table><b>")])])
        )
        assert_well_formed(html)

    def test_the_template_environment_has_autoescaping_on(self) -> None:
        from ipsec_sentinel.report.render_html import _environment

        assert _environment().autoescape


class TestTheSectionsAreDistinguishableWithoutColour:
    """A greyscale print, or a reader who cannot tell the two colours apart."""

    def test_each_section_has_its_own_heading(self) -> None:
        html = render_html(report())
        assert "Section A &mdash; verified findings" in html
        assert "Section B &mdash; inferred findings" in html

    def test_every_finding_carries_a_text_label(self) -> None:
        html = render_html(report())
        assert "Section A &mdash; verified</span>" in html
        assert "Section B &mdash; inferred</span>" in html

    def test_the_difference_is_explained_in_words(self) -> None:
        html = render_html(report())
        assert "How to read this report" in html
        assert "read directly from the negotiation" in html
        assert "estimated from traffic patterns" in html

    def test_the_labels_survive_with_styling_removed(self) -> None:
        """Strip every style block and the distinction must still be readable."""
        html = re.sub(r"<style>.*?</style>", "", render_html(report()), flags=re.S)
        assert "Section A" in html
        assert "Section B" in html
        assert "verified" in html and "inferred" in html


class TestTheSections:
    def test_the_exposure_section_lists_a_clean_tunnel(self) -> None:
        html = render_html(report([assessment("t-clean", [])]))
        assert "What encryption does not hide" in html
        assert "t-clean" in html

    def test_an_abstained_class_reads_as_not_stated(self) -> None:
        quiet = assessment("t-001", [])
        quiet = quiet.model_copy(
            update={
                "inferred_traffic": None,
                "inferred_traffic_confidence": None,
            }
        )
        html = render_html(report([quiet]))
        assert "not stated" in html

    def test_the_threat_matrix_renders_its_cves_as_plain_text(self) -> None:
        """A link nobody can follow is worth less than a URL a reader can copy."""
        built = report([assessment("t-001", [parsed()])])
        html = render_html(built)
        assert "CVE-2016-2183" in html
        assert "CVSS 7.5" in html
        assert 'href="https://nvd' not in html

    def test_the_matrix_names_findings_it_could_not_categorise(self) -> None:
        uncategorised = Finding(
            rule_id="SA-01",
            title="Long lifetime",
            severity=Severity.MEDIUM,
            evidence="e",
            standard_ref="r",
            remediation_hint="h",
        )
        built = report([assessment("t-001", [uncategorised])])
        assert built.threat_matrix.uncategorised_rules == ["SA-01"]
        assert "SA-01" in render_html(built)

    def test_the_pqc_section_renders_when_supplied(self) -> None:
        built = report(
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
        html = render_html(built)
        assert "exposed" in html
        assert "classical key exchange only" in html

    def test_an_absent_pqc_section_says_so_rather_than_being_blank(self) -> None:
        assert "No post-quantum assessment was included" in render_html(report())

    def test_documented_but_unobserved_tunnels_are_listed(self) -> None:
        inventory = Inventory(
            documented_list_supplied=True,
            unobserved=[KnownTunnel(endpoints=("10.0.0.1", "10.0.0.2"), name="branch-7")],
        )
        html = render_html(report(inventory=inventory))
        assert "Documented but not observed" in html
        assert "branch-7" in html

    def test_the_footer_states_the_tool_never_writes_to_a_device(self) -> None:
        html = render_html(report())
        assert "never writes to a network" in html
        assert "stores no credential" in html

    def test_the_provenance_is_printed(self) -> None:
        html = render_html(report())
        assert "nist_800_77r1" in html
        assert "capture_outer.pcap" in html


class TestPrintability:
    def test_a_print_stylesheet_is_present(self) -> None:
        assert "@media print" in render_html(report())

    def test_findings_are_kept_off_page_breaks(self) -> None:
        html = render_html(report())
        assert "page-break-inside: avoid" in html


class TestWritingToDisk:
    def test_it_writes_a_standalone_file(self, tmp_path: Path) -> None:
        destination = write_html(report(), tmp_path / "nested" / "report.html")
        assert destination.exists()
        assert_well_formed(destination.read_text(encoding="utf-8"))

    def test_the_file_is_utf8(self, tmp_path: Path) -> None:
        finding = parsed(evidence="peer identity: café — naïve")
        destination = write_html(report([assessment("t-001", [finding])]), tmp_path / "r.html")
        assert "café" in destination.read_text(encoding="utf-8")


class TestPackaging:
    def test_the_template_is_declared_as_package_data(self) -> None:
        """Otherwise a wheel renders no report, and only once installed."""
        config = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())
        patterns = config["tool"]["setuptools"]["package-data"]["ipsec_sentinel"]
        assert any("report/templates" in pattern for pattern in patterns), patterns

    def test_the_template_file_exists_where_the_module_looks(self) -> None:
        from ipsec_sentinel.report.render_html import TEMPLATE_DIR, TEMPLATE_NAME

        assert (TEMPLATE_DIR / TEMPLATE_NAME).is_file()


@pytest.mark.parametrize(
    ("count", "expected"),
    [(0, "0 B"), (999, "999 B"), (1000, "1.0 kB"), (250_000, "250.0 kB"), (5_000_000, "5.0 MB")],
)
def test_human_bytes(count: int, expected: str) -> None:
    assert human_bytes(count) == expected


def test_a_report_with_a_change_package_renders_its_steps() -> None:
    from ipsec_sentinel.remediate.generators.strongswan import generate_change_package
    from testbed.orchestrate.matrix import expand_matrix

    config = next(lc.config for lc in expand_matrix() if lc.label == "weak")
    package = generate_change_package("t-001", config, ["CRY-02"])
    html = render_html(report(remediation=[package]))
    assert_well_formed(html)
    assert "Remediation" in html
    assert "CRY-02" in html
    for step in package.sequence:
        assert str(step.order) in html


def test_the_threat_matrix_is_consistent_with_the_findings() -> None:
    built = report([assessment("t-001", [parsed()])])
    assert built.threat_matrix.rows == build_threat_matrix([assessment("t-001", [parsed()])]).rows
