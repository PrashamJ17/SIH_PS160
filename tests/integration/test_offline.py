"""Air-gapped operation, proved by taking the network away (build plan Step 11.4).

The deployment this tool is designed for is a host that watches a network under
investigation, and such a host frequently has no outbound access at all. So "works
offline" cannot be a design intention recorded in a docstring; it has to be a property
something checks.

These tests remove the network and then run the product. ``socket.socket``,
``socket.create_connection``, ``socket.getaddrinfo`` and ``socket.gethostbyname`` are
replaced with functions that raise, which is stricter than pulling the cable: a DNS
lookup fails here even when a resolver is reachable, and a lookup is itself a leak of
what is being analysed.

The interesting half is not that the pipeline completes. It is that a run without the
reference corpora **says so in the report**. A report with no ATT&CK names and no vendor
CVEs looks exactly like a report where nothing matched, and on an air-gapped host the
first is the normal case — so silence there would turn a degraded run into a clean bill
of health.
"""

from __future__ import annotations

import json
import socket
from collections.abc import Iterator
from pathlib import Path

import pytest

from ipsec_sentinel.analyse import analyse_capture
from ipsec_sentinel.assess.enrich import corpus_status, lookup_cves, technique
from ipsec_sentinel.report.export_json import export_json, report_schema
from ipsec_sentinel.report.models import EnrichmentStatus, Report
from ipsec_sentinel.report.render_html import render_html
from ipsec_sentinel.report.siem import report_to_cef, report_to_leef, report_to_syslog

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[2]
SWEEP = REPO_ROOT / "data" / "raw" / "sweep"
DEMO = REPO_ROOT / "demo" / "pcaps"


def _blocked(*_args: object, **_kwargs: object) -> None:
    raise OSError("the network is unavailable: this host is air-gapped")


@pytest.fixture
def air_gapped(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Remove every route out, including name resolution."""
    for name in ("socket", "create_connection", "getaddrinfo", "gethostbyname"):
        monkeypatch.setattr(socket, name, _blocked)
    yield


@pytest.fixture(scope="module")
def a_capture() -> Path:
    for candidate in (
        sorted(DEMO.glob("*.pcap")),
        sorted(SWEEP.glob("*/capture_outer.pcap")),
    ):
        if candidate:
            return candidate[0]
    pytest.skip("no capture is available")
    raise AssertionError("unreachable")


@pytest.mark.usefixtures("air_gapped")
class TestTheNetworkIsGenuinelyGone:
    """If the fixture does not bite, everything below it proves nothing."""

    def test_a_connection_attempt_fails(self) -> None:
        with pytest.raises(OSError, match="air-gapped"):
            socket.create_connection(("example.invalid", 80))

    def test_name_resolution_fails_too(self) -> None:
        with pytest.raises(OSError, match="air-gapped"):
            socket.getaddrinfo("example.invalid", 443)


@pytest.mark.usefixtures("air_gapped")
class TestThePipelineCompletes:
    def test_analysis_produces_a_report(self, a_capture: Path) -> None:
        report = analyse_capture(a_capture, baseline="default")
        assert isinstance(report, Report)
        assert report.metadata.source

    def test_every_output_format_renders(self, a_capture: Path) -> None:
        report = analyse_capture(a_capture, baseline="default")

        html = render_html(report)
        payload = export_json(report)
        assert html.lstrip().startswith("<!DOCTYPE html>")
        assert json.loads(payload)["metadata"]["source"]
        assert report_to_cef(report) is not None
        assert report_to_leef(report) is not None
        assert report_to_syslog(report) is not None

    def test_the_exported_report_still_validates_against_the_schema(self, a_capture: Path) -> None:
        """Degraded enrichment must not produce a payload a consumer would reject."""
        from jsonschema import Draft202012Validator

        report = analyse_capture(a_capture, baseline="default")
        Draft202012Validator(report_schema()).validate(json.loads(export_json(report)))

    def test_the_cli_runs_end_to_end(self, a_capture: Path, tmp_path: Path) -> None:
        from click.testing import CliRunner

        from ipsec_sentinel.cli import main

        html = tmp_path / "report.html"
        payload = tmp_path / "report.json"
        result = CliRunner().invoke(
            main,
            ["analyse", str(a_capture), "--out", str(html), "--json", str(payload)],
        )

        assert result.exit_code == 0, result.output
        assert html.stat().st_size > 0
        assert json.loads(payload.read_text())["metadata"]["source"]


class TestTheAssessmentDoesNotDependOnReachability:
    def test_findings_are_unchanged_by_the_absence_of_the_network(
        self, a_capture: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The assessment is a function of the capture, not of what the host can reach."""
        connected = analyse_capture(a_capture, baseline="default")
        for name in ("socket", "create_connection", "getaddrinfo", "gethostbyname"):
            monkeypatch.setattr(socket, name, _blocked)
        offline = analyse_capture(a_capture, baseline="default")

        assert [f.rule_id for f in offline.section_a_verified] == [
            f.rule_id for f in connected.section_a_verified
        ]
        assert offline.executive.estate_score == connected.executive.estate_score
        assert offline.executive.estate_grade == connected.executive.estate_grade


@pytest.mark.usefixtures("air_gapped")
class TestEnrichmentDegradesWithANoteRatherThanAnError:
    def test_a_cve_lookup_returns_empty_rather_than_raising(self, tmp_path: Path) -> None:
        assert lookup_cves("strongSwan", "5.9.8", cache_path=tmp_path / "absent.json") == []

    def test_a_cached_cve_is_still_found_offline(self, tmp_path: Path) -> None:
        """Cache, not network: the lookup path is identical either way."""
        cache = tmp_path / "cve.json"
        cache.write_text(
            json.dumps(
                {
                    "strongswan|5.9.8": [
                        {
                            "cve_id": "CVE-2023-41913",
                            "summary": "charon-tkm buffer overflow",
                            "severity": "CRITICAL",
                            "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-41913",
                        }
                    ]
                }
            )
        )
        found = lookup_cves("strongSwan", "5.9.8", cache_path=cache)
        assert [reference.cve_id for reference in found] == ["CVE-2023-41913"]

    def test_an_unknown_technique_resolves_to_none_rather_than_raising(self) -> None:
        assert technique("T9999") is None

    def test_the_report_carries_a_note_when_the_corpora_are_missing(
        self, a_capture: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            "ipsec_sentinel.report.build.corpus_status",
            lambda: type(corpus_status())(attack_techniques=0, cve_cache_entries=0),
        )
        report = analyse_capture(a_capture, baseline="default")

        assert report.metadata.enrichment.degraded
        note = report.metadata.enrichment.note
        assert note is not None
        assert "reduced reference data" in note
        assert "built in and unaffected" in note, (
            "the note must distinguish protocol CVEs, which are compiled in, from vendor "
            "CVEs, which are not"
        )
        assert "reduced reference data" in render_html(report)

    def test_the_threat_matrix_still_carries_protocol_cves(self, a_capture: Path) -> None:
        """These are compiled in, so an air-gapped report is not CVE-free."""
        report = analyse_capture(a_capture, baseline="default")
        if not report.section_a_verified:
            pytest.skip("this capture produced no findings to map")
        assert report.threat_matrix is not None

    def test_a_complete_corpus_produces_no_note(self) -> None:
        assert EnrichmentStatus(attack_techniques=800, cve_cache_entries=12).note is None
