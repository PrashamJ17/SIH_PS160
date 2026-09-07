"""Device-state findings in the report (follows Step 11.9).

Step 11.9 graded an installed ESP SA and printed the result. It reached the CLI and
stopped there: nothing in the HTML, the JSON or the score.

The design question this answers is how a device's self-report relates to a captured
tunnel, and there are two cases that behave differently on purpose.

**Matched** — the device describes a tunnel the capture also saw. Its findings attach to
that tunnel's assessment, so they flow into Section A stamped with the tunnel id *and*
lower the tunnel's score. A tunnel with 3DES installed should score worse, and a score
left stale after appending findings would be a lie.

**Unmatched** — the device describes a tunnel the capture never saw. Its findings are
still real and still deterministic, so they belong in Section A; but there is no tunnel to
attribute them to, and the estate score is a mean over assessed tunnels, so they cannot
move it. Inventing a tunnel to hang them on would be worse than the gap.

Everything here is deterministic — read from a device, not inferred — so it is Section A
throughout, and the evidence names the device so a reader can tell it from the wire.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from ipsec_sentinel.assess.inventory import Inventory
from ipsec_sentinel.collect import DeviceState, ESPParameters, parse_xfrm_state
from ipsec_sentinel.models import (
    Confidence,
    ESPFlow,
    Finding,
    Severity,
    TunnelAssessment,
)
from ipsec_sentinel.report.build import build_report
from ipsec_sentinel.report.device_state import summarise_device_states
from ipsec_sentinel.report.models import DeviceStateSummary, Report

NOW = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)
ENDPOINTS = ("10.0.0.1", "10.0.0.2")

WEAK_XFRM = """src 10.0.0.1 dst 10.0.0.2
\tproto esp spi 0xaaaa0001 reqid 1 mode tunnel
\treplay-window 0 flag af-unspec
\tauth-trunc hmac(md5) 0x{auth} 96
\tenc cbc(des3_ede) 0x{enc}
src 10.0.0.2 dst 10.0.0.1
\tproto esp spi 0xbbbb0002 reqid 1 mode tunnel
\treplay-window 0 flag af-unspec
\tauth-trunc hmac(md5) 0x{auth} 96
\tenc cbc(des3_ede) 0x{enc}
""".format(auth="cd" * 16, enc="ef" * 24)


def state(text: str = WEAK_XFRM, source: str = "gw01") -> DeviceState:
    return DeviceState(
        source=source,
        collected_at=NOW,
        kernel_sas=tuple(parse_xfrm_state(text)),
    )


def assessment(
    tunnel_id: str = "t-001", endpoints: tuple[str, str] = ENDPOINTS
) -> TunnelAssessment:
    return TunnelAssessment(
        tunnel_id=tunnel_id,
        endpoints=endpoints,
        esp_flows=[
            ESPFlow(
                spi="0x1",
                src_ip=endpoints[0],
                dst_ip=endpoints[1],
                packet_count=10,
                byte_count=1000,
                first_seen=NOW,
                last_seen=NOW,
            )
        ],
        findings=[],
        score=100,
        grade="A",
    )


def build(assessments: list[TunnelAssessment], states: list[DeviceState]) -> Report:
    summary, updated, unattached = summarise_device_states(assessments, states, baseline="default")
    return build_report(
        updated,
        Inventory(),
        "default",
        source="capture.pcap",
        generated_at=NOW,
        device_state=summary,
        extra_findings=unattached,
    )


class TestAMatchedDeviceAttachesToItsTunnel:
    def test_the_findings_reach_section_a(self) -> None:
        report = build([assessment()], [state()])
        assert {finding.rule_id for finding in report.section_a_verified} >= {"CRY-05", "CRY-06"}

    def test_they_carry_the_tunnel_they_belong_to(self) -> None:
        report = build([assessment()], [state()])
        installed = [f for f in report.section_a_verified if "installed on" in f.evidence]
        assert installed
        assert all(finding.tunnel_id == "t-001" for finding in installed)

    def test_the_tunnel_score_drops(self) -> None:
        """A tunnel running 3DES should not still read 100 because the wire was quiet."""
        _, updated, _ = summarise_device_states([assessment()], [state()], baseline="default")
        assert updated[0].score < 100
        assert updated[0].grade != "A"

    def test_the_estate_score_follows(self) -> None:
        clean = build([assessment()], [])
        graded = build([assessment()], [state()])
        assert graded.executive.estate_score < clean.executive.estate_score

    def test_the_entry_names_the_tunnel_it_matched(self) -> None:
        report = build([assessment()], [state()])
        assert report.device_state.entries[0].matched_tunnel == "t-001"

    def test_matching_is_direction_insensitive(self) -> None:
        """The kernel's src/dst are one direction of a pair; the tunnel's are canonical."""
        reversed_endpoints = (ENDPOINTS[1], ENDPOINTS[0])
        _, updated, _ = summarise_device_states(
            [assessment(endpoints=reversed_endpoints)], [state()], baseline="default"
        )
        assert updated[0].score < 100


class TestAnUnmatchedDeviceIsStillReported:
    def test_the_findings_still_reach_section_a(self) -> None:
        report = build([assessment(endpoints=("192.0.2.1", "192.0.2.2"))], [state()])
        assert {finding.rule_id for finding in report.section_a_verified} >= {"CRY-05"}

    def test_they_are_attributed_to_no_tunnel(self) -> None:
        """Inventing a tunnel id to hang them on would be worse than the gap."""
        report = build([assessment(endpoints=("192.0.2.1", "192.0.2.2"))], [state()])
        installed = [f for f in report.section_a_verified if "installed on" in f.evidence]
        assert installed
        assert all(finding.tunnel_id is None for finding in installed)

    def test_the_captured_tunnel_is_not_penalised_for_it(self) -> None:
        _, updated, _ = summarise_device_states(
            [assessment(endpoints=("192.0.2.1", "192.0.2.2"))], [state()], baseline="default"
        )
        assert updated[0].score == 100

    def test_the_entry_says_it_matched_nothing(self) -> None:
        report = build([assessment(endpoints=("192.0.2.1", "192.0.2.2"))], [state()])
        assert report.device_state.entries[0].matched_tunnel is None

    def test_the_note_says_the_estate_score_cannot_reflect_it(self) -> None:
        report = build([assessment(endpoints=("192.0.2.1", "192.0.2.2"))], [state()])
        assert "estate score" in report.device_state.note.lower()


class TestTheSectionDescribesEachDevice:
    def test_it_names_the_device_and_the_source(self) -> None:
        entry = build([assessment()], [state()]).device_state.entries[0]
        assert entry.source == "gw01"
        assert entry.origin == "kernel"

    def test_it_carries_the_installed_suite(self) -> None:
        entry = build([assessment()], [state()]).device_state.entries[0]
        assert entry.installed == "3des/md5"

    def test_it_grades_the_installed_sa_on_its_own(self) -> None:
        entry = build([assessment()], [state()]).device_state.entries[0]
        assert entry.score < 100
        assert entry.grade in {"D", "E", "F"}

    def test_it_counts_the_findings(self) -> None:
        entry = build([assessment()], [state()]).device_state.entries[0]
        assert entry.finding_count >= 2

    def test_it_names_what_the_device_could_not_say(self) -> None:
        entry = build([assessment()], [state()]).device_state.entries[0]
        assert {"ike_version", "dh_group"} <= set(entry.unknown)

    def test_a_device_reporting_nothing_usable_is_still_listed(self) -> None:
        """Silence from a gateway is itself worth seeing in the report."""
        empty = DeviceState(source="gw09", collected_at=NOW)
        summary, _, _ = summarise_device_states([assessment()], [empty], baseline="default")
        assert len(summary.entries) == 1
        assert summary.entries[0].installed is None
        assert summary.entries[0].score is None

    def test_several_devices_each_get_an_entry(self) -> None:
        report = build([assessment()], [state(source="gw01"), state(source="gw02")])
        assert [entry.source for entry in report.device_state.entries] == ["gw01", "gw02"]


class TestTheSeparationHolds:
    def test_no_device_finding_carries_a_confidence(self) -> None:
        """Read from a device is a parsed fact, not an inference."""
        report = build([assessment()], [state()])
        installed = [f for f in report.section_a_verified if "installed on" in f.evidence]
        assert installed
        assert all(finding.confidence is None for finding in installed)

    def test_nothing_device_derived_reaches_section_b(self) -> None:
        report = build([assessment()], [state()])
        assert not [f for f in report.section_b_inferred if "installed on" in f.evidence]

    def test_the_validator_still_refuses_a_mixed_report(self) -> None:
        inferred = Finding(
            rule_id="ANOM-01",
            title="x",
            severity=Severity.LOW,
            evidence="installed on gw01",
            standard_ref="n/a",
            remediation_hint="n/a",
            confidence=Confidence(value=0.5, method="test"),
        )
        with pytest.raises(ValueError, match="Section A"):
            build_report([], Inventory(), "default", source="s", generated_at=NOW).model_copy(
                update={"section_a_verified": [inferred]}
            ).enforce_separation()


class TestWithNoDeviceStateNothingChanges:
    def test_the_section_is_empty(self) -> None:
        report = build([assessment()], [])
        assert report.device_state.entries == []

    def test_the_report_is_otherwise_identical(self) -> None:
        before = build([assessment()], [])
        assert before.executive.estate_score == 100
        assert before.section_a_verified == []

    def test_a_report_built_without_the_argument_still_validates(self) -> None:
        report = build_report([], Inventory(), "default", source="s", generated_at=NOW)
        assert isinstance(report.device_state, DeviceStateSummary)
        assert report.device_state.entries == []


class TestItSurvivesTheRoundTrip:
    def test_json_keeps_the_section(self) -> None:
        report = build([assessment()], [state()])
        restored = Report.model_validate_json(report.model_dump_json())
        assert restored.device_state.entries[0].source == "gw01"
        assert restored.device_state.entries[0].installed == "3des/md5"

    def test_the_html_renders_it(self) -> None:
        from ipsec_sentinel.report.render_html import render_html

        html = render_html(build([assessment()], [state()]))
        assert "gw01" in html
        assert "3des/md5" in html

    def test_the_html_omits_the_section_when_there_is_none(self) -> None:
        from ipsec_sentinel.report.render_html import render_html

        assert "Device state" not in render_html(build([assessment()], []))

    def test_the_exported_report_validates_against_the_schema(self) -> None:
        import json

        from jsonschema import Draft202012Validator

        from ipsec_sentinel.report.export_json import export_json, report_schema

        payload = json.loads(export_json(build([assessment()], [state()])))
        Draft202012Validator(report_schema()).validate(payload)


class TestTheDaemonOriginIsDistinguished:
    def test_a_daemon_sourced_entry_says_so(self) -> None:
        from ipsec_sentinel.collect import NegotiatedChild

        daemon = DeviceState(
            source="gw03",
            collected_at=NOW,
            child=NegotiatedChild(
                installed=True,
                mode="tunnel",
                esp_encryption="3DES_CBC",
                esp_integrity="HMAC_MD5_96",
            ),
        )
        summary, _, _ = summarise_device_states([assessment()], [daemon], baseline="default")
        assert summary.entries[0].origin == "daemon"


class TestTheBaselineIsHonoured:
    def test_cnsa_grades_a_128_bit_key_the_default_accepts(self) -> None:
        aes128 = DeviceState(
            source="gw04",
            collected_at=NOW,
            kernel_sas=(),
        )
        # Built directly: the point is the baseline reaching assess_esp, not the parser.
        from ipsec_sentinel.assess.esp import assess_esp

        esp = ESPParameters(encryption="aes128", encryption_keylen=128, integrity="sha256")
        assert not assess_esp(esp, source="gw04", baseline="nist_800_77r1")
        assert assess_esp(esp, source="gw04", baseline="cnsa")
        assert aes128.is_empty


class TestItReachesTheReportThroughAnalyseCapture:
    """The seam an operator actually goes through."""

    @staticmethod
    def _capture() -> Path:
        found = sorted((Path(__file__).resolve().parents[2] / "demo" / "pcaps").glob("*.pcap"))
        if not found:
            pytest.skip("no demo capture is present")
        return found[0]

    def test_a_capture_with_no_device_state_has_an_empty_section(self) -> None:
        from ipsec_sentinel.analyse import analyse_capture

        report = analyse_capture(self._capture(), baseline="default")
        assert report.device_state.entries == []

    def test_device_state_reaches_the_report(self) -> None:
        from ipsec_sentinel.analyse import analyse_capture

        report = analyse_capture(
            self._capture(), baseline="default", device_states=[state(source="gw07")]
        )
        assert [entry.source for entry in report.device_state.entries] == ["gw07"]
        assert report.device_state.entries[0].installed == "3des/md5"

    def test_its_findings_reach_section_a(self) -> None:
        from ipsec_sentinel.analyse import analyse_capture

        report = analyse_capture(
            self._capture(), baseline="default", device_states=[state(source="gw07")]
        )
        installed = [f for f in report.section_a_verified if "installed on gw07" in f.evidence]
        assert {finding.rule_id for finding in installed} >= {"CRY-05", "CRY-06"}

    def test_the_executive_finding_count_includes_them(self) -> None:
        from ipsec_sentinel.analyse import analyse_capture

        without = analyse_capture(self._capture(), baseline="default")
        with_state = analyse_capture(
            self._capture(), baseline="default", device_states=[state(source="gw07")]
        )
        assert with_state.executive.verified_findings > without.executive.verified_findings
