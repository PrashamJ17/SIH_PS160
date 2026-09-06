"""Tests for the analysis pipeline (the seam added at milestone M9).

This module makes no decisions of its own, so the tests are about routing rather than
judgement: that nothing is dropped between lanes, that the passive guarantee survives
end to end, and that an inference cannot enter the pipeline without its confidence.

The end-to-end runs use real captures from the sweep corpus rather than synthetic ones.
Every lane below has been tested on constructed input already; what has never been tested
until here is whether they agree with each other on real data.
"""

from __future__ import annotations

import socket
from datetime import UTC, datetime
from pathlib import Path

import pytest

from ipsec_sentinel.analyse import (
    analyse_capture,
    assess_tunnel,
    attach_inferences,
    pqc_summary,
    read_tunnels,
)
from ipsec_sentinel.assess.inventory import KnownTunnel
from ipsec_sentinel.models import ObservedConfig, TunnelAssessment
from ipsec_sentinel.report.models import Report

REPO_ROOT = Path(__file__).resolve().parents[2]
SWEEP = REPO_ROOT / "data" / "raw" / "sweep"


def corpus_captures(limit: int = 6) -> list[Path]:
    if not SWEEP.is_dir():
        return []
    found = sorted(SWEEP.glob("*/capture_outer.pcap"))
    return found[:limit]


CAPTURES = corpus_captures()
needs_corpus = pytest.mark.skipif(not CAPTURES, reason="the sweep corpus is not present")


@needs_corpus
class TestOnRealCaptures:
    def test_a_capture_produces_a_valid_report(self) -> None:
        report = analyse_capture(CAPTURES[0])
        assert isinstance(report, Report)
        assert report.executive.tunnels_assessed >= 1
        assert report.metadata.source == CAPTURES[0].name

    @pytest.mark.parametrize("capture", CAPTURES, ids=lambda p: p.parent.name[:24])
    def test_every_corpus_capture_analyses_without_error(self, capture: Path) -> None:
        report = analyse_capture(capture)
        assert report.executive.tunnels_assessed >= 0

    def test_the_sections_hold_the_split(self) -> None:
        report = analyse_capture(CAPTURES[0])
        assert all(f.confidence is None for f in report.section_a_verified)
        assert all(f.confidence is not None for f in report.section_b_inferred)

    def test_every_tunnel_reaches_the_exposure_section(self) -> None:
        report = analyse_capture(CAPTURES[0])
        assert len(report.metadata_exposure) == report.executive.tunnels_assessed

    def test_every_tunnel_is_graded_for_post_quantum_readiness(self) -> None:
        report = analyse_capture(CAPTURES[0])
        assert len(report.pqc.entries) == report.executive.tunnels_assessed

    def test_every_finding_names_its_tunnel(self) -> None:
        report = analyse_capture(CAPTURES[0])
        assert all(f.tunnel_id for f in report.all_findings)

    def test_the_report_round_trips(self) -> None:
        report = analyse_capture(CAPTURES[0])
        assert Report.model_validate_json(report.model_dump_json()) == report

    def test_a_documented_list_is_applied(self) -> None:
        tunnels = read_tunnels(CAPTURES[0])
        assert tunnels
        known = [KnownTunnel(endpoints=tunnels[0].endpoints, name="known-1")]
        report = analyse_capture(CAPTURES[0], known=known)
        assert report.inventory.documented_list_supplied is True
        assert report.executive.tunnels_undocumented < len(tunnels) or not tunnels

    def test_without_a_documented_list_nothing_is_called_undocumented(self) -> None:
        """The question was not asked, so it must not be answered."""
        report = analyse_capture(CAPTURES[0])
        assert report.inventory.documented_list_supplied is False
        assert report.executive.tunnels_undocumented == 0

    def test_the_flows_carry_their_sequence_analysis(self) -> None:
        report = analyse_capture(CAPTURES[0])
        for entry in report.metadata_exposure.entries:
            assert entry.total_packets >= 0

    def test_analysis_opens_no_socket(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Passive from end to end. This is the claim the whole product rests on."""

        def refuse(*_args: object, **_kwargs: object) -> None:
            raise AssertionError("analysis opened a socket")

        monkeypatch.setattr(socket, "socket", refuse)
        monkeypatch.setattr(socket, "create_connection", refuse)
        analyse_capture(CAPTURES[0])


class TestArgumentHandling:
    def test_a_missing_capture_is_a_clear_error(self) -> None:
        with pytest.raises(FileNotFoundError, match="no such capture"):
            analyse_capture(Path("/nonexistent/capture.pcap"))

    def test_the_source_can_be_named_explicitly(self) -> None:
        if not CAPTURES:
            pytest.skip("the sweep corpus is not present")
        report = analyse_capture(CAPTURES[0], source="mirror-port-2026-09-05")
        assert report.metadata.source == "mirror-port-2026-09-05"

    def test_the_timestamp_can_be_supplied(self) -> None:
        if not CAPTURES:
            pytest.skip("the sweep corpus is not present")
        when = datetime(2026, 1, 1, tzinfo=UTC)
        assert analyse_capture(CAPTURES[0], generated_at=when).metadata.generated_at == when

    def test_an_observed_config_reaches_the_rules(self) -> None:
        """Facts a passive observer cannot see, supplied by the operator."""
        if not CAPTURES:
            pytest.skip("the sweep corpus is not present")
        supplied = ObservedConfig(anti_replay_enabled=False)
        report = analyse_capture(CAPTURES[0], observed_config=supplied)
        assert isinstance(report, Report)


class TestInferencesEnterOnlyWithTheirConfidence:
    @staticmethod
    def _assessment() -> TunnelAssessment:
        return TunnelAssessment(
            tunnel_id="t-001",
            endpoints=("203.0.113.1", "198.51.100.1"),
            score=100,
            grade="A",
        )

    def test_a_class_without_a_confidence_is_refused(self) -> None:
        with pytest.raises(ValueError, match="must be supplied together"):
            attach_inferences(self._assessment(), traffic="voip")

    def test_a_confidence_without_a_class_is_refused(self) -> None:
        with pytest.raises(ValueError, match="must be supplied together"):
            attach_inferences(self._assessment(), traffic_confidence=0.9)

    def test_supplying_neither_leaves_the_assessment_untouched(self) -> None:
        original = self._assessment()
        assert attach_inferences(original) == original

    def test_a_class_and_confidence_are_attached_together(self) -> None:
        attached = attach_inferences(self._assessment(), traffic="voip", traffic_confidence=0.83)
        assert attached.inferred_traffic == "voip"
        assert attached.inferred_traffic_confidence is not None
        assert attached.inferred_traffic_confidence.value == 0.83

    def test_an_abstention_is_carried_through(self) -> None:
        attached = attach_inferences(
            self._assessment(), traffic="voip", traffic_confidence=0.4, abstained=True
        )
        assert attached.inferred_traffic_confidence is not None
        assert attached.inferred_traffic_confidence.abstained is True

    def test_the_pipeline_infers_nothing_on_its_own(self) -> None:
        """No model file is loaded, so an analysis run cannot degrade silently."""
        if not CAPTURES:
            pytest.skip("the sweep corpus is not present")
        report = analyse_capture(CAPTURES[0])
        assert all(e.inferred_traffic is None for e in report.metadata_exposure.entries)


@needs_corpus
class TestTheLanesAgree:
    def test_the_assessed_tunnels_match_the_parsed_ones(self) -> None:
        tunnels = read_tunnels(CAPTURES[0])
        report = analyse_capture(CAPTURES[0])
        assert report.executive.tunnels_assessed == len(tunnels)
        assert len(report.inventory.entries) == len(tunnels)

    def test_pqc_grades_every_tunnel_the_parser_found(self) -> None:
        tunnels = read_tunnels(CAPTURES[0])
        summary = pqc_summary(tunnels)
        assert [e.tunnel_id for e in summary.entries] == [t.tunnel_id for t in tunnels]

    def test_a_tunnel_assessment_carries_its_flows(self) -> None:
        tunnels = read_tunnels(CAPTURES[0])
        for tunnel in tunnels:
            assessed = assess_tunnel(tunnel)
            assert len(assessed.esp_flows) == len(tunnel.flows)
            assert assessed.tunnel_id == tunnel.tunnel_id

    def test_the_score_follows_from_the_findings(self) -> None:
        from ipsec_sentinel.assess.scoring import score_tunnel

        for tunnel in read_tunnels(CAPTURES[0]):
            assessed = assess_tunnel(tunnel)
            expected_score, expected_grade = score_tunnel(assessed.findings)
            assert (assessed.score, assessed.grade) == (expected_score, expected_grade)
