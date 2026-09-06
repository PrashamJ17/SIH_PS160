"""Tests for metadata exposure (build plan Step 9.3).

The plan's three criteria come first. The rest exist because this section is the one a
reader is most likely to over-read: it is the only place a report says something about a
tunnel that has nothing wrong with it, and everything it says has to be either measured
or labelled as an estimate.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from ipsec_sentinel.models import Confidence, ESPFlow, Finding, Severity, TunnelAssessment
from ipsec_sentinel.report.exposure import build_exposure, exposure_for, session_count
from ipsec_sentinel.report.models import ExposureEntry

DAY = datetime(2026, 3, 4, 0, 0, tzinfo=UTC)


def flow(
    *,
    spi: str = "aabbccdd",
    start_hour: float = 9.0,
    duration_s: float = 600.0,
    packets: int = 100,
    total_bytes: int = 100_000,
    reverse: bool = False,
) -> ESPFlow:
    first = DAY + timedelta(hours=start_hour)
    src, dst = ("203.0.113.1", "198.51.100.1")
    if reverse:
        src, dst = dst, src
    return ESPFlow(
        spi=spi,
        src_ip=src,
        dst_ip=dst,
        packet_count=packets,
        byte_count=total_bytes,
        first_seen=first,
        last_seen=first + timedelta(seconds=duration_s),
    )


def tunnel(
    tunnel_id: str = "t-001",
    flows: list[ESPFlow] | None = None,
    *,
    traffic: str | None = None,
    confidence: float = 0.88,
    abstained: bool = False,
    findings: list[Finding] | None = None,
    score: int = 100,
    grade: str = "A",
) -> TunnelAssessment:
    inferred = (
        Confidence(value=confidence, method="calibrated_xgboost", abstained=abstained)
        if traffic is not None
        else None
    )
    return TunnelAssessment(
        tunnel_id=tunnel_id,
        endpoints=("203.0.113.1", "198.51.100.1"),
        esp_flows=flows if flows is not None else [flow()],
        findings=findings or [],
        score=score,
        grade=grade,
        inferred_traffic=traffic,
        inferred_traffic_confidence=inferred,
    )


class TestThePlansCriteria:
    def test_a_perfectly_configured_tunnel_still_produces_an_entry(self) -> None:
        """The point of the section. A grade-A tunnel is not an absence of exposure."""
        exposure = build_exposure([tunnel(score=100, grade="A", findings=[])])
        assert len(exposure) == 1
        assert exposure.entries[0].tunnel_id == "t-001"
        assert exposure.entries[0].total_bytes > 0

    def test_the_entry_includes_the_inferred_traffic_class(self) -> None:
        entry = exposure_for(tunnel(traffic="voip", confidence=0.91))
        assert entry.inferred_traffic == "voip"
        assert entry.inferred_traffic_confidence is not None
        assert entry.inferred_traffic_confidence.value == 0.91

    def test_the_active_hours_match_the_observed_timestamps(self) -> None:
        flows = [
            flow(spi="00000001", start_hour=2, duration_s=60),
            flow(spi="00000002", start_hour=14, duration_s=60),
            flow(spi="00000003", start_hour=21, duration_s=60),
        ]
        assert exposure_for(tunnel(flows=flows)).active_hours == [2, 14, 21]


class TestTheMeasurements:
    def test_volume_is_the_sum_across_both_directions(self) -> None:
        flows = [
            flow(spi="00000001", total_bytes=1000, packets=10),
            flow(spi="00000001", total_bytes=2500, packets=25, reverse=True),
        ]
        entry = exposure_for(tunnel(flows=flows))
        assert entry.total_bytes == 3500
        assert entry.total_packets == 35

    def test_a_session_is_an_sa_not_a_direction(self) -> None:
        """Each SA appears once per direction; counting flows would double every figure."""
        flows = [
            flow(spi="00000001"),
            flow(spi="00000001", reverse=True),
            flow(spi="00000002"),
            flow(spi="00000002", reverse=True),
        ]
        assert session_count(tunnel(flows=flows)) == 2
        assert exposure_for(tunnel(flows=flows)).session_count == 2

    def test_first_and_last_seen_span_every_flow(self) -> None:
        flows = [
            flow(spi="00000001", start_hour=3, duration_s=60),
            flow(spi="00000002", start_hour=18, duration_s=120),
        ]
        entry = exposure_for(tunnel(flows=flows))
        assert entry.first_seen == DAY + timedelta(hours=3)
        assert entry.last_seen == DAY + timedelta(hours=18, seconds=120)

    def test_a_flow_spanning_hours_marks_all_of_them_active(self) -> None:
        """22:00 for three hours ends exactly at 01:00, so hour 1 gets no time at all."""
        entry = exposure_for(tunnel(flows=[flow(start_hour=22, duration_s=3 * 3600)]))
        assert entry.active_hours == [0, 22, 23]

    def test_a_flow_reaching_into_an_hour_marks_it_active(self) -> None:
        entry = exposure_for(tunnel(flows=[flow(start_hour=22, duration_s=3 * 3600 + 60)]))
        assert entry.active_hours == [0, 1, 22, 23]

    def test_the_endpoints_are_carried_verbatim(self) -> None:
        entry = exposure_for(tunnel())
        assert entry.endpoints == ("203.0.113.1", "198.51.100.1")


class TestAbstentionIsNotAGuess:
    def test_an_abstained_classification_is_not_reported(self) -> None:
        """A reader shown "voip" cannot tell a confident answer from a coin flip."""
        entry = exposure_for(tunnel(traffic="voip", abstained=True))
        assert entry.inferred_traffic is None
        assert entry.inferred_traffic_confidence is None

    def test_an_unclassified_tunnel_still_gets_an_entry(self) -> None:
        entry = exposure_for(tunnel(traffic=None))
        assert entry.tunnel_id == "t-001"
        assert entry.inferred_traffic is None

    def test_a_confident_classification_carries_its_method(self) -> None:
        entry = exposure_for(tunnel(traffic="video"))
        assert entry.inferred_traffic_confidence is not None
        assert entry.inferred_traffic_confidence.method == "calibrated_xgboost"

    def test_the_class_and_its_confidence_are_inseparable(self) -> None:
        """The model refuses one without the other; this is what feeds it."""
        with pytest.raises(ValidationError):
            ExposureEntry(
                tunnel_id="t1",
                endpoints=("a", "b"),
                total_bytes=0,
                total_packets=0,
                session_count=0,
                inferred_traffic="voip",
            )


class TestATunnelWithNothingObserved:
    def test_a_negotiation_only_tunnel_still_appears(self) -> None:
        """It was seen negotiating. That alone tells an observer these two peers talk."""
        entry = exposure_for(tunnel(flows=[]))
        assert entry.tunnel_id == "t-001"
        assert entry.total_bytes == 0
        assert entry.session_count == 0
        assert entry.active_hours == []
        assert entry.first_seen is None

    def test_no_tunnels_produces_an_empty_section_not_a_missing_one(self) -> None:
        exposure = build_exposure([])
        assert len(exposure) == 0
        assert exposure.note


class TestTheSection:
    def test_every_tunnel_appears_exactly_once(self) -> None:
        exposure = build_exposure([tunnel(f"t-{i:03d}") for i in range(5)])
        assert len(exposure) == 5
        assert len({e.tunnel_id for e in exposure.entries}) == 5

    def test_the_order_matches_the_assessments(self) -> None:
        ids = ["t-c", "t-a", "t-b"]
        exposure = build_exposure([tunnel(i) for i in ids])
        assert [e.tunnel_id for e in exposure.entries] == ids

    def test_the_note_explains_why_a_good_tunnel_is_listed(self) -> None:
        note = build_exposure([tunnel()]).note
        assert "regardless of how well it is configured" in note
        assert "not the fact that it happened" in note

    def test_a_graded_a_tunnel_and_a_graded_f_one_both_appear(self) -> None:
        exposure = build_exposure(
            [
                tunnel("t-good", score=100, grade="A"),
                tunnel(
                    "t-bad",
                    score=10,
                    grade="F",
                    findings=[
                        Finding(
                            rule_id="CRY-05",
                            title="3DES",
                            severity=Severity.CRITICAL,
                            evidence="e",
                            standard_ref="r",
                            remediation_hint="h",
                        )
                    ],
                ),
            ]
        )
        assert {e.tunnel_id for e in exposure.entries} == {"t-good", "t-bad"}
