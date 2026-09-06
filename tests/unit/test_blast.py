"""Tests for blast radius assessment (build plan Step 8.5).

The plan's three criteria are the first class. The rest exist because the failure modes
here are all of the same shape: a confident answer derived from something that was never
observed. A window recommended for the one hour nobody watched, an abstaining classifier
read as "not VoIP", a sixty-second capture reported as a quiet tunnel — each looks like
a result and is really an absence of evidence.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from ipsec_sentinel.models import Confidence, ESPFlow, TunnelAssessment
from ipsec_sentinel.remediate.blast import (
    BUSY_THROUGHPUT_BPS,
    IDLE_THROUGHPUT_BPS,
    MIN_HOURS_FOR_DAILY_CYCLE,
    WINDOW_LENGTH_HOURS,
    assess_blast_radius,
    covers_daily_cycle,
    is_busy,
    is_idle,
    realtime_traffic,
    suggest_window,
)
from ipsec_sentinel.remediate.models import ChangeRisk
from ipsec_sentinel.traffic import HOURS_PER_DAY, empty_profile, profile_flows

DAY = datetime(2026, 3, 4, 0, 0, tzinfo=UTC)


def flow(
    *,
    start_hour: float = 0.0,
    duration_s: float = 3600.0,
    packets: int = 100,
    total_bytes: int = 100_000,
    spi: str = "aabbccdd",
) -> ESPFlow:
    first = DAY + timedelta(hours=start_hour)
    return ESPFlow(
        spi=spi,
        src_ip="203.0.113.1",
        dst_ip="198.51.100.1",
        packet_count=packets,
        byte_count=total_bytes,
        first_seen=first,
        last_seen=first + timedelta(seconds=duration_s),
    )


def tunnel(
    flows: list[ESPFlow] | None = None,
    *,
    traffic: str | None = None,
    confidence: float = 0.9,
    abstained: bool = False,
) -> TunnelAssessment:
    inferred = (
        Confidence(value=confidence, method="calibrated_xgboost", abstained=abstained)
        if traffic is not None
        else None
    )
    return TunnelAssessment(
        tunnel_id="t-001",
        endpoints=("203.0.113.1", "198.51.100.1"),
        esp_flows=flows if flows is not None else [],
        score=60,
        grade="C",
        inferred_traffic=traffic,
        inferred_traffic_confidence=inferred,
    )


def busy_flow() -> ESPFlow:
    """A minute of traffic comfortably above the busy threshold."""
    return flow(duration_s=60, packets=40_000, total_bytes=BUSY_THROUGHPUT_BPS * 60 * 2)


def idle_flow() -> ESPFlow:
    return flow(duration_s=600, packets=20, total_bytes=int(IDLE_THROUGHPUT_BPS * 600 * 0.1))


class TestThePlansCriteria:
    def test_a_high_volume_tunnel_requires_a_maintenance_window(self) -> None:
        assessment = assess_blast_radius(tunnel([busy_flow()]))
        assert assessment.requires_maintenance_window is True
        assert any("kB/s" in reason for reason in assessment.reasons)

    def test_an_idle_tunnel_does_not(self) -> None:
        assessment = assess_blast_radius(tunnel([idle_flow()]))
        assert assessment.requires_maintenance_window is False
        assert any("idle threshold" in reason for reason in assessment.reasons)

    def test_the_suggested_window_falls_in_the_observed_quiet_period(self) -> None:
        """A full day observed, busy in the afternoon and quiet before dawn."""
        flows = [
            flow(
                start_hour=hour,
                duration_s=3599,
                packets=100,
                total_bytes=1_000_000 if 12 <= hour < 18 else 10_000,
                spi=f"{hour:08x}",
            )
            for hour in range(HOURS_PER_DAY)
        ]
        window = suggest_window(profile_flows(flows))
        assert window is not None
        assert set(window.hours).isdisjoint(range(12, 18)), window.describe()
        assert window.confidence.value == 1.0
        assert window.confidence.method == "fraction_of_daily_cycle_observed"


class TestTheWindowIsOnlyOfferedWhenItIsSupported:
    def test_a_short_capture_yields_no_window(self) -> None:
        """Sixty seconds cannot locate the quiet time of day."""
        assert suggest_window(profile_flows([flow(duration_s=60)])) is None

    def test_the_absence_is_explained_rather_than_left_blank(self) -> None:
        assessment = assess_blast_radius(tunnel([flow(duration_s=60)]))
        assert assessment.window is None
        notes = " ".join(assessment.radius.notes)
        assert "too little to locate the daily trough" in notes
        assert "local knowledge" in notes

    def test_an_unobserved_hour_is_never_chosen(self) -> None:
        """The load-bearing one.

        Unobserved hours hold zero bytes, so a naive minimum picks the part of the day
        nobody watched — and recommends making the change during it.
        """
        watched = list(range(MIN_HOURS_FOR_DAILY_CYCLE + 4))
        flows = [
            flow(
                start_hour=hour,
                duration_s=3599,
                packets=100,
                total_bytes=500_000,
                spi=f"{hour:08x}",
            )
            for hour in watched
        ]
        window = suggest_window(profile_flows(flows))
        assert window is not None
        assert set(window.hours) <= set(watched), (
            f"{window.describe()} includes hours that were never observed"
        )

    def test_confidence_reflects_how_much_of_the_day_was_seen(self) -> None:
        flows = [
            flow(start_hour=h, duration_s=3599, packets=10, total_bytes=1000, spi=f"{h:08x}")
            for h in range(8)
        ]
        window = suggest_window(profile_flows(flows))
        assert window is not None
        # The module rounds to four places; the point is what the number means.
        assert window.confidence.value == pytest.approx(8 / HOURS_PER_DAY, abs=1e-4)

    def test_a_window_needs_a_contiguous_observed_stretch(self) -> None:
        """Observed hours scattered one at a time cannot host a two-hour window."""
        flows = [
            flow(start_hour=h, duration_s=60, packets=10, total_bytes=1000, spi=f"{h:08x}")
            for h in range(0, 2 * MIN_HOURS_FOR_DAILY_CYCLE, 2)
        ]
        assert WINDOW_LENGTH_HOURS > 1
        assert suggest_window(profile_flows(flows)) is None


class TestInferenceIsTreatedAsInference:
    def test_a_voip_tunnel_requires_a_window_even_when_quiet(self) -> None:
        """One call is not much traffic and is still noticed when it breaks."""
        assessment = assess_blast_radius(tunnel([idle_flow()], traffic="voip"))
        assert assessment.requires_maintenance_window is True
        assert any("voip" in reason for reason in assessment.reasons)

    def test_the_reason_carries_the_confidence_and_its_method(self) -> None:
        assessment = assess_blast_radius(tunnel([idle_flow()], traffic="video", confidence=0.81))
        reason = next(r for r in assessment.reasons if "video" in r)
        assert "0.81" in reason
        assert "calibrated_xgboost" in reason

    def test_an_abstention_is_not_read_as_a_negative(self) -> None:
        """ "I don't know" must not become "not VoIP, proceed"."""
        assert realtime_traffic(tunnel([idle_flow()], traffic="voip", abstained=True)) is None

    def test_a_non_realtime_class_does_not_force_a_window(self) -> None:
        assessment = assess_blast_radius(tunnel([idle_flow()], traffic="email"))
        assert assessment.requires_maintenance_window is False

    def test_an_unclassified_tunnel_is_judged_on_volume_alone(self) -> None:
        assert assess_blast_radius(tunnel([busy_flow()])).requires_maintenance_window is True
        assert assess_blast_radius(tunnel([idle_flow()])).requires_maintenance_window is False


class TestRisk:
    def test_a_lone_tunnel_is_single_tunnel_risk(self) -> None:
        assert assess_blast_radius(tunnel([busy_flow()])).radius.risk is ChangeRisk.SINGLE_TUNNEL

    def test_siblings_raise_it_to_multiple_tunnels(self) -> None:
        assessment = assess_blast_radius(tunnel([busy_flow()]), sibling_tunnels=["t-002", "t-003"])
        assert assessment.radius.risk is ChangeRisk.MULTIPLE_TUNNELS
        assert assessment.radius.tunnels_affected == 3
        assert "t-002" in " ".join(assessment.radius.notes)

    def test_a_gateway_wide_change_says_so(self) -> None:
        assessment = assess_blast_radius(tunnel([busy_flow()]), gateway_wide=True)
        assert assessment.radius.risk is ChangeRisk.GATEWAY_WIDE

    def test_an_unobserved_tunnel_is_not_reported_as_no_risk(self) -> None:
        """A tunnel we saw no traffic on is not a tunnel that carries none.

        ``ChangeRisk.NONE`` would be a claim about the world made from a sample that
        cannot support it.
        """
        assessment = assess_blast_radius(tunnel([]))
        assert assessment.radius.risk is not ChangeRisk.NONE
        assert assessment.requires_maintenance_window is False
        assert any("not the same as none being needed" in r for r in assessment.reasons)

    def test_both_endpoints_are_named_for_coordination(self) -> None:
        radius = assess_blast_radius(tunnel([busy_flow()])).radius
        assert radius.peers_requiring_coordination == ["203.0.113.1", "198.51.100.1"]
        assert "peer must be changed in the same window" in " ".join(radius.notes)

    def test_a_disruptive_change_is_scheduled_whatever_the_traffic(self) -> None:
        assessment = assess_blast_radius(tunnel([idle_flow()]), disruptive_change=True)
        assert assessment.requires_maintenance_window is True
        assert any("cannot be made transparently" in r for r in assessment.reasons)

    def test_the_reported_disruption_is_the_one_passed_in(self) -> None:
        """Nothing here invents a duration; Step 8.4 measured it."""
        assert assess_blast_radius(tunnel([busy_flow()])).radius.estimated_disruption_s == 0
        assessment = assess_blast_radius(tunnel([busy_flow()]), estimated_disruption_s=45)
        assert assessment.radius.estimated_disruption_s == 45


class TestTheGeneratorUsesTheObservation:
    """Wiring, asserted. A blast module the generator ignores is decoration."""

    @staticmethod
    def _package(label: str, findings: list[str], **kwargs: object):  # type: ignore[no-untyped-def]
        from ipsec_sentinel.remediate.generators.strongswan import generate_change_package
        from testbed.orchestrate.matrix import expand_matrix

        config = next(lc.config for lc in expand_matrix() if lc.label == label)
        return generate_change_package("t1", config, findings, **kwargs)  # type: ignore[arg-type]

    def test_a_busy_tunnel_makes_the_package_ask_for_a_window(self) -> None:
        package = self._package("weak", ["CRY-02"], observed=tunnel([busy_flow()]))
        assert package.requires_maintenance_window is True

    def test_the_same_tunnel_idle_does_not(self) -> None:
        package = self._package("weak", ["CRY-02"], observed=tunnel([idle_flow()]))
        assert package.requires_maintenance_window is False

    def test_the_reasons_reach_the_document_the_operator_reads(self) -> None:
        package = self._package("weak", ["CRY-02"], observed=tunnel([busy_flow()]))
        notes = " ".join(package.local_config.notes)
        assert "Blast radius:" in notes

    def test_the_disruption_reported_is_the_sequence_that_was_measured(self) -> None:
        """Step 8.4 measured 0.00s on a live pair; the package must not invent 5."""
        package = self._package("weak", ["CRY-02"], observed=tunnel([busy_flow()]))
        assert package.blast_radius.estimated_disruption_s == 0
        assert package.total_expected_disruption_s == 0

    def test_missing_observation_is_declared_rather_than_assumed_benign(self) -> None:
        package = self._package("weak", ["CRY-02"])
        assert package.requires_maintenance_window is False
        assert "rests on nothing measured" in " ".join(package.blast_radius.notes)

    def test_siblings_reach_the_package(self) -> None:
        package = self._package(
            "weak", ["CRY-02"], observed=tunnel([busy_flow()]), sibling_tunnels=["t-002"]
        )
        assert package.blast_radius.tunnels_affected == 2
        assert package.blast_radius.risk is ChangeRisk.MULTIPLE_TUNNELS

    def test_a_psk_rotation_still_forces_a_window_on_an_idle_tunnel(self) -> None:
        package = self._package("worst", ["IKE-03"], observed=tunnel([idle_flow()]))
        assert package.requires_maintenance_window is True


class TestTheThresholdsAreJudgementsNotMeasurements:
    """``is_idle`` and ``is_busy`` stayed in this module when the profiler moved out.

    They are decisions about whether a change needs scheduling, made against thresholds
    this module chose. The measurement itself has no opinion.
    """

    def test_an_unobserved_tunnel_is_neither_idle_nor_busy(self) -> None:
        """No observation is not an idle observation."""
        profile = empty_profile()
        assert is_idle(profile) is False
        assert is_busy(profile) is False

    def test_a_capture_too_short_to_rate_is_neither(self) -> None:
        profile = profile_flows([flow(duration_s=1, packets=5, total_bytes=10_000_000)])
        assert is_idle(profile) is False
        assert is_busy(profile) is False

    def test_a_busy_profile_reads_busy(self) -> None:
        assert is_busy(profile_flows([busy_flow()])) is True
        assert is_idle(profile_flows([busy_flow()])) is False

    def test_an_idle_profile_reads_idle(self) -> None:
        assert is_idle(profile_flows([idle_flow()])) is True
        assert is_busy(profile_flows([idle_flow()])) is False

    def test_a_short_capture_does_not_cover_the_daily_cycle(self) -> None:
        assert covers_daily_cycle(profile_flows([flow(duration_s=60)])) is False

    def test_enough_observed_hours_does(self) -> None:
        flows = [
            flow(start_hour=h, duration_s=3599, total_bytes=1000, spi=f"{h:08x}")
            for h in range(MIN_HOURS_FOR_DAILY_CYCLE)
        ]
        assert covers_daily_cycle(profile_flows(flows)) is True
