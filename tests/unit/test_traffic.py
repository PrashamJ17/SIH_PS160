"""Tests for traffic profiling (extracted with the module at Step 9.3).

These moved out of ``test_blast.py`` when the profiler moved out of ``blast.py``. What
is tested here is the measurement — which hours were watched, how bytes fall across
them — and not the remediation policy that reads it.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from ipsec_sentinel.models import ESPFlow
from ipsec_sentinel.traffic import (
    HOURS_PER_DAY,
    TrafficProfile,
    empty_profile,
    hour_shares,
    profile_flows,
    profile_samples,
)

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


class TestProfiling:
    def test_bytes_are_apportioned_across_the_hours_a_flow_spans(self) -> None:
        """Half an hour either side of a boundary splits evenly."""
        spanning = flow(start_hour=9.75, duration_s=1800, packets=100, total_bytes=1000)
        profile = profile_flows([spanning])
        assert profile.observed_hours == {9, 10}
        assert profile.bytes_by_hour[9] == pytest.approx(500, abs=2)
        assert profile.bytes_by_hour[10] == pytest.approx(500, abs=2)
        assert sum(profile.bytes_by_hour) == pytest.approx(1000, abs=2)

    def test_an_instantaneous_flow_lands_in_one_hour(self) -> None:
        profile = profile_flows([flow(start_hour=14, duration_s=0, total_bytes=700)])
        assert profile.observed_hours == {14}
        assert profile.bytes_by_hour[14] == 700

    def test_per_packet_samples_are_placed_exactly(self) -> None:
        """The reason ``profile_samples`` exists: a summary cannot see this shape."""
        samples = [(DAY + timedelta(hours=3, seconds=s), 100) for s in range(10)]
        samples += [(DAY + timedelta(hours=3, minutes=59, seconds=s), 100) for s in range(10)]
        profile = profile_samples(samples)
        assert profile.observed_hours == {3}
        assert profile.bytes_by_hour[3] == 2000
        assert profile.total_packets == 20

    def test_an_empty_profile_claims_nothing(self) -> None:
        profile = profile_flows([])
        assert profile.total_bytes == 0
        assert profile.observed_hours == frozenset()
        assert profile.is_measurable is False
        assert profile.busiest_hour is None
        assert profile.active_hours == []

    def test_a_capture_too_short_to_rate_reports_no_throughput(self) -> None:
        profile = profile_flows([flow(duration_s=1, packets=5, total_bytes=1_000_000)])
        assert profile.is_measurable is False
        assert profile.throughput_bps == 0.0

    def test_a_flow_that_ends_before_it_starts_is_refused(self) -> None:
        backwards = ESPFlow(
            spi="deadbeef",
            src_ip="203.0.113.1",
            dst_ip="198.51.100.1",
            packet_count=1,
            byte_count=100,
            first_seen=DAY + timedelta(hours=5),
            last_seen=DAY,
        )
        with pytest.raises(ValueError, match="ends before it starts"):
            profile_flows([backwards])

    def test_the_busiest_hour_is_read_from_observed_hours_only(self) -> None:
        flows = [
            flow(start_hour=1, duration_s=3599, total_bytes=50, spi="00000001"),
            flow(start_hour=2, duration_s=3599, total_bytes=9000, spi="00000002"),
        ]
        assert profile_flows(flows).busiest_hour == 2


class TestActiveHours:
    """``active_hours`` is what an exposure report shows a reader."""

    def test_only_hours_that_carried_something_are_active(self) -> None:
        profile = TrafficProfile(
            bytes_by_hour=tuple(1000 if h in (9, 14) else 0 for h in range(HOURS_PER_DAY)),
            observed_hours=frozenset(range(8, 18)),
            total_bytes=2000,
            total_packets=20,
            span_s=36000.0,
        )
        assert profile.active_hours == [9, 14]

    def test_an_unobserved_hour_is_never_active_even_with_bytes(self) -> None:
        """A byte count in an hour nobody watched is a bug upstream, not an active hour."""
        profile = TrafficProfile(
            bytes_by_hour=tuple(1000 for _ in range(HOURS_PER_DAY)),
            observed_hours=frozenset({3}),
            total_bytes=24000,
            total_packets=24,
            span_s=3600.0,
        )
        assert profile.active_hours == [3]

    def test_active_hours_are_sorted(self) -> None:
        flows = [
            flow(start_hour=h, duration_s=60, total_bytes=500, spi=f"{h:08x}") for h in (17, 2, 9)
        ]
        assert profile_flows(flows).active_hours == [2, 9, 17]

    def test_an_empty_profile_has_none(self) -> None:
        assert empty_profile().active_hours == []


class TestHourShares:
    def test_a_span_inside_one_hour_is_one_share(self) -> None:
        start = DAY + timedelta(hours=5, minutes=10)
        assert hour_shares(start, start + timedelta(minutes=20)) == [(5, 1.0)]

    def test_an_instant_is_attributed_to_its_own_hour(self) -> None:
        start = DAY + timedelta(hours=7)
        assert hour_shares(start, start) == [(7, 1.0)]

    def test_the_shares_sum_to_one(self) -> None:
        start = DAY + timedelta(hours=22, minutes=31)
        shares = hour_shares(start, start + timedelta(hours=4, minutes=7))
        assert sum(share for _, share in shares) == pytest.approx(1.0)

    def test_a_span_crossing_midnight_wraps(self) -> None:
        start = DAY + timedelta(hours=23, minutes=30)
        hours = [hour for hour, _ in hour_shares(start, start + timedelta(hours=1))]
        assert hours == [23, 0]
