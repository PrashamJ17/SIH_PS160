"""How much a tunnel carried, and when.

Extracted from ``remediate/blast.py`` at Step 9.3, when the exposure section needed the
same hourly profile. The split is along a real seam: *what was observed* is a neutral
fact about traffic, while *whether that counts as busy* is a remediation policy question
about scheduling a change. The thresholds stayed behind in ``blast.py``; the measurement
lives here.

One property is load-bearing throughout. ``observed_hours`` is recorded separately from
``bytes_by_hour``, because a zero in an hour nobody watched means "not watched", not
"quiet". Conflating the two is how a maintenance window ends up recommended for the
busiest hour of the day, and how an exposure report ends up claiming a tunnel is idle
overnight on the strength of a sixty-second capture.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final

from ipsec_sentinel.models import ESPFlow

HOURS_PER_DAY: Final = 24

# Below this the observation is too short for a rate to mean anything.
MIN_OBSERVATION_S: Final = 5.0


@dataclass(frozen=True)
class TrafficProfile:
    """How much the tunnel carried, and in which hours of the day.

    ``bytes_by_hour`` is indexed by hour of day. ``observed_hours`` records which of
    those hours the capture actually covers.
    """

    bytes_by_hour: tuple[int, ...]
    observed_hours: frozenset[int]
    total_bytes: int
    total_packets: int
    span_s: float

    def __post_init__(self) -> None:
        if len(self.bytes_by_hour) != HOURS_PER_DAY:
            raise ValueError(f"bytes_by_hour must have {HOURS_PER_DAY} entries")

    @property
    def throughput_bps(self) -> float:
        """Mean bytes per second across the observation, or 0 if it was too short."""
        if self.span_s < MIN_OBSERVATION_S:
            return 0.0
        return self.total_bytes / self.span_s

    @property
    def is_measurable(self) -> bool:
        return self.span_s >= MIN_OBSERVATION_S and self.total_packets > 0

    @property
    def active_hours(self) -> list[int]:
        """Observed hours in which the tunnel actually carried something, in order.

        Distinct from ``observed_hours``: an hour can be watched and quiet. This is the
        one a reader wants — "when is this link in use" — and it is a subset of what was
        watched, never an inference about the rest of the day.
        """
        return sorted(hour for hour in self.observed_hours if self.bytes_by_hour[hour] > 0)

    @property
    def busiest_hour(self) -> int | None:
        if not self.observed_hours:
            return None
        return max(self.observed_hours, key=lambda hour: self.bytes_by_hour[hour])


def empty_profile() -> TrafficProfile:
    return TrafficProfile(
        bytes_by_hour=(0,) * HOURS_PER_DAY,
        observed_hours=frozenset(),
        total_bytes=0,
        total_packets=0,
        span_s=0.0,
    )


def profile_flows(flows: Sequence[ESPFlow]) -> TrafficProfile:
    """Build an hourly profile from ESP flow summaries.

    A flow summary carries first and last seen but not per-packet times, so its bytes
    are apportioned across the hours it spans in proportion to how much of each hour it
    covers. That is an approximation, and it is why :func:`profile_samples` exists for
    callers that still hold per-packet data — a summary cannot distinguish a flow that
    sent everything in its first minute from one that trickled all day.
    """
    if not flows:
        return empty_profile()

    buckets = [0] * HOURS_PER_DAY
    observed: set[int] = set()
    for flow in flows:
        start, end = flow.first_seen, flow.last_seen
        if end < start:
            raise ValueError(f"flow {flow.spi} ends before it starts")
        for hour, share in hour_shares(start, end):
            buckets[hour] += round(flow.byte_count * share)
            observed.add(hour)

    first = min(flow.first_seen for flow in flows)
    last = max(flow.last_seen for flow in flows)
    return TrafficProfile(
        bytes_by_hour=tuple(buckets),
        observed_hours=frozenset(observed),
        total_bytes=sum(flow.byte_count for flow in flows),
        total_packets=sum(flow.packet_count for flow in flows),
        span_s=(last - first).total_seconds(),
    )


def hour_shares(start: datetime, end: datetime) -> list[tuple[int, float]]:
    """Fraction of ``start``..``end`` falling in each hour of day it touches."""
    total = (end - start).total_seconds()
    if total <= 0:
        return [(start.hour, 1.0)]

    shares: list[tuple[int, float]] = []
    cursor = start
    while cursor < end:
        boundary = (cursor + timedelta(hours=1)).replace(minute=0, second=0, microsecond=0)
        chunk_end = min(boundary, end)
        shares.append((cursor.hour, (chunk_end - cursor).total_seconds() / total))
        cursor = chunk_end
    return shares


def profile_samples(samples: Sequence[tuple[datetime, int]]) -> TrafficProfile:
    """Build an hourly profile from per-packet ``(timestamp, size)`` observations.

    Exact where :func:`profile_flows` approximates. Use this when the assembled flows
    are still in hand.
    """
    if not samples:
        return empty_profile()

    buckets = [0] * HOURS_PER_DAY
    observed: set[int] = set()
    for timestamp, size in samples:
        buckets[timestamp.hour] += size
        observed.add(timestamp.hour)

    times = [timestamp for timestamp, _ in samples]
    return TrafficProfile(
        bytes_by_hour=tuple(buckets),
        observed_hours=frozenset(observed),
        total_bytes=sum(size for _, size in samples),
        total_packets=len(samples),
        span_s=(max(times) - min(times)).total_seconds(),
    )
