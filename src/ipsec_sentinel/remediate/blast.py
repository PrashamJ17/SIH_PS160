"""Blast radius assessment: what a change can disturb, and when to make it.

The question an operator actually has is rarely "is this change safe?" but "is it safe
*now*?" A proposal swap that is unremarkable at 03:00 is a different proposition at
09:00 on a tunnel carrying calls. This module answers the second question from what was
observed rather than from what was configured.

Everything here is an **estimate**, and the module is built so that nothing it produces
can be mistaken for a parsed fact:

* Byte counts and timestamps come from the capture and are exact, but a capture is a
  sample. A tunnel that was idle for the sixty seconds we watched is not an idle tunnel.
  :func:`assess_blast_radius` never reports :attr:`ChangeRisk.NONE` for that reason.
* A daily traffic cycle cannot be recovered from a short capture. If the observation
  does not span enough of the day, :func:`suggest_window` returns ``None`` and says why
  rather than naming an hour it cannot support.
* Every window that *is* suggested carries a :class:`Confidence` whose ``method`` states
  exactly what the number means — the fraction of the daily cycle actually observed, not
  a calibrated probability from the model lane.

The application type comes from the Phase 7 classifier and is inferred, so it arrives
with its own confidence and is ignored here when the classifier abstained.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final

from pydantic import BaseModel, Field

from ipsec_sentinel.models import Confidence, ESPFlow, TunnelAssessment
from ipsec_sentinel.remediate.models import BlastRadius, ChangeRisk

HOURS_PER_DAY: Final = 24

# Traffic whose users notice a sub-second interruption. A dropped packet in a file
# transfer is retransmitted; a dropped packet in a call is heard.
REALTIME_CLASSES: Final[frozenset[str]] = frozenset({"voip", "video"})

# Sustained rates, not totals: a megabyte in ten seconds and a megabyte in an hour are
# not the same tunnel. Chosen against the traffic the testbed generates — a single
# G.711 call runs near 11 kB/s once ESP overhead is counted, so BUSY is a handful of
# concurrent sessions and IDLE is below one.
BUSY_THROUGHPUT_BPS: Final = 50_000
IDLE_THROUGHPUT_BPS: Final = 1_000

# Below this the observation is too short for a rate to mean anything.
MIN_OBSERVATION_S: Final = 5.0

# A trough cannot be located in a day that was mostly not observed. Six hours is not
# enough to be confident and is stated as such; less than six is not enough to speak.
MIN_HOURS_FOR_DAILY_CYCLE: Final = 6
WINDOW_LENGTH_HOURS: Final = 2


class MaintenanceWindow(BaseModel):
    """A suggested time of day to make the change, and how well founded it is."""

    start_hour: int = Field(ge=0, le=23)
    length_hours: int = Field(ge=1, le=24)
    rationale: str = Field(min_length=1)
    confidence: Confidence

    @property
    def hours(self) -> tuple[int, ...]:
        return tuple(
            (self.start_hour + offset) % HOURS_PER_DAY for offset in range(self.length_hours)
        )

    def describe(self) -> str:
        end = (self.start_hour + self.length_hours) % HOURS_PER_DAY
        return f"{self.start_hour:02d}:00-{end:02d}:00 local time"


@dataclass(frozen=True)
class TrafficProfile:
    """How much the tunnel carried, and when.

    ``bytes_by_hour`` is indexed by hour of day. ``observed_hours`` records which of
    those hours the capture actually covers, because a zero in an unobserved hour means
    "not watched", not "quiet", and conflating the two is how a maintenance window ends
    up recommended for the busiest hour of the day.
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
    def is_idle(self) -> bool:
        return self.is_measurable and self.throughput_bps < IDLE_THROUGHPUT_BPS

    @property
    def is_busy(self) -> bool:
        return self.is_measurable and self.throughput_bps >= BUSY_THROUGHPUT_BPS

    @property
    def covers_daily_cycle(self) -> bool:
        return len(self.observed_hours) >= MIN_HOURS_FOR_DAILY_CYCLE

    @property
    def busiest_hour(self) -> int | None:
        if not self.observed_hours:
            return None
        return max(self.observed_hours, key=lambda hour: self.bytes_by_hour[hour])


def _empty_profile() -> TrafficProfile:
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
    covers. That is an approximation, and it is the reason :func:`profile_samples`
    exists for callers that still hold per-packet data — the summary cannot distinguish
    a flow that sent everything in its first minute from one that trickled all day.
    """
    if not flows:
        return _empty_profile()

    buckets = [0] * HOURS_PER_DAY
    observed: set[int] = set()
    for flow in flows:
        start, end = flow.first_seen, flow.last_seen
        if end < start:
            raise ValueError(f"flow {flow.spi} ends before it starts")
        for hour, share in _hour_shares(start, end):
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


def _hour_shares(start: datetime, end: datetime) -> list[tuple[int, float]]:
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
        return _empty_profile()

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


def suggest_window(profile: TrafficProfile) -> MaintenanceWindow | None:
    """The quietest observed stretch of the day, or ``None`` if the day was not seen.

    Only observed hours are candidates. An unobserved hour has zero recorded bytes,
    which would otherwise make it look like the quietest time available — recommending
    a change during the one part of the day nobody watched.
    """
    if not profile.covers_daily_cycle:
        return None

    candidates = [
        hour
        for hour in sorted(profile.observed_hours)
        if all(
            (hour + offset) % HOURS_PER_DAY in profile.observed_hours
            for offset in range(WINDOW_LENGTH_HOURS)
        )
    ]
    if not candidates:
        return None

    def window_bytes(start: int) -> int:
        return sum(
            profile.bytes_by_hour[(start + offset) % HOURS_PER_DAY]
            for offset in range(WINDOW_LENGTH_HOURS)
        )

    start = min(candidates, key=lambda hour: (window_bytes(hour), hour))
    coverage = len(profile.observed_hours) / HOURS_PER_DAY
    quietest = window_bytes(start)
    busiest = profile.busiest_hour
    peak = profile.bytes_by_hour[busiest] if busiest is not None else 0
    return MaintenanceWindow(
        start_hour=start,
        length_hours=WINDOW_LENGTH_HOURS,
        rationale=(
            f"quietest observed {WINDOW_LENGTH_HOURS}-hour stretch: {quietest} bytes, "
            f"against a peak of {peak} bytes in hour {busiest:02d}. "
            f"{len(profile.observed_hours)} of {HOURS_PER_DAY} hours were observed."
        ),
        confidence=Confidence(
            value=round(coverage, 4),
            method="fraction_of_daily_cycle_observed",
        ),
    )


@dataclass(frozen=True)
class BlastAssessment:
    """What the change can disturb, whether to schedule it, and why."""

    radius: BlastRadius
    profile: TrafficProfile
    window: MaintenanceWindow | None
    requires_maintenance_window: bool
    reasons: tuple[str, ...]

    def summary(self) -> str:
        when = self.window.describe() if self.window else "no window suggested"
        need = "window required" if self.requires_maintenance_window else "no window required"
        return f"{self.radius.risk.value}, {need}, {when}"


def realtime_traffic(tunnel: TunnelAssessment) -> str | None:
    """The inferred application class, when it is real-time and the model committed.

    An abstention is not a quiet "no". The classifier abstaining means it does not know
    what this tunnel carries, and treating that as "not VoIP" would turn every uncertain
    case into a green light.
    """
    inferred = tunnel.inferred_traffic
    confidence = tunnel.inferred_traffic_confidence
    if inferred is None or confidence is None or confidence.abstained:
        return None
    return inferred if inferred in REALTIME_CLASSES else None


def assess_blast_radius(
    tunnel: TunnelAssessment,
    *,
    disruptive_change: bool = False,
    sibling_tunnels: Sequence[str] = (),
    gateway_wide: bool = False,
    estimated_disruption_s: int = 0,
) -> BlastAssessment:
    """Estimate what one tunnel's change can disturb and when it should be made.

    ``disruptive_change`` marks a change that cannot be made transparently at all — a
    pre-shared key rotation, say — which needs scheduling regardless of how quiet the
    tunnel looks.
    """
    profile = profile_flows(tunnel.esp_flows)
    reasons: list[str] = []
    notes: list[str] = []

    if gateway_wide:
        risk = ChangeRisk.GATEWAY_WIDE
    elif sibling_tunnels:
        risk = ChangeRisk.MULTIPLE_TUNNELS
    else:
        # Never ChangeRisk.NONE: a tunnel that carried nothing while we watched is not
        # a tunnel that carries nothing, and "no risk" is not a claim a sample supports.
        risk = ChangeRisk.SINGLE_TUNNEL

    realtime = realtime_traffic(tunnel)
    required = False
    if disruptive_change:
        required = True
        reasons.append(
            "the change cannot be made transparently — it interrupts the tunnel by "
            "construction, so it needs a scheduled window whatever the traffic looks like"
        )
    if realtime is not None:
        required = True
        confidence = tunnel.inferred_traffic_confidence
        assert confidence is not None  # realtime_traffic() returns None otherwise
        reasons.append(
            f"the tunnel is inferred to carry {realtime} (confidence "
            f"{confidence.value:.2f}, {confidence.method}); a sub-second interruption "
            f"is noticed by users of real-time traffic even when no session drops"
        )
    if profile.is_busy:
        required = True
        reasons.append(
            f"sustained {profile.throughput_bps / 1000:.1f} kB/s over "
            f"{profile.span_s:.0f}s of observation. A zero-disruption sequence still "
            f"warrants a window at this volume: any step can fail, and the rollback is "
            f"not instantaneous"
        )
    if not required:
        if profile.is_idle:
            reasons.append(
                f"observed at {profile.throughput_bps / 1000:.2f} kB/s, below the "
                f"{IDLE_THROUGHPUT_BPS / 1000:.0f} kB/s idle threshold"
            )
        elif not profile.is_measurable:
            reasons.append(
                f"only {profile.span_s:.0f}s of traffic was observed, too little to "
                f"estimate a rate; no window is required on the evidence available, "
                f"which is not the same as none being needed"
            )
        else:
            reasons.append(
                f"observed at {profile.throughput_bps / 1000:.1f} kB/s, below the "
                f"{BUSY_THROUGHPUT_BPS / 1000:.0f} kB/s threshold for scheduling"
            )

    window = suggest_window(profile)
    if window is None:
        notes.append(
            f"No maintenance window is suggested: {len(profile.observed_hours)} of "
            f"{HOURS_PER_DAY} hours were observed, which is too little to locate the "
            f"daily trough. Use local knowledge of the site's quiet period."
        )
    else:
        notes.append(f"Suggested window {window.describe()} — {window.rationale}")

    notes.append(
        "The peer must be changed in the same window. A proposal changed at one end "
        "only does not degrade — it stops the tunnel establishing at the next rekey."
    )
    if sibling_tunnels:
        notes.append(
            f"{len(sibling_tunnels)} other tunnel(s) terminate on this gateway and "
            f"share its configuration: {', '.join(sorted(sibling_tunnels))}"
        )

    peers = [endpoint for endpoint in tunnel.endpoints if endpoint]
    return BlastAssessment(
        radius=BlastRadius(
            risk=risk,
            tunnels_affected=1 + len(sibling_tunnels),
            peers_requiring_coordination=peers,
            estimated_disruption_s=estimated_disruption_s,
            notes=notes,
        ),
        profile=profile,
        window=window,
        requires_maintenance_window=required,
        reasons=tuple(reasons),
    )
