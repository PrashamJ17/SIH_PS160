"""What an observer learns from a tunnel it cannot decrypt.

This section is produced for **every** tunnel, and the grade-A ones are the point. A
report that lists only problems implies that a tunnel with no problems reveals nothing,
and that is false: strong cryptography protects the contents of a conversation and not
the fact that it happened, who took part, when, for how long, or how much was said.
Those are visible to anyone on the path, and no configuration change makes them go away.

Everything here is either measured or inferred, and the two never blur. Endpoints,
volumes, session counts and active hours are read from the capture. The application
class comes from the Phase 7 classifier and arrives with its calibrated confidence, or
does not arrive at all — an abstention is carried as "not stated", never as a quiet
guess, because a reader shown "voip" has no way to tell a confident classification from
a coin flip unless the number travels with it.
"""

from __future__ import annotations

from collections.abc import Sequence

from ipsec_sentinel.models import Confidence, TunnelAssessment
from ipsec_sentinel.report.models import ExposureEntry, MetadataExposure
from ipsec_sentinel.traffic import profile_flows


def session_count(assessment: TunnelAssessment) -> int:
    """Distinct security associations observed, not directions of them.

    Each SA appears twice in the flow list, once per direction, and counting flows
    would double every figure. Counted by SPI, since that is what identifies an SA.
    """
    return len({flow.spi for flow in assessment.esp_flows})


def exposure_for(assessment: TunnelAssessment) -> ExposureEntry:
    """The exposure entry for one tunnel, however well configured it is."""
    profile = profile_flows(assessment.esp_flows)
    timestamps = [flow.first_seen for flow in assessment.esp_flows]
    latest = [flow.last_seen for flow in assessment.esp_flows]

    return ExposureEntry(
        tunnel_id=assessment.tunnel_id,
        endpoints=assessment.endpoints,
        total_bytes=profile.total_bytes,
        total_packets=profile.total_packets,
        session_count=session_count(assessment),
        active_hours=profile.active_hours,
        first_seen=min(timestamps) if timestamps else None,
        last_seen=max(latest) if latest else None,
        inferred_traffic=_stated_traffic(assessment),
        inferred_traffic_confidence=_stated_confidence(assessment),
    )


def _stated_traffic(assessment: TunnelAssessment) -> str | None:
    """The application class, unless the classifier abstained.

    An abstention means the model does not know. Reporting the class it leaned towards
    anyway would put a guess in the same column as a confident answer.
    """
    confidence = assessment.inferred_traffic_confidence
    if confidence is None or confidence.abstained:
        return None
    return assessment.inferred_traffic


def _stated_confidence(assessment: TunnelAssessment) -> Confidence | None:
    confidence = assessment.inferred_traffic_confidence
    if confidence is None or confidence.abstained:
        return None
    return confidence


def build_exposure(assessments: Sequence[TunnelAssessment]) -> MetadataExposure:
    """One entry per tunnel, in the order they were assessed."""
    return MetadataExposure(entries=[exposure_for(a) for a in assessments])
