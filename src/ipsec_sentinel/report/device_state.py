"""Fold what devices report about themselves into the report.

Step 11.9 graded an installed ESP SA and printed it to a terminal. This puts it in the
document, which raises the one design question the work turns on: how a device's
self-report relates to a captured tunnel.

There are two cases and they behave differently on purpose.

**Matched.** The device describes a tunnel the capture also saw. Its findings attach to
that tunnel's assessment, so they flow into Section A stamped with the tunnel id and the
tunnel is rescored. A tunnel with 3DES installed must not still read 100 because the wire
happened to be quiet — and a score left unrecomputed after appending findings would be a
straightforward lie.

**Unmatched.** The device describes a tunnel the capture never saw. The findings are real
and deterministic, so they belong in Section A; but there is no tunnel to attribute them
to, and the estate score is a mean over assessed tunnels, so they cannot move it.
Inventing a tunnel to hang them on would be worse than the gap, so the gap is stated —
in the section's note, and by leaving ``tunnel_id`` as ``None``.

Matching is on the canonicalised endpoint pair. The kernel prints one SA per direction, so
its ``src``/``dst`` are one direction of a pair the tunnel holds canonically; comparing
raw would match half the time and look like a bug in the parser.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ipsec_sentinel.assess.esp import assess_esp
from ipsec_sentinel.assess.framework import DEFAULT_BASELINE, RuleRegistry
from ipsec_sentinel.assess.scoring import score_tunnel
from ipsec_sentinel.collect import ReportedConfig, config_from_state
from ipsec_sentinel.models import Finding, TunnelAssessment
from ipsec_sentinel.parser.correlate import endpoint_pair
from ipsec_sentinel.report.models import DeviceStateEntry, DeviceStateSummary

if TYPE_CHECKING:
    from collections.abc import Sequence

    from ipsec_sentinel.collect import DeviceState


def _empty_entry(state: DeviceState) -> DeviceStateEntry:
    """A device that reported nothing usable is still worth a row.

    Silence from a gateway is a fact about the estate: either it has no SA installed, or
    it runs an algorithm this tool cannot name. Omitting the row would make the two
    indistinguishable from never having been asked.
    """
    return DeviceStateEntry(source=state.source, endpoints=state.endpoints)


def summarise_device_states(
    assessments: Sequence[TunnelAssessment],
    states: Sequence[DeviceState],
    *,
    baseline: str = DEFAULT_BASELINE,
    registry: RuleRegistry | None = None,
) -> tuple[DeviceStateSummary, list[TunnelAssessment], list[Finding]]:
    """Grade each device's state and attach what matches a captured tunnel.

    Returns three things: the section, the assessments rescored where a device's
    findings were attached, and the findings that matched no captured tunnel.

    The third is separate rather than carried on the section because it belongs in
    Section A — it is deterministic — and holding the same findings in two places in one
    document is how two places come to disagree. The assessments are returned rather than
    mutated because a caller that passed a list should not find its contents silently
    changed underneath it.
    """
    by_tunnel: dict[str, list[Finding]] = {}
    entries: list[DeviceStateEntry] = []
    unattached: list[Finding] = []

    # Both sides canonicalised: a tunnel's endpoints and a kernel SA's src/dst are the
    # same pair in whichever order each happened to record it.
    index = {endpoint_pair(*assessment.endpoints): assessment for assessment in assessments}

    for state in states:
        reported: ReportedConfig | None = config_from_state(state)
        if reported is None or reported.esp is None:
            entries.append(_empty_entry(state))
            continue

        origin = reported.esp_source or "kernel"
        findings = assess_esp(
            reported.esp,
            source=state.source,
            origin=origin,
            baseline=baseline,
            registry=registry,
        )
        score, grade = score_tunnel(findings)

        endpoints = state.endpoints
        canonical = endpoint_pair(*endpoints) if endpoints else None
        matched = index.get(canonical) if canonical is not None else None

        if matched is not None:
            by_tunnel.setdefault(matched.tunnel_id, []).extend(findings)
        else:
            unattached.extend(findings)

        entries.append(
            DeviceStateEntry(
                source=state.source,
                origin=origin,
                endpoints=canonical,
                installed=reported.esp.suite(),
                mode=reported.esp.mode,
                replay_window=reported.esp.replay_window,
                spi=reported.esp.spi,
                matched_tunnel=matched.tunnel_id if matched is not None else None,
                score=score,
                grade=grade,
                finding_count=len(findings),
                unknown=sorted(reported.unknown),
            )
        )

    updated = [
        _attach(assessment, by_tunnel.get(assessment.tunnel_id)) for assessment in assessments
    ]
    return DeviceStateSummary(entries=entries), updated, unattached


def _attach(assessment: TunnelAssessment, findings: list[Finding] | None) -> TunnelAssessment:
    """Add a device's findings to a tunnel and rescore it.

    Rescoring is the part that matters. Appending findings and leaving ``score`` alone
    would report a tunnel as clean while listing what is wrong with it directly beneath.
    """
    if not findings:
        return assessment
    combined = [*assessment.findings, *findings]
    score, grade = score_tunnel(combined)
    return assessment.model_copy(update={"findings": combined, "score": score, "grade": grade})
