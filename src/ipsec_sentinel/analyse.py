"""The seam: a capture in, a report out.

Every lane in this project has been built and tested on its own — parsing, correlation,
assessment, remediation, reporting. This is where they meet, and it is deliberately thin.
It makes no decisions of its own; it routes the output of one lane into the input of the
next, and every judgement it appears to make belongs to a module that has its own tests.

Two things it does *not* do, both on purpose.

**It does not infer.** The classifier lane produces Section B findings, and wiring it in
here would mean loading a trained model to analyse a capture. A tunnel's inferred traffic
class is attached only when a caller supplies it, so an analysis run has no dependency on
a model file existing and cannot silently degrade to "no inferences" while looking
complete. :func:`attach_inferences` is the seam for callers that have a model.

**It opens no socket.** Analysis is passive from end to end. Delivering the result to a
SIEM is a separate, explicit step.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from ipsec_sentinel.assess.framework import DEFAULT_BASELINE, RuleRegistry
from ipsec_sentinel.assess.inventory import KnownTunnel, build_inventory
from ipsec_sentinel.assess.rules import default_registry
from ipsec_sentinel.assess.rules.pqc import grade_pqc
from ipsec_sentinel.assess.scoring import score_tunnel
from ipsec_sentinel.models import Confidence, ObservedConfig, TunnelAssessment
from ipsec_sentinel.parser.correlate import Tunnel, correlate
from ipsec_sentinel.parser.esp import assemble_esp_flows, extract_esp_packets
from ipsec_sentinel.parser.pcap import extract_ike_exchanges
from ipsec_sentinel.report.build import build_report
from ipsec_sentinel.report.models import PQCEntry, PQCSummary, Report

MAX_INFERENCE_CONFIDENCE: Final = 1.0


def read_tunnels(pcap: Path) -> list[Tunnel]:
    """Parse a capture into correlated tunnels.

    Both halves are read from the same file in one pass each: the IKE negotiations that
    say what was agreed, and the ESP flows that say what was carried. Correlation joins
    them, and keeps the ones it cannot join — an ESP flow with no negotiation in the
    capture is a real tunnel whose cryptography is simply unassessable, which is worth
    reporting rather than discarding.
    """
    exchanges = extract_ike_exchanges(pcap)
    flows = assemble_esp_flows(extract_esp_packets(pcap))
    return correlate(exchanges, flows)


def assess_tunnel(
    tunnel: Tunnel,
    baseline: str = DEFAULT_BASELINE,
    registry: RuleRegistry | None = None,
) -> TunnelAssessment:
    """Run the rule set over one tunnel and score it."""
    rules = registry or default_registry()
    findings = rules.run(tunnel, baseline).findings
    score, grade = score_tunnel(findings)
    return TunnelAssessment(
        tunnel_id=tunnel.tunnel_id,
        endpoints=tunnel.endpoints,
        ike=tunnel.ike,
        esp_flows=[flow.to_model() for flow in tunnel.flows],
        findings=findings,
        score=score,
        grade=grade,
    )


def attach_inferences(
    assessment: TunnelAssessment,
    *,
    traffic: str | None = None,
    traffic_confidence: float | None = None,
    method: str = "calibrated_xgboost",
    abstained: bool = False,
) -> TunnelAssessment:
    """Attach a classifier's output to an assessment.

    Separate from :func:`assess_tunnel` because an inference has a different provenance
    from everything else in that object, and because a caller without a trained model
    must end up with an assessment that says *nothing* about traffic class rather than
    one that quietly says "unknown" in a field a reader may take for an answer.
    """
    if (traffic is None) != (traffic_confidence is None):
        raise ValueError(
            "an inferred traffic class and its confidence must be supplied together; "
            "a class without a confidence is indistinguishable from a parsed fact"
        )
    if traffic is None:
        return assessment
    assert traffic_confidence is not None  # guarded above
    return assessment.model_copy(
        update={
            "inferred_traffic": traffic,
            "inferred_traffic_confidence": Confidence(
                value=traffic_confidence, method=method, abstained=abstained
            ),
        }
    )


def pqc_summary(tunnels: Sequence[Tunnel]) -> PQCSummary:
    """Post-quantum readiness for every tunnel whose negotiation was captured."""
    entries = []
    for tunnel in tunnels:
        graded = grade_pqc(tunnel)
        entries.append(
            PQCEntry(
                tunnel_id=tunnel.tunnel_id,
                grade=graded.grade,
                rationale=graded.rationale,
                post_quantum_groups=list(graded.post_quantum_groups),
                classical_groups=list(graded.classical_groups),
            )
        )
    return PQCSummary(entries=entries)


def analyse_capture(
    pcap: Path,
    *,
    baseline: str = DEFAULT_BASELINE,
    known: list[KnownTunnel] | None = None,
    observed_config: ObservedConfig | None = None,
    source: str | None = None,
    generated_at: datetime | None = None,
    registry: RuleRegistry | None = None,
) -> Report:
    """Analyse one capture end to end and return the report.

    ``observed_config`` carries the facts a passive observer cannot see — anti-replay
    settings, PFS where the exchange was encrypted. Supplied by the operator, applied to
    every tunnel in the capture, and absent by default, so the rules that depend on it
    stay silent rather than assuming.
    """
    if not pcap.is_file():
        raise FileNotFoundError(f"no such capture: {pcap}")

    tunnels = read_tunnels(pcap)
    if observed_config is not None:
        for tunnel in tunnels:
            tunnel.config = observed_config

    rules = registry or default_registry()
    assessments = [assess_tunnel(tunnel, baseline, rules) for tunnel in tunnels]

    return build_report(
        assessments,
        build_inventory(tunnels, known),
        baseline,
        source=source or pcap.name,
        generated_at=generated_at or datetime.now(UTC),
        pqc=pqc_summary(tunnels),
    )
