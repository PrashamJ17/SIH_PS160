"""The seam: a capture in, a report out.

Every lane in this project has been built and tested on its own — parsing, correlation,
assessment, remediation, reporting. This is where they meet, and it is deliberately thin.
It makes no decisions of its own; it routes the output of one lane into the input of the
next, and every judgement it appears to make belongs to a module that has its own tests.

Two things it does *not* do, both on purpose.

**It loads no model.** The classifier produces Section B findings, and wiring it in by
default would mean an analysis run depends on a model file existing — and a missing file
would then look exactly like a tunnel with nothing to infer. ``model_path`` is opt-in for
that reason, and :func:`attach_inferences` is the seam for callers that have a model.

The distinction is the *artefact*, not inference itself. Tunnel-versus-transport mode is
estimated from packet sizes by a heuristic that needs nothing on disk, so it is attached
always — and it carries a confidence like any other estimate, and abstains outright when
the flow never carried a packet small enough to tell the two apart.

**It opens no socket.** Analysis is passive from end to end. Delivering the result to a
SIEM is a separate, explicit step.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Final

from ipsec_sentinel.assess.framework import DEFAULT_BASELINE, RuleRegistry
from ipsec_sentinel.assess.inventory import KnownTunnel, build_inventory
from ipsec_sentinel.assess.rules import default_registry
from ipsec_sentinel.assess.rules.pqc import grade_pqc
from ipsec_sentinel.assess.scoring import score_tunnel
from ipsec_sentinel.models import Confidence, Finding, ObservedConfig, TunnelAssessment
from ipsec_sentinel.parser.correlate import Tunnel, correlate
from ipsec_sentinel.parser.esp import assemble_esp_flows, extract_esp_packets
from ipsec_sentinel.parser.pcap import extract_ike_exchanges
from ipsec_sentinel.report.build import build_report
from ipsec_sentinel.report.models import PQCEntry, PQCSummary, Report

if TYPE_CHECKING:
    from ipsec_sentinel.collect import DeviceState

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


def infer_mode(assessment: TunnelAssessment, tunnel: Tunnel) -> TunnelAssessment:
    """Estimate tunnel versus transport mode from the flow's smallest packets.

    Tunnel mode adds a full inner IP header that transport mode does not, so the floor a
    bare acknowledgement sets differs by twenty bytes (forty for IPv6). That is enough to
    tell the two apart and little enough that the estimate abstains readily: a flow that
    never carried a small packet gets ``unknown`` rather than a guess.

    Read from the **assembled** flows rather than the assessment's summaries. An
    :class:`~ipsec_sentinel.models.ESPFlow` carries counts and totals, so the smallest
    packet is not recoverable from it — dividing bytes by packets gives the mean, which
    sits nowhere near either floor and would make the heuristic abstain on every tunnel
    while looking as though it had run.

    Needs no model file, so unlike the traffic classifier it is attached to every
    analysis: the classifier is opt-in because a missing artefact would be
    indistinguishable from an absent inference, and a heuristic has no artefact to miss.
    """
    from ipsec_sentinel.ml.heuristic import MODE_UNKNOWN, estimate_mode

    sizes = [size for flow in tunnel.flows for size in flow.sizes]
    if not sizes:
        return assessment

    estimate = estimate_mode(
        {"packet_count": float(len(sizes)), "size_min": float(min(sizes))},
        ipv6=":" in assessment.endpoints[0],
    )
    if estimate.mode == MODE_UNKNOWN:
        return assessment
    return assessment.model_copy(
        update={
            "inferred_mode": estimate.mode,
            "inferred_mode_confidence": Confidence(
                value=estimate.confidence, method="packet_size_floor_heuristic"
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
    model_path: Path | None = None,
    device_states: Sequence[DeviceState] = (),
) -> Report:
    """Analyse one capture end to end and return the report.

    ``model_path`` is optional and, when given, attaches Section B inferences with
    their SHAP explanations. Omitting it produces a report that says *nothing* about
    traffic class rather than one that quietly says "unknown" — a run with no model must
    not be mistakable for a run that inferred nothing.

    ``observed_config`` carries the facts a passive observer cannot see — anti-replay
    settings, PFS where the exchange was encrypted. Supplied by the operator, applied to
    every tunnel in the capture, and absent by default, so the rules that depend on it
    stay silent rather than assuming.

    ``device_states`` are what gateways report about themselves. Where one describes a
    tunnel this capture also saw, its findings attach to that tunnel and change its score;
    where it describes a tunnel the capture missed, the findings are still reported and
    the device-state section says the estate score could not reflect them.
    """
    if not pcap.is_file():
        raise FileNotFoundError(f"no such capture: {pcap}")

    tunnels = read_tunnels(pcap)
    if observed_config is not None:
        for tunnel in tunnels:
            tunnel.config = observed_config

    rules = registry or default_registry()
    assessments = [infer_mode(assess_tunnel(tunnel, baseline, rules), tunnel) for tunnel in tunnels]

    exposure = None
    if model_path is not None:
        from ipsec_sentinel.ml.classify import classify_all
        from ipsec_sentinel.report.exposure import exposure_for
        from ipsec_sentinel.report.models import InferenceExplanation, MetadataExposure

        classified = classify_all(tunnels, model_path)
        assessments = [
            attach_inferences(
                assessment,
                traffic=classified[assessment.tunnel_id].predicted,
                traffic_confidence=classified[assessment.tunnel_id].confidence,
                method=classified[assessment.tunnel_id].method,
                abstained=classified[assessment.tunnel_id].abstained,
            )
            if assessment.tunnel_id in classified
            else assessment
            for assessment in assessments
        ]
        entries = []
        for assessment in assessments:
            entry = exposure_for(assessment)
            found = classified.get(assessment.tunnel_id)
            if found is not None and entry.inferred_traffic is not None and found.sentence:
                entry = entry.model_copy(
                    update={
                        "explanation": InferenceExplanation(
                            sentence=found.sentence,
                            contributions=list(found.contributions),
                            windows=found.windows,
                        )
                    }
                )
            entries.append(entry)
        # When no model is supplied this stays None and build_report falls back to
        # build_exposure, which produces the same entries without any inference.
        exposure = MetadataExposure(entries=entries)

    device_summary = None
    unattached: list[Finding] = []
    if device_states:
        from ipsec_sentinel.report.device_state import summarise_device_states

        device_summary, assessments, unattached = summarise_device_states(
            assessments, device_states, baseline=baseline, registry=rules
        )

    return build_report(
        assessments,
        build_inventory(tunnels, known),
        baseline,
        source=source or pcap.name,
        generated_at=generated_at or datetime.now(UTC),
        metadata_exposure=exposure,
        pqc=pqc_summary(tunnels),
        device_state=device_summary,
        extra_findings=unattached,
    )
