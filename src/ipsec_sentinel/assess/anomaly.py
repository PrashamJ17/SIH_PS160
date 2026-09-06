"""Configuration anomaly detection: finding the odd one out that violates no rule.

Every rule in this system encodes something already known to be wrong. This module
answers a different question — *which tunnel in this estate does not look like the
others* — and it catches the case rules structurally cannot: a configuration that is
perfectly acceptable in isolation and anomalous in context.

An estate of forty tunnels on AES-256/SHA-384/group 20 and one on AES-128/SHA-256/group
14 has no rule violations at all under most baselines. The odd one is still worth a
human glance, because in practice it is usually a gateway that was rebuilt from a
different template, restored from an old backup, or configured by someone who did not
have the standard to hand.

**Findings from this module carry a confidence**, unlike every rule-based finding, and
that is the architectural point rather than a detail. This is an inference: it says
"this differs from its peers", which is a statistical statement about a population, not
a fact read from a packet. Section B of a report holds it, and the confidence is the
model's own outlier score rather than a number chosen to look convincing.

**Below a minimum estate size it returns nothing at all.** Outlier detection over five
tunnels does not identify the unusual one; it identifies whichever one the algorithm
happened to isolate first, which would be a confident answer to a question the data
cannot support. That refusal is the most important behaviour here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final

from ipsec_sentinel.models import Confidence, Finding, Severity, TransformType
from ipsec_sentinel.parser.constants import dh_security_bits
from ipsec_sentinel.parser.correlate import Tunnel

# Below this, "the odd one out" is not a meaningful question. Ten is the point at which
# a single outlier is a tenth of the population rather than a fifth, and IsolationForest
# has enough splits to isolate on structure rather than on noise.
MIN_ESTATE_SIZE: Final = 10

# An outlier is a minority by definition. Set explicitly rather than left on
# scikit-learn's "auto", which assumes a contaminated dataset and, measured against
# this project's own corpus, flagged 224 of 252 tunnels — an answer that is useless
# even where it is arguably correct.
CONTAMINATION: Final = 0.1

# The share of the estate that must run the single most common configuration before
# "differs from its peers" means anything. An estate where the modal configuration is
# a fifth of the population has no standard to deviate from, and every tunnel is an
# outlier in the only sense the model can measure.
MIN_MODAL_SHARE: Final = 0.25

ANOMALY_RULE_ID: Final = "ANO-01"
ANOMALY_METHOD: Final = "IsolationForest over configuration feature vectors"

# Fixed so two runs over the same estate produce the same answer. A report that
# reordered its findings between runs would be impossible to diff or to trust.
RANDOM_SEED: Final = 20260906

FEATURE_NAMES: Final[tuple[str, ...]] = (
    "ike_version_major",
    "is_aggressive",
    "encryption_id",
    "encryption_key_bits",
    "integrity_id",
    "prf_id",
    "dh_security_bits",
    "proposal_count",
    "transform_count",
)


@dataclass(frozen=True)
class AnomalyResult:
    """One tunnel's outlier assessment."""

    tunnel_id: str
    is_anomaly: bool
    score: float
    """The model's decision function: negative is more anomalous."""
    features: dict[str, float]


def _first_transform_id(tunnel: Tunnel, kind: TransformType) -> int:
    if tunnel.ike is None:
        return 0
    for proposal in tunnel.ike.proposals_offered:
        for transform in proposal.transforms:
            if transform.type == kind:
                return transform.id
    return 0


def extract_features(tunnel: Tunnel) -> dict[str, float]:
    """Encode a tunnel's negotiated configuration as a numeric vector.

    Deliberately configuration-only: no packet counts, no byte volumes, no timings.
    Those describe what a tunnel *carried*, and including them would make a
    high-traffic tunnel look anomalous for being busy — which is a fact about the
    business, not about the configuration, and would bury the misconfigured gateway
    this module exists to find.
    """
    encryption_bits = 0
    proposal_count = 0
    transform_count = 0
    if tunnel.ike is not None:
        proposal_count = len(tunnel.ike.proposals_offered)
        for proposal in tunnel.ike.proposals_offered:
            transform_count += len(proposal.transforms)
            for transform in proposal.transforms:
                if transform.type == TransformType.ENCR and transform.key_length:
                    encryption_bits = max(encryption_bits, transform.key_length)

    dh_id = _first_transform_id(tunnel, TransformType.DH)
    return {
        "ike_version_major": 1.0 if (tunnel.ike and tunnel.ike.version == "IKEv1") else 2.0,
        "is_aggressive": 1.0 if (tunnel.ike and tunnel.ike.is_aggressive) else 0.0,
        "encryption_id": float(_first_transform_id(tunnel, TransformType.ENCR)),
        "encryption_key_bits": float(encryption_bits),
        "integrity_id": float(_first_transform_id(tunnel, TransformType.INTEG)),
        "prf_id": float(_first_transform_id(tunnel, TransformType.PRF)),
        "dh_security_bits": float(dh_security_bits(dh_id) or 0),
        "proposal_count": float(proposal_count),
        "transform_count": float(transform_count),
    }


def modal_share(rows: list[dict[str, float]]) -> float:
    """The fraction of the estate running the single most common configuration.

    The measure of whether this estate has a standard at all. Anomaly detection
    presupposes a norm to deviate from; without one, "unlike its peers" is true of
    everything and means nothing.
    """
    if not rows:
        return 0.0
    signatures = [tuple(row[name] for name in FEATURE_NAMES) for row in rows]
    return max(signatures.count(sig) for sig in set(signatures)) / len(signatures)


def _describe_difference(features: dict[str, float], population: list[dict[str, float]]) -> str:
    """Name the fields on which this tunnel differs from the estate majority.

    An outlier score alone is unactionable — "this tunnel is unusual" tells an operator
    nothing about where to look. The evidence names the fields and what the rest of the
    estate does instead.
    """
    differences: list[str] = []
    for name in FEATURE_NAMES:
        values = [row[name] for row in population]
        if not values:
            continue
        majority = max(set(values), key=values.count)
        share = values.count(majority) / len(values)
        # Only worth reporting when the estate genuinely has a convention.
        if share >= 0.6 and features[name] != majority:
            differences.append(
                f"{name}={features[name]:g} where {share:.0%} of the estate uses {majority:g}"
            )
    if not differences:
        return (
            "differs from the estate on the combination of its settings rather than any single one"
        )
    return "; ".join(differences)


def detect_config_anomalies(
    tunnels: list[Tunnel], min_estate_size: int = MIN_ESTATE_SIZE
) -> list[Finding]:
    """Flag tunnels whose configuration is unlike the rest of the estate.

    Returns ``[]`` when the estate is smaller than ``min_estate_size``: outlier
    detection over a handful of tunnels identifies whichever one the algorithm isolated
    first, not the unusual one, and a confident answer to an unanswerable question is
    the worst output available.
    """
    return [
        result_to_finding(r, tunnels)
        for r in score_anomalies(tunnels, min_estate_size)
        if r.is_anomaly
    ]


def score_anomalies(
    tunnels: list[Tunnel], min_estate_size: int = MIN_ESTATE_SIZE
) -> list[AnomalyResult]:
    """Score every tunnel, returning results whether or not they are anomalous."""
    if len(tunnels) < min_estate_size:
        return []

    rows = [extract_features(tunnel) for tunnel in tunnels]
    if modal_share(rows) < MIN_MODAL_SHARE:
        # No dominant configuration, so there is no template to deviate from. Running
        # the model anyway would flag most of the estate and call it a finding.
        return []

    from sklearn.ensemble import IsolationForest  # imported lazily: ML is an extra

    matrix = [[row[name] for name in FEATURE_NAMES] for row in rows]

    model = IsolationForest(
        random_state=RANDOM_SEED,
        contamination=CONTAMINATION,
        n_estimators=200,
    )
    model.fit(matrix)
    predictions = model.predict(matrix)
    scores = model.decision_function(matrix)

    return [
        AnomalyResult(
            tunnel_id=tunnel.tunnel_id,
            is_anomaly=bool(prediction == -1),
            score=float(score),
            features=row,
        )
        for tunnel, row, prediction, score in zip(tunnels, rows, predictions, scores, strict=True)
    ]


def _confidence_from_score(score: float) -> float:
    """Map the decision function onto [0, 1].

    The decision function is roughly [-0.5, 0.5] with negative meaning anomalous. This
    reports the model's own separation rather than a number chosen to look convincing,
    and it is deliberately capped below 1.0: an unsupervised outlier score is never
    certainty, and presenting it as such would be the overclaim the whole architecture
    exists to avoid.
    """
    return min(0.95, max(0.05, min(1.0, abs(score) * 2.0)))


def result_to_finding(result: AnomalyResult, tunnels: list[Tunnel]) -> Finding:
    """Turn an anomaly result into a Section B finding, with its confidence."""
    population = [extract_features(t) for t in tunnels]
    tunnel = next((t for t in tunnels if t.tunnel_id == result.tunnel_id), None)
    endpoints = f"{tunnel.endpoints[0]} and {tunnel.endpoints[1]}" if tunnel else result.tunnel_id
    return Finding(
        rule_id=ANOMALY_RULE_ID,
        title="Configuration differs from the rest of the estate",
        severity=Severity.INFO,
        evidence=(
            f"the tunnel between {endpoints} is a configuration outlier across "
            f"{len(tunnels)} tunnels: {_describe_difference(result.features, population)}. "
            f"This violates no rule — it is flagged because it does not match its peers, "
            f"which in practice usually means a gateway rebuilt from a different "
            f"template or restored from an old backup"
        ),
        standard_ref="NIST SP 800-77 Rev. 1 section 5.4 (configuration management)",
        remediation_hint=(
            "Compare this gateway's configuration against the estate standard. If the "
            "difference is deliberate, record why; if not, it is drift and will "
            "reappear on the next rebuild."
        ),
        confidence=Confidence(
            value=_confidence_from_score(result.score),
            method=ANOMALY_METHOD,
            abstained=False,
        ),
    )


def anomaly_summary(
    tunnels: list[Tunnel], min_estate_size: int = MIN_ESTATE_SIZE
) -> dict[str, Any]:
    """A short summary a report header can render."""
    results = score_anomalies(tunnels, min_estate_size)
    if not results:
        rows = [extract_features(t) for t in tunnels]
        share = modal_share(rows)
        return {
            "evaluated": len(tunnels),
            "anomalies": 0,
            "below_minimum": len(tunnels) < min_estate_size,
            "no_dominant_configuration": (
                len(tunnels) >= min_estate_size and share < MIN_MODAL_SHARE
            ),
            "modal_share": round(share, 3),
            "minimum_estate_size": min_estate_size,
        }
    return {
        "evaluated": len(results),
        "anomalies": sum(1 for r in results if r.is_anomaly),
        "below_minimum": False,
        "no_dominant_configuration": False,
        "modal_share": round(modal_share([r.features for r in results]), 3),
        "minimum_estate_size": min_estate_size,
    }
