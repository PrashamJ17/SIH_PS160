"""SHAP explanations: why the model said what it said, in a sentence.

An unexplained classification is an assertion. In a security report it is worse than
that — an analyst who cannot see the reasoning has no way to tell a sound inference from
a spurious correlation, and no basis for overruling the tool when it is wrong. So every
inferred finding this system emits can be traced to the features that drove it.

Two decisions worth stating.

**The explanation describes the base model, not the calibrated wrapper.** Calibration
rescales confidence; it does not change which features the trees split on. Attributions
therefore come from the underlying ensemble, and the confidence shown beside them comes
from the calibrated model. Explaining the wrapper instead would mean explaining a
one-dimensional post-hoc transform, which says nothing about the traffic.

**Feature names are rendered into English, not printed raw.** ``fwd_bwd_byte_ratio``
means nothing to the operator who has to act on the finding, and a sentence full of
identifiers is the kind of explainability that satisfies a checklist without informing
anyone. Every feature has a phrase, and a test asserts the rendered sentence contains no
raw identifier.

SHAP values are additive by construction: for the explained class they sum, with the
base value, to the model's output for that class. That property is what makes them
auditable rather than decorative, and it is asserted directly.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final

from ipsec_sentinel.features.flow import FEATURE_NAMES

if TYPE_CHECKING:  # pragma: no cover - typing only
    import pandas as pd

TOP_FEATURES: Final = 5

# Explanation must be fast enough to run per finding in a report over a large estate.
EXPLANATION_BUDGET_S: Final = 2.0

# How each feature reads in a sentence. Written out rather than derived from the
# identifier because the point is to say what the number means to someone triaging a
# tunnel, not to prettify a variable name.
FEATURE_PHRASES: Final[dict[str, str]] = {
    "packet_count": "the number of packets",
    "byte_count": "the total bytes carried",
    "duration_s": "the flow duration in seconds",
    "bytes_per_s": "the byte rate",
    "packets_per_s": "the packet rate",
    "size_mean": "the average packet size",
    "size_std": "packet size variation",
    "size_min": "the smallest packet",
    "size_max": "the largest packet",
    "size_median": "the median packet size",
    "size_p25": "the lower quartile of packet sizes",
    "size_p75": "the upper quartile of packet sizes",
    "size_p90": "the 90th-percentile packet size",
    "fwd_size_mean": "the average outbound packet size",
    "fwd_size_std": "outbound packet size variation",
    "fwd_size_min": "the smallest outbound packet",
    "fwd_size_max": "the largest outbound packet",
    "fwd_size_median": "the median outbound packet size",
    "bwd_size_mean": "the average inbound packet size",
    "bwd_size_std": "inbound packet size variation",
    "bwd_size_min": "the smallest inbound packet",
    "bwd_size_max": "the largest inbound packet",
    "bwd_size_median": "the median inbound packet size",
    "iat_mean": "the average gap between packets",
    "iat_std": "packet timing irregularity",
    "iat_min": "the shortest gap between packets",
    "iat_max": "the longest gap between packets",
    "iat_median": "the median gap between packets",
    "iat_p90": "the 90th-percentile gap between packets",
    "fwd_packet_count": "the number of outbound packets",
    "bwd_packet_count": "the number of inbound packets",
    "fwd_byte_count": "the outbound byte volume",
    "bwd_byte_count": "the inbound byte volume",
    "fwd_bwd_packet_ratio": "the outbound-to-inbound packet ratio",
    "fwd_bwd_byte_ratio": "the outbound-to-inbound byte ratio",
    "burst_count": "the number of traffic bursts",
    "burst_mean_packets": "the average burst length",
    "idle_mean_s": "the average idle gap",
    "idle_max_s": "the longest idle gap",
    "mtu_fraction": "the share of packets filling the MTU",
    "small_packet_fraction": "the share of very small packets",
    "size_entropy": "packet size entropy",
}


# Phrases are rendered as "<phrase> was <value>", so each must read as a noun phrase.
# An earlier version used clause-shaped phrases ("how irregular the packet timing was")
# and produced "the packet timing was was 0.0009".
assert not any(
    phrase.endswith((" was", " were", " varied")) for phrase in FEATURE_PHRASES.values()
), "feature phrases must be noun phrases, not clauses"


class ExplanationError(ValueError):
    """An explanation could not be produced."""


@dataclass(frozen=True)
class FeatureContribution:
    """One feature's signed contribution to the predicted class."""

    feature: str
    value: float
    contribution: float

    @property
    def phrase(self) -> str:
        return FEATURE_PHRASES.get(self.feature, self.feature)

    @property
    def direction(self) -> str:
        return "towards" if self.contribution >= 0 else "against"

    def render(self) -> str:
        # `%g` renders a negative zero as "-0", which reads as a real negative value.
        shown = 0.0 if self.value == 0 else self.value
        return f"{self.phrase} was {shown:.4g} (contribution {self.contribution:+.2f})"


@dataclass
class Explanation:
    """Why the model chose a class, with the arithmetic behind it."""

    predicted_class: str
    base_value: float
    prediction_value: float
    contributions: list[FeatureContribution] = field(default_factory=list)
    all_contributions: dict[str, float] = field(default_factory=dict)
    elapsed_s: float = 0.0

    @property
    def total_contribution(self) -> float:
        return sum(self.all_contributions.values())

    def is_additive(self, tolerance: float = 1e-3) -> bool:
        """Whether base value plus contributions reproduces the model's output.

        The property that makes SHAP auditable rather than decorative. If it does not
        hold, the numbers beside a finding are not an explanation of anything.
        """
        return abs((self.base_value + self.total_contribution) - self.prediction_value) <= tolerance

    def sentence(self) -> str:
        """The explanation as one readable sentence."""
        if not self.contributions:
            return f"Classified as {self.predicted_class} with no dominant feature."
        supporting = [c for c in self.contributions if c.contribution >= 0]
        chosen = supporting or self.contributions
        parts = [c.render() for c in chosen[:3]]
        joined = parts[0] if len(parts) == 1 else ", ".join(parts[:-1]) + " and " + parts[-1]
        return f"Classified as {self.predicted_class} because {joined}."


def _is_fitted_tree_model(model: Any) -> bool:
    """Whether this object is something SHAP's TreeExplainer can read directly."""
    return hasattr(model, "estimators_") or hasattr(model, "tree_") or hasattr(model, "get_booster")


def _base_estimator(model: Any) -> Any:
    """Reach the fitted tree ensemble inside a calibration wrapper.

    Unwrapping stops at the first fitted model rather than following every ``estimator``
    attribute down. A ``RandomForestClassifier`` exposes ``.estimator`` too — the
    *unfitted* DecisionTreeClassifier it clones for each tree — and recursing into that
    reaches an object with no learned structure at all, which SHAP rejects with an error
    that reads like a version problem rather than a wrong-object problem.

    Calibration rescales confidence and does not change which features the trees split
    on, so the attributions belong to the ensemble underneath.
    """
    seen = 0
    current = model
    while seen < 8:
        seen += 1
        # FrozenEstimator proxies attribute access to the model it wraps, so it looks
        # like a fitted ensemble to any hasattr check while being a type SHAP rejects.
        # It has to be unwrapped by type, before the fitted test.
        if type(current).__name__ == "FrozenEstimator":
            current = current.estimator
            continue
        if _is_fitted_tree_model(current):
            return current
        calibrated = getattr(current, "calibrated_classifiers_", None)
        if calibrated:
            current = calibrated[0].estimator
            continue
        inner = getattr(current, "estimator", None)
        if inner is None:
            return current
        current = inner
    return current  # pragma: no cover - defensive against a pathological nesting


def explain_prediction(
    model: Any,
    features: pd.DataFrame,
    class_names: list[str] | None = None,
    feature_names: list[str] | None = None,
    top: int = TOP_FEATURES,
) -> Explanation:
    """Explain a single prediction with signed SHAP contributions.

    ``features`` must hold exactly one row. Explaining a batch and returning the first
    would quietly attribute one flow's reasoning to another.
    """
    import numpy as np
    import shap

    names = list(feature_names or FEATURE_NAMES)
    if len(features) != 1:
        raise ExplanationError(f"expected exactly one row to explain, got {len(features)}")
    missing = [n for n in names if n not in features.columns]
    if missing:
        raise ExplanationError(f"the frame is missing features: {missing[:5]}")

    started = time.perf_counter()
    estimator = _base_estimator(model)
    matrix = features[names].to_numpy(dtype=float)

    try:
        explainer = shap.TreeExplainer(estimator)
        values = explainer.shap_values(matrix, check_additivity=False)
        expected = explainer.expected_value
    except Exception as exc:
        raise ExplanationError(f"SHAP could not explain this model: {exc}") from exc

    labels = list(class_names or getattr(estimator, "classes_", []))
    probabilities = estimator.predict_proba(matrix)[0]
    index = int(np.argmax(probabilities))
    predicted = str(labels[index]) if index < len(labels) else str(index)

    # shap returns (rows, features, classes) for multiclass tree models, or a list of
    # per-class arrays in older releases. Both are handled rather than assumed.
    array = np.asarray(values)
    if array.ndim == 3:
        row_values = array[0, :, index]
    elif array.ndim == 2 and isinstance(values, list):  # pragma: no cover - legacy shap
        row_values = np.asarray(values[index])[0]
    else:
        row_values = array[0]

    base = expected
    if isinstance(base, list | np.ndarray):
        base_array = np.asarray(base)
        base = float(base_array[index]) if base_array.size > index else float(base_array.flat[0])
    base = float(base)

    contributions = {name: float(row_values[i]) for i, name in enumerate(names)}
    ranked = sorted(contributions.items(), key=lambda kv: abs(kv[1]), reverse=True)
    top_features = [
        FeatureContribution(
            feature=name,
            value=float(features.iloc[0][name]),
            contribution=value,
        )
        for name, value in ranked[:top]
    ]

    return Explanation(
        predicted_class=predicted,
        base_value=base,
        prediction_value=base + sum(contributions.values()),
        contributions=top_features,
        all_contributions=contributions,
        elapsed_s=time.perf_counter() - started,
    )
