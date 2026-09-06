"""Prediction with abstention: the model is allowed to say it does not know.

Most classifiers are built to always answer. That is the right design for a
recommendation engine and the wrong one for a security tool, where a confident wrong
answer costs an analyst an afternoon and a wrong answer they were warned about costs
them nothing. **Abstention is a feature, not a failure mode.**

The mechanics are trivial — compare the top probability to a threshold — and the two
things that make it meaningful are not:

**The probabilities must be calibrated.** Abstaining below 0.6 on an uncalibrated score
is arbitrary, because an uncalibrated 0.6 does not mean "right six times in ten"; it
means "six of ten trees agreed", which is a different and unrelated quantity. This
module therefore expects a calibrated model, and the threshold is stated in the units
calibration gives it.

**The threshold has to be defensible against chance.** With seven classes, random
guessing scores 1/7 ≈ 0.14. A threshold of 0.6 is four times chance and, on a calibrated
model, means the tool answers only when it expects to be right at least three times in
five. That is a low bar for a human and a high one for a classifier asked to stay quiet
when it is unsure.

An abstention is reported as the class ``insufficient_signal`` with
``Confidence.abstained = True`` — never as a missing value, and never as the most likely
class with a low score attached. A caller that ignores the confidence field still gets
something honest.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final

from ipsec_sentinel.models import Confidence

if TYPE_CHECKING:  # pragma: no cover - typing only
    import pandas as pd

ABSTAIN_LABEL: Final = "insufficient_signal"
DEFAULT_THRESHOLD: Final = 0.6

# Above this share of abstentions the model is not usable in production: it is declining
# to answer so often that an operator would stop reading the section. Reported rather
# than enforced at predict time, because the right response is to retrain or lower the
# threshold deliberately, not to silently answer anyway.
MAX_REASONABLE_ABSTENTION: Final = 0.25

CONFIDENCE_METHOD: Final = "calibrated classifier, top-class probability"


class PredictionError(ValueError):
    """A prediction cannot be made from the inputs as given."""


@dataclass(frozen=True)
class Prediction:
    """One prediction, its confidence, and whether the model declined to answer."""

    label: str
    confidence: Confidence
    probabilities: dict[str, float]
    threshold: float

    @property
    def abstained(self) -> bool:
        return self.confidence.abstained

    @property
    def top_probability(self) -> float:
        return max(self.probabilities.values()) if self.probabilities else 0.0

    @property
    def best_label(self) -> str | None:
        """The class the model would have chosen had it answered.

        Kept for an analyst who wants to see the near-miss, and deliberately separate
        from :attr:`label` so nothing downstream can mistake a declined answer for a
        given one.
        """
        if not self.probabilities:
            return None
        return max(self.probabilities, key=lambda name: self.probabilities[name])


def _probability_rows(model: Any, matrix: Any, class_names: Sequence[str]) -> Any:
    probabilities = model.predict_proba(matrix)
    if probabilities.shape[1] != len(class_names):
        raise PredictionError(
            f"the model produced {probabilities.shape[1]} probability columns for "
            f"{len(class_names)} class names; the model and its metadata disagree"
        )
    return probabilities


def predict_with_abstention(
    model: Any,
    features: pd.DataFrame,
    class_names: Sequence[str],
    feature_names: Sequence[str],
    threshold: float = DEFAULT_THRESHOLD,
) -> list[Prediction]:
    """Predict each row, abstaining where the top probability is below ``threshold``.

    Returns one :class:`Prediction` per row, in input order.
    """
    if not 0.0 < threshold <= 1.0:
        raise PredictionError(
            f"threshold must be in (0, 1], got {threshold}. A threshold of 0 abstains "
            f"never, which defeats the purpose."
        )
    if features.empty:
        # Nothing to predict. Checked before the column check because an empty frame
        # produces no output either way, and refusing it would make the caller special-
        # case "no rows" for no benefit.
        return []
    missing = [name for name in feature_names if name not in features.columns]
    if missing:
        raise PredictionError(
            f"the frame is missing features the model was trained on: {missing[:5]}"
        )

    matrix = features[list(feature_names)].to_numpy(dtype=float)
    probabilities = _probability_rows(model, matrix, class_names)

    predictions: list[Prediction] = []
    for row in probabilities:
        distribution = {str(name): float(row[i]) for i, name in enumerate(class_names)}
        best = max(distribution, key=lambda name: distribution[name])
        top = distribution[best]
        abstained = top < threshold
        predictions.append(
            Prediction(
                label=ABSTAIN_LABEL if abstained else best,
                confidence=Confidence(value=top, method=CONFIDENCE_METHOD, abstained=abstained),
                probabilities=distribution,
                threshold=threshold,
            )
        )
    return predictions


def abstention_rate(predictions: Sequence[Prediction]) -> float:
    """The share of predictions the model declined to make."""
    if not predictions:
        return 0.0
    return sum(1 for p in predictions if p.abstained) / len(predictions)


@dataclass(frozen=True)
class AbstentionReport:
    """How often the model declined, and whether declining helped."""

    total: int
    abstained: int
    threshold: float
    accuracy_when_answered: float
    accuracy_if_forced: float

    @property
    def rate(self) -> float:
        return self.abstained / self.total if self.total else 0.0

    @property
    def is_reasonable(self) -> bool:
        return self.rate <= MAX_REASONABLE_ABSTENTION

    @property
    def precision_gained(self) -> float:
        """How much accuracy abstention bought.

        Negative would mean the model is declining on rows it would have got right,
        which makes the threshold actively harmful rather than merely conservative.
        """
        return self.accuracy_when_answered - self.accuracy_if_forced

    def summary(self) -> str:
        verdict = "reasonable" if self.is_reasonable else "TOO HIGH"
        return (
            f"abstained on {self.abstained}/{self.total} ({self.rate:.1%}, {verdict} "
            f"against {MAX_REASONABLE_ABSTENTION:.0%}) at threshold {self.threshold}; "
            f"accuracy {self.accuracy_if_forced:.1%} if forced to answer, "
            f"{self.accuracy_when_answered:.1%} when it chose to "
            f"({self.precision_gained:+.1%})"
        )


def evaluate_abstention(
    predictions: Sequence[Prediction], truth: Sequence[str]
) -> AbstentionReport:
    """Measure whether abstention earned its keep.

    Reports accuracy two ways: over the rows the model chose to answer, and over every
    row had it been forced. If the first is not clearly higher than the second, the
    threshold is discarding correct answers and should be lowered.
    """
    if len(predictions) != len(truth):
        raise PredictionError(f"{len(predictions)} predictions for {len(truth)} labels")
    if not predictions:
        return AbstentionReport(0, 0, DEFAULT_THRESHOLD, 0.0, 0.0)

    answered = [(p, t) for p, t in zip(predictions, truth, strict=True) if not p.abstained]
    correct_answered = sum(1 for p, t in answered if p.label == t)
    correct_forced = sum(1 for p, t in zip(predictions, truth, strict=True) if p.best_label == t)
    return AbstentionReport(
        total=len(predictions),
        abstained=sum(1 for p in predictions if p.abstained),
        threshold=predictions[0].threshold,
        accuracy_when_answered=correct_answered / len(answered) if answered else 0.0,
        accuracy_if_forced=correct_forced / len(predictions),
    )
