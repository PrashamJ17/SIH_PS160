"""Confidence calibration: making a probability mean what it says.

An uncalibrated classifier's "0.9" is a ranking, not a probability. Tree ensembles are
particularly bad at this — a random forest's confidence is the fraction of trees that
agreed, which is systematically overconfident in the middle of the range and clipped at
the ends. That matters here more than in most systems, because this project's whole
architecture rests on a reader being able to trust a confidence: Section B findings are
allowed to be uncertain precisely because they say *how* uncertain, and a 0.9 that is
right 60% of the time makes that promise false.

**Expected Calibration Error** is the measurement. Bin predictions by confidence, compare
each bin's average confidence against its actual accuracy, and average the gaps weighted
by bin size. A perfectly calibrated model scores 0. The build plan sets 0.15 as the line
below which a confidence may be shown to a user at all, and the test suite enforces it —
if calibration fails, the number is not displayed rather than displayed with a caveat.

**Calibration is fitted on data the base model never saw, grouped by capture.** Fitting
a calibrator on the model's training data teaches it to correct overconfidence the model
does not exhibit there, which produces a calibrator that is itself miscalibrated. The
split is grouped for the same reason every other split in this project is.

**The method is chosen on a validation split, never on the evaluation set.** The prior
going in was that Platt scaling (sigmoid) would win, because it fits two parameters per
class and this corpus is small, where isotonic regression is usually said to overfit.
The data disagreed: on this corpus sigmoid makes calibration *worse* (ECE 0.061 → 0.077)
while isotonic improves it substantially (→ 0.017).

Switching the default because isotonic scored better on the evaluation set would have
been selection on the test set — the same error this project refuses everywhere else. So
the training data is split three ways instead: a fit set for the base model, a
calibration set for the calibrator, and a **validation set on which the method is
chosen**. The evaluation set is touched only to report the final number. The prior is
recorded here rather than quietly deleted, because a prior the data overturns is worth
more in the record than one that was never stated.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:  # pragma: no cover - typing only
    import pandas as pd

DEFAULT_BINS: Final = 10
DEFAULT_METHOD: Final = "auto"
CALIBRATION_METHODS: Final[tuple[str, ...]] = ("sigmoid", "isotonic")
SUPPORTED_METHODS: Final[tuple[str, ...]] = (*CALIBRATION_METHODS, "auto")

# The build plan's threshold. Above this, a confidence is not trustworthy enough to put
# in front of a user, and the correct response is to withhold the number rather than
# show it with a disclaimer nobody reads.
MAX_ACCEPTABLE_ECE: Final = 0.15


class CalibrationError(ValueError):
    """Calibration could not be performed on the data as given."""


@dataclass(frozen=True)
class ReliabilityBin:
    """One bin of a reliability diagram."""

    lower: float
    upper: float
    count: int
    mean_confidence: float
    accuracy: float

    @property
    def gap(self) -> float:
        """How far this bin's confidence is from its accuracy. Signed: + is overconfident."""
        return self.mean_confidence - self.accuracy


@dataclass
class CalibrationReport:
    """Calibration measured before and after, with the diagram data behind it."""

    method: str
    ece_before: float
    ece_after: float
    selection: str = ""
    """How the method was chosen, so a reader can see it was not chosen by result."""
    bins_before: list[ReliabilityBin] = field(default_factory=list)
    bins_after: list[ReliabilityBin] = field(default_factory=list)
    n_calibration: int = 0
    n_evaluation: int = 0

    @property
    def improved(self) -> bool:
        return self.ece_after < self.ece_before

    @property
    def is_trustworthy(self) -> bool:
        """Whether the calibrated confidence may be shown to a user at all."""
        return self.ece_after <= MAX_ACCEPTABLE_ECE

    def summary(self) -> str:
        verdict = "trustworthy" if self.is_trustworthy else "NOT trustworthy"
        return (
            f"{self.method}: ECE {self.ece_before:.4f} -> {self.ece_after:.4f} "
            f"({verdict}, threshold {MAX_ACCEPTABLE_ECE}), "
            f"{self.n_calibration} calibration / {self.n_evaluation} evaluation rows"
            + (f"\n  {self.selection}" if self.selection else "")
        )


def expected_calibration_error(
    probabilities: Any, truth: Any, labels: list[str], bins: int = DEFAULT_BINS
) -> tuple[float, list[ReliabilityBin]]:
    """Expected Calibration Error and the reliability diagram behind it.

    Uses the standard top-label formulation: each prediction contributes its maximum
    class probability as its confidence, and whether that class was correct as its
    outcome. Empty bins are returned with zero count rather than dropped, so a diagram
    always has the same shape and two runs can be compared bin by bin.
    """
    import numpy as np

    probabilities = np.asarray(probabilities, dtype=float)
    if probabilities.ndim != 2:
        raise CalibrationError("probabilities must be a 2-D array of shape (n, classes)")
    if len(probabilities) != len(truth):
        raise CalibrationError(f"{len(probabilities)} probability rows for {len(truth)} labels")
    if len(probabilities) == 0:
        return 0.0, []

    confidence = probabilities.max(axis=1)
    predicted = np.array([labels[i] for i in probabilities.argmax(axis=1)])
    correct = predicted == np.asarray(truth)

    edges = np.linspace(0.0, 1.0, bins + 1)
    diagram: list[ReliabilityBin] = []
    total_error = 0.0
    for i in range(bins):
        lower, upper = edges[i], edges[i + 1]
        # The last bin is closed on the right so a confidence of exactly 1.0 lands in it.
        in_bin = (
            (confidence > lower) & (confidence <= upper)
            if i > 0
            else (confidence >= lower) & (confidence <= upper)
        )
        count = int(in_bin.sum())
        if count == 0:
            diagram.append(ReliabilityBin(float(lower), float(upper), 0, 0.0, 0.0))
            continue
        mean_confidence = float(confidence[in_bin].mean())
        accuracy = float(correct[in_bin].mean())
        diagram.append(ReliabilityBin(float(lower), float(upper), count, mean_confidence, accuracy))
        total_error += (count / len(confidence)) * abs(mean_confidence - accuracy)
    return float(total_error), diagram


def _grouped_holdout(
    frame: pd.DataFrame, fraction: float, seed: int, column: str = "capture_id"
) -> tuple[pd.DataFrame, pd.DataFrame]:
    from ipsec_sentinel.ml.split import split_by_capture

    return split_by_capture(frame, test_frac=fraction, seed=seed, column=column)


def calibrate_classifier(
    train: pd.DataFrame,
    evaluation: pd.DataFrame,
    model_name: str = "random_forest",
    target: str = "inner_traffic",
    method: str = DEFAULT_METHOD,
    seed: int = 42,
    bins: int = DEFAULT_BINS,
    calibration_fraction: float = 0.3,
) -> tuple[Any, CalibrationReport]:
    """Fit a base model, calibrate it, and measure ECE before and after.

    ``train`` is split by capture into a fit set and a calibration set; the base model
    never sees the calibration set, and neither ever sees ``evaluation``. All three
    numbers in the report are measured on ``evaluation``.
    """
    import numpy as np
    from sklearn.calibration import CalibratedClassifierCV
    from sklearn.frozen import FrozenEstimator

    from ipsec_sentinel.features.flow import FEATURE_NAMES
    from ipsec_sentinel.ml.train import _build_model, _validate

    if method not in SUPPORTED_METHODS:
        raise CalibrationError(
            f"unknown calibration method {method!r}; supported: {list(SUPPORTED_METHODS)}"
        )
    _validate(train, target)
    if evaluation.empty:
        raise CalibrationError("the evaluation set is empty; there is nothing to measure")

    labels = sorted(train[target].dropna().astype(str).unique().tolist())

    if method == "auto":
        # Choose on a validation split carved out of training data, never on the
        # evaluation set. The chosen method is then refitted below on the full
        # fit/calibration split so the returned model uses all the training data.
        remaining, validation = _grouped_holdout(train, 0.2, seed)
        scores: dict[str, float] = {}
        for candidate in CALIBRATION_METHODS:
            try:
                _model, trial = calibrate_classifier(
                    remaining,
                    validation,
                    model_name,
                    target,
                    candidate,
                    seed,
                    bins,
                    calibration_fraction,
                )
            except CalibrationError:
                continue
            scores[candidate] = trial.ece_after
        if not scores:
            raise CalibrationError(
                "no calibration method could be evaluated on the validation split"
            )
        chosen = min(scores, key=lambda name: scores[name])
        selection = "chosen on a held-out validation split: " + ", ".join(
            f"{k} ECE {v:.4f}" for k, v in sorted(scores.items())
        )
        model, report = calibrate_classifier(
            train,
            evaluation,
            model_name,
            target,
            chosen,
            seed,
            bins,
            calibration_fraction,
        )
        report.selection = selection
        return model, report

    fit_set, calibration_set = _grouped_holdout(train, calibration_fraction, seed)

    def matrix(frame: pd.DataFrame) -> Any:
        return frame[list(FEATURE_NAMES)].to_numpy(dtype=float)

    fit_truth = fit_set[target].astype(str).to_numpy()
    if len(set(fit_truth)) < 2:
        raise CalibrationError(
            "the fit split contains a single class; increase the training set or "
            "lower calibration_fraction"
        )

    base = _build_model(model_name, seed, len(labels))
    base.fit(matrix(fit_set), fit_truth)

    # FrozenEstimator replaced cv="prefit", removed in scikit-learn 1.6. Freezing is
    # the point: the calibrator must not refit the base model, or it would refit on the
    # calibration set and the separation this whole function depends on would be gone.
    calibrated = CalibratedClassifierCV(FrozenEstimator(base), method=method)
    calibrated.fit(matrix(calibration_set), calibration_set[target].astype(str).to_numpy())

    evaluation_truth = evaluation[target].astype(str).to_numpy()
    evaluation_matrix = matrix(evaluation)

    def aligned(model: Any) -> Any:
        """Probabilities in the full label order, zero-filled for unseen classes."""
        raw = model.predict_proba(evaluation_matrix)
        known = [str(c) for c in model.classes_]
        out = np.zeros((len(raw), len(labels)))
        for column, name in enumerate(known):
            out[:, labels.index(name)] = raw[:, column]
        return out

    ece_before, bins_before = expected_calibration_error(
        aligned(base), evaluation_truth, labels, bins
    )
    ece_after, bins_after = expected_calibration_error(
        aligned(calibrated), evaluation_truth, labels, bins
    )

    return calibrated, CalibrationReport(
        method=method,
        selection="method supplied by the caller",
        ece_before=ece_before,
        ece_after=ece_after,
        bins_before=bins_before,
        bins_after=bins_after,
        n_calibration=len(calibration_set),
        n_evaluation=len(evaluation),
    )


def reliability_diagram_rows(report: CalibrationReport) -> list[dict[str, float]]:
    """The diagram as plain rows, ready for a report table or a plot."""
    return [
        {
            "lower": b.lower,
            "upper": b.upper,
            "count": float(b.count),
            "mean_confidence": b.mean_confidence,
            "accuracy": b.accuracy,
            "gap": b.gap,
        }
        for b in report.bins_after
    ]
