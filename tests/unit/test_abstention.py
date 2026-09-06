"""Tests for prediction abstention (build plan Step 7.8).

Abstention is only meaningful if the confidence it thresholds is *discriminative* — if
the model does not know when it is wrong, declining below a threshold declines at
random. That property is enforced in the calibration module and relied on here.
"""

from __future__ import annotations

import warnings
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from ipsec_sentinel.features.flow import FEATURE_NAMES
from ipsec_sentinel.ml.predict import (
    ABSTAIN_LABEL,
    DEFAULT_THRESHOLD,
    MAX_REASONABLE_ABSTENTION,
    PredictionError,
    abstention_rate,
    evaluate_abstention,
    predict_with_abstention,
)

warnings.filterwarnings("ignore")

REAL = Path("data/processed/ml_dataset.parquet")
CLASSES = ["a", "b", "c"]


class StubModel:
    """Returns fixed probabilities, so threshold behaviour is tested in isolation."""

    def __init__(self, rows: list[list[float]]) -> None:
        self._rows = np.array(rows, dtype=float)

    def predict_proba(self, matrix: np.ndarray) -> np.ndarray:  # noqa: ARG002
        return self._rows


def frame(rows: int = 1) -> pd.DataFrame:
    return pd.DataFrame([dict.fromkeys(FEATURE_NAMES, 0.0) for _ in range(rows)])


class TestThresholdBehaviour:
    def test_a_high_confidence_input_returns_a_class(self) -> None:
        model = StubModel([[0.92, 0.05, 0.03]])
        prediction = predict_with_abstention(model, frame(), CLASSES, FEATURE_NAMES)[0]
        assert prediction.label == "a"
        assert prediction.abstained is False
        assert prediction.confidence.value == pytest.approx(0.92)

    def test_a_low_confidence_input_abstains(self) -> None:
        model = StubModel([[0.4, 0.35, 0.25]])
        prediction = predict_with_abstention(model, frame(), CLASSES, FEATURE_NAMES)[0]
        assert prediction.label == ABSTAIN_LABEL
        assert prediction.abstained is True

    def test_an_abstained_prediction_sets_confidence_abstained(self) -> None:
        """A caller that ignores the label still sees the model declined."""
        model = StubModel([[0.4, 0.35, 0.25]])
        prediction = predict_with_abstention(model, frame(), CLASSES, FEATURE_NAMES)[0]
        assert prediction.confidence.abstained is True
        assert prediction.confidence.method

    def test_an_answered_prediction_does_not_set_abstained(self) -> None:
        model = StubModel([[0.92, 0.05, 0.03]])
        prediction = predict_with_abstention(model, frame(), CLASSES, FEATURE_NAMES)[0]
        assert prediction.confidence.abstained is False

    def test_exactly_at_the_threshold_answers(self) -> None:
        model = StubModel([[DEFAULT_THRESHOLD, 0.2, 0.2]])
        prediction = predict_with_abstention(model, frame(), CLASSES, FEATURE_NAMES)[0]
        assert prediction.abstained is False

    def test_the_threshold_is_configurable(self) -> None:
        model = StubModel([[0.65, 0.2, 0.15]])
        assert not predict_with_abstention(model, frame(), CLASSES, FEATURE_NAMES, threshold=0.6)[
            0
        ].abstained
        assert predict_with_abstention(model, frame(), CLASSES, FEATURE_NAMES, threshold=0.7)[
            0
        ].abstained

    def test_the_near_miss_is_retained_separately_from_the_label(self) -> None:
        """An analyst can see what it would have said; nothing can mistake it for an answer."""
        model = StubModel([[0.4, 0.35, 0.25]])
        prediction = predict_with_abstention(model, frame(), CLASSES, FEATURE_NAMES)[0]
        assert prediction.label == ABSTAIN_LABEL
        assert prediction.best_label == "a"

    def test_the_full_distribution_is_returned(self) -> None:
        model = StubModel([[0.5, 0.3, 0.2]])
        prediction = predict_with_abstention(model, frame(), CLASSES, FEATURE_NAMES)[0]
        assert prediction.probabilities == pytest.approx({"a": 0.5, "b": 0.3, "c": 0.2})


class TestRefusals:
    def test_a_threshold_of_zero_is_refused(self) -> None:
        """It abstains never, which defeats the purpose."""
        with pytest.raises(PredictionError, match="threshold must be"):
            predict_with_abstention(
                StubModel([[1.0, 0.0, 0.0]]), frame(), CLASSES, FEATURE_NAMES, threshold=0.0
            )

    def test_a_threshold_above_one_is_refused(self) -> None:
        with pytest.raises(PredictionError, match="threshold must be"):
            predict_with_abstention(
                StubModel([[1.0, 0.0, 0.0]]), frame(), CLASSES, FEATURE_NAMES, threshold=1.5
            )

    def test_missing_features_are_refused(self) -> None:
        with pytest.raises(PredictionError, match="missing features"):
            predict_with_abstention(
                StubModel([[1.0, 0.0, 0.0]]),
                frame().drop(columns=[FEATURE_NAMES[0]]),
                CLASSES,
                FEATURE_NAMES,
            )

    def test_a_class_count_mismatch_is_refused(self) -> None:
        """The model and its metadata disagreeing is a silent-wrong-answer bug."""
        with pytest.raises(PredictionError, match="disagree"):
            predict_with_abstention(StubModel([[0.5, 0.5]]), frame(), CLASSES, FEATURE_NAMES)

    def test_an_empty_frame_returns_no_predictions(self) -> None:
        assert predict_with_abstention(StubModel([]), frame(0), CLASSES, FEATURE_NAMES) == []

    def test_mismatched_lengths_are_refused_in_evaluation(self) -> None:
        model = StubModel([[0.9, 0.05, 0.05]])
        predictions = predict_with_abstention(model, frame(), CLASSES, FEATURE_NAMES)
        with pytest.raises(PredictionError, match="predictions for"):
            evaluate_abstention(predictions, ["a", "b"])


class TestAbstentionRate:
    def test_it_counts_the_declined_share(self) -> None:
        model = StubModel([[0.9, 0.05, 0.05], [0.4, 0.35, 0.25], [0.3, 0.35, 0.35]])
        predictions = predict_with_abstention(model, frame(3), CLASSES, FEATURE_NAMES)
        assert abstention_rate(predictions) == pytest.approx(2 / 3)

    def test_no_predictions_is_zero_rather_than_a_crash(self) -> None:
        assert abstention_rate([]) == 0.0

    def test_evaluation_reports_accuracy_both_ways(self) -> None:
        """If declining does not raise accuracy, the threshold is discarding right answers."""
        model = StubModel([[0.95, 0.03, 0.02], [0.4, 0.35, 0.25]])
        predictions = predict_with_abstention(model, frame(2), CLASSES, FEATURE_NAMES)
        report = evaluate_abstention(predictions, ["a", "b"])
        assert report.accuracy_when_answered == 1.0
        assert report.accuracy_if_forced == 0.5
        assert report.precision_gained == pytest.approx(0.5)

    def test_a_harmful_threshold_shows_a_negative_gain(self) -> None:
        """Declining on rows it would have got right must be visible, not hidden."""
        model = StubModel([[0.95, 0.03, 0.02], [0.4, 0.35, 0.25]])
        predictions = predict_with_abstention(model, frame(2), CLASSES, FEATURE_NAMES)
        report = evaluate_abstention(predictions, ["b", "a"])
        assert report.precision_gained < 0


@pytest.mark.skipif(not REAL.exists(), reason="the ML dataset has not been built")
class TestAgainstTheRealCorpus:
    @staticmethod
    def _run(threshold: float = DEFAULT_THRESHOLD):  # type: ignore[no-untyped-def]
        from ipsec_sentinel.ml.calibrate import calibrate_classifier
        from ipsec_sentinel.ml.split import split_by_capture

        data = pd.read_parquet(REAL)
        train, evaluation = split_by_capture(data, test_frac=0.25, seed=42)
        model, _report = calibrate_classifier(train, evaluation)
        classes = sorted(train["inner_traffic"].dropna().astype(str).unique().tolist())
        predictions = predict_with_abstention(
            model, evaluation, classes, FEATURE_NAMES, threshold=threshold
        )
        return predictions, evaluation["inner_traffic"].astype(str).tolist()

    def test_the_abstention_rate_is_reasonable(self) -> None:
        """The plan's criterion: under 25%."""
        predictions, truth = self._run()
        report = evaluate_abstention(predictions, truth)
        assert report.rate <= MAX_REASONABLE_ABSTENTION, report.summary()
        assert report.is_reasonable is True

    def test_abstention_actually_removes_wrong_answers(self) -> None:
        """The whole justification. If it does not, the threshold is decoration."""
        predictions, truth = self._run()
        report = evaluate_abstention(predictions, truth)
        assert report.precision_gained > 0, report.summary()

    def test_the_model_does_abstain_on_something(self) -> None:
        """Zero abstentions at every threshold means the confidence is saturated."""
        predictions, _truth = self._run()
        assert abstention_rate(predictions) > 0.0

    def test_a_higher_threshold_abstains_at_least_as_often(self) -> None:
        low, _ = self._run(threshold=0.6)
        high, _ = self._run(threshold=0.9)
        assert abstention_rate(high) >= abstention_rate(low)
