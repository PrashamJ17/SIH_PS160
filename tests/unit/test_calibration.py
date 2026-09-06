"""Tests for confidence calibration (build plan Step 7.7).

`test_calibrated_ece_is_below_the_threshold` is the gate. Above 0.15 a confidence is not
trustworthy enough to put in front of a user, and the correct response is to withhold
the number rather than show it with a disclaimer nobody reads.
"""

from __future__ import annotations

import warnings
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from ipsec_sentinel.features.flow import FEATURE_NAMES
from ipsec_sentinel.ml.calibrate import (
    CALIBRATION_METHODS,
    DEFAULT_BINS,
    MAX_ACCEPTABLE_ECE,
    CalibrationError,
    calibrate_classifier,
    expected_calibration_error,
    reliability_diagram_rows,
)
from ipsec_sentinel.ml.split import split_by_capture

warnings.filterwarnings("ignore")

REAL = Path("data/processed/ml_dataset.parquet")


def synthetic(classes: int = 3, captures: int = 40, seed: int = 0) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    rows = []
    for c in range(classes):
        for capture in range(captures):
            for window in range(2):
                row = {name: float(rng.normal(c * 30, 12)) for name in FEATURE_NAMES}
                rows.append(
                    {
                        **row,
                        "inner_traffic": f"class{c}",
                        "capture_id": f"c{c}_{capture}",
                        "config_id": f"cfg{capture % 5}",
                        "window_index": window,
                    }
                )
    return pd.DataFrame(rows)


class TestExpectedCalibrationError:
    def test_a_perfectly_calibrated_predictor_scores_zero(self) -> None:
        """Always 100% confident and always right."""
        probabilities = np.array([[1.0, 0.0], [1.0, 0.0], [0.0, 1.0]])
        ece, _bins = expected_calibration_error(probabilities, ["a", "a", "b"], ["a", "b"])
        assert ece == pytest.approx(0.0)

    def test_a_confidently_wrong_predictor_scores_one(self) -> None:
        probabilities = np.array([[1.0, 0.0], [1.0, 0.0]])
        ece, _bins = expected_calibration_error(probabilities, ["b", "b"], ["a", "b"])
        assert ece == pytest.approx(1.0)

    def test_overconfidence_produces_a_positive_gap(self) -> None:
        probabilities = np.array([[0.9, 0.1]] * 10)
        truth = ["a"] * 5 + ["b"] * 5  # 90% confident, 50% accurate
        ece, bins = expected_calibration_error(probabilities, truth, ["a", "b"])
        assert ece == pytest.approx(0.4)
        populated = [b for b in bins if b.count]
        assert populated[0].gap > 0, "overconfidence must read as a positive gap"

    def test_the_diagram_has_the_requested_bin_count(self) -> None:
        probabilities = np.array([[0.7, 0.3]] * 20)
        _ece, bins = expected_calibration_error(
            probabilities, ["a"] * 20, ["a", "b"], bins=DEFAULT_BINS
        )
        assert len(bins) == DEFAULT_BINS

    def test_empty_bins_are_kept_so_diagrams_can_be_compared(self) -> None:
        probabilities = np.array([[0.95, 0.05]] * 5)
        _ece, bins = expected_calibration_error(probabilities, ["a"] * 5, ["a", "b"])
        assert len(bins) == DEFAULT_BINS
        assert sum(1 for b in bins if b.count == 0) == DEFAULT_BINS - 1

    def test_a_confidence_of_exactly_one_lands_in_the_last_bin(self) -> None:
        probabilities = np.array([[1.0, 0.0]])
        _ece, bins = expected_calibration_error(probabilities, ["a"], ["a", "b"])
        assert bins[-1].count == 1

    def test_no_rows_is_zero_error_rather_than_a_crash(self) -> None:
        ece, bins = expected_calibration_error(np.zeros((0, 2)), [], ["a", "b"])
        assert ece == 0.0
        assert bins == []

    def test_mismatched_lengths_are_refused(self) -> None:
        with pytest.raises(CalibrationError, match="probability rows"):
            expected_calibration_error(np.array([[0.5, 0.5]]), ["a", "b"], ["a", "b"])

    def test_a_one_dimensional_input_is_refused(self) -> None:
        with pytest.raises(CalibrationError, match="2-D"):
            expected_calibration_error(np.array([0.5, 0.5]), ["a"], ["a", "b"])


class TestCalibrationImprovesTheModel:
    @staticmethod
    def _run(method: str = "auto"):  # type: ignore[no-untyped-def]
        frame = synthetic()
        train, evaluation = split_by_capture(frame, test_frac=0.25, seed=42)
        return calibrate_classifier(train, evaluation, method=method)

    def test_ece_after_calibration_is_lower_than_before(self) -> None:
        _model, report = self._run()
        assert report.ece_after < report.ece_before, report.summary()
        assert report.improved is True

    def test_calibrated_ece_is_below_the_threshold(self) -> None:
        """The gate: above this the confidence must not be shown to a user."""
        _model, report = self._run()
        assert report.ece_after <= MAX_ACCEPTABLE_ECE
        assert report.is_trustworthy is True

    def test_calibrated_probabilities_sum_to_one(self) -> None:
        model, _report = self._run()
        frame = synthetic()
        probabilities = model.predict_proba(frame[list(FEATURE_NAMES)].to_numpy(dtype=float))
        assert np.allclose(probabilities.sum(axis=1), 1.0)

    def test_calibrated_probabilities_are_in_range(self) -> None:
        model, _report = self._run()
        frame = synthetic()
        probabilities = model.predict_proba(frame[list(FEATURE_NAMES)].to_numpy(dtype=float))
        assert probabilities.min() >= 0.0
        assert probabilities.max() <= 1.0

    def test_the_reliability_diagram_has_the_expected_bin_count(self) -> None:
        _model, report = self._run()
        assert len(report.bins_before) == DEFAULT_BINS
        assert len(report.bins_after) == DEFAULT_BINS
        assert len(reliability_diagram_rows(report)) == DEFAULT_BINS

    def test_the_diagram_rows_carry_the_gap(self) -> None:
        _model, report = self._run()
        rows = reliability_diagram_rows(report)
        assert all(
            {"lower", "upper", "count", "mean_confidence", "accuracy", "gap"} <= set(r)
            for r in rows
        )


class TestMethodSelection:
    def test_the_method_is_chosen_on_a_validation_split(self) -> None:
        """Choosing on the evaluation set would be selection on the test set."""
        frame = synthetic()
        train, evaluation = split_by_capture(frame, test_frac=0.25, seed=42)
        _model, report = calibrate_classifier(train, evaluation, method="auto")
        assert report.method in CALIBRATION_METHODS
        assert "validation split" in report.selection
        for candidate in CALIBRATION_METHODS:
            assert candidate in report.selection, "both candidates must be reported"

    def test_an_explicit_method_is_honoured_and_labelled(self) -> None:
        frame = synthetic()
        train, evaluation = split_by_capture(frame, test_frac=0.25, seed=42)
        _model, report = calibrate_classifier(train, evaluation, method="isotonic")
        assert report.method == "isotonic"
        assert report.selection == "method supplied by the caller"

    def test_an_unknown_method_is_refused(self) -> None:
        frame = synthetic()
        train, evaluation = split_by_capture(frame, test_frac=0.25, seed=42)
        with pytest.raises(CalibrationError, match="unknown calibration method"):
            calibrate_classifier(train, evaluation, method="magic")

    def test_an_empty_evaluation_set_is_refused(self) -> None:
        frame = synthetic()
        with pytest.raises(CalibrationError, match="evaluation set is empty"):
            calibrate_classifier(frame, frame.iloc[0:0])


@pytest.mark.skipif(not REAL.exists(), reason="the ML dataset has not been built")
class TestAgainstTheRealCorpus:
    @staticmethod
    def _run():  # type: ignore[no-untyped-def]
        frame = pd.read_parquet(REAL)
        train, evaluation = split_by_capture(frame, test_frac=0.25, seed=42)
        return calibrate_classifier(train, evaluation)

    def test_calibration_improves_ece_on_real_data(self) -> None:
        _model, report = self._run()
        assert report.ece_after < report.ece_before, report.summary()

    def test_real_calibrated_ece_is_below_the_threshold(self) -> None:
        _model, report = self._run()
        assert report.ece_after <= MAX_ACCEPTABLE_ECE, report.summary()

    def test_isotonic_is_selected_and_the_alternative_is_recorded(self) -> None:
        """The prior said sigmoid; the data said otherwise, and the record says both."""
        _model, report = self._run()
        assert "sigmoid" in report.selection
        assert "isotonic" in report.selection
