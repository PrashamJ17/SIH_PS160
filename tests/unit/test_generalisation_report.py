"""Tests for the generalisation report (build plan Step 7.6, uncuttable).

The test that matters most is `test_the_document_is_written_even_when_the_result_is_bad`.
A generalisation report that only appears when the numbers are flattering is not a
generalisation report — it is a marketing artifact with a scientific shape.
"""

from __future__ import annotations

import json
import warnings
from pathlib import Path

import pandas as pd
import pytest

from ipsec_sentinel.features.flow import FEATURE_NAMES
from ipsec_sentinel.ml.train import EvaluationResult
from scripts.generalisation_report import (
    SPLIT_CAPTURE,
    SPLIT_CONFIG,
    SPLIT_DH,
    SPLIT_ORDER,
    SPLIT_RANDOM,
    run_all_splits,
    write_report,
)

warnings.filterwarnings("ignore")


def corpus(classes: int = 3, configs: int = 5, seed: int = 0, separable: bool = True):  # type: ignore[no-untyped-def]
    """A small corpus with the grouping structure the real one has."""
    import numpy as np

    rng = np.random.default_rng(seed)
    groups = ["A", "B", "C", "D"]
    rows = []
    for c in range(classes):
        for capture in range(12):
            for window in range(2):
                centre = c * 100 if separable else 0
                row = {name: float(rng.normal(centre, 5)) for name in FEATURE_NAMES}
                rows.append(
                    {
                        **row,
                        "inner_traffic": f"class{c}",
                        "capture_id": f"c{c}_{capture}",
                        "config_id": f"cfg{(c * 12 + capture) % configs}",
                        "dh_group": groups[capture % len(groups)],
                        "window_index": window,
                    }
                )
    return pd.DataFrame(rows)


class TestAllFourSplits:
    def test_the_report_generates_all_four_splits(self) -> None:
        results = run_all_splits(corpus())
        assert set(results) == set(SPLIT_ORDER)

    def test_each_split_reports_accuracy_and_macro_f1(self) -> None:
        for result in run_all_splits(corpus()).values():
            assert 0.0 <= result.accuracy <= 1.0
            assert 0.0 <= result.macro_f1 <= 1.0

    def test_each_split_includes_a_confusion_matrix(self) -> None:
        """The plan's explicit criterion."""
        for name, result in run_all_splits(corpus()).items():
            assert result.confusion_matrix, f"{name} has no confusion matrix"
            size = len(result.labels)
            assert len(result.confusion_matrix) == size
            assert all(len(row) == size for row in result.confusion_matrix)
            assert sum(sum(row) for row in result.confusion_matrix) == result.rows

    def test_each_split_includes_per_class_scores(self) -> None:
        for result in run_all_splits(corpus()).values():
            assert len(result.per_class) == len(result.labels)

    def test_the_split_strategy_is_recorded_on_each_result(self) -> None:
        results = run_all_splits(corpus())
        assert "leaky" in results[SPLIT_RANDOM].split_strategy
        assert "configurations" in results[SPLIT_CONFIG].split_strategy
        assert "DH groups" in results[SPLIT_DH].split_strategy

    def test_the_capture_split_does_not_leak(self) -> None:
        from ipsec_sentinel.ml.split import assert_no_overlap, split_by_capture

        train, test = split_by_capture(corpus())
        assert_no_overlap(train, test)


class TestTheDocumentIsAlwaysWritten:
    def test_the_document_is_written_even_when_the_result_is_bad(self, tmp_path: Path) -> None:
        """No silent suppression of an unflattering result."""
        unlearnable = corpus(separable=False)
        results = run_all_splits(unlearnable)
        accuracies = [r.accuracy for r in results.values()]
        assert max(accuracies) < 0.7, "this corpus was meant to be unlearnable"

        output = tmp_path / "GENERALISATION.md"
        written = write_report(results, unlearnable, output, json_output=tmp_path / "r.json")
        assert written.exists()
        text = written.read_text()
        for name in SPLIT_ORDER:
            assert name.split(" (")[0] in text

    def test_a_poor_number_appears_in_the_document_verbatim(self, tmp_path: Path) -> None:
        unlearnable = corpus(separable=False)
        results = run_all_splits(unlearnable)
        write_report(results, unlearnable, tmp_path / "g.md", json_output=None)
        text = (tmp_path / "g.md").read_text()
        expected = f"{results[SPLIT_CAPTURE].accuracy:.1%}"
        assert expected in text, "the measured accuracy must appear as measured"

    def test_the_json_sidecar_is_written(self, tmp_path: Path) -> None:
        frame = corpus()
        results = run_all_splits(frame)
        write_report(results, frame, tmp_path / "g.md", json_output=tmp_path / "g.json")
        payload = json.loads((tmp_path / "g.json").read_text())
        assert set(payload) == set(SPLIT_ORDER)
        assert "confusion_matrix" in payload[SPLIT_CAPTURE]


class TestDocumentContent:
    @staticmethod
    def _document(tmp_path: Path) -> str:
        frame = corpus()
        results = run_all_splits(frame)
        write_report(results, frame, tmp_path / "g.md", json_output=None)
        return (tmp_path / "g.md").read_text()

    def test_it_states_that_it_is_written_regardless_of_the_numbers(self, tmp_path: Path) -> None:
        assert "whatever the numbers are" in self._document(tmp_path)

    def test_it_labels_the_random_split_as_leaky(self, tmp_path: Path) -> None:
        text = self._document(tmp_path)
        assert "leaky" in text
        assert "never to be quoted alone" in text

    def test_it_reports_windows_per_capture(self, tmp_path: Path) -> None:
        """It bounds how much a leaking split could inflate the score."""
        assert "windows per capture" in self._document(tmp_path)

    def test_it_warns_that_a_small_leak_gap_has_little_power(self, tmp_path: Path) -> None:
        """The most tempting over-claim in the whole report."""
        text = self._document(tmp_path)
        assert "not evidence that leakage is harmless" in text

    def test_it_lists_its_limitations(self, tmp_path: Path) -> None:
        text = self._document(tmp_path)
        assert "## Limitations" in text
        assert "upper bound" in text

    def test_it_names_the_configuration_split_as_the_deployable_number(
        self, tmp_path: Path
    ) -> None:
        assert "Closest to what a deployed analyser faces" in self._document(tmp_path)


REAL_DOC = Path("docs/GENERALISATION.md")


@pytest.mark.skipif(not REAL_DOC.exists(), reason="the report has not been generated")
class TestTheCommittedReport:
    def test_it_contains_all_four_splits(self) -> None:
        text = REAL_DOC.read_text()
        for name in SPLIT_ORDER:
            assert name.split(" (")[0] in text

    def test_it_contains_a_confusion_matrix_per_split(self) -> None:
        assert REAL_DOC.read_text().count("actual \\ predicted") == len(SPLIT_ORDER)

    def test_it_records_the_tunnel_mode_limitation(self) -> None:
        assert "tunnel mode" in REAL_DOC.read_text()


class TestEvaluationShape:
    def test_a_class_absent_from_training_is_kept_in_the_report(self) -> None:
        """Dropping it would turn a real failure into a clean-looking score."""
        from ipsec_sentinel.ml.train import evaluate_holdout

        frame = corpus(classes=3)
        train = frame[frame["inner_traffic"] != "class2"]
        test = frame[frame["inner_traffic"] == "class2"]
        result: EvaluationResult = evaluate_holdout(train, test)
        assert "class2" in result.labels
        assert result.accuracy == 0.0, "an unseen class cannot be predicted"
