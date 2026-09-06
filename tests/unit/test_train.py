"""Tests for traffic classifier training (build plan Step 7.5).

The synthetic convergence test is a check on the pipeline, not a claim about the model.
It proves the plumbing fits together — features in, labels out, folds grouped — on data
constructed to be separable. The number that means anything comes from Step 7.6, on
held-out configurations.
"""

from __future__ import annotations

import json
import warnings
from pathlib import Path

import pandas as pd
import pytest

from ipsec_sentinel.features.flow import FEATURE_NAMES
from ipsec_sentinel.ml.train import (
    MODEL_GRADIENT_BOOSTING,
    MODEL_RANDOM_FOREST,
    SUPPORTED_MODELS,
    TrainingError,
    compare_models,
    cross_validate,
    current_git_sha,
    dataset_checksum,
    load_model,
    predict_with,
    train_and_persist,
)

warnings.filterwarnings("ignore")


def synthetic(classes: int = 3, per_class: int = 40, seed: int = 0) -> pd.DataFrame:
    """A separable dataset: each class sits in its own region of feature space."""
    import numpy as np

    rng = np.random.default_rng(seed)
    rows = []
    for c in range(classes):
        for i in range(per_class):
            row = {name: float(rng.normal(c * 100, 3)) for name in FEATURE_NAMES}
            rows.append(
                {
                    **row,
                    "inner_traffic": f"class{c}",
                    # One capture per two rows, so grouping is meaningful.
                    "capture_id": f"cap{c}_{i // 2}",
                    "config_id": f"cfg{c}",
                }
            )
    return pd.DataFrame(rows)


class TestPipelineConvergence:
    """A sanity check on the plumbing, not a claim about performance."""

    @pytest.mark.parametrize("model", SUPPORTED_MODELS)
    def test_a_separable_synthetic_set_scores_above_ninety_percent(self, model: str) -> None:
        result = cross_validate(synthetic(), model_name=model)
        assert result.accuracy > 0.9, f"{model} scored {result.accuracy:.3f}"
        assert result.macro_f1 > 0.9

    def test_the_result_reports_what_it_measured(self) -> None:
        result = cross_validate(synthetic())
        assert result.rows == 120
        assert result.folds >= 2
        assert "grouped" in result.split_strategy
        assert "capture_id" in result.split_strategy

    def test_per_class_scores_cover_every_class(self) -> None:
        result = cross_validate(synthetic(classes=4))
        assert len(result.per_class) == 4
        assert {c.label for c in result.per_class} == {f"class{i}" for i in range(4)}
        assert sum(c.support for c in result.per_class) == result.rows

    def test_the_confusion_matrix_is_square_and_totals_the_rows(self) -> None:
        result = cross_validate(synthetic(classes=3))
        assert len(result.confusion_matrix) == 3
        assert all(len(row) == 3 for row in result.confusion_matrix)
        assert sum(sum(row) for row in result.confusion_matrix) == result.rows

    def test_both_models_are_compared_on_the_same_folds(self) -> None:
        results = compare_models(synthetic())
        assert set(results) == set(SUPPORTED_MODELS)
        assert {r.rows for r in results.values()} == {120}


class TestRefusals:
    def test_a_single_class_raises_a_clear_error(self) -> None:
        """A model that answers unconditionally and scores 100% is not a result."""
        frame = synthetic(classes=1)
        with pytest.raises(TrainingError, match="at least two"):
            cross_validate(frame)

    def test_an_empty_dataset_raises(self) -> None:
        with pytest.raises(TrainingError, match="empty dataset"):
            cross_validate(pd.DataFrame())

    def test_a_missing_target_column_raises(self) -> None:
        with pytest.raises(TrainingError, match="inner_traffic"):
            cross_validate(synthetic().drop(columns=["inner_traffic"]))

    def test_missing_feature_columns_raise(self) -> None:
        with pytest.raises(TrainingError, match="missing feature columns"):
            cross_validate(synthetic().drop(columns=[FEATURE_NAMES[0]]))

    def test_a_missing_capture_id_raises_rather_than_leaking(self) -> None:
        """Without groups every score would be inflated by sibling windows."""
        with pytest.raises(TrainingError, match="capture_id"):
            cross_validate(synthetic().drop(columns=["capture_id"]))

    def test_an_unknown_model_name_raises(self) -> None:
        with pytest.raises(TrainingError, match="unknown model"):
            cross_validate(synthetic(), model_name="magic")


class TestPersistence:
    @pytest.mark.parametrize("model", SUPPORTED_MODELS)
    def test_a_saved_model_reloads_and_predicts_identically(
        self, model: str, tmp_path: Path
    ) -> None:
        frame = synthetic()
        path = tmp_path / "model.joblib"
        metadata = train_and_persist(frame, path, model_name=model)

        loaded, loaded_metadata = load_model(path)
        assert loaded_metadata.model_name == metadata.model_name

        before = predict_with(loaded, loaded_metadata, frame)
        after = predict_with(*load_model(path), frame)
        assert before == after
        assert len(before) == len(frame)

    def test_the_metadata_records_the_dataset_checksum(self) -> None:
        frame = synthetic()
        assert dataset_checksum(frame) == dataset_checksum(frame.copy())
        assert dataset_checksum(frame) != dataset_checksum(synthetic(seed=1))

    def test_the_checksum_identifies_the_data_not_the_row_order(self) -> None:
        """Two builds of the same corpus must agree even if the rows are ordered differently."""
        frame = synthetic()
        shuffled = frame.sample(frac=1.0, random_state=7).reset_index(drop=True)
        assert dataset_checksum(frame) == dataset_checksum(shuffled)

    def test_the_metadata_is_written_beside_the_model(self, tmp_path: Path) -> None:
        path = tmp_path / "model.joblib"
        metadata = train_and_persist(synthetic(), path)
        sidecar = path.with_suffix(".metadata.json")
        assert sidecar.exists()
        written = json.loads(sidecar.read_text())
        assert written["dataset_checksum"] == metadata.dataset_checksum
        assert written["feature_names"] == list(FEATURE_NAMES)
        assert written["dataset_rows"] == 120

    def test_the_metadata_records_the_commit_it_was_trained_at(self, tmp_path: Path) -> None:
        """A model whose provenance is unknown cannot be defended."""
        metadata = train_and_persist(synthetic(), tmp_path / "m.joblib")
        assert metadata.git_sha
        assert metadata.trained_at

    def test_current_git_sha_never_raises(self) -> None:
        assert isinstance(current_git_sha(), str)

    def test_predicting_with_missing_features_is_refused(self, tmp_path: Path) -> None:
        """Fed the wrong columns a model predicts confidently and wrongly."""
        path = tmp_path / "model.joblib"
        train_and_persist(synthetic(), path)
        model, metadata = load_model(path)
        with pytest.raises(TrainingError, match="missing features"):
            predict_with(model, metadata, synthetic().drop(columns=[FEATURE_NAMES[3]]))


REAL = Path("data/processed/ml_dataset.parquet")


@pytest.mark.skipif(not REAL.exists(), reason="the ML dataset has not been built")
class TestAgainstTheRealCorpus:
    def test_both_models_beat_the_recorded_baselines(self) -> None:
        """The bar was fixed in docs/BASELINES.md before either model was trained."""
        frame = pd.read_parquet(REAL)
        for model in SUPPORTED_MODELS:
            result = cross_validate(frame, model_name=model)
            assert result.accuracy > 0.246, f"{model} did not beat the depth-1 tree"
            assert result.macro_f1 > 0.129

    def test_the_folds_are_grouped_by_capture(self) -> None:
        frame = pd.read_parquet(REAL)
        result = cross_validate(frame, model_name=MODEL_RANDOM_FOREST)
        assert result.groups == frame["capture_id"].nunique()

    def test_every_traffic_class_is_scored(self) -> None:
        frame = pd.read_parquet(REAL)
        result = cross_validate(frame, model_name=MODEL_GRADIENT_BOOSTING)
        assert len(result.per_class) == 7
