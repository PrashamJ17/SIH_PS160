"""Tests for SHAP explanations (build plan Step 7.9).

An unexplained classification is an assertion. In a security report it is worse: an
analyst who cannot see the reasoning has no basis for overruling the tool when it is
wrong.
"""

from __future__ import annotations

import re
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from ipsec_sentinel.features.flow import FEATURE_NAMES
from ipsec_sentinel.ml.explain import (
    EXPLANATION_BUDGET_S,
    FEATURE_PHRASES,
    TOP_FEATURES,
    ExplanationError,
    explain_prediction,
)
from ipsec_sentinel.ml.split import split_by_capture
from ipsec_sentinel.ml.train import _build_model

warnings.filterwarnings("ignore")

REAL = Path("data/processed/ml_dataset.parquet")


def synthetic(classes: int = 3, captures: int = 25, seed: int = 0) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    rows = []
    for c in range(classes):
        for capture in range(captures):
            for _window in range(2):
                row = {name: float(rng.normal(c * 20, 8)) for name in FEATURE_NAMES}
                rows.append(
                    {
                        **row,
                        "inner_traffic": f"class{c}",
                        "capture_id": f"c{c}_{capture}",
                        "config_id": f"cfg{capture % 4}",
                    }
                )
    return pd.DataFrame(rows)


def fitted(frame: pd.DataFrame):  # type: ignore[no-untyped-def]
    labels = sorted(frame["inner_traffic"].astype(str).unique().tolist())
    model = _build_model("random_forest", 42, len(labels))
    model.fit(
        frame[list(FEATURE_NAMES)].to_numpy(dtype=float),
        frame["inner_traffic"].astype(str).to_numpy(),
    )
    return model, labels


class TestExplanationShape:
    def test_it_returns_exactly_five_features(self) -> None:
        frame = synthetic()
        model, labels = fitted(frame)
        explanation = explain_prediction(model, frame.iloc[[0]], labels, list(FEATURE_NAMES))
        assert len(explanation.contributions) == TOP_FEATURES

    def test_the_top_count_is_configurable(self) -> None:
        frame = synthetic()
        model, labels = fitted(frame)
        explanation = explain_prediction(model, frame.iloc[[0]], labels, list(FEATURE_NAMES), top=3)
        assert len(explanation.contributions) == 3

    def test_the_top_features_are_the_largest_by_absolute_contribution(self) -> None:
        frame = synthetic()
        model, labels = fitted(frame)
        explanation = explain_prediction(model, frame.iloc[[0]], labels, list(FEATURE_NAMES))
        magnitudes = [abs(c.contribution) for c in explanation.contributions]
        assert magnitudes == sorted(magnitudes, reverse=True)
        largest = sorted((abs(v) for v in explanation.all_contributions.values()), reverse=True)[
            :TOP_FEATURES
        ]
        assert magnitudes == pytest.approx(largest)

    def test_every_feature_is_attributed(self) -> None:
        frame = synthetic()
        model, labels = fitted(frame)
        explanation = explain_prediction(model, frame.iloc[[0]], labels, list(FEATURE_NAMES))
        assert set(explanation.all_contributions) == set(FEATURE_NAMES)


class TestAdditivity:
    def test_contributions_sum_to_the_prediction_minus_the_base_value(self) -> None:
        """The property that makes SHAP auditable rather than decorative."""
        frame = synthetic()
        model, labels = fitted(frame)
        explanation = explain_prediction(model, frame.iloc[[0]], labels, list(FEATURE_NAMES))
        assert explanation.is_additive(), (
            f"base {explanation.base_value} + contributions "
            f"{explanation.total_contribution} != {explanation.prediction_value}"
        )

    def test_additivity_holds_across_many_rows(self) -> None:
        frame = synthetic()
        model, labels = fitted(frame)
        for i in range(0, len(frame), 17):
            explanation = explain_prediction(model, frame.iloc[[i]], labels, list(FEATURE_NAMES))
            assert explanation.is_additive(), f"row {i}"

    def test_a_broken_sum_is_detected(self) -> None:
        """The check must be able to fail, or asserting it proves nothing."""
        from ipsec_sentinel.ml.explain import Explanation

        broken = Explanation(
            predicted_class="x",
            base_value=0.2,
            prediction_value=0.9,
            all_contributions={"a": 0.1},
        )
        assert broken.is_additive() is False


class TestReadableSentence:
    @staticmethod
    def _sentence() -> str:
        frame = synthetic()
        model, labels = fitted(frame)
        return explain_prediction(model, frame.iloc[[0]], labels, list(FEATURE_NAMES)).sentence()

    def test_it_names_the_predicted_class(self) -> None:
        assert self._sentence().startswith("Classified as ")

    def test_it_contains_no_raw_feature_identifiers(self) -> None:
        """`fwd_bwd_byte_ratio` means nothing to the operator who has to act on it."""
        sentence = self._sentence()
        for name in FEATURE_NAMES:
            assert name not in sentence, f"raw identifier {name!r} leaked into the sentence"

    def test_it_contains_real_english_phrases(self) -> None:
        sentence = self._sentence()
        assert any(phrase in sentence for phrase in FEATURE_PHRASES.values())

    def test_it_quotes_signed_contributions(self) -> None:
        assert re.search(r"contribution [+-]\d", self._sentence())

    def test_it_ends_as_a_sentence(self) -> None:
        assert self._sentence().endswith(".")

    def test_every_feature_has_a_phrase(self) -> None:
        missing = [name for name in FEATURE_NAMES if name not in FEATURE_PHRASES]
        assert not missing, f"features without a readable phrase: {missing}"

    def test_no_phrase_is_clause_shaped(self) -> None:
        """Rendered as "<phrase> was <value>", a clause produces "... was was 0.0009"."""
        offenders = [
            name
            for name, phrase in FEATURE_PHRASES.items()
            if phrase.endswith((" was", " were", " varied"))
        ]
        assert not offenders, offenders

    def test_a_negative_zero_renders_as_zero(self) -> None:
        from ipsec_sentinel.ml.explain import FeatureContribution

        rendered = FeatureContribution("size_entropy", -0.0, 0.09).render()
        assert "-0" not in rendered


class TestPerformance:
    def test_an_explanation_takes_under_two_seconds(self) -> None:
        """The plan's budget. A report explains one finding per tunnel."""
        frame = synthetic()
        model, labels = fitted(frame)
        explanation = explain_prediction(model, frame.iloc[[0]], labels, list(FEATURE_NAMES))
        assert explanation.elapsed_s < EXPLANATION_BUDGET_S, explanation.elapsed_s

    def test_repeated_explanations_stay_within_budget(self) -> None:
        frame = synthetic()
        model, labels = fitted(frame)
        for i in range(10):
            explanation = explain_prediction(model, frame.iloc[[i]], labels, list(FEATURE_NAMES))
            assert explanation.elapsed_s < EXPLANATION_BUDGET_S


class TestRefusals:
    def test_explaining_more_than_one_row_is_refused(self) -> None:
        """Returning the first would attribute one flow's reasoning to another."""
        frame = synthetic()
        model, labels = fitted(frame)
        with pytest.raises(ExplanationError, match="exactly one row"):
            explain_prediction(model, frame.iloc[0:3], labels, list(FEATURE_NAMES))

    def test_missing_features_are_refused(self) -> None:
        frame = synthetic()
        model, labels = fitted(frame)
        with pytest.raises(ExplanationError, match="missing features"):
            explain_prediction(
                model,
                frame.iloc[[0]].drop(columns=[FEATURE_NAMES[0]]),
                labels,
                list(FEATURE_NAMES),
            )


@pytest.mark.skipif(not REAL.exists(), reason="the ML dataset has not been built")
class TestAgainstTheRealCorpus:
    @staticmethod
    def _setup():  # type: ignore[no-untyped-def]
        from ipsec_sentinel.ml.calibrate import calibrate_classifier

        data = pd.read_parquet(REAL)
        train, evaluation = split_by_capture(data, test_frac=0.25, seed=42)
        model, _report = calibrate_classifier(train, evaluation)
        classes = sorted(train["inner_traffic"].dropna().astype(str).unique().tolist())
        return model, evaluation, classes

    def test_a_calibrated_model_can_be_explained(self) -> None:
        """The wrapper must be unwrapped to the ensemble SHAP can actually read."""
        model, evaluation, classes = self._setup()
        explanation = explain_prediction(model, evaluation.iloc[[0]], classes, list(FEATURE_NAMES))
        assert explanation.is_additive()
        assert explanation.predicted_class in classes

    def test_real_explanations_read_as_sentences(self) -> None:
        model, evaluation, classes = self._setup()
        for i in (0, 10, 50):
            sentence = explain_prediction(
                model, evaluation.iloc[[i]], classes, list(FEATURE_NAMES)
            ).sentence()
            assert " was was " not in sentence
            assert sentence.count(".") >= 1
            for name in FEATURE_NAMES:
                assert name not in sentence
