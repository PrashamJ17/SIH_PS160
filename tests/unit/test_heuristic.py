"""Tests for the mode-inference heuristic baseline (build plan Step 7.4)."""

from __future__ import annotations

from pathlib import Path

import pytest

from ipsec_sentinel.ml.heuristic import (
    MODE_TRANSPORT,
    MODE_TUNNEL,
    MODE_UNKNOWN,
    estimate_mode,
    expected_floor,
    heuristic_accuracy,
    infer_mode_heuristic,
)


def features(size_min: float, packet_count: float = 50.0) -> dict[str, float]:
    return {"packet_count": packet_count, "size_min": size_min}


class TestSyntheticModes:
    def test_tunnel_mode_sizes_are_called_tunnel(self) -> None:
        mode, confidence = infer_mode_heuristic(features(expected_floor(MODE_TUNNEL)))
        assert mode == MODE_TUNNEL
        assert confidence > 0.5

    def test_transport_mode_sizes_are_called_transport(self) -> None:
        mode, confidence = infer_mode_heuristic(features(expected_floor(MODE_TRANSPORT)))
        assert mode == MODE_TRANSPORT
        assert confidence > 0.5

    def test_ipv6_floors_are_forty_bytes_apart(self) -> None:
        assert (
            expected_floor(MODE_TUNNEL, ipv6=True) - expected_floor(MODE_TRANSPORT, ipv6=True) == 40
        )

    def test_ipv4_floors_are_twenty_bytes_apart(self) -> None:
        assert expected_floor(MODE_TUNNEL) - expected_floor(MODE_TRANSPORT) == 20

    def test_the_ipv6_variant_is_used_when_asked(self) -> None:
        mode, _ = infer_mode_heuristic(features(expected_floor(MODE_TUNNEL, ipv6=True)), ipv6=True)
        assert mode == MODE_TUNNEL


class TestAmbiguityAndAbstention:
    def test_a_size_between_the_floors_gives_low_confidence(self) -> None:
        midpoint = (expected_floor(MODE_TUNNEL) + expected_floor(MODE_TRANSPORT)) / 2
        _mode, confidence = infer_mode_heuristic(features(midpoint))
        assert confidence <= 0.55

    def test_a_size_far_from_both_floors_abstains(self) -> None:
        """Guessing here would inflate coverage and void every later comparison."""
        mode, confidence = infer_mode_heuristic(features(900.0))
        assert mode == MODE_UNKNOWN
        assert confidence == 0.0

    def test_an_empty_flow_abstains(self) -> None:
        assert infer_mode_heuristic(features(0.0, packet_count=0.0))[0] == MODE_UNKNOWN

    def test_the_rationale_explains_an_abstention(self) -> None:
        estimate = estimate_mode(features(900.0))
        assert "bare acknowledgement" in estimate.rationale

    def test_confidence_is_capped_below_certainty(self) -> None:
        """A 20-byte offset under padding is never conclusive."""
        for size in (82.0, 102.0, 90.0):
            assert infer_mode_heuristic(features(size))[1] <= 0.75


class TestAccuracyReporting:
    def test_coverage_and_accuracy_are_reported_separately(self) -> None:
        """A baseline abstaining on most rows is not a highly accurate baseline."""
        rows = [
            (features(expected_floor(MODE_TUNNEL)), MODE_TUNNEL),
            (features(900.0), MODE_TUNNEL),
        ]
        result = heuristic_accuracy(rows)
        assert result["coverage"] == 0.5
        assert result["accuracy"] == 1.0

    def test_an_empty_input_reports_zeros(self) -> None:
        assert heuristic_accuracy([])["accuracy"] == 0.0

    def test_a_wrong_answer_lowers_accuracy_not_coverage(self) -> None:
        rows = [(features(expected_floor(MODE_TRANSPORT)), MODE_TUNNEL)]
        result = heuristic_accuracy(rows)
        assert result["coverage"] == 1.0
        assert result["accuracy"] == 0.0


class TestDocumentedBaseline:
    """The measured numbers must stay in step with what docs/BASELINES.md claims."""

    DOC = Path("docs/BASELINES.md")

    def test_the_baseline_document_exists(self) -> None:
        assert self.DOC.exists()

    def test_it_records_coverage_and_accuracy(self) -> None:
        text = self.DOC.read_text()
        assert "70.7%" in text
        assert "95.1%" in text

    def test_it_states_that_the_corpus_has_only_one_mode(self) -> None:
        """Without this, the 95.1% reads as skill. It is not."""
        text = self.DOC.read_text()
        assert "exactly one mode" in text
        assert "not evidence of skill" in text.lower()

    def test_it_forbids_claiming_a_win_on_this_corpus(self) -> None:
        assert "No model may claim to beat this baseline" in self.DOC.read_text()

    @pytest.mark.skipif(
        not Path("data/processed/ml_dataset.parquet").exists(),
        reason="the ML dataset has not been built",
    )
    def test_the_measured_numbers_still_match_the_document(self) -> None:
        """If the corpus changes, the document must be updated rather than drift."""
        import pandas as pd

        from ipsec_sentinel.features.flow import FEATURE_NAMES

        frame = pd.read_parquet("data/processed/ml_dataset.parquet")
        rows = [(row[list(FEATURE_NAMES)].to_dict(), row["mode"]) for _, row in frame.iterrows()]
        result = heuristic_accuracy(rows)
        assert result["coverage"] == pytest.approx(0.707, abs=0.02)
        assert result["accuracy"] == pytest.approx(0.951, abs=0.02)

    @pytest.mark.skipif(
        not Path("data/processed/ml_dataset.parquet").exists(),
        reason="the ML dataset has not been built",
    )
    def test_the_corpus_really_does_contain_only_tunnel_mode(self) -> None:
        import pandas as pd

        frame = pd.read_parquet("data/processed/ml_dataset.parquet")
        assert set(frame["mode"].unique()) == {"tunnel"}
