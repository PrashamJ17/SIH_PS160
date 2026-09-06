"""Tests for leakage-free splitting (build plan Step 7.3).

`test_no_capture_id_appears_in_both_sides` is the critical assertion in this project's
ML work. Windows from one capture are near-duplicates; a random split scatters siblings
across both sides and the resulting accuracy measures memorisation. It is the easiest
way to produce a fraudulent-looking result without intending to.
"""

from __future__ import annotations

import pandas as pd
import pytest

from ipsec_sentinel.ml.split import (
    SplitError,
    assert_no_overlap,
    describe_split,
    split_by_capture,
    split_by_config,
    split_by_dh_group,
)


def frame(
    captures: int = 20, configs: int = 4, windows: int = 3, groups: tuple[str, ...] = ("A", "B")
) -> pd.DataFrame:
    rows = []
    for c in range(captures):
        for w in range(windows):
            rows.append(
                {
                    "capture_id": f"cap{c:03d}",
                    "config_id": f"cfg{c % configs}",
                    "dh_group": groups[c % len(groups)],
                    "window_index": w,
                    "feature": float(c * 10 + w),
                    "inner_traffic": ("web", "voip", "video")[c % 3],
                }
            )
    return pd.DataFrame(rows)


class TestTheCriticalAssertion:
    def test_no_capture_id_appears_in_both_sides(self) -> None:
        """The assertion the credibility of every accuracy figure rests on."""
        train, test = split_by_capture(frame())
        assert set(train["capture_id"]) & set(test["capture_id"]) == set()

    def test_the_overlap_is_zero_across_many_seeds(self) -> None:
        for seed in range(25):
            train, test = split_by_capture(frame(), seed=seed)
            assert not set(train["capture_id"]) & set(test["capture_id"]), seed

    def test_every_row_lands_on_exactly_one_side(self) -> None:
        source = frame()
        train, test = split_by_capture(source)
        assert len(train) + len(test) == len(source)

    def test_assert_no_overlap_catches_a_leak(self) -> None:
        """The helper must be able to fail, or checking with it proves nothing."""
        source = frame()
        with pytest.raises(SplitError, match="both train and test"):
            assert_no_overlap(source, source)

    def test_assert_no_overlap_passes_a_clean_split(self) -> None:
        train, test = split_by_capture(frame())
        assert_no_overlap(train, test)


class TestCaptureSplit:
    def test_both_sides_are_non_empty(self) -> None:
        train, test = split_by_capture(frame())
        assert len(train) > 0
        assert len(test) > 0

    def test_it_is_reproducible_with_a_fixed_seed(self) -> None:
        """Two runs that disagree are two different experiments."""
        first = split_by_capture(frame(), seed=7)[1]["capture_id"].tolist()
        second = split_by_capture(frame(), seed=7)[1]["capture_id"].tolist()
        assert first == second

    def test_a_different_seed_gives_a_different_split(self) -> None:
        a = set(split_by_capture(frame(), seed=1)[1]["capture_id"])
        b = set(split_by_capture(frame(), seed=2)[1]["capture_id"])
        assert a != b

    def test_the_test_fraction_is_approximately_honoured(self) -> None:
        _train, test = split_by_capture(frame(captures=100), test_frac=0.25)
        share = test["capture_id"].nunique() / 100
        assert 0.2 <= share <= 0.3

    def test_windows_of_one_capture_stay_together(self) -> None:
        """The whole point: siblings must not be separated."""
        train, test = split_by_capture(frame(windows=5))
        for side in (train, test):
            for capture, group in side.groupby("capture_id"):
                assert len(group) == 5, f"{capture} was split across sides"

    def test_an_empty_dataset_is_refused(self) -> None:
        with pytest.raises(SplitError, match="empty dataset"):
            split_by_capture(pd.DataFrame())

    def test_a_single_capture_is_refused(self) -> None:
        """One group cannot be split without leaving a side empty."""
        with pytest.raises(SplitError, match="at least two"):
            split_by_capture(frame(captures=1))

    def test_a_missing_grouping_column_is_refused(self) -> None:
        with pytest.raises(SplitError, match="capture_id"):
            split_by_capture(frame().drop(columns=["capture_id"]))

    @pytest.mark.parametrize("fraction", [0.0, 1.0, -0.1, 1.5])
    def test_an_impossible_test_fraction_is_refused(self, fraction: float) -> None:
        with pytest.raises(SplitError, match="between 0 and 1"):
            split_by_capture(frame(), test_frac=fraction)


class TestConfigSplit:
    def test_held_out_configs_appear_only_in_test(self) -> None:
        train, test = split_by_config(frame(), ["cfg0", "cfg1"])
        assert set(test["config_id"]) == {"cfg0", "cfg1"}
        assert not set(train["config_id"]) & {"cfg0", "cfg1"}

    def test_both_sides_are_non_empty(self) -> None:
        train, test = split_by_config(frame(), ["cfg0"])
        assert len(train) > 0 and len(test) > 0

    def test_holding_out_everything_is_refused(self) -> None:
        with pytest.raises(SplitError, match="empty side"):
            split_by_config(frame(configs=2), ["cfg0", "cfg1"])

    def test_holding_out_nothing_is_refused(self) -> None:
        with pytest.raises(SplitError, match="not a split"):
            split_by_config(frame(), [])

    def test_holding_out_an_absent_config_is_refused(self) -> None:
        """Otherwise it silently produces a train-only split with an empty test side."""
        with pytest.raises(SplitError, match="not in the dataset"):
            split_by_config(frame(), ["cfg-does-not-exist"])

    def test_capture_ids_also_do_not_overlap(self) -> None:
        """A config split implies a capture split; if it did not, it would leak."""
        train, test = split_by_config(frame(), ["cfg0"])
        assert_no_overlap(train, test)


class TestDHGroupSplit:
    def test_test_contains_only_the_specified_groups(self) -> None:
        train, test = split_by_dh_group(frame(groups=("A", "B", "C")), ["A"], ["B", "C"])
        assert set(test["dh_group"]) == {"B", "C"}
        assert set(train["dh_group"]) == {"A"}

    def test_overlapping_groups_are_refused(self) -> None:
        """The leak this split exists to prevent."""
        with pytest.raises(SplitError, match="both sides"):
            split_by_dh_group(frame(groups=("A", "B")), ["A", "B"], ["B"])

    def test_an_absent_group_is_refused(self) -> None:
        with pytest.raises(SplitError, match="not present"):
            split_by_dh_group(frame(groups=("A", "B")), ["A"], ["Z"])

    def test_an_empty_side_is_refused(self) -> None:
        with pytest.raises(SplitError, match="at least one group"):
            split_by_dh_group(frame(), ["A"], [])

    def test_both_sides_are_non_empty(self) -> None:
        train, test = split_by_dh_group(frame(groups=("A", "B")), ["A"], ["B"])
        assert len(train) > 0 and len(test) > 0


class TestSplitReport:
    def test_it_measures_the_overlap_it_claims_to_prevent(self) -> None:
        train, test = split_by_capture(frame())
        report = describe_split(train, test, "capture_id", "by capture")
        assert report.overlap == 0
        assert report.is_leak_free is True

    def test_it_detects_an_overlap_when_there_is_one(self) -> None:
        source = frame()
        report = describe_split(source, source, "capture_id", "deliberately leaking")
        assert report.overlap > 0
        assert report.is_leak_free is False

    def test_the_description_states_the_numbers(self) -> None:
        train, test = split_by_capture(frame())
        text = describe_split(train, test, "capture_id", "by capture").describe()
        assert "train" in text and "test" in text and "overlap 0" in text


class TestAgainstTheRealDataset:
    @staticmethod
    def _dataset() -> pd.DataFrame | None:
        from pathlib import Path

        path = Path("data/processed/ml_dataset.parquet")
        return pd.read_parquet(path) if path.exists() else None

    def test_the_real_dataset_splits_without_leaking(self) -> None:
        data = self._dataset()
        if data is None:
            pytest.skip("the ML dataset has not been built")
        train, test = split_by_capture(data)
        assert_no_overlap(train, test)
        assert len(train) > len(test)

    def test_a_real_config_holdout_does_not_leak_captures(self) -> None:
        data = self._dataset()
        if data is None:
            pytest.skip("the ML dataset has not been built")
        holdout = sorted(data["config_id"].unique())[:5]
        train, test = split_by_config(data, holdout)
        assert_no_overlap(train, test)
        assert set(test["config_id"]) == set(holdout)
