"""Leakage-free dataset splitting.

This is the step that decides whether every accuracy figure in this project is worth
reading, and it is worth being blunt about why.

Windows cut from one capture are near-duplicates of each other. They share a tunnel, a
configuration, a generator, a five-minute slice of the same TCP session — often the same
packets in adjacent windows. A random ``train_test_split`` scatters those siblings
across both sides, so the model is scored on windows whose near-twins it memorised. The
number that comes out is high, stable, reproducible, and measures nothing. It is the
single easiest way to produce a fraudulent-looking result without intending to, and it
is why the first function here splits on ``capture_id`` and the tests assert **zero
overlap** rather than merely checking the split ran.

Three splits, answering three different questions:

* :func:`split_by_capture` — *can it generalise to a new recording of a configuration
  it has seen?* The honest baseline. Still optimistic, because the test captures share
  configurations with training.
* :func:`split_by_config` — *can it generalise to a configuration it has never seen?*
  Much harder, and the number that belongs in a report, because a deployed analyser
  meets configurations that were not in anyone's training set.
* :func:`split_by_dh_group` — *did it learn traffic shape, or did it learn the cipher?*
  Train on some Diffie-Hellman groups and test on others. If accuracy collapses, the
  model was reading a crypto artifact rather than the traffic, which is the confound
  the whole corpus design exists to expose.

Every split refuses rather than returns a degenerate result. An empty side is not a
split; it is a mistake that would otherwise surface as a suspiciously perfect score.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    import pandas as pd

DEFAULT_SEED = 42
DEFAULT_TEST_FRACTION = 0.2


class SplitError(ValueError):
    """A split could not be made without producing an empty or leaking side."""


@dataclass(frozen=True)
class SplitReport:
    """What a split actually did, so a report can state it rather than assert it."""

    strategy: str
    train_rows: int
    test_rows: int
    train_groups: int
    test_groups: int
    grouping_column: str
    overlap: int = 0

    @property
    def is_leak_free(self) -> bool:
        return self.overlap == 0

    def describe(self) -> str:
        return (
            f"{self.strategy}: {self.train_rows} train / {self.test_rows} test rows, "
            f"{self.train_groups} / {self.test_groups} distinct {self.grouping_column}, "
            f"overlap {self.overlap}"
        )


def _require_non_empty(train: pd.DataFrame, test: pd.DataFrame, strategy: str) -> None:
    if train.empty or test.empty:
        raise SplitError(
            f"{strategy} produced an empty side ({len(train)} train, {len(test)} test). "
            f"An empty side is not a split — it would surface later as an implausibly "
            f"high score with nothing to attribute it to."
        )


def describe_split(
    train: pd.DataFrame, test: pd.DataFrame, column: str, strategy: str
) -> SplitReport:
    """Measure a split, including the overlap it is supposed not to have."""
    train_groups = set(train[column].unique()) if not train.empty else set()
    test_groups = set(test[column].unique()) if not test.empty else set()
    return SplitReport(
        strategy=strategy,
        train_rows=len(train),
        test_rows=len(test),
        train_groups=len(train_groups),
        test_groups=len(test_groups),
        grouping_column=column,
        overlap=len(train_groups & test_groups),
    )


def split_by_capture(
    frame: pd.DataFrame,
    test_frac: float = DEFAULT_TEST_FRACTION,
    seed: int = DEFAULT_SEED,
    column: str = "capture_id",
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Split so that no capture appears on both sides.

    Grouped rather than stratified: stratifying by label would balance the classes and
    reintroduce the leak, because the same capture supplies rows for its own label on
    both sides. Class balance is the lesser problem; a leaking split is fatal.

    The seed is fixed so a reported number can be reproduced exactly. Two runs that
    disagree are two different experiments.
    """
    import numpy as np

    if frame.empty:
        raise SplitError("cannot split an empty dataset")
    if column not in frame.columns:
        raise SplitError(f"the dataset has no {column!r} column to group on")
    if not 0.0 < test_frac < 1.0:
        raise SplitError(f"test_frac must be between 0 and 1, got {test_frac}")

    groups = sorted(frame[column].astype(str).unique())
    if len(groups) < 2:
        raise SplitError(
            f"only {len(groups)} distinct {column} in the dataset; a grouped split "
            f"needs at least two, or one side is necessarily empty"
        )

    rng = np.random.default_rng(seed)
    shuffled = list(groups)
    rng.shuffle(shuffled)
    test_count = max(1, min(len(shuffled) - 1, round(len(shuffled) * test_frac)))
    test_groups = set(shuffled[:test_count])

    mask = frame[column].astype(str).isin(test_groups)
    train, test = frame[~mask].copy(), frame[mask].copy()
    _require_non_empty(train, test, f"split_by_capture(seed={seed})")
    return train, test


def split_randomly(
    frame: pd.DataFrame,
    test_frac: float = DEFAULT_TEST_FRACTION,
    seed: int = DEFAULT_SEED,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Split rows at random, ignoring groups. **This leaks, deliberately.**

    Provided for one purpose: to measure how much a leaking split inflates the score,
    so the generalisation report can show the gap rather than assert it. Sibling
    windows from one capture land on both sides and the model is scored on near-copies
    of what it memorised.

    Never use this to produce a number that will be quoted on its own. It is the
    optimistic upper bound and the report labels it as such.
    """
    import numpy as np

    if frame.empty:
        raise SplitError("cannot split an empty dataset")
    if not 0.0 < test_frac < 1.0:
        raise SplitError(f"test_frac must be between 0 and 1, got {test_frac}")

    rng = np.random.default_rng(seed)
    order = rng.permutation(len(frame))
    cut = max(1, min(len(frame) - 1, round(len(frame) * test_frac)))
    test_positions = set(order[:cut].tolist())
    mask = np.array([i in test_positions for i in range(len(frame))])
    train, test = frame[~mask].copy(), frame[mask].copy()
    _require_non_empty(train, test, "split_randomly")
    return train, test


def split_by_config(
    frame: pd.DataFrame,
    holdout_configs: list[str],
    column: str = "config_id",
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Hold out entire configurations — the generalisation test.

    Harder than a capture split and more honest, because a deployed analyser meets
    configurations nobody trained on. A model that scores well here has learned
    something about traffic; one that only scores well on a capture split has learned
    something about the corpus.
    """
    if frame.empty:
        raise SplitError("cannot split an empty dataset")
    if column not in frame.columns:
        raise SplitError(f"the dataset has no {column!r} column to group on")
    if not holdout_configs:
        raise SplitError("no configurations were held out; that is not a split")

    requested = {str(c) for c in holdout_configs}
    present = set(frame[column].astype(str).unique())
    missing = sorted(requested - present)
    if missing:
        raise SplitError(
            f"held-out configurations are not in the dataset: {missing}. Holding out "
            f"something absent would silently produce a train-only split."
        )

    mask = frame[column].astype(str).isin(requested)
    train, test = frame[~mask].copy(), frame[mask].copy()
    _require_non_empty(train, test, "split_by_config")
    return train, test


def split_by_dh_group(
    frame: pd.DataFrame,
    train_groups: list[str],
    test_groups: list[str],
    column: str = "dh_group",
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Train on some Diffie-Hellman groups and test on others.

    The confound probe. If a traffic classifier's accuracy survives this, it is reading
    traffic shape; if it collapses, it was reading a cipher artifact — and the corpus
    was designed to make that visible rather than to hide it.
    """
    if frame.empty:
        raise SplitError("cannot split an empty dataset")
    if column not in frame.columns:
        raise SplitError(f"the dataset has no {column!r} column to group on")

    train_set = {str(g) for g in train_groups}
    test_set = {str(g) for g in test_groups}
    if not train_set or not test_set:
        raise SplitError("both sides must name at least one group")
    shared = sorted(train_set & test_set)
    if shared:
        raise SplitError(
            f"groups {shared} appear on both sides; that is the leak this split exists to prevent"
        )

    present = set(frame[column].astype(str).unique())
    missing = sorted((train_set | test_set) - present)
    if missing:
        raise SplitError(f"groups not present in the dataset: {missing}")

    values = frame[column].astype(str)
    train = frame[values.isin(train_set)].copy()
    test = frame[values.isin(test_set)].copy()
    _require_non_empty(train, test, "split_by_dh_group")
    return train, test


def assert_no_overlap(train: pd.DataFrame, test: pd.DataFrame, column: str = "capture_id") -> None:
    """Raise if any group appears on both sides.

    Exported so callers can re-check a split they did not make themselves. Cheap
    enough to run every time, and the one assertion worth never skipping.
    """
    overlap = set(train[column].astype(str)) & set(test[column].astype(str))
    if overlap:
        raise SplitError(
            f"{len(overlap)} {column} value(s) appear in both train and test: "
            f"{sorted(overlap)[:5]}. Every score from this split is inflated."
        )
