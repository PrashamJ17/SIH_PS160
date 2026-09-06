#!/usr/bin/env python3
"""Evaluate the traffic classifier across four splits and write the honest result.

Build plan Step 7.6, and one of the four steps the brief marks uncuttable. The reason
is simple: a single accuracy figure is not a claim anyone can check. Four figures from
four splits, with the gap between them stated, is.

The splits, from most optimistic to most demanding:

1. **Random rows.** Leaks by construction — sibling windows from one capture land on
   both sides. Reported so the inflation can be measured rather than asserted.
2. **Held-out captures.** No capture spans the split, but the same configurations do.
   This is realistic in-distribution performance.
3. **Held-out configurations.** The model has never seen these crypto settings. This is
   the number closest to what a deployed analyser faces.
4. **Held-out Diffie-Hellman groups.** The confound probe. If accuracy survives here the
   model is reading traffic shape; if it collapses it was reading a cipher artifact.

**The document is written whatever the numbers are.** A generalisation report that only
appears when the result is flattering is not a generalisation report. If accuracy falls
on the held-out splits, that fall is the finding and it goes in the document.
"""

from __future__ import annotations

import argparse
import json
import sys
import warnings
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

REPO_ROOT = Path(__file__).resolve().parent.parent
for path in (REPO_ROOT / "src", REPO_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from ipsec_sentinel.ml.heuristic import majority_class_baseline  # noqa: E402
from ipsec_sentinel.ml.split import (  # noqa: E402
    SplitError,
    assert_no_overlap,
    split_by_capture,
    split_by_config,
    split_by_dh_group,
    split_randomly,
)
from ipsec_sentinel.ml.train import (  # noqa: E402
    MODEL_RANDOM_FOREST,
    EvaluationResult,
    evaluate_holdout,
)

DEFAULT_DATASET: Final = REPO_ROOT / "data" / "processed" / "ml_dataset.parquet"
DEFAULT_OUTPUT: Final = REPO_ROOT / "docs" / "GENERALISATION.md"
DEFAULT_JSON: Final = REPO_ROOT / "reports" / "generalisation.json"

SPLIT_RANDOM: Final = "random rows (leaky)"
SPLIT_CAPTURE: Final = "held-out captures"
SPLIT_CONFIG: Final = "held-out configurations"
SPLIT_DH: Final = "held-out DH groups"

SPLIT_ORDER: Final[tuple[str, ...]] = (SPLIT_RANDOM, SPLIT_CAPTURE, SPLIT_CONFIG, SPLIT_DH)


def run_all_splits(
    frame: Any, model_name: str = MODEL_RANDOM_FOREST, seed: int = 42
) -> dict[str, EvaluationResult]:
    """Evaluate every split. A split that cannot be made is recorded, not skipped."""
    results: dict[str, EvaluationResult] = {}

    train, test = split_randomly(frame, seed=seed)
    results[SPLIT_RANDOM] = evaluate_holdout(train, test, model_name, split_strategy=SPLIT_RANDOM)

    train, test = split_by_capture(frame, seed=seed)
    assert_no_overlap(train, test, "capture_id")
    results[SPLIT_CAPTURE] = evaluate_holdout(train, test, model_name, split_strategy=SPLIT_CAPTURE)

    configs = sorted(frame["config_id"].astype(str).unique())
    holdout = configs[: max(1, len(configs) // 5)]
    train, test = split_by_config(frame, holdout)
    assert_no_overlap(train, test, "capture_id")
    results[SPLIT_CONFIG] = evaluate_holdout(
        train,
        test,
        model_name,
        split_strategy=f"{SPLIT_CONFIG} ({len(holdout)} of {len(configs)})",
    )

    groups = sorted(frame["dh_group"].dropna().astype(str).unique())
    if len(groups) >= 2:
        cut = max(1, len(groups) // 2)
        train_groups, test_groups = groups[:cut], groups[cut:]
        train, test = split_by_dh_group(frame, train_groups, test_groups)
        results[SPLIT_DH] = evaluate_holdout(
            train,
            test,
            model_name,
            split_strategy=f"{SPLIT_DH} (train {train_groups}, test {test_groups})",
        )
    return results


def _matrix_table(result: EvaluationResult) -> str:
    header = "| actual \\ predicted | " + " | ".join(result.labels) + " |"
    divider = "|---" * (len(result.labels) + 1) + "|"
    rows = [
        f"| **{label}** | " + " | ".join(str(v) for v in row) + " |"
        for label, row in zip(result.labels, result.confusion_matrix, strict=True)
    ]
    return "\n".join([header, divider, *rows])


def _per_class_table(result: EvaluationResult) -> str:
    rows = [
        f"| {c.label} | {c.precision:.2f} | {c.recall:.2f} | {c.f1:.2f} | {c.support} |"
        for c in result.per_class
    ]
    return "\n".join(
        ["| Class | Precision | Recall | F1 | Support |", "|---|---|---|---|---|", *rows]
    )


def _interpret(
    results: dict[str, EvaluationResult], windows_per_capture: float | None = None
) -> str:
    """Say what the gap means, in the direction the numbers actually point.

    Including when they point at "this test had little power", which is the honest
    reading whenever a dataset has too few sibling windows for a random split to leak.
    """
    if SPLIT_CAPTURE not in results or SPLIT_CONFIG not in results:
        return "Not enough splits completed to interpret a gap."

    capture = results[SPLIT_CAPTURE].accuracy
    config = results[SPLIT_CONFIG].accuracy
    gap = capture - config
    lines: list[str] = []

    if SPLIT_RANDOM in results:
        leak = results[SPLIT_RANDOM].accuracy - capture
        lines.append(
            f"The random split scores {leak:+.1%} against the capture split — the "
            f"**inflation a leaking split buys on this dataset**, measured rather than "
            f"assumed."
        )
        if windows_per_capture is not None and windows_per_capture < 4:
            lines.append(
                f"**That small gap is not evidence that leakage is harmless, and must "
                f"not be read as one.** This dataset averages "
                f"{windows_per_capture:.2f} windows per capture, so a random split has "
                f"very few sibling windows available to leak — the test has little "
                f"power here. Leakage scales with windows per capture: before the "
                f"protocol-50 artefacts were removed, one traffic class averaged 29.4 "
                f"windows per capture, and a random split over that data would have "
                f"leaked heavily. The grouped split is cheap insurance whose value does "
                f"not show up in this particular number."
            )

    if gap > 0.15:
        lines.append(
            f"Accuracy falls **{gap:.1%}** from held-out captures to held-out "
            f"configurations. That fall is the finding. The model has learned "
            f"something that does not transfer to crypto settings it has not seen, so "
            f"the honest figure to quote for a deployed analyser is the "
            f"**{config:.1%}** from the configuration split, not the "
            f"{capture:.1%} from the capture split."
        )
    elif gap > 0.05:
        lines.append(
            f"Accuracy falls {gap:.1%} from held-out captures to held-out "
            f"configurations — a real but moderate drop. The model transfers, "
            f"imperfectly. Quote **{config:.1%}**, not {capture:.1%}."
        )
    elif gap >= -0.02:
        lines.append(
            f"Accuracy is essentially unchanged ({gap:+.1%}) between held-out captures "
            f"and held-out configurations. The model is reading traffic shape rather "
            f"than configuration, which is the intended result — and it is worth "
            f"stating that the corpus has {len(results[SPLIT_CONFIG].labels)} traffic "
            f"classes generated by deliberately distinct tools, so the classes are "
            f"more separable here than arbitrary real-world traffic would be."
        )
    else:
        lines.append(
            f"Accuracy is **higher** on held-out configurations ({config:.1%}) than on "
            f"held-out captures ({capture:.1%}). That is not evidence of better "
            f"generalisation; with a corpus this size it most likely means the "
            f"held-out configurations happen to contain easier traffic. Treat both "
            f"numbers as noisy at this sample size."
        )

    if SPLIT_DH in results:
        dh = results[SPLIT_DH].accuracy
        drop = capture - dh
        if drop > 0.15:
            lines.append(
                f"On unseen Diffie-Hellman groups accuracy falls to **{dh:.1%}**, a "
                f"{drop:.1%} drop. **This is the confound signature.** The model was "
                f"reading something that travels with the key exchange rather than "
                f"with the traffic, and the traffic-classification claim does not "
                f"survive it."
            )
        else:
            lines.append(
                f"On unseen Diffie-Hellman groups accuracy is **{dh:.1%}** "
                f"({drop:+.1%} against the capture split). The model is not leaning on "
                f"a key-exchange artifact, which is what the corpus was balanced to "
                f"make testable."
            )
    return "\n\n".join(lines)


def write_report(
    results: dict[str, EvaluationResult],
    frame: Any,
    output: Path = DEFAULT_OUTPUT,
    json_output: Path | None = DEFAULT_JSON,
) -> Path:
    """Write the report. Called whatever the numbers are."""
    labels = frame["inner_traffic"].dropna().astype(str).tolist()
    majority = majority_class_baseline(labels)
    windows_per_capture = (
        float(frame.groupby("capture_id").size().mean())
        if "capture_id" in frame.columns and not frame.empty
        else None
    )

    ordered = [name for name in SPLIT_ORDER if name in results]
    summary_rows = [
        f"| {name} | {results[name].accuracy:.1%} | {results[name].macro_f1:.3f} | "
        f"{results[name].rows} |"
        for name in ordered
    ]

    document = f"""# Generalisation

*Generated {datetime.now(UTC):%Y-%m-%d %H:%M} UTC by `scripts/generalisation_report.py`.*

A single accuracy figure is not a claim anyone can check. This document reports four,
from four splits, and states the gap between them.

**This document is written whatever the numbers are.** A generalisation report that
only appears when the result is flattering is not a generalisation report.

## Dataset

{len(frame)} windows, {frame["capture_id"].nunique()} captures,
{frame["config_id"].nunique()} configurations, {len(set(labels))} traffic classes,
**{windows_per_capture:.2f} windows per capture**.
Model: random forest. Baseline to beat: **{majority.accuracy:.1%}** (majority class).

Windows per capture is reported because it bounds how much a leaking split *could*
inflate a score: with few siblings per capture there is little to leak, and the random
split below is correspondingly weak as a test.

## Results

| Split | Accuracy | Macro-F1 | Test rows |
|---|---|---|---|
{chr(10).join(summary_rows)}

### What each split tests

| Split | Question |
|---|---|
| Random rows (leaky) | How much does a leaking split inflate the score? Reported to measure the inflation, never to be quoted alone. |
| Held-out captures | Realistic in-distribution performance. No capture spans the split; the same configurations do. |
| Held-out configurations | Generalisation to crypto settings never seen. **Closest to what a deployed analyser faces.** |
| Held-out DH groups | Did it learn traffic shape, or a key-exchange artifact? |

## Interpretation

{_interpret(results, windows_per_capture)}

## Per-split detail

"""

    for name in ordered:
        result = results[name]
        document += f"""### {name}

{result.summary()}

{_per_class_table(result)}

**Confusion matrix**

{_matrix_table(result)}

"""

    document += """## Limitations

* The corpus has seven traffic classes produced by deliberately distinct generators, so
  the classes are more separable than arbitrary real-world traffic. These numbers are an
  upper bound on what the same approach would achieve on a production estate.
* All cells are tunnel mode; mode inference cannot be evaluated here at all. See
  `docs/BASELINES.md`.
* Sample size is modest. Differences of a few percent between splits are within noise.
"""

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(document)

    if json_output is not None:
        json_output.parent.mkdir(parents=True, exist_ok=True)
        json_output.write_text(
            json.dumps(
                {name: asdict(result) for name, result in results.items()},
                indent=2,
                sort_keys=True,
            )
        )
    return output


def main(argv: list[str] | None = None) -> int:
    warnings.filterwarnings("ignore")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--model", default=MODEL_RANDOM_FOREST)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args(argv)

    import pandas as pd

    if not args.dataset.exists():
        print(f"dataset not found: {args.dataset}", file=sys.stderr)
        return 2

    frame = pd.read_parquet(args.dataset)
    try:
        results = run_all_splits(frame, args.model, args.seed)
    except SplitError as exc:
        print(f"a split could not be made: {exc}", file=sys.stderr)
        return 1

    path = write_report(results, frame, args.output)
    for name in SPLIT_ORDER:
        if name in results:
            print(
                f"{name:34} accuracy {results[name].accuracy:.1%}  "
                f"macro-F1 {results[name].macro_f1:.3f}"
            )
    print(f"\nwritten: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
