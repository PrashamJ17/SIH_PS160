#!/usr/bin/env python3
"""Execute the M7 acceptance checklist and report pass/fail per item.

One item cannot be satisfied on this corpus and is reported BLOCKED with the reason
rather than passed. A gate that quietly converts an impossible check into a green tick
is worse than no gate.
"""

from __future__ import annotations

import json
import subprocess
import sys
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

import pandas as pd

REPO_ROOT = Path(__file__).resolve().parent.parent
for path in (REPO_ROOT / "src", REPO_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

warnings.filterwarnings("ignore")

from ipsec_sentinel.features.flow import FEATURE_NAMES  # noqa: E402
from ipsec_sentinel.ml.calibrate import (  # noqa: E402
    MAX_ACCEPTABLE_ECE,
    CalibrationReport,
    calibrate_classifier,
)
from ipsec_sentinel.ml.explain import explain_prediction  # noqa: E402
from ipsec_sentinel.ml.predict import (  # noqa: E402
    MAX_REASONABLE_ABSTENTION,
    abstention_rate,
    evaluate_abstention,
    predict_with_abstention,
)
from ipsec_sentinel.ml.split import assert_no_overlap, split_by_capture  # noqa: E402
from ipsec_sentinel.ml.train import cross_validate  # noqa: E402

DATASET: Final = REPO_ROOT / "data" / "processed" / "ml_dataset.parquet"
GENERALISATION: Final = REPO_ROOT / "docs" / "GENERALISATION.md"
CONFOUND: Final = REPO_ROOT / "docs" / "CONFOUND_AUDIT.md"
BASELINES: Final = REPO_ROOT / "docs" / "BASELINES.md"


@dataclass
class Check:
    name: str
    status: str
    detail: str

    def __str__(self) -> str:
        return f"[{self.status}] {self.name}\n       {self.detail}"


def _frame() -> pd.DataFrame:
    return pd.read_parquet(DATASET)


def _calibrated() -> tuple[Any, CalibrationReport, pd.DataFrame, list[str]]:
    frame = _frame()
    train, evaluation = split_by_capture(frame, test_frac=0.25, seed=42)
    model, report = calibrate_classifier(train, evaluation)
    classes = sorted(train["inner_traffic"].dropna().astype(str).unique().tolist())
    return model, report, evaluation, classes


def check_trained_with_capture_splitting() -> Check:
    name = "Traffic classifier trained with capture-level splitting"
    if not DATASET.exists():
        return Check(name, "SKIP", "the ML dataset has not been built")
    result = cross_validate(_frame())
    if "capture_id" not in result.split_strategy:
        return Check(name, "FAIL", result.split_strategy)
    return Check(name, "PASS", result.summary())


def check_zero_capture_overlap() -> Check:
    name = "Zero capture_id overlap between train and test"
    if not DATASET.exists():
        return Check(name, "SKIP", "the ML dataset has not been built")
    frame = _frame()
    checked = 0
    for seed in range(25):
        train, test = split_by_capture(frame, seed=seed)
        assert_no_overlap(train, test, "capture_id")
        checked += 1
    return Check(name, "PASS", f"{checked} seeds, zero overlap in every one")


def check_generalisation_published() -> Check:
    name = "Generalisation report published with all four splits"
    if not GENERALISATION.exists():
        return Check(name, "FAIL", "docs/GENERALISATION.md is missing")
    text = GENERALISATION.read_text()
    required = ["random rows", "held-out captures", "held-out configurations", "held-out DH groups"]
    missing = [r for r in required if r not in text]
    if missing:
        return Check(name, "FAIL", f"splits missing from the report: {missing}")
    matrices = text.count("actual \\ predicted")
    if matrices < 4:
        return Check(name, "FAIL", f"only {matrices} confusion matrices")
    return Check(name, "PASS", f"4 splits, {matrices} confusion matrices")


def check_beats_mode_heuristic() -> Check:
    name = "Model beats the heuristic baseline for mode inference"
    if not DATASET.exists():
        return Check(name, "SKIP", "the ML dataset has not been built")
    modes = sorted(_frame()["mode"].dropna().unique().tolist())
    if len(modes) < 2:
        return Check(
            name,
            "BLOCKED",
            f"the corpus contains a single mode {modes}. Transport-mode cells were "
            f"dropped in Phase 2 because they produced zero ESP, so no classifier can "
            f"be compared against the heuristic here - one answering 'tunnel' "
            f"unconditionally would score 100%. Recorded in docs/BASELINES.md, which "
            f"states that no model may claim to beat this baseline on this corpus. "
            f"Closing it needs transport-mode cells carrying real ESP: a testbed "
            f"change, not a modelling one.",
        )
    return Check(name, "FAIL", "two modes present but no comparison implemented")


def check_ece() -> Check:
    name = f"ECE below {MAX_ACCEPTABLE_ECE} after calibration"
    if not DATASET.exists():
        return Check(name, "SKIP", "the ML dataset has not been built")
    _model, report, _evaluation, _classes = _calibrated()
    status = "PASS" if report.ece_after <= MAX_ACCEPTABLE_ECE else "FAIL"
    return Check(name, status, report.summary().replace("\n  ", " | "))


def check_abstention() -> Check:
    name = f"Abstention working, rate under {MAX_REASONABLE_ABSTENTION:.0%}"
    if not DATASET.exists():
        return Check(name, "SKIP", "the ML dataset has not been built")
    model, _report, evaluation, classes = _calibrated()
    predictions = predict_with_abstention(model, evaluation, classes, list(FEATURE_NAMES))
    result = evaluate_abstention(
        predictions, evaluation["inner_traffic"].astype(str).tolist()
    )
    if abstention_rate(predictions) == 0.0:
        return Check(name, "FAIL", "the model never abstains; the confidence is saturated")
    if not result.is_reasonable:
        return Check(name, "FAIL", result.summary())
    return Check(name, "PASS", result.summary())


def check_explanations() -> Check:
    name = "SHAP explanations render as readable sentences"
    if not DATASET.exists():
        return Check(name, "SKIP", "the ML dataset has not been built")
    model, _report, evaluation, classes = _calibrated()
    sentences = []
    for i in (0, 5, 25):
        explanation = explain_prediction(
            model, evaluation.iloc[[i]], classes, list(FEATURE_NAMES)
        )
        if not explanation.is_additive():
            return Check(name, "FAIL", "SHAP values do not sum to the prediction")
        sentence = explanation.sentence()
        leaked = [n for n in FEATURE_NAMES if n in sentence]
        if leaked:
            return Check(name, "FAIL", f"raw identifiers in the sentence: {leaked[:3]}")
        sentences.append(sentence)
    return Check(name, "PASS", sentences[0][:150] + "...")


def check_confound_audit() -> Check:
    name = "Confound audit published"
    if not CONFOUND.exists():
        return Check(name, "FAIL", "docs/CONFOUND_AUDIT.md is missing")
    text = CONFOUND.read_text()
    for section in ("conditioned on cipher", "packet sizes", "Mutual information"):
        if section not in text:
            return Check(name, "FAIL", f"missing section: {section}")
    return Check(name, "PASS", "all three measurements present with a verdict")


def check_ml_findings_carry_confidence() -> Check:
    name = "Every ML-derived finding carries a non-None confidence"
    if not DATASET.exists():
        return Check(name, "SKIP", "the ML dataset has not been built")
    model, _report, evaluation, classes = _calibrated()
    predictions = predict_with_abstention(model, evaluation, classes, list(FEATURE_NAMES))
    missing = [p for p in predictions if p.confidence is None]
    if missing:
        return Check(name, "FAIL", f"{len(missing)} predictions with no confidence")

    from ipsec_sentinel.assess.anomaly import detect_config_anomalies
    from ipsec_sentinel.parser.correlate import Tunnel

    anomaly_findings = detect_config_anomalies(
        [Tunnel(tunnel_id=f"t{i}", endpoints=("a", "b")) for i in range(12)]
    )
    bad = [f for f in anomaly_findings if f.confidence is None]
    if bad:
        return Check(name, "FAIL", f"{len(bad)} anomaly findings with no confidence")
    return Check(
        name, "PASS",
        f"{len(predictions)} predictions and every anomaly finding carry a confidence",
    )


def check_ml_tests_pass() -> Check:
    name = "The ML test suites pass"
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/unit", "-k",
         "features or ml_dataset or split or heuristic or train or generalisation or "
         "calibration or abstention or explain or confound"],
        capture_output=True, text=True, cwd=REPO_ROOT, timeout=3600, check=False,
    )
    summary = next(
        (line for line in reversed(result.stdout.splitlines()) if "passed" in line),
        "no summary",
    )
    status = "PASS" if result.returncode == 0 else "FAIL"
    return Check(name, status, summary.strip())


CHECKS = (
    check_trained_with_capture_splitting,
    check_zero_capture_overlap,
    check_generalisation_published,
    check_beats_mode_heuristic,
    check_ece,
    check_abstention,
    check_explanations,
    check_confound_audit,
    check_ml_findings_carry_confidence,
    check_ml_tests_pass,
)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Run the M7 acceptance checklist.")
    parser.add_argument("--only", help="run only checks whose name contains this substring")
    args = parser.parse_args(argv)

    selected = [c for c in CHECKS if not args.only or args.only in c.__name__]
    print("M7 — ML lane complete\n")
    results = [check() for check in selected]
    for result in results:
        print(result)
        print()

    failed = [r for r in results if r.status == "FAIL"]
    blocked = [r for r in results if r.status == "BLOCKED"]
    skipped = [r for r in results if r.status == "SKIP"]
    passed = len(results) - len(failed) - len(blocked) - len(skipped)
    print(
        f"{passed}/{len(results)} passed, {len(failed)} failed, "
        f"{len(blocked)} blocked, {len(skipped)} skipped"
    )
    if blocked:
        print("\nBLOCKED items are not failures and not passes. They cannot be satisfied")
        print("with the corpus as it stands, and the reason is recorded above.")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
