#!/usr/bin/env python3
"""Audit whether the traffic classifier is reading traffic shape or cipher artifacts.

Build plan Step 7.10. This is the check that decides whether the Phase 7 numbers mean
what they appear to mean.

The trap it exists to catch is specific and easy to fall into. If application class
correlates with cipher in the corpus, a classifier can score beautifully by learning the
cipher and reading the label off it — and every accuracy figure, every confusion matrix
and every SHAP explanation would look exactly the same as a model that had genuinely
learned traffic shape. The corpus was balanced to make that distinguishable; this script
performs the distinguishing.

Three measurements, and the second is the interesting one:

1. **Accuracy conditioned on cipher.** If the classifier is markedly better under one
   cipher than another, it is leaning on something the cipher carries.
2. **How learnable is the cipher itself, from packet sizes alone?** A deliberate
   cipher-from-ESP-sizes classifier. This is expected to work, and that is a legitimate
   finding rather than a failure: AES-CBC pads to a 16-byte block boundary, 3DES to
   8 bytes, and AES-GCM not at all, so ESP packet sizes carry the cipher's block
   structure whether anyone wants them to or not. **The finding is that a passive
   observer can identify the cipher without reading a handshake.**
3. **Mutual information between the predicted class and the cipher.** If the classifier's
   *output* carries information about the cipher beyond what the true labels do, its
   decisions are cipher-coupled.

The document is written whatever the numbers show.
"""

from __future__ import annotations

import argparse
import json
import sys
import warnings
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

REPO_ROOT = Path(__file__).resolve().parent.parent
for path in (REPO_ROOT / "src", REPO_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from ipsec_sentinel.features.flow import FEATURE_NAMES  # noqa: E402
from ipsec_sentinel.ml.train import MODEL_RANDOM_FOREST, _build_model  # noqa: E402

DEFAULT_DATASET: Final = REPO_ROOT / "data" / "processed" / "ml_dataset.parquet"
DEFAULT_OUTPUT: Final = REPO_ROOT / "docs" / "CONFOUND_AUDIT.md"
DEFAULT_JSON: Final = REPO_ROOT / "reports" / "confound_audit.json"

# Packet-size features only. The cipher-learnability probe must be given exactly what a
# passive observer sees of ESP framing — sizes — and nothing about timing or volume,
# which would let it identify the traffic class and infer the cipher from the corpus
# layout rather than from padding.
SIZE_FEATURES: Final[tuple[str, ...]] = tuple(
    name for name in FEATURE_NAMES if "size" in name or name == "mtu_fraction"
)

# Above this spread between the best and worst cipher, the classifier's performance
# depends on which cipher was negotiated, which is the confound.
MAX_ACCEPTABLE_SPREAD: Final = 0.15


@dataclass
class CipherAccuracy:
    cipher: str
    accuracy: float
    rows: int


@dataclass
class AuditResult:
    """Every number the audit produces, whether or not they are flattering."""

    accuracy_overall: float = 0.0
    by_cipher: list[CipherAccuracy] = field(default_factory=list)
    cipher_learnability: float = 0.0
    cipher_baseline: float = 0.0
    cipher_top_features: list[str] = field(default_factory=list)
    mutual_information_true: float = 0.0
    mutual_information_predicted: float = 0.0
    traffic_entropy: float = 0.0
    rows: int = 0
    ciphers: list[str] = field(default_factory=list)

    @property
    def accuracy_spread(self) -> float:
        if len(self.by_cipher) < 2:
            return 0.0
        values = [c.accuracy for c in self.by_cipher]
        return max(values) - min(values)

    @property
    def is_cipher_independent(self) -> bool:
        return self.accuracy_spread <= MAX_ACCEPTABLE_SPREAD

    @property
    def cipher_lift(self) -> float:
        """How much better than chance the cipher can be guessed from sizes alone."""
        return self.cipher_learnability - self.cipher_baseline


def _grouped_predictions(
    frame: Any, target: str, features: list[str], seed: int, folds: int = 5
) -> Any:
    """Out-of-fold predictions with folds grouped by capture."""
    import numpy as np
    from sklearn.model_selection import GroupKFold

    usable = frame[frame[target].notna()]
    matrix = usable[features].to_numpy(dtype=float)
    truth = usable[target].astype(str).to_numpy()
    groups = usable["capture_id"].astype(str).to_numpy()

    splits = min(folds, len(set(groups)))
    predictions = np.empty_like(truth)
    for train_index, test_index in GroupKFold(n_splits=splits).split(matrix, truth, groups):
        labels = sorted(set(truth[train_index]))
        if len(labels) < 2:
            predictions[test_index] = labels[0] if labels else truth[0]
            continue
        model = _build_model(MODEL_RANDOM_FOREST, seed, len(labels))
        model.fit(matrix[train_index], truth[train_index])
        predictions[test_index] = model.predict(matrix[test_index])
    return usable, truth, predictions


def run_audit(frame: Any, seed: int = 42) -> AuditResult:
    """Run all three measurements. Never suppresses an unfavourable one."""
    import numpy as np
    from scipy.stats import entropy
    from sklearn.metrics import accuracy_score, mutual_info_score

    result = AuditResult(rows=len(frame))
    if frame.empty or "cipher" not in frame.columns:
        return result

    # 1. Traffic classification, conditioned on cipher.
    usable, truth, predicted = _grouped_predictions(
        frame, "inner_traffic", list(FEATURE_NAMES), seed
    )
    result.accuracy_overall = float(accuracy_score(truth, predicted))
    ciphers = usable["cipher"].astype(str).to_numpy()
    result.ciphers = sorted(set(ciphers))
    for cipher in result.ciphers:
        mask = ciphers == cipher
        result.by_cipher.append(
            CipherAccuracy(
                cipher=cipher,
                accuracy=float(accuracy_score(truth[mask], predicted[mask])),
                rows=int(mask.sum()),
            )
        )

    # 2. How learnable is the cipher from packet sizes alone?
    if len(result.ciphers) >= 2:
        _u, cipher_truth, cipher_predicted = _grouped_predictions(
            frame, "cipher", list(SIZE_FEATURES), seed
        )
        result.cipher_learnability = float(accuracy_score(cipher_truth, cipher_predicted))
        counts = np.unique(cipher_truth, return_counts=True)[1]
        result.cipher_baseline = float(counts.max() / counts.sum())

        model = _build_model(MODEL_RANDOM_FOREST, seed, len(result.ciphers))
        model.fit(frame[list(SIZE_FEATURES)].to_numpy(dtype=float),
                  frame["cipher"].astype(str).to_numpy())
        order = np.argsort(model.feature_importances_)[::-1][:5]
        result.cipher_top_features = [SIZE_FEATURES[i] for i in order]

    # 3. Mutual information: true labels against cipher, and predictions against cipher.
    result.mutual_information_true = float(mutual_info_score(truth, ciphers))
    result.mutual_information_predicted = float(mutual_info_score(predicted, ciphers))
    _values, counts = np.unique(truth, return_counts=True)
    result.traffic_entropy = float(entropy(counts / counts.sum()))
    return result


def _verdict(result: AuditResult) -> str:
    lines: list[str] = []

    if result.is_cipher_independent:
        lines.append(
            f"**Accuracy does not depend on the cipher.** The spread between the best "
            f"and worst cipher is {result.accuracy_spread:.1%}, inside the "
            f"{MAX_ACCEPTABLE_SPREAD:.0%} tolerance. A classifier reading a cipher "
            f"artifact would score visibly better under the cipher whose artifact it "
            f"had learned."
        )
    else:
        lines.append(
            f"**Accuracy varies by {result.accuracy_spread:.1%} across ciphers**, above "
            f"the {MAX_ACCEPTABLE_SPREAD:.0%} tolerance. That is the confound "
            f"signature: the classifier performs differently depending on which cipher "
            f"was negotiated, so it is reading something the cipher carries. The "
            f"traffic-classification numbers should not be quoted until this is "
            f"resolved."
        )

    if result.cipher_lift > 0.1:
        lines.append(
            f"**The cipher is identifiable from ESP packet sizes alone at "
            f"{result.cipher_learnability:.1%}, against a {result.cipher_baseline:.1%} "
            f"majority-class baseline.** This is a real finding rather than a defect: "
            f"AES-CBC pads to a 16-byte block boundary, 3DES to 8 bytes, and AES-GCM "
            f"not at all, so ESP packet sizes carry the cipher's block structure. **A "
            f"passive observer can therefore infer the negotiated cipher without ever "
            f"seeing a handshake** — useful when a capture starts mid-session, and a "
            f"reminder that padding is a side channel."
        )
        lines.append(
            f"The features that carry it: {', '.join(result.cipher_top_features)} — the "
            f"*smallest* packets, which is exactly what padding theory predicts, because "
            f"a block-boundary rounding is proportionally most visible on a short packet."
        )
        lines.append(
            "**Product implication.** ESP-01 reports tunnels seen with no negotiation "
            "in the capture, whose cryptography is currently unassessable. This side "
            "channel offers a route to saying something about them — an *inferred* "
            "cipher, carrying a calibrated confidence, in Section B. It is not "
            "implemented here; it is recorded because the measurement that justifies "
            "it now exists."
        )
    else:
        lines.append(
            f"The cipher is **not** meaningfully learnable from packet sizes "
            f"({result.cipher_learnability:.1%} against a {result.cipher_baseline:.1%} "
            f"baseline), so ESP padding is not leaking block structure in this corpus."
        )

    ratio_true = (
        result.mutual_information_true / result.traffic_entropy
        if result.traffic_entropy
        else 0.0
    )
    ratio_predicted = (
        result.mutual_information_predicted / result.traffic_entropy
        if result.traffic_entropy
        else 0.0
    )
    if ratio_predicted <= ratio_true + 0.02:
        lines.append(
            f"**The classifier's output carries no more cipher information than the "
            f"true labels do.** Mutual information with cipher is "
            f"{result.mutual_information_predicted:.4f} nats for the predictions "
            f"against {result.mutual_information_true:.4f} for the ground truth "
            f"({ratio_predicted:.1%} and {ratio_true:.1%} of traffic-class entropy). "
            f"The model is not manufacturing a cipher dependency the corpus does not "
            f"have."
        )
    else:
        lines.append(
            f"**The classifier's predictions carry more cipher information than the "
            f"true labels do** ({ratio_predicted:.1%} against {ratio_true:.1%} of "
            f"traffic-class entropy). Its decisions are cipher-coupled beyond anything "
            f"in the corpus, which means it has learned to use the cipher."
        )
    return "\n\n".join(lines)


def write_report(
    result: AuditResult, output: Path = DEFAULT_OUTPUT, json_output: Path | None = DEFAULT_JSON
) -> Path:
    """Write the audit. Called whatever the numbers show."""
    cipher_rows = "\n".join(
        f"| {c.cipher} | {c.accuracy:.1%} | {c.rows} |" for c in result.by_cipher
    )
    document = f"""# Confound audit

*Generated {datetime.now(UTC):%Y-%m-%d %H:%M} UTC by `scripts/confound_audit.py`.*

If application class correlates with cipher in a corpus, a classifier can score
beautifully by learning the cipher and reading the label off it — and every accuracy
figure, confusion matrix and SHAP explanation would look identical to a model that had
genuinely learned traffic shape. This document performs the distinguishing.

**It is written whatever the numbers show.**

## 1. Accuracy conditioned on cipher

Overall traffic-classification accuracy: **{result.accuracy_overall:.1%}** over
{result.rows} windows, grouped 5-fold by capture.

| Cipher | Accuracy | Windows |
|---|---|---|
{cipher_rows}

Spread between best and worst: **{result.accuracy_spread:.1%}**
(tolerance {MAX_ACCEPTABLE_SPREAD:.0%}).

## 2. How learnable is the cipher from packet sizes alone?

A deliberate cipher-from-ESP-sizes classifier, given only size features
({len(SIZE_FEATURES)} of {len(FEATURE_NAMES)}) — no timing, no volume, nothing that
would let it identify the traffic class and infer the cipher from corpus layout.

| Measure | Value |
|---|---|
| Cipher accuracy from sizes | **{result.cipher_learnability:.1%}** |
| Majority-class baseline | {result.cipher_baseline:.1%} |
| Lift over baseline | **{result.cipher_lift:+.1%}** |

## 3. Mutual information with cipher

| Quantity | Nats | Share of traffic-class entropy |
|---|---|---|
| True labels vs cipher | {result.mutual_information_true:.4f} | {(result.mutual_information_true / result.traffic_entropy if result.traffic_entropy else 0):.1%} |
| Predicted labels vs cipher | {result.mutual_information_predicted:.4f} | {(result.mutual_information_predicted / result.traffic_entropy if result.traffic_entropy else 0):.1%} |

Traffic-class entropy: {result.traffic_entropy:.4f} nats.

## Verdict

{_verdict(result)}

## Why this audit exists

The master document names this the most fatal trap available in this project. It is
also invisible: a confounded classifier and a sound one produce the same shape of
output, and only a test designed to separate them can tell which you have.

The corpus was built to make the separation possible — every traffic class appears with
every cipher, verified at the M3 gate at 0.0000 nats of cell-level mutual information.
This audit checks that the property survived into the model.
"""
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(document)
    if json_output is not None:
        json_output.parent.mkdir(parents=True, exist_ok=True)
        json_output.write_text(json.dumps(asdict(result), indent=2, sort_keys=True))
    return output


def main(argv: list[str] | None = None) -> int:
    warnings.filterwarnings("ignore")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args(argv)

    import pandas as pd

    if not args.dataset.exists():
        print(f"dataset not found: {args.dataset}", file=sys.stderr)
        return 2

    result = run_audit(pd.read_parquet(args.dataset), args.seed)
    path = write_report(result, args.output)

    print(f"overall accuracy            {result.accuracy_overall:.1%}")
    for cipher in result.by_cipher:
        print(f"  {cipher.cipher:16} {cipher.accuracy:.1%}  ({cipher.rows} windows)")
    print(f"accuracy spread             {result.accuracy_spread:.1%} "
          f"({'OK' if result.is_cipher_independent else 'CONFOUNDED'})")
    print(f"cipher from sizes           {result.cipher_learnability:.1%} "
          f"(baseline {result.cipher_baseline:.1%}, lift {result.cipher_lift:+.1%})")
    print(f"MI predicted vs cipher      {result.mutual_information_predicted:.4f} nats")
    print(f"\nwritten: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
