"""Train and compare traffic classifiers, honestly.

Two things here are not standard practice and are deliberate.

**Cross-validation is grouped by capture, never stratified by label.** Windows cut from
one capture are near-duplicates, so a stratified fold puts siblings on both sides and
returns a number that measures memorisation. Grouping costs class balance across folds
and that is the correct trade: imbalance makes a number noisier, leakage makes it wrong.

**Every trained model carries the checksum of the data it was trained on.** A model file
whose provenance is unknown cannot be defended, and "which dataset produced this?" is
the first question anyone reviewing a result should ask. The metadata records the
dataset checksum, the git commit, the feature names in order, and the class names — so a
model that is silently fed a different feature ordering fails loudly instead of
predicting nonsense.

The comparison between random forest and gradient boosting is reported rather than
resolved. Picking the winner on the same folds used to measure it would be selection on
the test set, so :func:`compare_models` returns both and the choice is made explicitly
downstream against a held-out split.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from ipsec_sentinel.features.flow import FEATURE_NAMES

if TYPE_CHECKING:  # pragma: no cover - typing only
    import pandas as pd

DEFAULT_SEED: Final = 42
DEFAULT_TARGET: Final = "inner_traffic"
DEFAULT_FOLDS: Final = 5

MODEL_RANDOM_FOREST: Final = "random_forest"
MODEL_GRADIENT_BOOSTING: Final = "xgboost"
SUPPORTED_MODELS: Final[tuple[str, ...]] = (MODEL_RANDOM_FOREST, MODEL_GRADIENT_BOOSTING)


class TrainingError(ValueError):
    """Training cannot proceed on the data as given."""


@dataclass
class ClassScore:
    """Per-class precision, recall and F1."""

    label: str
    precision: float
    recall: float
    f1: float
    support: int


@dataclass
class EvaluationResult:
    """What a model scored, and on what."""

    model_name: str
    target: str
    accuracy: float
    macro_f1: float
    per_class: list[ClassScore] = field(default_factory=list)
    confusion_matrix: list[list[int]] = field(default_factory=list)
    labels: list[str] = field(default_factory=list)
    folds: int = 0
    rows: int = 0
    groups: int = 0
    split_strategy: str = "grouped cross-validation by capture_id"

    def summary(self) -> str:
        return (
            f"{self.model_name}: accuracy {self.accuracy:.3f}, macro-F1 "
            f"{self.macro_f1:.3f} over {self.rows} rows in {self.groups} groups "
            f"({self.split_strategy})"
        )


@dataclass
class ModelMetadata:
    """Everything needed to say what a model is and where it came from."""

    model_name: str
    target: str
    feature_names: list[str]
    class_names: list[str]
    dataset_checksum: str
    dataset_rows: int
    git_sha: str
    trained_at: str
    seed: int

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True)


def dataset_checksum(frame: pd.DataFrame) -> str:
    """A stable checksum of the training data.

    Computed over the feature and label columns in a fixed order, so it identifies the
    data rather than the file — two builds of the same corpus produce the same
    checksum even if the parquet bytes differ.
    """
    import pandas as pd  # noqa: F401  (imported for the type at runtime)

    columns = [c for c in frame.columns if c in {*FEATURE_NAMES, "capture_id", "config_id"}]
    ordered = frame[sorted(columns)].sort_values(by=sorted(columns)).reset_index(drop=True)
    digest = hashlib.sha256(ordered.to_csv(index=False).encode()).hexdigest()
    return digest


def current_git_sha() -> str:
    """The commit this model was trained at, or ``"unknown"`` outside a repository."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):  # pragma: no cover - defensive
        return "unknown"
    return result.stdout.strip() if result.returncode == 0 else "unknown"


def _build_model(name: str, seed: int, n_classes: int) -> Any:
    if name == MODEL_RANDOM_FOREST:
        from sklearn.ensemble import RandomForestClassifier

        return RandomForestClassifier(
            n_estimators=300, random_state=seed, n_jobs=1, class_weight="balanced"
        )
    if name == MODEL_GRADIENT_BOOSTING:
        from xgboost import XGBClassifier

        return XGBClassifier(
            n_estimators=300,
            max_depth=6,
            learning_rate=0.1,
            random_state=seed,
            n_jobs=1,
            objective="multi:softprob" if n_classes > 2 else "binary:logistic",
            num_class=n_classes if n_classes > 2 else None,
            eval_metric="mlogloss" if n_classes > 2 else "logloss",
            verbosity=0,
        )
    raise TrainingError(f"unknown model {name!r}; supported: {list(SUPPORTED_MODELS)}")


def _validate(frame: pd.DataFrame, target: str) -> tuple[list[str], int]:
    if frame.empty:
        raise TrainingError("cannot train on an empty dataset")
    if target not in frame.columns:
        raise TrainingError(f"the dataset has no {target!r} column")
    missing = [name for name in FEATURE_NAMES if name not in frame.columns]
    if missing:
        raise TrainingError(f"the dataset is missing feature columns: {missing[:5]}")

    labels = sorted(frame[target].dropna().unique().tolist())
    if len(labels) < 2:
        raise TrainingError(
            f"{target!r} has {len(labels)} distinct value(s) in this dataset "
            f"({labels}); a classifier needs at least two. Training anyway would "
            f"produce a model that answers unconditionally and scores 100%, which is "
            f"not a result."
        )
    if "capture_id" not in frame.columns:
        raise TrainingError(
            "the dataset has no capture_id column, so folds cannot be grouped and "
            "every score would be inflated by leakage between sibling windows"
        )
    return [str(label) for label in labels], frame["capture_id"].nunique()


def cross_validate(
    frame: pd.DataFrame,
    model_name: str = MODEL_RANDOM_FOREST,
    target: str = DEFAULT_TARGET,
    seed: int = DEFAULT_SEED,
    folds: int = DEFAULT_FOLDS,
) -> EvaluationResult:
    """Score a model with folds grouped by capture, never stratified by label."""
    import numpy as np
    from sklearn.metrics import (
        accuracy_score,
        confusion_matrix,
        f1_score,
        precision_recall_fscore_support,
    )
    from sklearn.model_selection import GroupKFold

    labels, group_count = _validate(frame, target)
    usable = frame[frame[target].notna()]
    matrix = usable[list(FEATURE_NAMES)].to_numpy(dtype=float)
    truth = usable[target].astype(str).to_numpy()
    groups = usable["capture_id"].astype(str).to_numpy()

    splits = min(folds, len(set(groups)))
    if splits < 2:
        raise TrainingError(
            f"only {len(set(groups))} distinct capture_id; grouped cross-validation "
            f"needs at least two"
        )

    predictions = np.empty_like(truth)
    splitter = GroupKFold(n_splits=splits)
    for train_index, test_index in splitter.split(matrix, truth, groups):
        model = _build_model(model_name, seed, len(labels))
        fitted_labels = sorted(set(truth[train_index]))
        if len(fitted_labels) < 2:
            predictions[test_index] = fitted_labels[0] if fitted_labels else labels[0]
            continue
        if model_name == MODEL_GRADIENT_BOOSTING:
            lookup = {label: i for i, label in enumerate(fitted_labels)}
            model = _build_model(model_name, seed, len(fitted_labels))
            model.fit(matrix[train_index], [lookup[t] for t in truth[train_index]])
            encoded = model.predict(matrix[test_index])
            predictions[test_index] = [fitted_labels[int(i)] for i in encoded]
        else:
            model.fit(matrix[train_index], truth[train_index])
            predictions[test_index] = model.predict(matrix[test_index])

    precision, recall, f1, support = precision_recall_fscore_support(
        truth, predictions, labels=labels, zero_division=0
    )
    return EvaluationResult(
        model_name=model_name,
        target=target,
        accuracy=float(accuracy_score(truth, predictions)),
        macro_f1=float(f1_score(truth, predictions, average="macro", zero_division=0)),
        per_class=[
            ClassScore(
                label=label,
                precision=float(precision[i]),
                recall=float(recall[i]),
                f1=float(f1[i]),
                support=int(support[i]),
            )
            for i, label in enumerate(labels)
        ],
        confusion_matrix=confusion_matrix(truth, predictions, labels=labels).tolist(),
        labels=labels,
        folds=splits,
        rows=len(usable),
        groups=group_count,
    )


def evaluate_holdout(
    train: pd.DataFrame,
    test: pd.DataFrame,
    model_name: str = MODEL_RANDOM_FOREST,
    target: str = DEFAULT_TARGET,
    seed: int = DEFAULT_SEED,
    split_strategy: str = "held-out split",
) -> EvaluationResult:
    """Fit on one frame and score on another.

    Classes present in test but absent from training are kept in the label set rather
    than dropped. A model that has never seen a class cannot predict it, and silently
    removing it from the report would turn a real failure into a clean-looking score.
    """
    import numpy as np
    from sklearn.metrics import (
        accuracy_score,
        confusion_matrix,
        f1_score,
        precision_recall_fscore_support,
    )

    _validate(train, target)
    if test.empty:
        raise TrainingError("the test side is empty; there is nothing to score")

    train_used = train[train[target].notna()]
    test_used = test[test[target].notna()]
    train_labels = sorted(train_used[target].astype(str).unique().tolist())
    all_labels = sorted(set(train_labels) | set(test_used[target].astype(str).unique().tolist()))

    train_matrix = train_used[list(FEATURE_NAMES)].to_numpy(dtype=float)
    test_matrix = test_used[list(FEATURE_NAMES)].to_numpy(dtype=float)
    train_truth = train_used[target].astype(str).to_numpy()
    test_truth = test_used[target].astype(str).to_numpy()

    model = _build_model(model_name, seed, len(train_labels))
    if model_name == MODEL_GRADIENT_BOOSTING:
        lookup = {label: i for i, label in enumerate(train_labels)}
        model.fit(train_matrix, [lookup[t] for t in train_truth])
        predicted = np.array([train_labels[int(i)] for i in model.predict(test_matrix)])
    else:
        model.fit(train_matrix, train_truth)
        predicted = model.predict(test_matrix)

    precision, recall, f1, support = precision_recall_fscore_support(
        test_truth, predicted, labels=all_labels, zero_division=0
    )
    return EvaluationResult(
        model_name=model_name,
        target=target,
        accuracy=float(accuracy_score(test_truth, predicted)),
        macro_f1=float(f1_score(test_truth, predicted, average="macro", zero_division=0)),
        per_class=[
            ClassScore(
                label=label,
                precision=float(precision[i]),
                recall=float(recall[i]),
                f1=float(f1[i]),
                support=int(support[i]),
            )
            for i, label in enumerate(all_labels)
        ],
        confusion_matrix=confusion_matrix(test_truth, predicted, labels=all_labels).tolist(),
        labels=all_labels,
        folds=1,
        rows=len(test_used),
        groups=test_used["capture_id"].nunique() if "capture_id" in test_used else 0,
        split_strategy=split_strategy,
    )


def compare_models(
    frame: pd.DataFrame,
    target: str = DEFAULT_TARGET,
    seed: int = DEFAULT_SEED,
    folds: int = DEFAULT_FOLDS,
) -> dict[str, EvaluationResult]:
    """Score every supported model on the same folds.

    Returns both rather than naming a winner. Choosing on the folds used to measure is
    selection on the test set; the decision belongs to a held-out split, made
    explicitly.
    """
    return {name: cross_validate(frame, name, target, seed, folds) for name in SUPPORTED_MODELS}


def train_and_persist(
    frame: pd.DataFrame,
    path: Path,
    model_name: str = MODEL_RANDOM_FOREST,
    target: str = DEFAULT_TARGET,
    seed: int = DEFAULT_SEED,
) -> ModelMetadata:
    """Fit on the whole dataset and write the model beside its provenance."""
    import joblib

    labels, _groups = _validate(frame, target)
    usable = frame[frame[target].notna()]
    matrix = usable[list(FEATURE_NAMES)].to_numpy(dtype=float)
    truth = usable[target].astype(str).to_numpy()

    model = _build_model(model_name, seed, len(labels))
    if model_name == MODEL_GRADIENT_BOOSTING:
        lookup = {label: i for i, label in enumerate(labels)}
        model.fit(matrix, [lookup[t] for t in truth])
    else:
        model.fit(matrix, truth)

    metadata = ModelMetadata(
        model_name=model_name,
        target=target,
        feature_names=list(FEATURE_NAMES),
        class_names=labels,
        dataset_checksum=dataset_checksum(frame),
        dataset_rows=len(usable),
        git_sha=current_git_sha(),
        trained_at=datetime.now(UTC).isoformat(),
        seed=seed,
    )

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": model, "metadata": asdict(metadata)}, path)
    path.with_suffix(".metadata.json").write_text(metadata.to_json())
    return metadata


def load_model(path: Path) -> tuple[Any, ModelMetadata]:
    """Load a persisted model and its metadata.

    **joblib is pickle-based, so loading a model executes code from that file.** That is
    a property of the format, not of this function, and it cannot be checked away: a
    hostile ``.joblib`` is arbitrary code execution the moment it is read.

    The policy this project takes is that a model is a **local artefact the operator
    produced**, with ``sentinel model train``, from a dataset they built. It is not
    untrusted input in the way a capture is — a capture arrives from the network and is
    parsed defensively; a model arrives from the operator's own disk. Anyone who can
    write the model file already has whatever access writing files on that host implies.

    What follows from that, and is stated here because it is easy to get wrong: **do not
    load a model somebody sent you.** A pre-trained model from a third party is a
    program, and running it is a decision, not a convenience. Retrain instead; the
    dataset checksum in the metadata is what makes a retrained model comparable.
    """
    import joblib

    payload = joblib.load(Path(path))
    return payload["model"], ModelMetadata(**payload["metadata"])


def predict_with(model: Any, metadata: ModelMetadata, frame: pd.DataFrame) -> list[str]:
    """Predict, refusing a frame whose features do not match the model's.

    A model silently fed a different feature ordering does not fail — it predicts
    confidently and wrongly, which is the worst of both.
    """
    missing = [name for name in metadata.feature_names if name not in frame.columns]
    if missing:
        raise TrainingError(
            f"the frame is missing features this model was trained on: {missing[:5]}"
        )
    matrix = frame[metadata.feature_names].to_numpy(dtype=float)
    predicted = model.predict(matrix)
    if metadata.model_name == MODEL_GRADIENT_BOOSTING:
        return [metadata.class_names[int(i)] for i in predicted]
    return [str(p) for p in predicted]
