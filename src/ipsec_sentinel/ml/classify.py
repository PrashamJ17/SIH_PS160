"""Classify a live tunnel's traffic, and say why.

Kept out of :mod:`ipsec_sentinel.analyse` on purpose. Analysis must work with no model
present — a run that silently produced no inferences because a file was missing would be
indistinguishable from one that inferred nothing because there was nothing to infer, and
the second is a real result while the first is a broken install.

Everything this produces is a Section B estimate. It arrives with a calibrated
confidence, it abstains when the model is not confident enough to be useful, and the SHAP
contributions travel with it so a reader can see which features drove the answer rather
than being asked to trust it.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from ipsec_sentinel.features.dataset import (
    DEFAULT_WINDOW_S,
    MIN_PACKETS_PER_WINDOW,
    _to_directed,
    _windows,
)
from ipsec_sentinel.features.flow import extract_flow_features
from ipsec_sentinel.parser.correlate import Tunnel
from ipsec_sentinel.parser.esp import AssembledFlow, ESPPacket

DEFAULT_MODEL_PATH: Final = Path("models/traffic.joblib")


class ClassifierUnavailableError(RuntimeError):
    """No usable model, said out loud rather than by returning nothing."""


@dataclass(frozen=True)
class Classification:
    """One tunnel's inferred application class, with the reasoning behind it."""

    tunnel_id: str
    predicted: str
    confidence: float
    abstained: bool
    method: str
    windows: int
    contributions: tuple[tuple[str, float], ...] = ()
    sentence: str = ""

    @property
    def stated(self) -> str | None:
        """The class, or ``None`` when the model abstained.

        An abstention is not a quiet "probably voip". It is the model saying it does not
        know, and the caller must not be able to read it as an answer by accident.
        """
        return None if self.abstained else self.predicted


def _flow_windows(flow: AssembledFlow, window_s: int, min_packets: int) -> list[list[Any]]:
    packets = [
        ESPPacket(
            timestamp=timestamp,
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            spi=flow.spi,
            sequence=sequence,
            size=size,
        )
        for timestamp, sequence, size in zip(
            flow.timestamps, flow.sequences, flow.sizes, strict=True
        )
    ]
    return [
        _to_directed(window)
        for _, window in _windows(packets, window_s)
        if len(window) >= min_packets
    ]


def load_classifier(path: Path = DEFAULT_MODEL_PATH) -> tuple[Any, Any]:
    """Load a persisted model and its metadata, or say why it cannot be used."""
    if not path.exists():
        raise ClassifierUnavailableError(
            f"no model at {path}. Train one with `sentinel model train`, or run without "
            f"one — the assessment does not depend on it."
        )
    try:
        from ipsec_sentinel.ml.train import load_model

        return load_model(path)
    except Exception as exc:  # a corrupt or incompatible artefact is not a crash
        raise ClassifierUnavailableError(f"the model at {path} could not be loaded: {exc}") from exc


def classify_tunnel(
    tunnel: Tunnel,
    model: Any,
    metadata: Any,
    *,
    window_s: int = DEFAULT_WINDOW_S,
    min_packets: int = MIN_PACKETS_PER_WINDOW,
    explain: bool = True,
) -> Classification | None:
    """Infer what one tunnel carries, or ``None`` if it carried too little to judge.

    ``None`` rather than a low-confidence guess: a tunnel with three packets has no
    traffic shape, and inventing one would put a number on nothing.
    """
    import pandas as pd

    from ipsec_sentinel.ml.predict import predict_with_abstention

    windows = [w for flow in tunnel.flows for w in _flow_windows(flow, window_s, min_packets)]
    if not windows:
        return None

    rows = [extract_flow_features(window) for window in windows]
    frame = pd.DataFrame(rows)[metadata.feature_names]
    predictions = predict_with_abstention(
        model, frame, metadata.class_names, metadata.feature_names
    )
    if not predictions:
        return None

    # The estate cares about what the tunnel carries, not what each 10-second window
    # carried. The most confident window speaks for the tunnel, and the count of windows
    # travels with it so a reader can weigh one window against thirty.
    best = max(predictions, key=lambda p: p.confidence.value)

    contributions: tuple[tuple[str, float], ...] = ()
    sentence = ""
    if explain:
        from ipsec_sentinel.ml.explain import explain_prediction

        index = predictions.index(best)
        explanation = explain_prediction(
            model, frame.iloc[[index]], metadata.class_names, metadata.feature_names
        )
        contributions = tuple((c.feature, c.contribution) for c in explanation.contributions)
        sentence = explanation.sentence()

    # ``best_label`` is the class, always. ``label`` is the class *or* an abstention
    # sentinel, and preferring it meant an abstention reported its predicted class as
    # "insufficient_signal" — turning a near-miss on voip into a nonsense answer, and
    # putting the sentinel into the SHAP sentence beside it.
    #
    # The class and the abstention are separate facts and are carried separately:
    # ``predicted`` says what the model leaned towards, ``abstained`` says whether it
    # was willing to commit, and :attr:`Classification.stated` returns ``None`` unless
    # it was. Nothing downstream can read a declined answer as a given one.
    predicted = best.best_label or best.label or "unknown"
    return Classification(
        tunnel_id=tunnel.tunnel_id,
        predicted=predicted,
        confidence=best.confidence.value,
        abstained=best.abstained,
        method=best.confidence.method,
        windows=len(windows),
        contributions=contributions,
        sentence=sentence,
    )


def classify_all(
    tunnels: list[Tunnel], path: Path = DEFAULT_MODEL_PATH, *, explain: bool = True
) -> dict[str, Classification]:
    """Classify every tunnel that carried enough traffic to have a shape."""
    model, metadata = load_classifier(path)
    results: dict[str, Classification] = {}
    for tunnel in tunnels:
        classified = classify_tunnel(tunnel, model, metadata, explain=explain)
        if classified is not None:
            results[tunnel.tunnel_id] = classified
    return results
