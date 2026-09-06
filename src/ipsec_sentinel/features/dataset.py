"""Assemble the labelled ML dataset: one row per (flow, window).

Two decisions here determine whether every later number is meaningful.

**Labels come from what was negotiated, not from what was configured.** The manifest
carries both, and they can disagree — a peer may accept a weaker proposal than the one
intended, or fail to install the child SA at all. Training on intent would teach a model
to predict the configuration file rather than the traffic, and the resulting accuracy
would be a measurement of the testbed rather than of anything real. Where the negotiated
value is missing, the label is ``None`` and the row is dropped for that target rather
than silently backfilled from intent.

**Every row carries its grouping keys.** ``capture_id`` and ``config_id`` are not
metadata here; they are what makes the next step possible. Windows cut from one capture
are near-duplicates of each other, so a random train/test split puts sibling windows on
both sides and produces an accuracy that measures memorisation. Splitting on these keys
is the only thing standing between an honest number and a flattering one, and they have
to be present on every row for that to be possible.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from ipsec_sentinel.features.flow import FEATURE_NAMES, DirectedPacket, extract_flow_features
from ipsec_sentinel.parser.esp import ESPPacket, assemble_esp_flows, extract_esp_packets

if TYPE_CHECKING:  # pragma: no cover - import cycle avoidance only
    import pandas as pd

DEFAULT_WINDOW_S: Final = 30

# A window with fewer packets than this produces a feature vector with nothing in it:
# no inter-arrival distribution, no burst structure, no meaningful percentiles. The
# extractor returns finite zeros for all of them, which is correct behaviour and
# useless training data — a row of zeros labelled "voip" teaches a model that voip
# looks like nothing.
#
# It also removes a class of artefact this corpus actually contains. The replay
# generator emits protocol-50 packets from its source corpus onto the transit link;
# each carries a distinct random SPI, so each becomes a one-packet pseudo-flow. Those
# survive the parser's structural floor when they are large enough, and they inflated
# one traffic class from 36% to 61% of the dataset before this threshold was added.
#
# Ten is the smallest count at which the inter-arrival and burst features have more
# than one sample to describe.
MIN_PACKETS_PER_WINDOW: Final = 10

# Columns that are neither features nor labels: they identify the row's provenance and
# drive leakage-free splitting.
GROUPING_COLUMNS: Final[tuple[str, ...]] = (
    "capture_id",
    "config_id",
    "flow_key",
    "window_index",
)

LABEL_COLUMNS: Final[tuple[str, ...]] = (
    "inner_traffic",
    "traffic_variant",
    "mode",
    "cipher",
    "cipher_keylen",
    "integrity",
    "dh_group",
    "ike_version",
    "pfs",
    "impairment",
)


@dataclass(frozen=True)
class LabelledFlowWindow:
    """One window of one flow, with its features, labels and provenance."""

    capture_id: str
    config_id: str
    flow_key: str
    window_index: int
    features: dict[str, float]
    labels: dict[str, Any]

    def as_row(self) -> dict[str, Any]:
        row: dict[str, Any] = {
            "capture_id": self.capture_id,
            "config_id": self.config_id,
            "flow_key": self.flow_key,
            "window_index": self.window_index,
        }
        row.update(self.features)
        row.update(self.labels)
        return row


def load_manifest(path: Path) -> dict[str, Any]:
    """Read one manifest, raising nothing the caller cannot act on."""
    loaded = json.loads(Path(path).read_text())
    if not isinstance(loaded, dict):
        raise ValueError(f"{path}: expected a mapping at the top level")
    return loaded


def labels_from_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    """Extract labels, preferring negotiated reality over configured intent.

    ``pfs`` is the exception and is taken from intent, because whether a child SA
    performed its own Diffie-Hellman exchange is not recoverable from the manifest's
    negotiated section — the same limit the SA rules document. It is labelled here
    because the testbed knows it; a deployed analyser does not, which is exactly why
    PFS-01 refuses to guess.
    """
    negotiated_ike = manifest.get("negotiated_ike") or {}
    negotiated_child = manifest.get("negotiated_child") or {}
    intent = manifest.get("intent") or {}
    meta = manifest.get("capture_meta") or {}

    return {
        "inner_traffic": meta.get("generator"),
        "traffic_variant": meta.get("variant"),
        "mode": negotiated_child.get("mode") or intent.get("mode"),
        "cipher": negotiated_ike.get("encryption"),
        "cipher_keylen": negotiated_ike.get("encryption_keylen"),
        "integrity": negotiated_ike.get("integrity"),
        "dh_group": negotiated_ike.get("dh_group"),
        "ike_version": negotiated_ike.get("ike_version"),
        "pfs": intent.get("pfs"),
        "impairment": meta.get("impairment"),
    }


def _windows(packets: list[ESPPacket], window_s: int) -> Iterator[tuple[int, list[ESPPacket]]]:
    """Split a flow's packets into fixed-length windows from its first packet.

    Windows are anchored to the flow's own start rather than to wall-clock boundaries,
    so a capture that happens to begin mid-minute is not penalised with a truncated
    first window. Empty windows are not emitted: a window with no packets is not an
    observation of silence, it is an absence of data.
    """
    if not packets:
        return
    ordered = sorted(packets, key=lambda p: p.timestamp)
    start = ordered[0].timestamp
    span = timedelta(seconds=window_s)
    current: list[ESPPacket] = []
    index = 0
    boundary = start + span
    for packet in ordered:
        while packet.timestamp >= boundary:
            if current:
                yield index, current
            current = []
            index += 1
            boundary += span
        current.append(packet)
    if current:
        yield index, current


def _to_directed(packets: list[ESPPacket]) -> list[DirectedPacket]:
    """Mark direction relative to the first packet seen in the flow."""
    if not packets:
        return []
    ordered = sorted(packets, key=lambda p: p.timestamp)
    forward_src = ordered[0].src_ip
    return [
        DirectedPacket(timestamp=p.timestamp, size=p.size, forward=(p.src_ip == forward_src))
        for p in ordered
    ]


def windows_for_capture(
    manifest_path: Path,
    window_s: int = DEFAULT_WINDOW_S,
    min_packets: int = MIN_PACKETS_PER_WINDOW,
) -> list[LabelledFlowWindow]:
    """Every labelled flow window from one capture with enough packets to have a shape."""
    manifest = load_manifest(manifest_path)
    meta = manifest.get("capture_meta") or {}
    pcap = manifest_path.parent / str(meta.get("outer_pcap", "capture_outer.pcap"))
    if not pcap.exists():
        return []

    labels = labels_from_manifest(manifest)
    rows: list[LabelledFlowWindow] = []
    for flow in assemble_esp_flows(extract_esp_packets(pcap)):
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
        for index, window in _windows(packets, window_s):
            if len(window) < min_packets:
                continue
            rows.append(
                LabelledFlowWindow(
                    capture_id=str(manifest.get("capture_id", manifest_path.parent.name)),
                    config_id=str(manifest.get("config_id", "")),
                    flow_key=f"{flow.src_ip}->{flow.dst_ip}:{flow.spi}",
                    window_index=index,
                    features=extract_flow_features(_to_directed(window)),
                    labels=dict(labels),
                )
            )
    return rows


def build_ml_dataset(
    manifests: Iterable[Path],
    window_s: int = DEFAULT_WINDOW_S,
    min_packets: int = MIN_PACKETS_PER_WINDOW,
) -> pd.DataFrame:
    """Build the full labelled dataset, one row per (flow, window).

    Columns are ordered grouping keys, then features, then labels, so a reader opening
    the frame sees provenance before numbers.
    """
    import pandas as pd

    rows = [
        window.as_row()
        for manifest in manifests
        for window in windows_for_capture(Path(manifest), window_s, min_packets)
    ]
    columns = [*GROUPING_COLUMNS, *FEATURE_NAMES, *LABEL_COLUMNS]
    if not rows:
        return pd.DataFrame(columns=list(columns))
    frame = pd.DataFrame(rows)
    return frame[list(columns)]


def find_manifests(root: Path) -> list[Path]:
    """Every capture manifest under a sweep directory, in a stable order."""
    return sorted(Path(root).glob("*/manifest.json"))


def dataset_summary(frame: pd.DataFrame) -> dict[str, Any]:
    """A short description a report or a notebook header can print."""
    if frame.empty:
        return {"rows": 0, "captures": 0, "configs": 0}
    return {
        "rows": len(frame),
        "captures": int(frame["capture_id"].nunique()),
        "configs": int(frame["config_id"].nunique()),
        "flows": int(frame["flow_key"].nunique()),
        "traffic_classes": sorted(frame["inner_traffic"].dropna().unique().tolist()),
        "ciphers": sorted(frame["cipher"].dropna().unique().tolist()),
        "dh_groups": sorted(frame["dh_group"].dropna().unique().tolist()),
    }
