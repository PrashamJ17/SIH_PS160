"""Traffic-shape features from an encrypted flow.

Everything here is computed from four observable quantities — packet size, direction,
arrival time, and sequence number — because those are all ESP leaves visible. There is
no cipher field to read and no payload to inspect, so any statement this system makes
about *what a tunnel is carrying* has to be built from these numbers and carries a
calibrated confidence. This module is the boundary where the inference lane begins.

Two properties are load-bearing and tested directly.

**Determinism.** The same packet list must produce the byte-identical feature vector,
every time, on every machine. A model trained on features that drift is a model whose
evaluation numbers mean nothing, and a report whose numbers change between runs cannot
be diffed or trusted. Every statistic here is computed with exact arithmetic over a
fixed ordering, and a test asserts exact float equality across repeated extraction.

**Total, never NaN.** An empty flow, a single-packet flow and a flow whose packets all
arrived in the same microsecond must each produce a full vector of finite numbers. NaN
propagates silently through a model and turns into a prediction nobody can trace, so
every division here has an explicit zero case and the tests cover each one.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from itertools import pairwise
from typing import Final

# A packet at or above this size is treated as MTU-filling. 1400 rather than 1500
# because ESP adds its own header, trailer and padding to the inner packet, so a
# tunnelled full-MTU packet arrives a little under the link MTU.
MTU_THRESHOLD: Final = 1400

# Below this a packet is carrying control or keepalive traffic rather than payload.
SMALL_PACKET_THRESHOLD: Final = 100

# Gap after which the flow is considered to have gone idle and a new burst to begin.
BURST_GAP_S: Final = 1.0


@dataclass(frozen=True)
class DirectedPacket:
    """One observed packet: when it arrived, how big it was, and which way it went."""

    timestamp: datetime
    size: int
    forward: bool
    """True for the direction the flow was first seen in."""


FEATURE_NAMES: Final[tuple[str, ...]] = (
    # Volume
    "packet_count",
    "byte_count",
    "duration_s",
    "bytes_per_s",
    "packets_per_s",
    # Size
    "size_mean",
    "size_std",
    "size_min",
    "size_max",
    "size_median",
    "size_p25",
    "size_p75",
    "size_p90",
    # Size, forward
    "fwd_size_mean",
    "fwd_size_std",
    "fwd_size_min",
    "fwd_size_max",
    "fwd_size_median",
    # Size, backward
    "bwd_size_mean",
    "bwd_size_std",
    "bwd_size_min",
    "bwd_size_max",
    "bwd_size_median",
    # Timing
    "iat_mean",
    "iat_std",
    "iat_min",
    "iat_max",
    "iat_median",
    "iat_p90",
    # Direction
    "fwd_packet_count",
    "bwd_packet_count",
    "fwd_byte_count",
    "bwd_byte_count",
    "fwd_bwd_packet_ratio",
    "fwd_bwd_byte_ratio",
    # Burst
    "burst_count",
    "burst_mean_packets",
    "idle_mean_s",
    "idle_max_s",
    # Shape
    "mtu_fraction",
    "small_packet_fraction",
    "size_entropy",
)

FEATURE_COUNT: Final = len(FEATURE_NAMES)


def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _std(values: list[float]) -> float:
    """Population standard deviation, zero for fewer than two samples.

    Population rather than sample: these are the packets that arrived, not a sample
    drawn from a larger population, and the n-1 correction would divide by zero on a
    single-packet flow.
    """
    if len(values) < 2:
        return 0.0
    mean = _mean(values)
    return math.sqrt(sum((v - mean) ** 2 for v in values) / len(values))


def _percentile(values: list[float], fraction: float) -> float:
    """Linear-interpolated percentile over a sorted copy.

    Implemented rather than taken from numpy so the result cannot shift with a library
    upgrade. A model trained on one interpolation rule and scored under another would
    degrade silently, and this is exactly the kind of drift the determinism test exists
    to prevent.
    """
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    position = fraction * (len(ordered) - 1)
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return float(ordered[lower])
    weight = position - lower
    return float(ordered[lower] * (1.0 - weight) + ordered[upper] * weight)


def _ratio(numerator: float, denominator: float) -> float:
    """Divide, yielding 0.0 rather than NaN or infinity when there is nothing to divide by."""
    return numerator / denominator if denominator else 0.0


def _entropy(sizes: list[int]) -> float:
    """Shannon entropy of the packet size distribution, in bits.

    A constant-rate codec produces near-zero entropy; a mixed web session produces a
    lot. It is one of the few shape features that survives padding, because padding
    changes the sizes but not how varied they are.
    """
    if not sizes:
        return 0.0
    counts = Counter(sizes)
    total = len(sizes)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _size_block(sizes: list[int], prefix: str, full: bool) -> dict[str, float]:
    values = [float(s) for s in sizes]
    block = {
        f"{prefix}size_mean": _mean(values),
        f"{prefix}size_std": _std(values),
        f"{prefix}size_min": float(min(values)) if values else 0.0,
        f"{prefix}size_max": float(max(values)) if values else 0.0,
        f"{prefix}size_median": _percentile(values, 0.5),
    }
    if full:
        block[f"{prefix}size_p25"] = _percentile(values, 0.25)
        block[f"{prefix}size_p75"] = _percentile(values, 0.75)
        block[f"{prefix}size_p90"] = _percentile(values, 0.90)
    return block


def extract_flow_features(packets: list[DirectedPacket]) -> dict[str, float]:
    """Compute the full feature vector for one flow window.

    Packets are sorted by timestamp before anything is computed, so the result is
    independent of the order they were collected in. Capture files interleave
    directions and a flow assembled from two captures can arrive in any order; a
    feature vector that depended on that would be unreproducible for reasons unrelated
    to the traffic.
    """
    ordered = sorted(packets, key=lambda p: (p.timestamp, p.size, p.forward))

    if not ordered:
        return dict.fromkeys(FEATURE_NAMES, 0.0)

    sizes = [p.size for p in ordered]
    forward = [p.size for p in ordered if p.forward]
    backward = [p.size for p in ordered if not p.forward]

    span = (ordered[-1].timestamp - ordered[0].timestamp).total_seconds()
    inter_arrivals = [
        (later.timestamp - earlier.timestamp).total_seconds()
        for earlier, later in pairwise(ordered)
    ]

    # A burst is a run of packets with no gap longer than BURST_GAP_S between them.
    burst_count = 1
    burst_lengths: list[int] = []
    current_burst = 1
    idles: list[float] = []
    for gap in inter_arrivals:
        if gap > BURST_GAP_S:
            burst_count += 1
            burst_lengths.append(current_burst)
            current_burst = 1
            idles.append(gap)
        else:
            current_burst += 1
    burst_lengths.append(current_burst)

    byte_count = float(sum(sizes))
    features: dict[str, float] = {
        "packet_count": float(len(ordered)),
        "byte_count": byte_count,
        "duration_s": span,
        "bytes_per_s": _ratio(byte_count, span),
        "packets_per_s": _ratio(float(len(ordered)), span),
        "iat_mean": _mean(inter_arrivals),
        "iat_std": _std(inter_arrivals),
        "iat_min": min(inter_arrivals) if inter_arrivals else 0.0,
        "iat_max": max(inter_arrivals) if inter_arrivals else 0.0,
        "iat_median": _percentile(inter_arrivals, 0.5),
        "iat_p90": _percentile(inter_arrivals, 0.90),
        "fwd_packet_count": float(len(forward)),
        "bwd_packet_count": float(len(backward)),
        "fwd_byte_count": float(sum(forward)),
        "bwd_byte_count": float(sum(backward)),
        "fwd_bwd_packet_ratio": _ratio(float(len(forward)), float(len(backward))),
        "fwd_bwd_byte_ratio": _ratio(float(sum(forward)), float(sum(backward))),
        "burst_count": float(burst_count),
        "burst_mean_packets": _mean([float(b) for b in burst_lengths]),
        "idle_mean_s": _mean(idles),
        "idle_max_s": max(idles) if idles else 0.0,
        "mtu_fraction": _ratio(
            float(sum(1 for s in sizes if s >= MTU_THRESHOLD)), float(len(sizes))
        ),
        "small_packet_fraction": _ratio(
            float(sum(1 for s in sizes if s < SMALL_PACKET_THRESHOLD)), float(len(sizes))
        ),
        "size_entropy": _entropy(sizes),
    }
    features.update(_size_block(sizes, "", full=True))
    features.update(_size_block(forward, "fwd_", full=False))
    features.update(_size_block(backward, "bwd_", full=False))

    # Emitted in the declared order so the vector and the names never disagree.
    return {name: features[name] for name in FEATURE_NAMES}


def feature_vector(packets: list[DirectedPacket]) -> list[float]:
    """The features as a plain vector, in :data:`FEATURE_NAMES` order."""
    computed = extract_flow_features(packets)
    return [computed[name] for name in FEATURE_NAMES]
