"""Tests for flow feature extraction (build plan Step 7.1).

Two properties carry the weight here. **Determinism**: a model trained on features that
drift is a model whose evaluation numbers mean nothing. **Never NaN**: NaN propagates
silently through a model and becomes a prediction nobody can trace, so every division
has an explicit zero case and each one is covered.
"""

from __future__ import annotations

import math
import random
from datetime import UTC, datetime, timedelta

import pytest

from ipsec_sentinel.features.flow import (
    BURST_GAP_S,
    FEATURE_COUNT,
    FEATURE_NAMES,
    MTU_THRESHOLD,
    SMALL_PACKET_THRESHOLD,
    DirectedPacket,
    extract_flow_features,
    feature_vector,
)

BASE = datetime(2026, 9, 6, 12, 0, 0, tzinfo=UTC)


def packet(offset_s: float, size: int, forward: bool = True) -> DirectedPacket:
    return DirectedPacket(timestamp=BASE + timedelta(seconds=offset_s), size=size, forward=forward)


class TestHandComputedValues:
    """A known packet list against values worked out by hand."""

    @staticmethod
    def _flow() -> list[DirectedPacket]:
        # Four packets, one second apart, sizes 100/200/300/400, alternating direction.
        return [
            packet(0.0, 100, True),
            packet(1.0, 200, False),
            packet(2.0, 300, True),
            packet(3.0, 400, False),
        ]

    def test_volume(self) -> None:
        f = extract_flow_features(self._flow())
        assert f["packet_count"] == 4.0
        assert f["byte_count"] == 1000.0
        assert f["duration_s"] == 3.0
        assert f["bytes_per_s"] == pytest.approx(1000 / 3)
        assert f["packets_per_s"] == pytest.approx(4 / 3)

    def test_size_statistics(self) -> None:
        f = extract_flow_features(self._flow())
        assert f["size_mean"] == 250.0
        assert f["size_min"] == 100.0
        assert f["size_max"] == 400.0
        assert f["size_median"] == 250.0
        assert f["size_p25"] == 175.0
        assert f["size_p75"] == 325.0

    def test_population_standard_deviation(self) -> None:
        """Population, not sample: these are the packets that arrived."""
        f = extract_flow_features(self._flow())
        expected = math.sqrt(((150**2) + (50**2) + (50**2) + (150**2)) / 4)
        assert f["size_std"] == pytest.approx(expected)

    def test_directional_split(self) -> None:
        f = extract_flow_features(self._flow())
        assert f["fwd_packet_count"] == 2.0
        assert f["bwd_packet_count"] == 2.0
        assert f["fwd_byte_count"] == 400.0
        assert f["bwd_byte_count"] == 600.0
        assert f["fwd_size_mean"] == 200.0
        assert f["bwd_size_mean"] == 300.0

    def test_direction_ratios(self) -> None:
        f = extract_flow_features(self._flow())
        assert f["fwd_bwd_packet_ratio"] == 1.0
        assert f["fwd_bwd_byte_ratio"] == pytest.approx(400 / 600)

    def test_inter_arrival_times(self) -> None:
        f = extract_flow_features(self._flow())
        assert f["iat_mean"] == 1.0
        assert f["iat_min"] == 1.0
        assert f["iat_max"] == 1.0
        assert f["iat_std"] == 0.0

    def test_shape(self) -> None:
        f = extract_flow_features(self._flow())
        assert f["mtu_fraction"] == 0.0
        assert f["small_packet_fraction"] == 0.0
        assert f["size_entropy"] == pytest.approx(2.0)  # four equally likely sizes

    def test_mtu_and_small_fractions_are_measured(self) -> None:
        flow = [packet(0.0, MTU_THRESHOLD), packet(1.0, SMALL_PACKET_THRESHOLD - 1)]
        f = extract_flow_features(flow)
        assert f["mtu_fraction"] == 0.5
        assert f["small_packet_fraction"] == 0.5


class TestDeterminism:
    """The property a trustworthy model depends on."""

    @staticmethod
    def _random_flow(seed: int, count: int = 300) -> list[DirectedPacket]:
        rng = random.Random(seed)
        return [
            packet(rng.uniform(0, 30), rng.randint(64, 1500), rng.random() > 0.5)
            for _ in range(count)
        ]

    def test_the_same_input_twice_gives_identical_floats(self) -> None:
        flow = self._random_flow(1)
        assert feature_vector(flow) == feature_vector(flow), "exact float equality"

    def test_shuffling_the_input_does_not_change_the_vector(self) -> None:
        """Captures interleave directions; collection order must not leak into features."""
        flow = self._random_flow(2)
        shuffled = list(flow)
        random.Random(99).shuffle(shuffled)
        assert feature_vector(flow) == feature_vector(shuffled)

    def test_repeated_extraction_is_stable_over_many_runs(self) -> None:
        flow = self._random_flow(3)
        first = feature_vector(flow)
        for _ in range(20):
            assert feature_vector(flow) == first

    def test_percentiles_do_not_depend_on_a_third_party_library(self) -> None:
        """Implemented in-project so a library upgrade cannot silently shift them."""
        flow = [packet(float(i), i * 10) for i in range(1, 11)]
        f = extract_flow_features(flow)
        assert f["size_p25"] == pytest.approx(32.5)
        assert f["size_median"] == pytest.approx(55.0)
        assert f["size_p90"] == pytest.approx(91.0)


class TestNeverNaN:
    @staticmethod
    def _finite(features: dict[str, float]) -> bool:
        return all(math.isfinite(v) for v in features.values())

    def test_an_empty_flow_returns_zeros_not_nan(self) -> None:
        f = extract_flow_features([])
        assert self._finite(f)
        assert all(v == 0.0 for v in f.values())

    def test_a_single_packet_flow_does_not_divide_by_zero(self) -> None:
        f = extract_flow_features([packet(0.0, 512)])
        assert self._finite(f)
        assert f["duration_s"] == 0.0
        assert f["bytes_per_s"] == 0.0
        assert f["size_mean"] == 512.0
        assert f["size_std"] == 0.0

    def test_all_packets_at_the_same_instant(self) -> None:
        """Zero duration must not become an infinite rate."""
        f = extract_flow_features([packet(0.0, 100) for _ in range(50)])
        assert self._finite(f)
        assert f["bytes_per_s"] == 0.0
        assert f["packets_per_s"] == 0.0

    def test_a_unidirectional_flow_does_not_divide_by_zero(self) -> None:
        f = extract_flow_features([packet(float(i), 100, True) for i in range(5)])
        assert self._finite(f)
        assert f["bwd_packet_count"] == 0.0
        assert f["fwd_bwd_packet_ratio"] == 0.0
        assert f["bwd_size_mean"] == 0.0

    def test_a_backward_only_flow_does_not_divide_by_zero(self) -> None:
        f = extract_flow_features([packet(float(i), 100, False) for i in range(5)])
        assert self._finite(f)
        assert f["fwd_packet_count"] == 0.0
        assert f["fwd_bwd_byte_ratio"] == 0.0

    def test_zero_sized_packets_are_survived(self) -> None:
        assert self._finite(extract_flow_features([packet(float(i), 0) for i in range(5)]))

    @pytest.mark.parametrize("count", [0, 1, 2, 3, 500])
    def test_every_flow_length_is_finite(self, count: int) -> None:
        flow = [packet(i * 0.01, 100 + i) for i in range(count)]
        assert self._finite(extract_flow_features(flow))


class TestVectorShape:
    def test_the_vector_length_is_constant_across_inputs(self) -> None:
        for flow in (
            [],
            [packet(0.0, 100)],
            [packet(float(i), 100 + i, i % 2 == 0) for i in range(200)],
        ):
            assert len(feature_vector(flow)) == FEATURE_COUNT

    def test_the_names_match_the_vector_length(self) -> None:
        assert len(FEATURE_NAMES) == FEATURE_COUNT
        assert len(set(FEATURE_NAMES)) == FEATURE_COUNT, "duplicate feature name"

    def test_the_keys_are_exactly_the_declared_names(self) -> None:
        assert set(extract_flow_features([packet(0.0, 100)])) == set(FEATURE_NAMES)

    def test_the_vector_order_matches_the_declared_order(self) -> None:
        flow = [packet(float(i), 100 + i) for i in range(10)]
        computed = extract_flow_features(flow)
        assert feature_vector(flow) == [computed[name] for name in FEATURE_NAMES]


class TestBursts:
    def test_a_continuous_flow_is_one_burst(self) -> None:
        flow = [packet(i * 0.1, 100) for i in range(20)]
        assert extract_flow_features(flow)["burst_count"] == 1.0

    def test_a_gap_starts_a_new_burst(self) -> None:
        flow = [packet(0.0, 100), packet(0.1, 100), packet(10.0, 100), packet(10.1, 100)]
        f = extract_flow_features(flow)
        assert f["burst_count"] == 2.0
        assert f["burst_mean_packets"] == 2.0
        assert f["idle_max_s"] == pytest.approx(9.9)

    def test_a_gap_at_exactly_the_threshold_does_not_split(self) -> None:
        flow = [packet(0.0, 100), packet(BURST_GAP_S, 100)]
        assert extract_flow_features(flow)["burst_count"] == 1.0

    def test_a_flow_with_no_idle_reports_zero_idle(self) -> None:
        f = extract_flow_features([packet(i * 0.1, 100) for i in range(10)])
        assert f["idle_mean_s"] == 0.0
        assert f["idle_max_s"] == 0.0


class TestEntropy:
    def test_a_constant_rate_flow_has_zero_size_entropy(self) -> None:
        """A codec at a fixed bitrate is the low-entropy extreme."""
        assert (
            extract_flow_features([packet(i * 0.02, 172) for i in range(100)])["size_entropy"]
            == 0.0
        )

    def test_varied_sizes_have_higher_entropy(self) -> None:
        varied = extract_flow_features(
            [packet(i * 0.02, 64 + (i * 37) % 1400) for i in range(100)]
        )["size_entropy"]
        assert varied > 4.0
