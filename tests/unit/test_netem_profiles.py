"""Unit tests for impairment profile definitions (build plan Step 2.9)."""

from __future__ import annotations

import pytest

from testbed.orchestrate.netem import PROFILES, PROFILES_BY_NAME, ImpairmentProfile, profile


class TestProfileSet:
    def test_the_five_named_profiles_exist(self) -> None:
        assert {p.name for p in PROFILES} == {"clean", "lan", "wan_good", "wan_poor", "satellite"}

    def test_profiles_are_ordered_by_increasing_severity(self) -> None:
        delays = [p.delay_ms for p in PROFILES]
        assert delays == sorted(delays)

    def test_names_are_unique(self) -> None:
        assert len(PROFILES_BY_NAME) == len(PROFILES)

    def test_unknown_profile_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="unknown impairment profile"):
            profile("dial_up")

    def test_lookup_returns_the_profile(self) -> None:
        assert profile("wan_poor").delay_ms == 80


class TestCleanProfile:
    def test_clean_asks_for_no_shaping(self) -> None:
        assert profile("clean").is_clean is True

    @pytest.mark.parametrize("name", ["lan", "wan_good", "wan_poor", "satellite"])
    def test_every_other_profile_shapes(self, name: str) -> None:
        assert profile(name).is_clean is False


class TestNetemArguments:
    def test_delay_and_jitter_are_expressed(self) -> None:
        args = profile("wan_poor").netem_args()
        assert args[0] == "netem"
        assert "delay" in args
        assert "80ms" in args
        assert "15ms" in args

    def test_jitter_uses_a_normal_distribution(self) -> None:
        """Uniform jitter is not what a real path does."""
        assert "distribution" in profile("wan_good").netem_args()

    def test_zero_jitter_omits_the_distribution(self) -> None:
        assert "distribution" not in profile("lan").netem_args()

    def test_loss_is_expressed_as_a_percentage(self) -> None:
        args = profile("satellite").netem_args()
        assert "loss" in args
        assert "2.0%" in args

    def test_no_loss_omits_the_loss_clause(self) -> None:
        assert "loss" not in profile("lan").netem_args()

    def test_rate_cap_is_expressed(self) -> None:
        assert "10mbit" in profile("wan_poor").netem_args()

    def test_absent_rate_cap_is_omitted(self) -> None:
        assert "rate" not in profile("clean").netem_args()

    def test_round_trip_delay_counts_both_directions(self) -> None:
        """netem shapes egress, so both gateways contribute to the round trip."""
        assert profile("wan_poor").expected_min_rtt_ms() == 160.0

    def test_a_custom_profile_expands_correctly(self) -> None:
        custom = ImpairmentProfile("custom", 5, 1, 0.5, 50)
        args = custom.netem_args()
        assert args == [
            "netem",
            "delay",
            "5ms",
            "1ms",
            "distribution",
            "normal",
            "loss",
            "0.5%",
            "rate",
            "50mbit",
        ]
