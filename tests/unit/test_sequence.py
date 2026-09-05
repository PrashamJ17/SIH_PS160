"""Tests for ESP sequence and replay analysis (build plan Step 5.3).

The last class is the important one. Everything above it checks the analyser against
sequences this file constructed, which proves the arithmetic and nothing else. The
cross-check measures loss on real captures and compares it against the loss `tc netem`
was *told* to inject — ground truth this project did not compute, so it can disagree.
"""

from __future__ import annotations

import time
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path

import pytest

from ipsec_sentinel.parser.esp import AssembledFlow, analyse_sequence, flows_from_capture
from testbed.orchestrate.netem import PROFILES_BY_NAME

BASE = datetime(2026, 9, 5, 12, 0, 0, tzinfo=UTC)


def flow(sequences: list[int]) -> AssembledFlow:
    return AssembledFlow(
        spi="deadbeef",
        src_ip="192.0.2.1",
        dst_ip="192.0.2.2",
        sizes=[100] * len(sequences),
        sequences=list(sequences),
        timestamps=[BASE + timedelta(milliseconds=i) for i in range(len(sequences))],
    )


class TestCleanSequences:
    def test_a_perfect_sequence_has_no_gaps_and_no_duplicates(self) -> None:
        analysis = analyse_sequence(flow(list(range(1, 101))))
        assert analysis.gap_count == 0
        assert analysis.duplicates == 0
        assert analysis.reorders == 0
        assert analysis.missing_count == 0
        assert analysis.loss_ratio == 0.0
        assert analysis.replay_suspected is False

    def test_the_span_is_reported(self) -> None:
        analysis = analyse_sequence(flow(list(range(1, 101))))
        assert (analysis.lowest, analysis.highest) == (1, 100)
        assert analysis.expected_count == 100
        assert analysis.packet_count == 100

    def test_an_empty_flow_analyses_to_nothing_rather_than_raising(self) -> None:
        analysis = analyse_sequence(flow([]))
        assert analysis.packet_count == 0
        assert analysis.gap_count == 0
        assert analysis.loss_ratio == 0.0

    def test_a_single_packet_flow_is_not_loss(self) -> None:
        analysis = analyse_sequence(flow([7]))
        assert analysis.missing_count == 0
        assert analysis.expected_count == 1


class TestLoss:
    def test_one_missing_number_is_one_gap_of_size_one(self) -> None:
        analysis = analyse_sequence(flow([n for n in range(1, 101) if n != 50]))
        assert analysis.gap_count == 1
        assert analysis.gaps[0].size == 1
        assert analysis.gaps[0].start == analysis.gaps[0].end == 50
        assert analysis.missing_count == 1

    def test_a_run_of_missing_numbers_is_one_gap_not_many(self) -> None:
        """A burst loss is one event; counting it as five overstates the instability."""
        analysis = analyse_sequence(flow([n for n in range(1, 21) if n not in range(5, 10)]))
        assert analysis.gap_count == 1
        assert analysis.gaps[0].size == 5

    def test_separate_losses_are_separate_gaps(self) -> None:
        analysis = analyse_sequence(flow([n for n in range(1, 21) if n not in (5, 15)]))
        assert analysis.gap_count == 2
        assert analysis.missing_count == 2

    def test_loss_ratio_is_missing_over_expected(self) -> None:
        analysis = analyse_sequence(flow([n for n in range(1, 100) if n % 10 != 0]))
        assert analysis.missing_count == 9  # 10, 20, ... 90
        assert analysis.expected_count == 99
        assert analysis.loss_ratio == pytest.approx(9 / 99)

    def test_loss_past_the_last_arrival_is_not_counted(self) -> None:
        """A passive observer cannot know a packet was sent if none after it arrived.

        Counting the tail as loss would let a flow that simply ended look like one
        that failed, and every truncated capture would report phantom loss.
        """
        analysis = analyse_sequence(flow([1, 2, 3]))
        assert analysis.missing_count == 0
        assert analysis.highest == 3


class TestReordering:
    def test_one_swap_is_one_reorder_and_no_gaps(self) -> None:
        analysis = analyse_sequence(flow([1, 3, 2, 4]))
        assert analysis.reorders == 1
        assert analysis.gap_count == 0
        assert analysis.duplicates == 0

    def test_reordering_is_not_counted_as_loss(self) -> None:
        """Every number arrived; only the order was wrong."""
        analysis = analyse_sequence(flow([5, 4, 3, 2, 1]))
        assert analysis.missing_count == 0
        assert analysis.reorders == 4

    def test_in_order_arrival_produces_no_reorders(self) -> None:
        assert analyse_sequence(flow([1, 2, 3, 4, 5])).reorders == 0


class TestReplay:
    def test_a_duplicate_sets_replay_suspected(self) -> None:
        analysis = analyse_sequence(flow([1, 2, 3, 50, 50, 4]))
        assert analysis.duplicates == 1
        assert analysis.replay_suspected is True

    def test_many_duplicates_are_all_counted(self) -> None:
        analysis = analyse_sequence(flow([1, 1, 1, 2, 2]))
        assert analysis.duplicates == 3

    def test_no_duplicates_means_no_suspicion(self) -> None:
        assert analyse_sequence(flow(list(range(1, 51)))).replay_suspected is False

    def test_the_finding_is_suspicion_rather_than_detection(self) -> None:
        """A passive observer cannot distinguish a replay from a network duplicate.

        The evidence is real; the conclusion is not certain. Naming it `detected`
        would be exactly the overclaim this project exists to avoid.
        """
        from ipsec_sentinel.parser.esp import SequenceAnalysis

        assert hasattr(SequenceAnalysis, "replay_suspected")
        assert not hasattr(SequenceAnalysis, "replay_detected")


class TestWrapping:
    def test_a_wrap_is_a_wrap_and_not_four_billion_missing_packets(self) -> None:
        analysis = analyse_sequence(flow([0xFFFFFFFE, 0xFFFFFFFF, 0, 1]))
        assert analysis.wraps == 1
        assert analysis.missing_count == 0
        assert analysis.gap_count == 0

    def test_a_wrap_is_not_counted_as_a_reorder(self) -> None:
        assert analyse_sequence(flow([0xFFFFFFFF, 0, 1])).reorders == 0

    def test_loss_across_a_wrap_is_still_seen(self) -> None:
        analysis = analyse_sequence(flow([0xFFFFFFFE, 0, 1]))
        assert analysis.wraps == 1
        assert analysis.missing_count == 1  # 0xFFFFFFFF never arrived

    def test_two_wraps_are_counted(self) -> None:
        analysis = analyse_sequence(flow([0xFFFFFFFF, 0, 0xFFFFFFFF, 0]))
        assert analysis.wraps == 2

    def test_a_flow_with_no_wrap_reports_none(self) -> None:
        assert analyse_sequence(flow([1, 2, 3])).wraps == 0


CAPTURES = sorted(Path("data/raw/sweep").glob("*/capture_outer.pcap"))

# Enough captures to estimate a sub-percent loss rate, few enough that this stays a
# unit test. The sample is a deterministic stride over the sorted list rather than the
# first N, because cell IDs sort by configuration hash and the first N would over-weight
# a handful of configurations.
CROSS_CHECK_SAMPLE = 60


def _profile_of(cell_name: str) -> str | None:
    for name in ("clean", "wan_good", "wan_poor"):
        if cell_name.endswith(f"_{name}_r0"):
            return name
    return None


@lru_cache(maxsize=1)
def _measured_loss() -> dict[str, tuple[float, ...]]:
    """Loss ratio per flow, grouped by impairment profile.

    Cached: every test in the cross-check needs the same measurement, and parsing the
    corpus four times would put a minute of capture parsing into `make verify` — which
    runs before every commit, and which nobody keeps running if it is slow.
    """
    candidates = [p for p in CAPTURES if _profile_of(p.parent.name) is not None]
    stride = max(1, len(candidates) // CROSS_CHECK_SAMPLE)
    sampled = candidates[::stride][:CROSS_CHECK_SAMPLE]

    by_profile: dict[str, list[float]] = defaultdict(list)
    for pcap in sampled:
        profile = _profile_of(pcap.parent.name)
        assert profile is not None
        for assembled in flows_from_capture(pcap):
            # Short flows cannot measure a sub-percent loss rate at all.
            if assembled.packet_count < 20:
                continue
            by_profile[profile].append(analyse_sequence(assembled).loss_ratio)
    return {name: tuple(values) for name, values in by_profile.items()}


@pytest.mark.skipif(len(CAPTURES) < 30, reason="too few sweep captures for a cross-check")
class TestImpairmentCrossCheck:
    """Validate the analyser against loss the testbed was told to inject.

    This is the only test in the file whose expected values this project did not
    compute. `tc netem` was configured with a loss percentage per profile; the
    analyser measures loss independently, from ESP sequence numbers, on captures
    strongSwan produced. If the two agree, the analyser measures reality.
    """

    def test_clean_flows_show_no_loss_at_all(self) -> None:
        measured = _measured_loss()
        assert measured.get("clean"), "no clean flows to check"
        assert max(measured["clean"]) == 0.0, (
            "the clean profile injects no loss, so any gap is either a capture defect "
            "or a bug in the analyser"
        )

    def test_impaired_flows_show_loss(self) -> None:
        measured = _measured_loss()
        assert measured.get("wan_poor"), "no wan_poor flows to check"
        lossy = [ratio for ratio in measured["wan_poor"] if ratio > 0]
        assert lossy, "wan_poor injects 1% loss; no flow showed any"

    def test_measured_loss_recovers_the_injected_rate(self) -> None:
        """The strongest form: the number, not just its sign."""
        measured = _measured_loss()
        for profile in ("wan_good", "wan_poor"):
            if not measured.get(profile):
                pytest.skip(f"no {profile} flows yet")
            injected = PROFILES_BY_NAME[profile].loss_pct / 100.0
            mean = sum(measured[profile]) / len(measured[profile])
            assert mean == pytest.approx(injected, rel=0.5), (
                f"{profile}: netem was told to drop {injected:.2%}, sequence numbers "
                f"show {mean:.4%}"
            )

    def test_loss_increases_with_the_severity_of_the_profile(self) -> None:
        measured = _measured_loss()
        if not all(measured.get(n) for n in ("clean", "wan_good", "wan_poor")):
            pytest.skip("not all profiles present yet")
        means = {name: sum(values) / len(values) for name, values in measured.items()}
        assert means["clean"] < means["wan_good"] < means["wan_poor"]


class TestSpanIsNotWalked:
    """Regression: gap-finding must be O(packets), never O(sequence span).

    The first version walked every integer between the lowest and highest sequence
    number. That is fine for a well-behaved flow, where the span is roughly the packet
    count — and catastrophic for anything else. Two counter wraps put four billion
    values between lowest and highest, so a four-packet flow took 82 seconds to
    analyse. A flow arriving from a hostile peer is attacker-controlled input, and an
    analyser that can be stalled by six bytes of it is the same defect the parser
    fuzzing exists to prevent, one layer up.
    """

    TIME_LIMIT_S = 1.0

    def _timed(self, sequences: list[int]) -> float:
        started = time.perf_counter()
        analyse_sequence(flow(sequences))
        return time.perf_counter() - started

    def test_two_wraps_are_analysed_immediately(self) -> None:
        assert self._timed([0xFFFFFFFF, 0, 0xFFFFFFFF, 0]) < self.TIME_LIMIT_S

    def test_a_maximally_wide_span_is_analysed_immediately(self) -> None:
        assert self._timed([0, 0xFFFFFFFF]) < self.TIME_LIMIT_S

    def test_many_wraps_are_analysed_immediately(self) -> None:
        assert self._timed([0xFFFFFFFF, 0] * 50) < self.TIME_LIMIT_S

    def test_a_wide_span_still_reports_the_gap_correctly(self) -> None:
        """Fast and wrong would be no better than slow and right."""
        analysis = analyse_sequence(flow([0, 0xFFFFFFFF]))
        assert analysis.gap_count == 1
        assert analysis.gaps[0].start == 1
        assert analysis.gaps[0].end == 0xFFFFFFFE
        assert analysis.missing_count == 0xFFFFFFFF - 1
