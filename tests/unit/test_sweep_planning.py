"""Tests for sweep planning, balance and resumability (build plan Step 3.2)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from testbed.orchestrate.matrix import expand_matrix
from testbed.orchestrate.sweep import (
    DEFAULT_IMPAIRMENTS,
    MAX_SLOTS,
    BalanceError,
    Slot,
    SweepState,
    check_balance,
    load_state,
    plan_sweep,
    remaining_cells,
    save_state,
    slots,
)
from testbed.traffic.registry import GENERATOR_NAMES

CONFIG_COUNT = len(expand_matrix())


class TestPlanSize:
    def test_cell_count_is_configs_times_generators_times_impairments_times_repeats(
        self,
    ) -> None:
        plan = plan_sweep(repeats=2)
        expected = CONFIG_COUNT * len(GENERATOR_NAMES) * len(DEFAULT_IMPAIRMENTS) * 2
        assert len(plan) == expected

    def test_single_repeat_is_the_default(self) -> None:
        plan = plan_sweep()
        assert len(plan) == CONFIG_COUNT * len(GENERATOR_NAMES) * len(DEFAULT_IMPAIRMENTS)

    def test_max_configs_truncates_the_plan(self) -> None:
        plan = plan_sweep(max_configs=3)
        assert len(plan) == 3 * len(GENERATOR_NAMES) * len(DEFAULT_IMPAIRMENTS)

    def test_cell_ids_are_unique(self) -> None:
        ids = [cell.cell_id for cell in plan_sweep(repeats=2).cells]
        assert len(ids) == len(set(ids))

    def test_planning_is_deterministic(self) -> None:
        """A resumed sweep replans; the identities must come out identical."""
        assert [c.cell_id for c in plan_sweep().cells] == [c.cell_id for c in plan_sweep().cells]

    def test_unknown_generator_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="unknown generator"):
            plan_sweep(generators=("telepathy",))

    def test_unknown_impairment_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="unknown impairment profile"):
            plan_sweep(impairments=("hurricane",))


class TestCoverage:
    def test_every_generator_appears(self) -> None:
        plan = plan_sweep()
        assert {c.generator for c in plan.cells} == set(GENERATOR_NAMES)

    def test_every_impairment_appears(self) -> None:
        plan = plan_sweep()
        assert {c.impairment for c in plan.cells} == set(DEFAULT_IMPAIRMENTS)

    def test_every_variant_of_every_generator_appears(self) -> None:
        """Variants are cycled rather than multiplied, but none may be dropped."""
        from testbed.traffic.registry import variants_of

        plan = plan_sweep()
        for generator in GENERATOR_NAMES:
            seen = {c.variant for c in plan.cells if c.generator == generator}
            assert seen == set(variants_of(generator)), f"{generator}: {seen}"

    def test_every_configuration_appears(self) -> None:
        plan = plan_sweep()
        assert len({c.config.config_id() for c in plan.cells}) == CONFIG_COUNT


class TestBalance:
    """The automated guard against the confound trap."""

    def test_every_generator_meets_every_encryption(self) -> None:
        coverage = check_balance(plan_sweep())
        encryptions = {c.config.encryption for c in plan_sweep().cells}
        for generator, seen in coverage.items():
            assert seen == encryptions, f"{generator} misses {encryptions - seen}"

    def test_balance_holds_for_a_truncated_plan(self) -> None:
        """Even a short sweep must not confound class with cipher."""
        check_balance(plan_sweep(max_configs=10))

    def test_a_confounded_plan_is_rejected(self) -> None:
        """Construct the trap deliberately and confirm it is caught."""
        plan = plan_sweep(max_configs=CONFIG_COUNT)
        gcm_only = [
            c
            for c in plan.cells
            if not (c.generator == "voip" and "gcm" not in c.config.encryption)
        ]
        confounded = type(plan)(tuple(gcm_only), plan.impairments, plan.repeats, plan.generators)
        with pytest.raises(BalanceError, match="confound"):
            check_balance(confounded)


class TestSlots:
    def test_slot_subnets_are_disjoint(self) -> None:
        allocated = [
            subnet
            for slot in slots(MAX_SLOTS)
            for subnet in (slot.transit_subnet, slot.left_subnet, slot.right_subnet)
        ]
        assert len(allocated) == len(set(allocated))

    def test_addresses_lie_inside_their_own_subnets(self) -> None:
        import ipaddress

        for slot in slots(4):
            for subnet, address in (
                (slot.transit_subnet, slot.left_transit),
                (slot.transit_subnet, slot.right_transit),
                (slot.left_subnet, slot.left_host),
                (slot.right_subnet, slot.right_host),
                (slot.right_subnet, slot.mail_origin),
            ):
                assert ipaddress.ip_address(address) in ipaddress.ip_network(subnet)

    def test_slot_zero_matches_the_single_pair_defaults(self) -> None:
        """A one-pair run and slot 0 must be the same topology."""
        zero = Slot(0)
        assert zero.left_transit == "10.100.0.2"
        assert zero.left_host == "10.110.0.10"

    @pytest.mark.parametrize("count", [0, -1, MAX_SLOTS + 1])
    def test_invalid_parallelism_is_rejected(self, count: int) -> None:
        with pytest.raises(ValueError, match="parallelism"):
            slots(count)

    def test_compose_env_covers_every_address_the_file_reads(self) -> None:
        env = Slot(2).compose_env()
        for key in (
            "TRANSIT_SUBNET",
            "LEFT_TRANSIT_IP",
            "RIGHT_TRANSIT_IP",
            "LEFT_PROTECTED_SUBNET",
            "LEFT_PROTECTED_IP",
            "LEFT_HOST_IP",
            "RIGHT_PROTECTED_SUBNET",
            "RIGHT_PROTECTED_IP",
            "RIGHT_HOST_IP",
            "VIDEO_ORIGIN_IP",
            "WEB_ORIGIN_IP",
            "MAIL_ORIGIN_IP",
            "XMPP_ORIGIN_IP",
        ):
            assert key in env


class TestResumability:
    def test_no_state_means_everything_remains(self) -> None:
        plan = plan_sweep(max_configs=2)
        assert len(remaining_cells(plan, None)) == len(plan)

    def test_ten_completed_cells_leaves_total_minus_ten(self) -> None:
        plan = plan_sweep(max_configs=2)
        done = [c.cell_id for c in plan.cells[:10]]
        state = SweepState(
            started_at=datetime.now(UTC), updated_at=datetime.now(UTC), completed=done
        )
        assert len(remaining_cells(plan, state)) == len(plan) - 10

    def test_failed_cells_are_not_retried(self) -> None:
        """A cell that failed already ran; re-running it would double-count."""
        plan = plan_sweep(max_configs=2)
        state = SweepState(
            started_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
            completed=[plan.cells[0].cell_id],
            failed=[plan.cells[1].cell_id],
        )
        remaining = remaining_cells(plan, state)
        assert len(remaining) == len(plan) - 2
        assert plan.cells[1].cell_id not in {c.cell_id for c in remaining}

    def test_remaining_preserves_plan_order(self) -> None:
        plan = plan_sweep(max_configs=2)
        state = SweepState(
            started_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
            completed=[plan.cells[3].cell_id],
        )
        remaining = [c.cell_id for c in remaining_cells(plan, state)]
        assert remaining == [c.cell_id for c in plan.cells if c.cell_id != plan.cells[3].cell_id]

    def test_state_round_trips_through_disk(self, tmp_path: Path) -> None:
        path = tmp_path / "sweep_state.json"
        state = SweepState(
            started_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
            completed=["a", "b"],
            failed=["c"],
        )
        save_state(path, state)
        restored = load_state(path)
        assert restored is not None
        assert restored.completed == ["a", "b"]
        assert restored.failed == ["c"]

    def test_a_corrupt_state_file_does_not_lose_the_corpus(self, tmp_path: Path) -> None:
        """Returning None restarts the sweep; raising would strand a finished corpus."""
        path = tmp_path / "sweep_state.json"
        path.write_text("{ this is not json")
        assert load_state(path) is None

    def test_missing_state_file_is_not_an_error(self, tmp_path: Path) -> None:
        assert load_state(tmp_path / "absent.json") is None

    def test_save_is_atomic(self, tmp_path: Path) -> None:
        """A crash mid-write must not destroy the resume point."""
        path = tmp_path / "sweep_state.json"
        save_state(
            path,
            SweepState(started_at=datetime.now(UTC), updated_at=datetime.now(UTC), completed=["a"]),
        )
        assert not path.with_suffix(".tmp").exists()
        assert load_state(path) is not None
