"""Guards against the failure mode that cost 199 cells in under a minute.

A sweep terminated with SIGTERM skipped the runner's teardown, leaving containers that
pinned their networks. The next sweep reused slot 0, collided on the orphaned subnet,
and — because a sequential sweep never changes slot — collided on every cell after it
too. These tests cover the three guards that make the sequence impossible.
"""

from __future__ import annotations

import os
import signal
import subprocess
from pathlib import Path

import pytest

from testbed.orchestrate.sweep import (
    CELL_PROJECT_PREFIX,
    SweepLockError,
    SweepState,
    plan_sweep,
    purge_stale_cells,
    remaining_cells,
    sweep_lock,
    teardown_on_signal,
)


def _state(completed: list[str], failed: list[str]) -> SweepState:
    from datetime import UTC, datetime

    now = datetime.now(UTC)
    return SweepState(started_at=now, updated_at=now, completed=completed, failed=failed)


class TestRetryFailed:
    def test_failed_cells_are_skipped_by_default(self) -> None:
        plan = plan_sweep(max_configs=2)
        first, second = plan.cells[0].cell_id, plan.cells[1].cell_id
        pending = remaining_cells(plan, _state([first], [second]))
        assert {cell.cell_id for cell in pending}.isdisjoint({first, second})

    def test_retry_failed_reruns_them_but_not_completed_ones(self) -> None:
        plan = plan_sweep(max_configs=2)
        first, second = plan.cells[0].cell_id, plan.cells[1].cell_id
        ids = {
            cell.cell_id
            for cell in remaining_cells(plan, _state([first], [second]), retry_failed=True)
        }
        assert second in ids, "an environmental failure must be retryable"
        assert first not in ids, "a completed cell must never run twice"

    def test_a_missing_state_means_everything_is_pending(self) -> None:
        plan = plan_sweep(max_configs=1)
        assert len(remaining_cells(plan, None)) == len(plan.cells)


class TestSweepLock:
    @staticmethod
    def _expect_refusal(lock: Path) -> None:
        with pytest.raises(SweepLockError, match="already running"), sweep_lock(lock):
            pass

    def test_a_second_sweep_is_refused_while_the_first_holds_the_lock(self, tmp_path: Path) -> None:
        lock = tmp_path / "sweep.lock"
        with sweep_lock(lock):
            self._expect_refusal(lock)

    def test_the_lock_is_released_on_exit(self, tmp_path: Path) -> None:
        lock = tmp_path / "sweep.lock"
        with sweep_lock(lock):
            assert lock.exists()
        assert not lock.exists()

    def test_the_lock_is_released_even_when_the_sweep_raises(self, tmp_path: Path) -> None:
        lock = tmp_path / "sweep.lock"
        with pytest.raises(ValueError), sweep_lock(lock):
            raise ValueError("cell exploded")
        assert not lock.exists()

    def test_a_lock_owned_by_a_dead_process_is_reclaimed(self, tmp_path: Path) -> None:
        """A sweep killed by the OS must not require manual cleanup."""
        lock = tmp_path / "sweep.lock"
        lock.write_text("999999")  # PID that cannot be running
        with sweep_lock(lock) as pid:
            assert pid == os.getpid()

    def test_an_unreadable_lock_is_treated_as_stale(self, tmp_path: Path) -> None:
        lock = tmp_path / "sweep.lock"
        lock.write_text("not-a-pid")
        with sweep_lock(lock) as pid:
            assert pid == os.getpid()

    def test_the_lock_records_the_owning_pid(self, tmp_path: Path) -> None:
        lock = tmp_path / "sweep.lock"
        with sweep_lock(lock):
            assert lock.read_text().strip() == str(os.getpid())


class TestPurgeStaleCells:
    def test_containers_are_removed_before_networks(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A container still attached pins its network, and the network is what collides."""
        calls: list[list[str]] = []

        def fake_run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
            calls.append(argv)
            if argv[1:3] == ["ps", "-aq"]:
                return subprocess.CompletedProcess(argv, 0, "cont1\n", "")
            if argv[1:3] == ["network", "ls"]:
                return subprocess.CompletedProcess(argv, 0, "net1\n", "")
            return subprocess.CompletedProcess(argv, 0, "", "")

        monkeypatch.setattr(subprocess, "run", fake_run)
        removed = purge_stale_cells()

        assert removed == ["cont1", "net1"]
        rm_container = calls.index(["docker", "rm", "-f", "cont1"])
        rm_network = calls.index(["docker", "network", "rm", "net1"])
        assert rm_container < rm_network

    def test_only_sentinel_cell_resources_are_targeted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The purge must never touch the user's unrelated containers."""
        calls: list[list[str]] = []

        def fake_run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, "", "")

        monkeypatch.setattr(subprocess, "run", fake_run)
        purge_stale_cells()

        filters = [argv[argv.index("--filter") + 1] for argv in calls if "--filter" in argv]
        assert filters, "the purge must filter, never list everything"
        assert all(f == f"name={CELL_PROJECT_PREFIX}" for f in filters)

    def test_nothing_to_purge_is_not_an_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            subprocess,
            "run",
            lambda argv, **_: subprocess.CompletedProcess(argv, 0, "", ""),
        )
        assert purge_stale_cells() == []


class TestTeardownOnSignal:
    def test_sigterm_raises_instead_of_terminating(self) -> None:
        """Default SIGTERM kills the interpreter outright and skips every finally block."""
        torn_down = False
        with pytest.raises(KeyboardInterrupt, match="signal"), teardown_on_signal():
            try:
                os.kill(os.getpid(), signal.SIGTERM)
            finally:
                torn_down = True
        assert torn_down, "the finally block must have run"

    def test_the_previous_handler_is_restored(self) -> None:
        before = signal.getsignal(signal.SIGTERM)
        with teardown_on_signal():
            assert signal.getsignal(signal.SIGTERM) is not before
        assert signal.getsignal(signal.SIGTERM) is before
