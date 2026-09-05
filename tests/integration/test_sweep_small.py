"""A small live sweep, including interruption and resume (build plan Step 3.2)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from testbed.orchestrate.sweep import (
    STATE_FILENAME,
    load_state,
    plan_sweep,
    remaining_cells,
    run_sweep,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.slow,
    pytest.mark.usefixtures("strongswan_image", "traffic_image"),
]

# One configuration, two generators, two impairments: four cells.
MINI = {
    "generators": ("icmp", "voip"),
    "impairments": ("clean", "lan"),
    "max_configs": 1,
}


@pytest.fixture(scope="module")
def mini_sweep(tmp_path_factory: pytest.TempPathFactory):  # type: ignore[no-untyped-def]
    out = tmp_path_factory.mktemp("sweep")
    plan = plan_sweep(**MINI)  # type: ignore[arg-type]
    state = run_sweep(plan, out, duration_s=6)
    return plan, state, out


def test_the_mini_plan_is_four_cells() -> None:
    assert len(plan_sweep(**MINI)) == 4  # type: ignore[arg-type]


def test_all_four_cells_ran(mini_sweep) -> None:  # type: ignore[no-untyped-def]
    plan, state, _ = mini_sweep
    assert len(state.attempted) == len(plan) == 4


def test_all_four_cells_succeeded(mini_sweep) -> None:  # type: ignore[no-untyped-def]
    _, state, _ = mini_sweep
    assert state.failed == [], f"cells failed: {state.failed}"
    assert len(state.completed) == 4


def test_every_cell_wrote_a_manifest(mini_sweep) -> None:  # type: ignore[no-untyped-def]
    plan, _, out = mini_sweep
    for cell in plan.cells:
        manifest = out / cell.cell_id / "manifest.json"
        assert manifest.exists(), f"no manifest for {cell.cell_id}"
        assert json.loads(manifest.read_text())["capture_id"] == cell.cell_id


def test_every_cell_wrote_both_captures(mini_sweep) -> None:  # type: ignore[no-untyped-def]
    plan, _, out = mini_sweep
    for cell in plan.cells:
        assert (out / cell.cell_id / "capture_outer.pcap").exists()
        assert (out / cell.cell_id / "capture_inner.pcap").exists()


def test_manifests_record_negotiated_parameters(mini_sweep) -> None:  # type: ignore[no-untyped-def]
    plan, _, out = mini_sweep
    for cell in plan.cells:
        manifest = json.loads((out / cell.cell_id / "manifest.json").read_text())
        assert manifest["negotiation_matched_intent"] is True, manifest["mismatches"]
        assert manifest["negotiated_ike"]["established"] is True


def test_state_file_is_written(mini_sweep) -> None:  # type: ignore[no-untyped-def]
    _, _, out = mini_sweep
    assert (out / STATE_FILENAME).exists()


def test_a_completed_sweep_has_nothing_left_to_do(mini_sweep) -> None:  # type: ignore[no-untyped-def]
    plan, _, out = mini_sweep
    assert remaining_cells(plan, load_state(out / STATE_FILENAME)) == []


def test_rerunning_a_completed_sweep_runs_nothing(mini_sweep) -> None:  # type: ignore[no-untyped-def]
    """Resume must be idempotent: no cell may run twice."""
    plan, _, out = mini_sweep
    ran: list[str] = []
    state = run_sweep(plan, out, duration_s=6, on_cell=lambda o: ran.append(o.cell_id))
    assert ran == [], f"a completed sweep re-ran cells: {ran}"
    assert len(state.attempted) == 4


def test_an_interrupted_sweep_resumes_where_it_stopped(
    tmp_path: Path,
) -> None:
    """State is written after every cell, so an interruption costs one cell at most."""
    plan = plan_sweep(**MINI)  # type: ignore[arg-type]
    out = tmp_path / "interrupted"

    first_pass: list[str] = []
    run_sweep(plan, out, duration_s=6, limit=2, on_cell=lambda o: first_pass.append(o.cell_id))
    assert len(first_pass) == 2

    partial = load_state(out / STATE_FILENAME)
    assert partial is not None
    assert len(partial.attempted) == 2
    assert len(remaining_cells(plan, partial)) == 2

    second_pass: list[str] = []
    run_sweep(plan, out, duration_s=6, on_cell=lambda o: second_pass.append(o.cell_id))

    assert len(second_pass) == 2, "resume did not run exactly the remaining cells"
    assert set(first_pass) & set(second_pass) == set(), "a cell ran twice across the resume"
    assert set(first_pass) | set(second_pass) == {c.cell_id for c in plan.cells}


def test_state_is_written_after_every_cell_not_at_the_end(tmp_path: Path) -> None:
    """If state were written only at the end, a kill would lose the whole sweep."""
    plan = plan_sweep(**MINI)  # type: ignore[arg-type]
    out = tmp_path / "incremental"
    seen_counts: list[int] = []

    def record(_outcome) -> None:  # type: ignore[no-untyped-def]
        state = load_state(out / STATE_FILENAME)
        seen_counts.append(len(state.attempted) if state else 0)

    run_sweep(plan, out, duration_s=6, limit=2, on_cell=record)
    assert seen_counts == [1, 2], f"state did not grow one cell at a time: {seen_counts}"
