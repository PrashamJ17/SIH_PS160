"""Plan and execute the full dataset sweep, survivably.

Three properties matter more than throughput here.

**Resumability.** State is written after every cell, so a sweep killed at cell 900 of
1200 resumes at 901 rather than starting again. Cell identity is a stable hash of the
configuration and the generator, not a position in a list, so a replan produces the
same identities and a resumed sweep skips exactly what it already ran.

**Balance.** The plan is checked before anything runs: every generator must appear
with every encryption algorithm. Without that the corpus confounds application class
with cipher, and a classifier trained on it reads cipher artifacts while appearing to
read traffic shape — the most fatal of the traps in the master document.

**Isolation.** Concurrent pairs get disjoint subnets from a slot allocator, because
two pairs sharing 10.100.0.0/24 do not fail cleanly; the second simply cannot start.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from pydantic import BaseModel, Field

from testbed.orchestrate.matrix import expand_matrix
from testbed.orchestrate.netem import PROFILES, ImpairmentProfile, profile
from testbed.orchestrate.runner import CellSpec, RunOutcome, run_cell
from testbed.traffic.registry import GENERATOR_NAMES, spec

DEFAULT_IMPAIRMENTS: Final[tuple[str, ...]] = ("clean", "wan_good", "wan_poor")
STATE_FILENAME: Final = "sweep_state.json"


@dataclass(frozen=True)
class Slot:
    """One concurrency slot's private address space.

    Slots are disjoint by construction: transit, left-protected and right-protected
    each occupy their own /16-spaced band, so slot N never collides with slot M.
    """

    index: int

    @property
    def transit_subnet(self) -> str:
        return f"10.{100 + self.index}.0.0/24"

    @property
    def left_transit(self) -> str:
        return f"10.{100 + self.index}.0.2"

    @property
    def right_transit(self) -> str:
        return f"10.{100 + self.index}.0.3"

    @property
    def left_subnet(self) -> str:
        return f"10.{110 + self.index}.0.0/24"

    @property
    def left_protected(self) -> str:
        return f"10.{110 + self.index}.0.2"

    @property
    def left_host(self) -> str:
        return f"10.{110 + self.index}.0.10"

    @property
    def right_subnet(self) -> str:
        return f"10.{120 + self.index}.0.0/24"

    @property
    def right_protected(self) -> str:
        return f"10.{120 + self.index}.0.2"

    @property
    def right_host(self) -> str:
        return f"10.{120 + self.index}.0.10"

    @property
    def video_origin(self) -> str:
        return f"10.{120 + self.index}.0.20"

    @property
    def web_origin(self) -> str:
        return f"10.{120 + self.index}.0.21"

    @property
    def mail_origin(self) -> str:
        return f"10.{120 + self.index}.0.22"

    @property
    def xmpp_origin(self) -> str:
        return f"10.{120 + self.index}.0.23"

    def compose_env(self) -> dict[str, str]:
        """Address overrides for this slot's compose project."""
        return {
            "TRANSIT_SUBNET": self.transit_subnet,
            "LEFT_TRANSIT_IP": self.left_transit,
            "RIGHT_TRANSIT_IP": self.right_transit,
            "LEFT_PROTECTED_SUBNET": self.left_subnet,
            "LEFT_PROTECTED_IP": self.left_protected,
            "LEFT_HOST_IP": self.left_host,
            "RIGHT_PROTECTED_SUBNET": self.right_subnet,
            "RIGHT_PROTECTED_IP": self.right_protected,
            "RIGHT_HOST_IP": self.right_host,
            "VIDEO_ORIGIN_IP": self.video_origin,
            "WEB_ORIGIN_IP": self.web_origin,
            "MAIL_ORIGIN_IP": self.mail_origin,
            "XMPP_ORIGIN_IP": self.xmpp_origin,
        }


MAX_SLOTS: Final = 10


def slots(count: int) -> list[Slot]:
    if not 1 <= count <= MAX_SLOTS:
        raise ValueError(f"parallelism must be between 1 and {MAX_SLOTS}, got {count}")
    return [Slot(i) for i in range(count)]


class BalanceError(ValueError):
    """The planned sweep would produce a confounded corpus."""


@dataclass(frozen=True)
class SweepPlan:
    """Every cell the sweep intends to run, in a deterministic order."""

    cells: tuple[CellSpec, ...]
    impairments: tuple[str, ...]
    repeats: int
    generators: tuple[str, ...] = field(default=GENERATOR_NAMES)

    def __len__(self) -> int:
        return len(self.cells)


def plan_sweep(
    *,
    generators: tuple[str, ...] = GENERATOR_NAMES,
    impairments: tuple[str, ...] = DEFAULT_IMPAIRMENTS,
    repeats: int = 1,
    matrix_path: Path | None = None,
    max_configs: int | None = None,
    cross_impairments: bool = True,
) -> SweepPlan:
    """Build the full cell list: configurations x generators x impairments x repeats.

    Each generator's variants are cycled across configurations rather than multiplied
    into them, so variant coverage does not multiply the sweep's size while every
    variant still appears.

    ``cross_impairments=False`` cycles impairment profiles across cells instead of
    crossing them in, cutting the sweep to a third of its size while still exercising
    every profile. Use it when wall-clock cost matters more than having every
    configuration observed under every path condition.
    """
    for name in generators:
        spec(name)
    for name in impairments:
        profile(name)

    configs = [lc.config for lc in expand_matrix(matrix_path)]
    if max_configs is not None:
        configs = configs[:max_configs]

    cells: list[CellSpec] = []
    for repeat in range(repeats):
        for config_index, config in enumerate(configs):
            for generator in generators:
                variants = spec(generator).variants
                variant = variants[(config_index + repeat) % len(variants)]
                chosen = (
                    impairments
                    if cross_impairments
                    else (impairments[len(cells) % len(impairments)],)
                )
                for impairment in chosen:
                    cells.append(
                        CellSpec(
                            config=config,
                            generator=generator,
                            variant=variant,
                            impairment=impairment,
                            repeat=repeat,
                        )
                    )
    return SweepPlan(tuple(cells), tuple(impairments), repeats, tuple(generators))


def check_balance(plan: SweepPlan) -> dict[str, set[str]]:
    """Assert every generator meets every encryption algorithm.

    This is the automated guard against the confound trap. If VoIP only ever runs over
    AES-GCM and video only over AES-CBC, an "application classifier" trained on the
    result is really a cipher detector, and no downstream care recovers from it.
    """
    seen: dict[str, set[str]] = {}
    for cell in plan.cells:
        seen.setdefault(cell.generator, set()).add(cell.config.encryption)

    encryptions = {cell.config.encryption for cell in plan.cells}
    missing = {
        generator: encryptions - covered
        for generator, covered in seen.items()
        if encryptions - covered
    }
    if missing:
        raise BalanceError(
            "the planned sweep would confound application class with cipher; "
            f"these generators never meet these encryptions: {missing}"
        )
    return seen


class SweepState(BaseModel):
    """What the sweep has already done. Written after every cell."""

    started_at: datetime
    updated_at: datetime
    completed: list[str] = Field(default_factory=list)
    failed: list[str] = Field(default_factory=list)
    outcomes: dict[str, dict[str, Any]] = Field(default_factory=dict)

    @property
    def attempted(self) -> set[str]:
        """Cells that ran, successfully or not — neither should run twice."""
        return set(self.completed) | set(self.failed)


def load_state(path: Path) -> SweepState | None:
    if not path.exists():
        return None
    try:
        return SweepState.model_validate_json(path.read_text())
    except Exception:
        return None


def save_state(path: Path, state: SweepState) -> None:
    """Persist atomically: a crash mid-write must not destroy the resume point."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(state.model_dump_json(indent=2))
    temporary.replace(path)


def remaining_cells(plan: SweepPlan, state: SweepState | None) -> list[CellSpec]:
    """Cells still to run, in plan order."""
    if state is None:
        return list(plan.cells)
    done = state.attempted
    return [cell for cell in plan.cells if cell.cell_id not in done]


def run_sweep(
    plan: SweepPlan,
    out_root: Path,
    *,
    duration_s: int = 60,
    replay_source: Path | None = None,
    state_path: Path | None = None,
    limit: int | None = None,
    on_cell: Any = None,
) -> SweepState:
    """Execute the plan, recording state after every cell.

    Sequential by default. A cell's failure is recorded and the sweep continues: one
    unbuildable configuration must not cost the other 1199 cells.
    """
    check_balance(plan)
    out_root.mkdir(parents=True, exist_ok=True)
    state_file = state_path or (out_root / STATE_FILENAME)

    state = load_state(state_file) or SweepState(
        started_at=datetime.now(UTC), updated_at=datetime.now(UTC)
    )
    pending = remaining_cells(plan, state)
    if limit is not None:
        pending = pending[:limit]

    slot = Slot(0)
    for cell in pending:
        outcome: RunOutcome = run_cell(
            cell,
            _impairment(cell.impairment),
            duration_s=duration_s,
            out_dir=out_root / cell.cell_id,
            replay_source=replay_source,
            slot_env=slot.compose_env(),
            addresses=slot,
        )
        if outcome.success:
            state.completed.append(cell.cell_id)
        else:
            state.failed.append(cell.cell_id)
        state.outcomes[cell.cell_id] = json.loads(outcome.model_dump_json())
        state.updated_at = datetime.now(UTC)
        # Written after EVERY cell: an interrupted sweep must resume, not restart.
        save_state(state_file, state)
        if on_cell is not None:
            on_cell(outcome)
    return state


def _impairment(name: str) -> ImpairmentProfile:
    for candidate in PROFILES:
        if candidate.name == name:
            return candidate
    raise ValueError(f"unknown impairment {name!r}")
