#!/usr/bin/env python3
"""Command-line entry point for the dataset sweep."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from testbed.orchestrate.sweep import check_balance, plan_sweep, run_sweep  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the dataset sweep.")
    parser.add_argument("--out", type=Path, default=REPO_ROOT / "data" / "raw" / "sweep")
    parser.add_argument("--duration-s", type=int, default=30)
    parser.add_argument("--replay-source", type=Path, default=None)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--max-configs", type=int, default=None)
    parser.add_argument("--cross-impairments", action="store_true")
    parser.add_argument(
        "--retry-failed",
        action="store_true",
        help=(
            "re-run cells previously recorded as failed. Use after an environmental "
            "failure (leftover containers, docker restart); not for configurations "
            "the testbed genuinely cannot build."
        ),
    )
    args = parser.parse_args(argv)

    plan = plan_sweep(
        max_configs=args.max_configs, cross_impairments=args.cross_impairments
    )
    check_balance(plan)
    print(f"planned {len(plan)} cells; writing to {args.out}", flush=True)

    done = 0

    def report(outcome) -> None:  # type: ignore[no-untyped-def]
        nonlocal done
        done += 1
        status = "ok " if outcome.success else "FAIL"
        detail = "" if outcome.success else f" :: {(outcome.error or '')[:110]}"
        print(
            f"[{done:>4}/{len(plan)}] {status} {outcome.cell_id}"
            f" outer={outcome.outer_packets} inner={outcome.inner_packets}{detail}",
            flush=True,
        )

    state = run_sweep(
        plan, args.out, duration_s=args.duration_s,
        replay_source=args.replay_source, limit=args.limit,
        retry_failed=args.retry_failed, on_cell=report,
    )
    print(f"\ncompleted={len(state.completed)} failed={len(state.failed)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
