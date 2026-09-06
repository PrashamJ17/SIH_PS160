#!/usr/bin/env python3
"""Sweep the transport-mode matrix, additively, into the existing corpus.

Separate from `run_sweep.py` because the two matrices exist for different reasons. The
tunnel matrix covers the cryptographic space and its configuration IDs are fixed by the
M3-verified corpus; this one exists only so mode inference has a second class to learn
from, and is restricted to the generators that can produce protected traffic under
transport mode at all.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
for path in (REPO_ROOT, REPO_ROOT / "src"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from testbed.orchestrate.runner import RunOutcome  # noqa: E402
from testbed.orchestrate.sweep import plan_sweep, run_sweep  # noqa: E402

# Transport mode protects the peers themselves, so only generators addressing the far
# peer directly can produce ESP under it. The sidecar-backed generators fetch from an
# origin behind the far gateway, which transport routes around unprotected.
#
# `replay` is excluded, and the reason is worth stating because it is not obvious.
# tcpreplay injects raw frames at layer 2, which bypasses the kernel's XFRM output
# path entirely — so on a gateway they leave the interface unencrypted no matter what
# policy is installed. In tunnel mode it works because the *host* injects and the
# gateway encapsulates the frames as forwarded traffic; in transport mode the gateway
# is both injector and encryptor, and the injection sidesteps the encryption. The
# runner's ESP guard catches this correctly, reporting "the SA established but the
# generated traffic was not protected by it".
TRANSPORT_GENERATORS = ("icmp", "voip")
TRANSPORT_MATRIX = REPO_ROOT / "testbed" / "configs" / "matrix_transport.yaml"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=REPO_ROOT / "data" / "raw" / "sweep")
    parser.add_argument("--duration-s", type=int, default=30)
    parser.add_argument("--replay-source", type=Path, default=None)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--retry-failed", action="store_true")
    args = parser.parse_args(argv)

    plan = plan_sweep(
        generators=TRANSPORT_GENERATORS,
        cross_impairments=False,
        matrix_path=TRANSPORT_MATRIX,
    )
    print(f"planned {len(plan.cells)} transport cells; writing to {args.out}")

    seen = 0

    def report(outcome: RunOutcome) -> None:
        nonlocal seen
        seen += 1
        status = "ok " if outcome.success else "FAIL"
        detail = "" if outcome.success else f" :: {outcome.error}"
        print(
            f"[{seen:4}/{len(plan.cells)}] {status} {outcome.cell_id} "
            f"outer={outcome.outer_packets} inner={outcome.inner_packets}{detail}",
            flush=True,
        )

    state = run_sweep(
        plan, args.out, duration_s=args.duration_s,
        replay_source=args.replay_source, limit=args.limit,
        retry_failed=args.retry_failed, on_cell=report,
    )
    print(f"\ncompleted={len(state.completed)} failed={len(state.failed)}")
    return 0 if not state.failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
