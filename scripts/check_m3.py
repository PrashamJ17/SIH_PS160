#!/usr/bin/env python3
"""Execute the M3 acceptance checklist against a packaged corpus.

The milestone lists nine criteria. Checking them by eye across hundreds of cells is
how a gate quietly passes on a corpus that does not meet it, so each one is evaluated
here and reported pass or fail with the number behind it.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

REPO_ROOT: Final = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "src"))

from ipsec_sentinel.data.pcap_scan import count_flows  # noqa: E402

MIN_CONFIGS: Final = 24
MIN_CLASSES: Final = 7
MIN_IMPAIRMENTS: Final = 3
MIN_DH_PER_ENCRYPTION: Final = 2
MIN_CONFIGS_PER_CLASS: Final = 3
MIN_FLOWS: Final = 2000


@dataclass
class Check:
    name: str
    passed: bool
    detail: str


def evaluate(index: dict[str, Any], sweep_root: Path, audit: Path) -> list[Check]:
    cells: list[dict[str, Any]] = [c for c in index["cells_detail"] if isinstance(c, dict)]
    checks: list[Check] = []

    configs = {c["config_id"] for c in cells}
    checks.append(
        Check(
            f"at least {MIN_CONFIGS} distinct tunnel configurations captured",
            len(configs) >= MIN_CONFIGS,
            f"{len(configs)} distinct configurations",
        )
    )

    classes = {c["generator"] for c in cells}
    checks.append(
        Check(
            "all 7 traffic classes represented",
            len(classes) >= MIN_CLASSES,
            f"{len(classes)}: {sorted(classes)}",
        )
    )

    impairments = {c["impairment"] for c in cells}
    checks.append(
        Check(
            f"at least {MIN_IMPAIRMENTS} impairment profiles used",
            len(impairments) >= MIN_IMPAIRMENTS,
            f"{len(impairments)}: {sorted(impairments)}",
        )
    )

    by_encryption: dict[str, set[str]] = defaultdict(set)
    for cell in cells:
        by_encryption[str(cell["encryption"])].add(str(cell["dh_group"]))
    worst = min(by_encryption.items(), key=lambda kv: len(kv[1])) if by_encryption else ("-", set())
    checks.append(
        Check(
            f"every encryption appears with at least {MIN_DH_PER_ENCRYPTION} DH groups",
            all(len(v) >= MIN_DH_PER_ENCRYPTION for v in by_encryption.values()),
            f"minimum is {worst[0]} with {len(worst[1])} groups; "
            f"all: { {k: len(v) for k, v in sorted(by_encryption.items())} }",
        )
    )

    by_class: dict[str, set[str]] = defaultdict(set)
    for cell in cells:
        by_class[str(cell["generator"])].add(str(cell["config_id"]))
    worst_class = min(by_class.items(), key=lambda kv: len(kv[1])) if by_class else ("-", set())
    checks.append(
        Check(
            f"every traffic class appears with at least {MIN_CONFIGS_PER_CLASS} configurations",
            all(len(v) >= MIN_CONFIGS_PER_CLASS for v in by_class.values()),
            f"minimum is {worst_class[0]} with {len(worst_class[1])} configurations",
        )
    )

    total_flows = 0
    for cell in cells:
        inner = sweep_root / str(cell["cell_id"]) / "capture_inner.pcap"
        if inner.exists():
            total_flows += len(count_flows(inner))
    checks.append(
        Check(
            f"total labelled flows at least {MIN_FLOWS}",
            total_flows >= MIN_FLOWS,
            f"{total_flows:,} distinct flows across all cells",
        )
    )

    checks.append(
        Check(
            "every packaged cell negotiated what was configured",
            index["cells_not_matching_intent"] == 0,
            f"{index['cells_matching_intent']} of {index['cells']} matched intent",
        )
    )

    checks.append(
        Check(
            "external dataset audit generated",
            audit.exists() and audit.stat().st_size > 0,
            f"{audit} ({audit.stat().st_size if audit.exists() else 0} bytes)",
        )
    )

    warnings: list[str] = list(index.get("balance_warnings") or [])
    checks.append(
        Check(
            "corpus is not confounded (class vs cipher)",
            not warnings,
            "no confound warnings" if not warnings else f"{len(warnings)} warnings",
        )
    )
    return checks


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check the M3 acceptance criteria.")
    parser.add_argument("--index", type=Path, default=REPO_ROOT / "dataset" / "INDEX.json")
    parser.add_argument("--sweep", type=Path, default=REPO_ROOT / "data" / "raw" / "sweep")
    parser.add_argument(
        "--audit", type=Path, default=REPO_ROOT / "docs" / "external_dataset_audit.md"
    )
    args = parser.parse_args(argv)

    if not args.index.exists():
        print(f"no index at {args.index}; run scripts/package_dataset.py first", file=sys.stderr)
        return 1

    index = json.loads(args.index.read_text())
    checks = evaluate(index, args.sweep, args.audit)

    width = max(len(c.name) for c in checks)
    print(f"{'M3 acceptance criterion':<{width}}  result")
    print("-" * (width + 10))
    for check in checks:
        print(f"{check.name:<{width}}  {'PASS' if check.passed else 'FAIL'}  {check.detail}")
    failed = [c for c in checks if not c.passed]
    print()
    print(f"{len(checks) - len(failed)}/{len(checks)} criteria met")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
