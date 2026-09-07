"""Every number the deck states, read from the repository rather than remembered.

Phase 12's governing rule is that no slide may carry a figure a script in this repo did
not produce. This module is where that rule is enforced: the deck builder imports from
here, and everything here is either counted live from the code or parsed out of a
committed document.

Where a figure was measured on a testbed run rather than being derivable now — the
benchmark timings, the held-out accuracies — it is parsed from the document that
published it, so editing the deck cannot silently disagree with `PROGRESS.md`.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Final

REPO_ROOT: Final = Path(__file__).resolve().parents[2]
DOCS: Final = REPO_ROOT / "docs"


# --------------------------------------------------------------------- counted live


def rule_count() -> int:
    from ipsec_sentinel.assess.rules import default_registry

    return len(default_registry().rules)


def baseline_counts() -> tuple[int, int]:
    """(published baselines, built-in tags)."""
    from ipsec_sentinel.assess.baselines.schema import load_baselines
    from ipsec_sentinel.assess.framework import BUILTIN_TAGS

    return len(load_baselines()), len(BUILTIN_TAGS)


def unverified_baselines() -> list[str]:
    """The ones encoded from public description rather than a controlling document."""
    from ipsec_sentinel.assess.baselines.schema import get_baseline, load_baselines

    return sorted(name for name in load_baselines() if not get_baseline(name).verified)


def vendor_generator_count() -> int:
    return (
        len(list((REPO_ROOT / "src" / "ipsec_sentinel" / "remediate" / "generators").glob("*.py")))
        - 2
    )


def test_counts() -> tuple[int, int]:
    """(unit, integration), by collection rather than by memory."""
    counts = []
    targets = (("tests/unit", "not integration"), ("tests/integration", "integration"))
    for target, marker in targets:
        result = subprocess.run(
            [
                str(REPO_ROOT / ".venv" / "bin" / "pytest"),
                target,
                "-m",
                marker,
                "--collect-only",
                "-q",
                "-p",
                "no:cacheprovider",
                "--no-header",
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=900,
            check=False,
        )
        # This project's pytest config prints a per-file tally rather than a grand
        # total ("tests/unit/test_watch.py: 47"), so the total is the sum of them.
        per_file = re.findall(r"^\S+\.py: (\d+)$", result.stdout, re.MULTILINE)
        if per_file:
            counts.append(sum(int(n) for n in per_file))
            continue
        match = re.search(r"(\d+)/?\d* tests? collected", result.stdout)
        counts.append(int(match.group(1)) if match else 0)
    if not all(counts):
        raise RuntimeError(f"could not count tests: got {counts}")
    return counts[0], counts[1]


def git_sha() -> str:
    from ipsec_sentinel.version import git_sha as sha

    return sha() or "unknown"


# ------------------------------------------------------------ parsed from documents


def _table_rows(document: Path, header: str) -> list[list[str]]:
    """Rows of the markdown table whose header line contains `header`."""
    lines = document.read_text().splitlines()
    for index, line in enumerate(lines):
        if header in line and line.lstrip().startswith("|"):
            rows = []
            for candidate in lines[index + 2 :]:
                if not candidate.lstrip().startswith("|"):
                    break
                rows.append([cell.strip() for cell in candidate.strip().strip("|").split("|")])
            return rows
    raise LookupError(f"no table with header {header!r} in {document.name}")


@dataclass(frozen=True)
class Split:
    name: str
    accuracy: float
    macro_f1: float
    rows: int


def generalisation() -> list[Split]:
    """The held-out results, from the document that published them."""
    splits = []
    for row in _table_rows(DOCS / "GENERALISATION.md", "| Split | Accuracy"):
        if len(row) < 4:
            continue
        splits.append(
            Split(
                name=row[0],
                accuracy=float(row[1].rstrip("%")),
                macro_f1=float(row[2]),
                rows=int(row[3]),
            )
        )
    return splits


@dataclass(frozen=True)
class Benchmark:
    target: str
    measured: str
    margin: str


def benchmarks() -> list[Benchmark]:
    """The performance table from PROGRESS.md's Step 11.2 entry."""
    rows = _table_rows(REPO_ROOT / "PROGRESS.md", "| Target | Measured | Margin |")
    return [Benchmark(r[0], r[1].replace("**", ""), r[2]) for r in rows if len(r) >= 3]


def dataset_shape() -> tuple[int, int]:
    """(rows, classes) from the trained model's own metadata."""
    import json

    meta = json.loads((REPO_ROOT / "models" / "traffic.metadata.json").read_text())
    return meta["dataset_rows"], len(meta["class_names"])


def container_size_gb() -> float | None:
    """Measured from the built image, or None when it is not present."""
    result = subprocess.run(
        ["docker", "image", "inspect", "ipsec-sentinel:test", "--format", "{{.Size}}"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if result.returncode != 0 or not result.stdout.strip().isdigit():
        return None
    return int(result.stdout.strip()) / 1024**3


def demo_grades() -> dict[str, tuple[str, int]]:
    """Grade and score for each demo capture, by analysing them now."""
    from pathlib import Path as _Path

    from ipsec_sentinel.analyse import analyse_capture

    out: dict[str, tuple[str, int]] = {}
    for capture in sorted((REPO_ROOT / "demo" / "pcaps").glob("*.pcap")):
        report = analyse_capture(_Path(capture), baseline="nist_800_77r1")
        out[capture.stem] = (report.executive.estate_grade, report.executive.estate_score)
    return out
