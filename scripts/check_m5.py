#!/usr/bin/env python3
"""Execute the M5 acceptance checklist and report pass/fail per item.

Same shape as the M4 gate: an executable check rather than commands typed once, so a
later regression fails it instead of quietly invalidating a claim. Exits non-zero if
any item fails; items that cannot run report SKIP and never count as passes.
"""

from __future__ import annotations

import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Final

REPO_ROOT = Path(__file__).resolve().parent.parent
for path in (REPO_ROOT / "src", REPO_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from ipsec_sentinel.assess.inventory import (  # noqa: E402
    build_inventory,
    known_from_endpoints,
)
from ipsec_sentinel.parser.correlate import Tunnel, correlate  # noqa: E402
from ipsec_sentinel.parser.esp import (  # noqa: E402
    analyse_sequence,
    assemble_esp_flows,
    extract_esp_packets,
)
from ipsec_sentinel.parser.pcap import extract_ike_exchanges  # noqa: E402
from testbed.orchestrate.netem import PROFILES_BY_NAME  # noqa: E402

SWEEP_ROOT: Final = REPO_ROOT / "data" / "raw" / "sweep"
MIN_FLOW_PACKETS: Final = 20


@dataclass
class Check:
    name: str
    status: str
    detail: str

    def __str__(self) -> str:
        return f"[{self.status}] {self.name}\n       {self.detail}"


def captures() -> list[Path]:
    if not SWEEP_ROOT.exists():
        return []
    return sorted(SWEEP_ROOT.glob("*/capture_outer.pcap"))


def tunnels_of(pcap: Path) -> list[Tunnel]:
    return correlate(extract_ike_exchanges(pcap), assemble_esp_flows(extract_esp_packets(pcap)))


def check_all_captures_correlate() -> Check:
    name = "All dataset PCAPs produce correlated tunnels"
    files = captures()
    if not files:
        return Check(name, "SKIP", "no sweep captures present")
    empty: list[str] = []
    multi: list[str] = []
    total = 0
    for pcap in files:
        tunnels = tunnels_of(pcap)
        total += len(tunnels)
        if not tunnels:
            empty.append(pcap.parent.name)
        elif len(tunnels) != 1:
            multi.append(f"{pcap.parent.name}={len(tunnels)}")
    if empty:
        return Check(name, "FAIL", f"{len(empty)} captures produced no tunnel: {empty[:5]}")
    if multi:
        return Check(
            name,
            "FAIL",
            f"{len(multi)} captures produced more than one tunnel (each cell is one "
            f"tunnel between one pair): {multi[:5]}",
        )
    return Check(name, "PASS", f"{len(files)} captures, {total} tunnels, one per cell")


def check_sequence_matches_impairment() -> Check:
    name = "Sequence analysis matches known impairment levels"
    by_profile: dict[str, list[float]] = defaultdict(list)
    for pcap in captures():
        cell = pcap.parent.name
        profile = next(
            (p for p in ("clean", "wan_good", "wan_poor") if cell.endswith(f"_{p}_r0")),
            None,
        )
        if profile is None:
            continue
        for flow in assemble_esp_flows(extract_esp_packets(pcap)):
            if flow.packet_count < MIN_FLOW_PACKETS:
                continue
            by_profile[profile].append(analyse_sequence(flow).loss_ratio)
    if not by_profile:
        return Check(name, "SKIP", "no sweep captures present")

    lines: list[str] = []
    failures: list[str] = []
    for profile in ("clean", "wan_good", "wan_poor"):
        values = by_profile.get(profile)
        if not values:
            continue
        injected = PROFILES_BY_NAME[profile].loss_pct / 100.0
        measured = sum(values) / len(values)
        lines.append(f"{profile}: injected {injected:.2%}, measured {measured:.4%}")
        if injected == 0.0:
            if max(values) != 0.0:
                failures.append(f"{profile} shows loss where none was injected")
        elif not (0.5 * injected <= measured <= 1.5 * injected):
            failures.append(f"{profile} measured {measured:.4%} vs injected {injected:.2%}")
    if failures:
        return Check(name, "FAIL", "; ".join(failures))
    return Check(name, "PASS", "; ".join(lines))


def check_undocumented_detection() -> Check:
    name = "Inventory correctly flags a synthetic undocumented tunnel"
    files = captures()
    if not files:
        return Check(name, "SKIP", "no sweep captures present")
    real: list[Tunnel] = []
    for pcap in files[:20]:
        real.extend(tunnels_of(pcap))
    if not real:
        return Check(name, "FAIL", "no real tunnels to document")

    planted = Tunnel(
        tunnel_id="planted00000",
        endpoints=("203.0.113.77", "203.0.113.88"),
    )
    known = known_from_endpoints([tuple(t.endpoints) for t in real])  # type: ignore[misc]
    inventory = build_inventory([*real, planted], known=known)
    flagged = inventory.undocumented
    if len(flagged) != 1:
        return Check(
            name,
            "FAIL",
            f"expected exactly the planted tunnel, got {len(flagged)}: "
            f"{[e.endpoints for e in flagged][:5]}",
        )
    if flagged[0].endpoints != ("203.0.113.77", "203.0.113.88"):
        return Check(name, "FAIL", f"flagged the wrong tunnel: {flagged[0].endpoints}")
    return Check(
        name,
        "PASS",
        f"{len(real)} real tunnels documented and cleared, the planted one flagged",
    )


def check_all_tests_pass() -> Check:
    name = "All earlier tests still pass"
    result = subprocess.run(
        # NB: no -q here. pyproject already sets it in addopts, and a second one means
        # -qq, which suppresses the summary line this check reports.
        [sys.executable, "-m", "pytest", "-m", "not integration"],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        timeout=1800,
        check=False,
    )
    summary = next(
        (line for line in reversed(result.stdout.splitlines()) if "passed" in line),
        "no summary line",
    )
    status = "PASS" if result.returncode == 0 else "FAIL"
    return Check(name, status, summary.strip())


CHECKS = (
    check_all_captures_correlate,
    check_sequence_matches_impairment,
    check_undocumented_detection,
    check_all_tests_pass,
)


def main() -> int:
    print("M5 — ESP analysis complete\n")
    results = [check() for check in CHECKS]
    for result in results:
        print(result)
        print()
    failed = [r for r in results if r.status == "FAIL"]
    skipped = [r for r in results if r.status == "SKIP"]
    print(
        f"{len(results) - len(failed) - len(skipped)}/{len(results)} passed, "
        f"{len(failed)} failed, {len(skipped)} skipped"
    )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
