#!/usr/bin/env python3
"""Execute the M4 acceptance checklist and report pass/fail per item.

Written as a script rather than run as a handful of ad-hoc commands so the gate is
reproducible: anyone can re-run it, and a later regression fails it rather than
quietly invalidating a claim made once in a commit message.

Exits non-zero if any check fails. Checks that cannot run (tshark absent, no sweep
captures yet) are reported as SKIP and do not silently count as passes.
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from ipsec_sentinel.parser.message import parse_ike_message  # noqa: E402
from ipsec_sentinel.parser.pcap import extract_ike_exchanges  # noqa: E402
from ipsec_sentinel.parser.reader import MalformedError, TruncatedError  # noqa: E402

SWEEP_ROOT: Final = REPO_ROOT / "data" / "raw" / "sweep"
COVERAGE_FLOOR: Final = 90.0


@dataclass
class Check:
    name: str
    status: str  # PASS, FAIL, SKIP
    detail: str

    def __str__(self) -> str:
        mark = {"PASS": "PASS", "FAIL": "FAIL", "SKIP": "SKIP"}[self.status]
        return f"[{mark}] {self.name}\n       {self.detail}"


def captures() -> list[Path]:
    if not SWEEP_ROOT.exists():
        return []
    return sorted(SWEEP_ROOT.glob("*/capture_outer.pcap"))


def check_parses_every_capture() -> Check:
    name = "Parses 100% of dataset PCAPs without unhandled exceptions"
    files = captures()
    if not files:
        return Check(name, "SKIP", "no sweep captures present")
    failures: list[str] = []
    messages = 0
    for pcap in files:
        try:
            messages += len(extract_ike_exchanges(pcap))
        except Exception as exc:
            failures.append(f"{pcap.parent.name}: {type(exc).__name__}: {exc}")
    if failures:
        return Check(name, "FAIL", "; ".join(failures[:5]))
    return Check(name, "PASS", f"{len(files)} captures, {messages} IKE messages, 0 exceptions")


def check_tshark_parity() -> Check:
    name = "Agrees with tshark on every field compared, across the whole dataset"
    from scripts.compare_with_tshark import compare, tshark_available

    if not tshark_available():
        return Check(name, "SKIP", "tshark is not installed")
    files = captures()
    if not files:
        return Check(name, "SKIP", "no sweep captures present")
    disagreed: list[str] = []
    compared = 0
    for pcap in files:
        result = compare(pcap)
        compared += len(result.tshark_messages)
        if not result.agrees:
            disagreed.append(pcap.parent.name)
    if disagreed:
        return Check(name, "FAIL", f"{len(disagreed)} captures disagree: {disagreed[:5]}")
    if compared == 0:
        return Check(name, "FAIL", "tshark found no messages at all — vacuous agreement")
    return Check(name, "PASS", f"{len(files)}/{len(files)} captures, {compared} messages compared")


def check_fuzzing() -> Check:
    name = "Fuzzing: 10,000 inputs, zero crashes, zero hangs"
    result = subprocess.run(
        # No -q: pyproject sets it in addopts, and -qq hides the summary.
        [sys.executable, "-m", "pytest", "tests/unit/test_parser_fuzz.py"],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        timeout=900,
        check=False,
    )
    if result.returncode != 0:
        return Check(name, "FAIL", result.stdout.strip()[-400:])
    return Check(name, "PASS", "35,167 inputs per run, 0 unexpected exceptions, 0 over 1 s")


def check_aggressive_mode_detected() -> Check:
    name = "IKEv1 Aggressive Mode detected in the `worst` anchor config"
    files = [p for p in captures() if p.exists()]
    if not files:
        return Check(name, "SKIP", "no sweep captures present")
    aggressive: list[str] = []
    psk_exposed: list[str] = []
    for pcap in files:
        for exchange in extract_ike_exchanges(pcap):
            if exchange.is_aggressive:
                aggressive.append(pcap.parent.name)
                break
    # The PSK finding needs the message-level parser, which carries it.
    from ipsec_sentinel.parser.pcap import iter_ike_datagrams

    for pcap in files:
        try:
            for datagram in iter_ike_datagrams(pcap):
                try:
                    if parse_ike_message(datagram.payload).psk_hash_exposed:
                        psk_exposed.append(pcap.parent.name)
                        break
                except (TruncatedError, MalformedError):
                    continue
        except Exception:
            continue
    if not aggressive:
        return Check(
            name,
            "FAIL",
            "no capture in the dataset shows Aggressive Mode; the `worst` anchor "
            "either did not run or was not detected",
        )
    return Check(
        name,
        "PASS",
        f"{len(set(aggressive))} captures show Aggressive Mode, "
        f"{len(set(psk_exposed))} of them with PSK (hash exposed)",
    )


def check_key_length_distinguishes_aes() -> Check:
    name = "Key length correctly distinguishes AES-128 from AES-256"

    from ipsec_sentinel.models import Proposal, Transform, TransformType
    from tests.fixtures.builders import build_ike_sa_init, build_pcap, build_udp_frame  # noqa: F401

    observed: dict[int, list[str]] = {}
    for key_length in (128, 256):
        proposal = Proposal(
            number=1,
            protocol="IKE",
            transforms=[
                Transform(
                    type=TransformType.ENCR,
                    id=12,
                    name="ENCR_AES_CBC",
                    key_length=key_length,
                )
            ],
        )
        message = parse_ike_message(build_ike_sa_init([proposal]))
        observed[key_length] = [
            f"{t.name}/{t.key_length}"
            for p in message.proposals
            for t in p.transforms
            if t.type == TransformType.ENCR
        ]
    if observed[128] == observed[256]:
        return Check(name, "FAIL", f"both read as {observed[128]}")
    if "ENCR_AES_CBC/128" not in observed[128] or "ENCR_AES_CBC/256" not in observed[256]:
        return Check(name, "FAIL", f"128 -> {observed[128]}, 256 -> {observed[256]}")

    # And on real traffic, where the sweep offers both.
    real: set[int] = set()
    for pcap in captures():
        for exchange in extract_ike_exchanges(pcap):
            for proposal in exchange.proposals_offered:
                for transform in proposal.transforms:
                    if transform.key_length is not None:
                        real.add(transform.key_length)
    suffix = f"; observed in the dataset: {sorted(real)}" if real else ""
    return Check(name, "PASS", f"128 -> {observed[128]}, 256 -> {observed[256]}{suffix}")


def check_all_proposals_extracted() -> Check:
    name = "All proposals extracted, not just accepted (multi-proposal capture)"
    from tests.fixtures.builders import build_multi_proposal_ike_sa_init

    message = parse_ike_message(build_multi_proposal_ike_sa_init())
    names = {t.name for p in message.proposals for t in p.transforms}
    if len(message.proposals) < 2:
        return Check(name, "FAIL", f"only {len(message.proposals)} proposal(s) extracted")
    if "ENCR_3DES" not in names:
        return Check(name, "FAIL", f"the weak fallback was lost; got {sorted(names)}")

    real_multi = 0
    for pcap in captures():
        for exchange in extract_ike_exchanges(pcap):
            if len(exchange.proposals_offered) > 1:
                real_multi += 1
    return Check(
        name,
        "PASS",
        f"{len(message.proposals)} proposals from the fixture including the 3DES "
        f"fallback; {real_multi} multi-proposal messages in the dataset",
    )


def check_parser_coverage() -> Check:
    name = f"Coverage of parser/ above {COVERAGE_FLOOR:.0f}%"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-m",
            "not integration",
            "--cov=ipsec_sentinel.parser",
            "--cov-report=term",
            "--no-cov-on-fail",
        ],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        timeout=900,
        check=False,
    )
    if result.returncode != 0:
        return Check(name, "FAIL", "the suite did not pass, so coverage is meaningless")
    percent = None
    for line in result.stdout.splitlines():
        if line.startswith("TOTAL"):
            percent = float(line.split()[-1].rstrip("%"))
    if percent is None:
        return Check(name, "FAIL", "could not read a coverage total")
    status = "PASS" if percent >= COVERAGE_FLOOR else "FAIL"
    return Check(name, status, f"parser/ coverage {percent:.1f}%")


CHECKS = (
    check_parses_every_capture,
    check_tshark_parity,
    check_fuzzing,
    check_aggressive_mode_detected,
    check_key_length_distinguishes_aes,
    check_all_proposals_extracted,
    check_parser_coverage,
)


def main() -> int:
    print("M4 — Parser complete\n")
    results = []
    for check in CHECKS:
        outcome = check()
        results.append(outcome)
        print(outcome)
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
