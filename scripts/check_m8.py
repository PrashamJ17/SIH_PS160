#!/usr/bin/env python3
"""Execute the M8 acceptance checklist and report pass/fail per item.

Each check runs the thing it claims to check. Where an item cannot be satisfied by this
testbed it is reported BLOCKED with the reason, never converted into a green tick — a
gate that launders an impossible check into a pass is worse than no gate.

The live items are checked by running the integration tests that establish them, which
takes minutes and needs Docker. ``--fast`` skips those and says so.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final

REPO_ROOT = Path(__file__).resolve().parent.parent
for path in (REPO_ROOT / "src", REPO_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from ipsec_sentinel.assess.rules import default_registry  # noqa: E402
from ipsec_sentinel.models import ESPFlow, TunnelAssessment  # noqa: E402
from ipsec_sentinel.remediate.generators import (  # noqa: E402
    cisco,
    fortigate,
    juniper,
    libreswan,
    paloalto,
    strongswan,
)
from ipsec_sentinel.remediate.generators.base import DeploymentStatus  # noqa: E402
from ipsec_sentinel.remediate.models import (  # noqa: E402
    FORBIDDEN_TRANSPORTS,
    ConfigRole,
)
from ipsec_sentinel.remediate.sequence import STEP_COUNT  # noqa: E402
from ipsec_sentinel.remediate.verify import VerificationStatus  # noqa: E402
from testbed.orchestrate.matrix import expand_matrix  # noqa: E402

REMEDIATE: Final = REPO_ROOT / "src" / "ipsec_sentinel" / "remediate"
VENDORS: Final = (cisco, fortigate, juniper, libreswan, paloalto)
PYTEST: Final = REPO_ROOT / ".venv" / "bin" / "pytest"


@dataclass
class Check:
    name: str
    status: str
    detail: str

    def __str__(self) -> str:
        return f"[{self.status}] {self.name}\n       {self.detail}"


def anchor(label: str):  # type: ignore[no-untyped-def]
    return next(lc.config for lc in expand_matrix() if lc.label == label)


def _run_tests(node_ids: list[str], timeout: int = 3600) -> tuple[bool, str]:
    result = subprocess.run(
        # No explicit -q: pyproject's addopts already supplies one, and a second makes
        # it -qq, which suppresses the very summary line this parses for. The check
        # would still pass on the return code while reporting no evidence at all.
        [str(PYTEST), *node_ids, "-m", "integration", "--no-header", "-p", "no:cacheprovider"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    tail = (result.stdout + result.stderr).strip().splitlines()
    wanted = ("passed", "failed", "error")
    summary = next(
        (line for line in reversed(tail) if any(word in line for word in wanted)),
        f"exit {result.returncode}, but no pytest summary line was found",
    )
    return result.returncode == 0, summary


# --------------------------------------------------------------------- the checklist


def check_both_ends_for_every_finding_type() -> Check:
    name = "Both-ends configs generated for every finding type"
    addressable = sorted(strongswan.ADDRESSABLE)
    all_rules = sorted({rule.id for rule in default_registry().rules})
    unaddressable = [rule for rule in all_rules if rule not in addressable]

    failures: list[str] = []
    for rule_id in addressable:
        # "worst" triggers the widest set; anything it cannot fix is a real gap.
        try:
            package = strongswan.generate_change_package("m8", anchor("worst"), [rule_id])
        except Exception as exc:  # reported as a failed check, not raised
            failures.append(f"{rule_id}: {type(exc).__name__}: {exc}")
            continue
        if package.local_config.role is not ConfigRole.LOCAL:
            failures.append(f"{rule_id}: local document has role {package.local_config.role}")
        if package.peer_config.role is not ConfigRole.PEER:
            failures.append(f"{rule_id}: peer document has role {package.peer_config.role}")
        if not package.local_config.content or not package.peer_config.content:
            failures.append(f"{rule_id}: an end has empty content")
        if package.local_config.content == package.peer_config.content:
            failures.append(f"{rule_id}: both ends are byte-identical")

    if failures:
        return Check(name, "FAIL", "; ".join(failures[:5]))
    return Check(
        name,
        "PASS",
        f"{len(addressable)} addressable finding types each produce two distinct "
        f"documents. {len(unaddressable)} of {len(all_rules)} rules are declared "
        f"outside the generator's scope and named in the package notes: "
        f"{', '.join(unaddressable)}",
    )


def check_strongswan_deploys_live(fast: bool) -> Check:
    name = "strongSwan configs deploy successfully live"
    if fast:
        return Check(name, "SKIP", "--fast: the live deployment tests were not run")
    ok, summary = _run_tests(["tests/integration/test_gen_strongswan_live.py"])
    return Check(name, "PASS" if ok else "FAIL", f"test_gen_strongswan_live.py: {summary}")


def check_libreswan_deploys_live() -> Check:
    name = "Libreswan configs deploy successfully live"
    return Check(
        name,
        "BLOCKED",
        "the testbed runs strongSwan only, so no Libreswan peer exists to deploy onto. "
        "The generator is syntax-validated and every document it emits says so in its "
        "own header; a test pins that status so it cannot silently be claimed as tested. "
        "Unblocking needs a Libreswan container image in testbed/compose.",
    )


def check_zero_downtime_verified_live(fast: bool) -> Check:
    name = "Zero-downtime sequence verified with zero packet loss during the change"
    if fast:
        return Check(name, "SKIP", "--fast: the live sequencing tests were not run")
    ok, summary = _run_tests(["tests/integration/test_sequence_live.py"])
    return Check(
        name,
        "PASS" if ok else "FAIL",
        f"test_sequence_live.py: {summary}. The suite asserts zero lost probes and a "
        f"zero-second outage across the change, that the probe covered >95% of it, and "
        f"— as a control on the measurement — that the naive replacement does produce a "
        f"sustained outage the same instrument can read.",
    )


def check_non_testbed_vendors_marked() -> Check:
    name = "Non-testbed vendors clearly marked as syntax-only"
    failures: list[str] = []
    marked: list[str] = []
    for module in VENDORS:
        status = getattr(module, "STATUS", None)
        if status is None:
            failures.append(f"{module.__name__} declares no STATUS")
            continue
        rendered = module.render(anchor("worst"), "left")
        if status is DeploymentStatus.SYNTAX_VALIDATED:
            if "syntax-validated" not in rendered:
                failures.append(f"{module.VENDOR}: the caveat is not in the emitted document")
            else:
                marked.append(module.VENDOR)
        elif status is DeploymentStatus.LIVE_TESTED:
            failures.append(f"{module.VENDOR} claims live-tested but has no live test")

    # strongSwan's constant is Final, so comparing it here would be checked away by
    # the type system and prove nothing at run time. What is worth checking is that the
    # claim reaches the document an operator reads.
    live = strongswan.render(anchor("worst"), "left")
    if DeploymentStatus.LIVE_TESTED.value not in live:
        failures.append("the strongSwan document does not state that it is live-tested")
    if "This tool never writes to a device" not in live:
        failures.append("the strongSwan document omits the never-writes statement")
    if failures:
        return Check(name, "FAIL", "; ".join(failures))
    return Check(
        name,
        "PASS",
        f"{len(marked)} vendors carry the caveat in every emitted document "
        f"({', '.join(marked)}); strongSwan alone is marked live-tested",
    )


def check_auto_verification_closes_a_finding(fast: bool) -> Check:
    name = "Auto-verification closes a finding after a live rekey"
    if fast:
        return Check(name, "SKIP", "--fast: the live verification tests were not run")
    ok, summary = _run_tests(["tests/integration/test_verify_live.py"])
    return Check(
        name,
        "PASS" if ok else "FAIL",
        f"test_verify_live.py: {summary}. One real change is walked end to end and all "
        f"four verdicts are observed in order — {VerificationStatus.FAILED.value} before "
        f"it, {VerificationStatus.PARTIAL.value} after the target is negotiated while "
        f"the old proposal is still offered, {VerificationStatus.PENDING.value} after "
        f"the removal but before the next negotiation, and "
        f"{VerificationStatus.VERIFIED.value} once the wire confirms it, which closes "
        f"the finding.",
    )


def check_the_tool_never_executes_a_change() -> Check:
    """Read the remediation lane's imports and calls; do not take its word for it."""
    name = "The tool never executes a change (no device write API on any code path)"
    offences: list[str] = []
    scanned = 0
    write_calls = {"connect", "send_config_set", "send_command", "sendline", "load_merge_candidate"}

    for path in sorted(REMEDIATE.rglob("*.py")):
        scanned += 1
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] in FORBIDDEN_TRANSPORTS:
                        offences.append(f"{path.name} imports {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                root = (node.module or "").split(".")[0]
                if root in FORBIDDEN_TRANSPORTS:
                    offences.append(f"{path.name} imports from {node.module}")
            elif isinstance(node, ast.Call):
                func = node.func
                attribute = func.attr if isinstance(func, ast.Attribute) else None
                if attribute in write_calls:
                    offences.append(f"{path.name}:{node.lineno} calls .{attribute}()")
                if isinstance(func, ast.Name) and func.id in {"exec", "eval"}:
                    offences.append(f"{path.name}:{node.lineno} calls {func.id}()")

    if offences:
        return Check(name, "FAIL", "; ".join(offences))
    return Check(
        name,
        "PASS",
        f"{scanned} modules in the remediation lane parsed: no import of any of the "
        f"{len(FORBIDDEN_TRANSPORTS)} forbidden transports "
        f"({', '.join(sorted(FORBIDDEN_TRANSPORTS))}), no device-write call, no "
        f"exec/eval. The tool emits documents; humans apply them.",
    )


def check_the_sequence_and_verification_agree() -> Check:
    """The two halves of the loop must describe the same change.

    Not on the plan's list. Added because Step 8.6 found the verification module reading
    a field the parser never set, and a checklist that only exercises each half
    separately would not have caught it.
    """
    name = "The change package, the sequence and the verifier describe the same change"
    package = strongswan.generate_change_package("m8", anchor("weak"), ["CRY-02"])
    corrected, _ = strongswan.harden(anchor("weak"))
    problems: list[str] = []

    if len(package.sequence) != STEP_COUNT:
        problems.append(f"{len(package.sequence)} steps, expected {STEP_COUNT}")
    if package.total_expected_disruption_s != 0:
        problems.append(f"declares {package.total_expected_disruption_s}s of disruption")
    if package.blast_radius.estimated_disruption_s != package.total_expected_disruption_s:
        problems.append(
            f"blast radius says {package.blast_radius.estimated_disruption_s}s while the "
            f"sequence sums to {package.total_expected_disruption_s}s"
        )
    if not any(corrected.proposal_string() in step for step in package.verification):
        problems.append("no verification step names the target proposal")
    if not any(corrected.proposal_string() in step.action for step in package.sequence):
        problems.append("no sequence step names the target proposal")

    busy = TunnelAssessment(
        tunnel_id="m8",
        endpoints=("203.0.113.1", "198.51.100.1"),
        esp_flows=[
            ESPFlow(
                spi="aabbccdd",
                src_ip="203.0.113.1",
                dst_ip="198.51.100.1",
                packet_count=40_000,
                byte_count=6_000_000,
                first_seen=datetime(2026, 3, 4, 9, 0, tzinfo=UTC),
                last_seen=datetime(2026, 3, 4, 9, 0, tzinfo=UTC) + timedelta(seconds=60),
            )
        ],
        score=40,
        grade="D",
    )
    observed = strongswan.generate_change_package("m8", anchor("weak"), ["CRY-02"], observed=busy)
    if not observed.requires_maintenance_window:
        problems.append("a busy tunnel did not raise a maintenance window")

    if problems:
        return Check(name, "FAIL", "; ".join(problems))
    return Check(
        name,
        "PASS",
        f"{STEP_COUNT} steps, 0s declared disruption agreeing with the blast radius, "
        f"the target proposal named in both the sequence and the verification steps, "
        f"and an observed busy tunnel raising a maintenance window",
    )


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Run the M8 acceptance checklist.")
    parser.add_argument("--fast", action="store_true", help="skip the live Docker checks")
    parser.add_argument("--only", help="run only checks whose name contains this substring")
    args = parser.parse_args(argv)

    checks = [
        check_both_ends_for_every_finding_type,
        lambda: check_strongswan_deploys_live(args.fast),
        check_libreswan_deploys_live,
        lambda: check_zero_downtime_verified_live(args.fast),
        check_non_testbed_vendors_marked,
        lambda: check_auto_verification_closes_a_finding(args.fast),
        check_the_tool_never_executes_a_change,
        check_the_sequence_and_verification_agree,
    ]
    names = [
        "both_ends",
        "strongswan_live",
        "libreswan_live",
        "zero_downtime",
        "vendors_marked",
        "auto_verification",
        "never_executes",
        "agree",
    ]
    selected = [
        check for check, key in zip(checks, names, strict=True) if not args.only or args.only in key
    ]

    print("M8 — Remediation complete\n")
    results = [check() for check in selected]
    for result in results:
        print(result)
        print()

    failed = [r for r in results if r.status == "FAIL"]
    blocked = [r for r in results if r.status == "BLOCKED"]
    skipped = [r for r in results if r.status == "SKIP"]
    passed = len(results) - len(failed) - len(blocked) - len(skipped)
    print(
        f"{passed}/{len(results)} passed, {len(failed)} failed, "
        f"{len(blocked)} blocked, {len(skipped)} skipped"
    )
    if blocked:
        print("\nBLOCKED items are not failures and not passes. They cannot be satisfied")
        print("with the testbed as it stands, and the reason is recorded above.")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
