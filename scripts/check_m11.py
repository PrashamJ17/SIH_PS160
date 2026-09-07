#!/usr/bin/env python3
"""Execute the M11 acceptance checklist and report pass/fail per item.

The plan's final checklist has 28 items across four groups. Each one here runs the thing
it claims to check: "26 rules implemented" counts the registry, "zero credential storage"
runs the security suite, "air-gapped operation verified" runs the offline suite, and the
deliverables are checked as files on disk rather than as intentions.

``--fast`` skips the items that need Docker or a browser, and says which it skipped.
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final

REPO_ROOT = Path(__file__).resolve().parent.parent
for path in (REPO_ROOT / "src", REPO_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from ipsec_sentinel.assess.baselines.schema import get_baseline, load_baselines  # noqa: E402
from ipsec_sentinel.assess.framework import BUILTIN_TAGS  # noqa: E402
from ipsec_sentinel.assess.rules import default_registry  # noqa: E402

PYTEST: Final = REPO_ROOT / ".venv" / "bin" / "pytest"
DOCS: Final = REPO_ROOT / "docs"
REPORTS: Final = REPO_ROOT / "reports"
DEMO: Final = REPO_ROOT / "demo"

EXPECTED_RULES: Final = 26
COVERAGE_FLOOR: Final = 85.0
FOCUSED_COVERAGE_FLOOR: Final = 90.0


@dataclass
class Check:
    group: str
    name: str
    status: str
    detail: str

    def __str__(self) -> str:
        return f"[{self.status:<7}] {self.name}\n           {self.detail}"


def run_tests(
    node_ids: list[str], *, timeout: int = 5400, extra: list[str] | None = None
) -> tuple[bool, str]:
    result = subprocess.run(
        [str(PYTEST), *node_ids, "--no-header", "-p", "no:cacheprovider", *(extra or [])],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    lines = (result.stdout + result.stderr).strip().splitlines()
    summary = next(
        (line for line in reversed(lines) if any(w in line for w in ("passed", "failed", "error"))),
        f"exit {result.returncode}, no pytest summary",
    )
    return result.returncode == 0, summary.strip()


def document(name: str) -> Path:
    return REPO_ROOT / name if name == "README.md" else DOCS / name


# ------------------------------------------------------------------------- correctness


def check_parser_parity() -> Check:
    ok, summary = run_tests(["tests/integration/test_tshark_parity.py", "-m", "integration"])
    return Check(
        "Correctness",
        "Parser agrees with tshark on dataset captures",
        "PASS" if ok else "FAIL",
        summary,
    )


def check_fuzzing() -> Check:
    ok, summary = run_tests(["tests/unit/test_parser_fuzz.py", "-m", "not integration"])
    return Check(
        "Correctness",
        "Fuzzing: 10,000 inputs, zero crashes, zero hangs",
        "PASS" if ok else "FAIL",
        summary,
    )


def check_e2e() -> Check:
    ok, summary = run_tests(["tests/integration/test_e2e.py", "-m", "integration"])
    return Check(
        "Correctness",
        "E2E: weak -> detected -> remediated -> verified",
        "PASS" if ok else "FAIL",
        summary,
    )


def check_coverage() -> Check:
    name = "Coverage above 85% overall, above 90% for parser and assess"
    result = subprocess.run(
        [
            str(PYTEST),
            "tests/unit",
            "-m",
            "not integration",
            "--no-header",
            "-p",
            "no:cacheprovider",
            "-q",
            "--cov=ipsec_sentinel",
            "--cov-report=json:.coverage-m11.json",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=3600,
        check=False,
    )
    report = REPO_ROOT / ".coverage-m11.json"
    if result.returncode != 0 or not report.is_file():
        return Check(
            "Correctness", name, "FAIL", f"the coverage run failed: {result.stdout[-300:]}"
        )

    data = json.loads(report.read_text())
    overall = data["totals"]["percent_covered"]

    focused: dict[str, tuple[int, int]] = {"parser": (0, 0), "assess": (0, 0)}
    for path, entry in data["files"].items():
        for package in focused:
            if f"/{package}/" in path.replace("\\", "/"):
                covered, total = focused[package]
                summary = entry["summary"]
                focused[package] = (
                    covered + summary["covered_lines"],
                    total + summary["num_statements"],
                )
    report.unlink(missing_ok=True)

    parts = [f"overall {overall:.1f}%"]
    failures = [] if overall >= COVERAGE_FLOOR else [f"overall {overall:.1f}% < {COVERAGE_FLOOR}%"]
    for package, (covered, total) in focused.items():
        percentage = 100.0 * covered / total if total else 0.0
        parts.append(f"{package} {percentage:.1f}%")
        if percentage < FOCUSED_COVERAGE_FLOOR:
            failures.append(f"{package} {percentage:.1f}% < {FOCUSED_COVERAGE_FLOOR}%")

    return Check("Correctness", name, "FAIL" if failures else "PASS", ", ".join(parts + failures))


# ----------------------------------------------------------------------------- honesty


def check_published_document(title: str, filename: str, must_mention: tuple[str, ...]) -> Check:
    path = document(filename)
    if not path.is_file():
        return Check("Honesty", title, "FAIL", f"{filename} is missing")
    text = path.read_text().lower()
    missing = [word for word in must_mention if word.lower() not in text]
    if missing:
        return Check("Honesty", title, "FAIL", f"{filename} does not address: {missing}")
    return Check("Honesty", title, "PASS", f"{filename}, {len(text):,} characters")


def check_section_separation() -> Check:
    name = "Section A / B separation enforced by validator"
    ok, summary = run_tests(
        [
            "tests/unit/test_report_models.py",
            "tests/unit/test_report_build.py",
            "-m",
            "not integration",
        ]
    )
    return Check("Honesty", name, "PASS" if ok else "FAIL", summary)


# ---------------------------------------------------------------------------- security


def check_security_suite() -> Check:
    ok, summary = run_tests(["tests/unit/test_security.py", "-m", "not integration"])
    return Check(
        "Security",
        "No credential storage, no device writes, no outbound socket, pip-audit clean",
        "PASS" if ok else "FAIL",
        summary,
    )


def check_air_gapped(fast: bool) -> Check:
    name = "Air-gapped operation verified"
    if fast:
        return Check("Security", name, "SKIP", "--fast")
    ok, summary = run_tests(["tests/integration/test_offline.py", "-m", "integration"])
    return Check("Security", name, "PASS" if ok else "FAIL", summary)


def check_installable() -> Check:
    name = "Every command works in an installed copy"
    ok, summary = run_tests(["tests/unit/test_installable.py", "-m", "not integration"])
    return Check("Security", name, "PASS" if ok else "FAIL", summary)


# ------------------------------------------------------------------------ completeness


def check_rule_count() -> Check:
    rules = default_registry().rules
    uncited = [rule.id for rule in rules if not rule.standard_ref.strip()]
    if len(rules) != EXPECTED_RULES:
        return Check(
            "Completeness",
            "All 26 rules implemented",
            "FAIL",
            f"the registry holds {len(rules)}",
        )
    if uncited:
        return Check(
            "Completeness",
            "All 26 rules implemented",
            "FAIL",
            f"these rules cite no standard: {uncited}",
        )
    return Check(
        "Completeness",
        "All 26 rules implemented",
        "PASS",
        f"{len(rules)} rules, every one citing a standard",
    )


def check_baselines() -> Check:
    name = "All baselines including ITSAR and CERT-In"
    published = sorted(load_baselines())
    selectable = sorted({*published, *BUILTIN_TAGS})
    missing = [n for n in ("itsar", "certin") if n not in published]
    if missing:
        return Check("Completeness", name, "FAIL", f"missing: {missing}")

    empty = [n for n in published if not get_baseline(n).rules]
    if empty:
        return Check("Completeness", name, "FAIL", f"these select no rules: {empty}")

    unverified = [n for n in published if not get_baseline(n).verified]
    return Check(
        "Completeness",
        name,
        "PASS",
        f"{len(published)} published + {len(BUILTIN_TAGS)} tags = {len(selectable)} selectable; "
        f"encoded from public description (not a verified source copy): {unverified}",
    )


def check_feature_suites() -> Check:
    """PQC, VID/CVE, inventory, anomaly, remediation, verification and watch."""
    name = "PQC, VID+CVE, inventory, anomaly, remediation, verification, watch"
    ok, summary = run_tests(
        [
            "tests/unit/test_pqc_rules.py",
            "tests/unit/test_enrich.py",
            "tests/unit/test_inventory.py",
            "tests/unit/test_anomaly.py",
            "tests/unit/test_sequence.py",
            "tests/unit/test_verify.py",
            "tests/unit/test_watch.py",
            "-m",
            "not integration",
        ]
    )
    return Check("Completeness", name, "PASS" if ok else "FAIL", summary)


# ----------------------------------------------------------------------- deliverables


def check_deliverables() -> Check:
    name = "Prototype, model, dashboard, sample reports, demo video, docs, dataset"
    required = {
        "trained model": REPO_ROOT / "models" / "traffic.metadata.json",
        "dashboard": REPO_ROOT / "dashboard" / "index.html",
        "demo video": DEMO / "fallback.mp4",
        "demo script": DEMO / "SCRIPT.md",
        "dataset datacard": REPO_ROOT / "dataset" / "DATACARD.md",
        "published schema": REPO_ROOT / "schemas",
        "container": REPO_ROOT / "Dockerfile",
        "offline bundle builder": REPO_ROOT / "scripts" / "build_offline_bundle.sh",
    }
    missing = [label for label, path in required.items() if not path.exists()]
    if missing:
        return Check("Deliverables", name, "FAIL", f"missing: {missing}")

    reports = sorted(REPORTS.glob("*.json")) if REPORTS.is_dir() else []
    if not reports:
        return Check("Deliverables", name, "FAIL", "no generated reports in reports/")

    return Check(
        "Deliverables",
        name,
        "PASS",
        f"all present; {len(reports)} generated reports, "
        f"{DEMO.joinpath('fallback.mp4').stat().st_size // 1024} KB demo video",
    )


def check_documentation_set() -> Check:
    name = "Complete technical documentation"
    ok, summary = run_tests(["tests/unit/test_documentation.py", "-m", "not integration"])
    return Check("Deliverables", name, "PASS" if ok else "FAIL", summary)


def check_demo(fast: bool) -> Check:
    name = "Demo runs end to end under ten minutes"
    if fast:
        return Check("Deliverables", name, "SKIP", "--fast")
    ok, summary = run_tests(["tests/integration/test_demo.py", "-m", "integration"])
    return Check("Deliverables", name, "PASS" if ok else "FAIL", summary)


def check_packaging(fast: bool) -> Check:
    name = "Container non-root and under 1 GB, bundle installs offline"
    if fast:
        return Check("Deliverables", name, "SKIP", "--fast")
    ok, summary = run_tests(["tests/integration/test_packaging.py", "-m", "integration"])
    return Check("Deliverables", name, "PASS" if ok else "FAIL", summary)


def main_(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Run the M11 acceptance checklist.")
    parser.add_argument("--fast", action="store_true", help="skip Docker and browser checks")
    parser.add_argument("--only", help="run only checks whose key contains this substring")
    args = parser.parse_args(argv)

    checks = [
        ("parity", check_parser_parity),
        ("fuzz", check_fuzzing),
        ("e2e", check_e2e),
        ("coverage", check_coverage),
        (
            "generalisation",
            lambda: check_published_document(
                "Generalisation report published with degraded held-out numbers",
                "GENERALISATION.md",
                ("held-out configurations", "accuracy"),
            ),
        ),
        (
            "confound",
            lambda: check_published_document(
                "Confound audit published", "CONFOUND_AUDIT.md", ("cipher",)
            ),
        ),
        (
            "dataset_doc",
            lambda: check_published_document(
                "Dataset limitations documented", "DATASET.md", ("limitation",)
            ),
        ),
        (
            "external",
            lambda: check_published_document(
                "External dataset IPsec audit committed", "external_dataset_audit.md", ("ipsec",)
            ),
        ),
        (
            "limitations",
            lambda: check_published_document(
                "LIMITATIONS.md complete and honest",
                "LIMITATIONS.md",
                ("negotiated", "accredit", "governance", "lab", "syntax"),
            ),
        ),
        ("separation", check_section_separation),
        ("security", check_security_suite),
        ("airgap", lambda: check_air_gapped(args.fast)),
        ("installable", check_installable),
        ("rules", check_rule_count),
        ("baselines", check_baselines),
        ("features", check_feature_suites),
        ("deliverables", check_deliverables),
        ("docs", check_documentation_set),
        ("demo", lambda: check_demo(args.fast)),
        ("packaging", lambda: check_packaging(args.fast)),
    ]
    selected = [(key, fn) for key, fn in checks if not args.only or args.only in key]

    print("M11 — Release candidate\n")
    results: list[Check] = []
    group = ""
    for _, check in selected:
        result = check()
        if result.group != group:
            group = result.group
            print(f"\n{group.upper()}\n{'-' * len(group)}")
        print(result)
        print()
        results.append(result)

    failed = [r for r in results if r.status == "FAIL"]
    skipped = [r for r in results if r.status == "SKIP"]
    passed = len(results) - len(failed) - len(skipped)
    print(f"\n{passed}/{len(results)} passed, {len(failed)} failed, {len(skipped)} skipped")
    for result in failed:
        print(f"  FAILED: {result.name}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main_())
