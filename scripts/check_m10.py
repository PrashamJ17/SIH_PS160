#!/usr/bin/env python3
"""Execute the M10 acceptance checklist and report pass/fail per item.

Each item runs the thing it claims to check. "CLI covers every workflow" is checked by
invoking every command the plan lists rather than by reading the source, and the offline
and drift items run the browser and the testbed rather than inspecting them.

``--fast`` skips the items that need Docker or a browser, and says so.
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final

REPO_ROOT = Path(__file__).resolve().parent.parent
for path in (REPO_ROOT / "src", REPO_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from click.testing import CliRunner  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from ipsec_sentinel.api.app import create_app  # noqa: E402
from ipsec_sentinel.cli import main  # noqa: E402

PYTEST: Final = REPO_ROOT / ".venv" / "bin" / "pytest"
SWEEP: Final = REPO_ROOT / "data" / "raw" / "sweep"
DASHBOARD: Final = REPO_ROOT / "dashboard"

# Every workflow the build plan's Step 10.1 lists, plus watch from Step 10.4.
PLANNED_COMMANDS: Final[tuple[tuple[str, ...], ...]] = (
    ("analyse",),
    ("inventory",),
    ("watch",),
    ("scan",),
    ("remediate",),
    ("dataset", "build"),
    ("dataset", "audit"),
    ("model", "train"),
    ("model", "evaluate"),
)


@dataclass
class Check:
    name: str
    status: str
    detail: str

    def __str__(self) -> str:
        return f"[{self.status}] {self.name}\n       {self.detail}"


def a_capture() -> Path | None:
    found = sorted(SWEEP.glob("*/capture_outer.pcap"))
    return found[0] if found else None


def _run_tests(node_ids: list[str], timeout: int = 5400) -> tuple[bool, str]:
    result = subprocess.run(
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


def check_cli_covers_every_workflow() -> Check:
    name = "CLI covers every workflow"
    runner = CliRunner()
    missing: list[str] = []
    for command in PLANNED_COMMANDS:
        result = runner.invoke(main, [*command, "--help"])
        if result.exit_code != 0:
            missing.append(" ".join(command))
    if missing:
        return Check(name, "FAIL", f"these commands do not exist or error: {missing}")

    capture = a_capture()
    if capture is None:
        return Check(name, "SKIP", "the sweep corpus is not present")

    # Reachable is not the same as working. The read-only workflows are actually run.
    exercised: list[str] = []
    for argv, label in (
        (["analyse", str(capture), "--baseline", "default", "--quiet"], "analyse"),
        (["inventory", str(capture)], "inventory"),
        (["remediate", str(capture), "--baseline", "default"], "remediate"),
        (["version"], "version"),
    ):
        result = runner.invoke(main, argv)
        if result.exit_code != 0:
            return Check(
                name, "FAIL", f"`{label}` exited {result.exit_code}: {result.output[:200]}"
            )
        exercised.append(label)

    refused = runner.invoke(main, ["scan", "192.0.2.1"])
    if refused.exit_code == 0:
        return Check(name, "FAIL", "`scan` ran without --i-have-authorisation")

    return Check(
        name,
        "PASS",
        f"{len(PLANNED_COMMANDS)} planned commands present; {', '.join(exercised)} run "
        f"end to end on a real capture; scan refuses without authorisation "
        f"(exit {refused.exit_code})",
    )


def check_api_security_tests() -> Check:
    name = "API passes all security tests"
    result = subprocess.run(
        [
            str(PYTEST),
            "tests/unit/test_api.py",
            "-k",
            "TestSecurity or TestUploadValidation",
            "--no-header",
            "-p",
            "no:cacheprovider",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=1800,
        check=False,
    )
    tail = (result.stdout + result.stderr).strip().splitlines()
    summary = next((line for line in reversed(tail) if "passed" in line or "failed" in line), "")
    if result.returncode != 0:
        return Check(name, "FAIL", summary or result.stdout[-300:])

    # The plan names three specific ones; confirm they exist rather than trusting a count.
    source = (REPO_ROOT / "tests" / "unit" / "test_api.py").read_text()
    required = {
        "path traversal": "test_a_traversing_filename_writes_nothing_outside_the_temp_dir",
        "temp dir only": "test_the_upload_never_lands_at_a_user_controlled_path",
        "nosniff": "test_every_response_forbids_content_sniffing",
        "size limit": "test_an_oversized_upload_returns_413",
    }
    absent = [label for label, fn in required.items() if fn not in source]
    if absent:
        return Check(name, "FAIL", f"the plan's security tests are missing: {absent}")
    return Check(name, "PASS", f"{summary}; all four named security tests present")


def check_dashboard_offline(fast: bool) -> Check:
    name = "Dashboard loads and functions offline"
    if fast:
        return Check(name, "SKIP", "--fast: the browser tests were not run")
    ok, summary = _run_tests(["tests/integration/test_dashboard.py"])
    return Check(
        name,
        "PASS" if ok else "FAIL",
        f"test_dashboard.py: {summary}. The offline test aborts every request outside the "
        f"server's own origin and then drives an upload to completion, rather than "
        f"inspecting the markup for URLs.",
    )


def check_dashboard_is_self_contained() -> Check:
    """Static half of the same claim: nothing is referenced that could fail to load."""
    name = "Dashboard references nothing external"
    if not DASHBOARD.is_dir():
        return Check(name, "FAIL", "there is no dashboard/ directory")
    offending: list[str] = []
    for path in sorted(DASHBOARD.glob("*")):
        if path.suffix not in (".html", ".js", ".css"):
            continue
        body = path.read_text()
        for marker in ("http://", "https://", "//cdn", "cdnjs", "unpkg", "googleapis"):
            if marker in body:
                offending.append(f"{path.name}: {marker}")
    if offending:
        return Check(name, "FAIL", f"external references: {offending}")
    files = sorted(p.name for p in DASHBOARD.glob("*") if p.suffix in (".html", ".js", ".css"))
    return Check(name, "PASS", f"{files} reference nothing outside this origin")


def check_watch_detects_weakening(fast: bool) -> Check:
    name = "Watch mode detects a live config weakening within 60 seconds"
    if fast:
        return Check(name, "SKIP", "--fast: the live watch tests were not run")
    ok, summary = _run_tests(["tests/integration/test_watch.py"])
    return Check(
        name,
        "PASS" if ok else "FAIL",
        f"test_watch.py: {summary}. A strong tunnel is replaced with a weak one between "
        f"the same endpoints and the alert is asserted against the plan's 60-second "
        f"deadline; a control asserts an unchanged tunnel reports nothing.",
    )


def check_the_rekey_blind_spot(fast: bool) -> Check:
    """Not on the plan's list. Added because Step 10.4 found the limit and 10.4b closed it."""
    name = "Drift is detectable without seeing the negotiation"
    if fast:
        return Check(name, "SKIP", "--fast: the live collector tests were not run")
    ok, summary = _run_tests(["tests/integration/test_collect_live.py"])
    return Check(
        name,
        "PASS" if ok else "FAIL",
        f"test_collect_live.py: {summary}. A rekey is carried in CREATE_CHILD_SA and is "
        f"encrypted, so the wire only reveals parameters at IKE_SA_INIT. Reading the "
        f"device's own state closes that, and the same tests assert no session key "
        f"reaches a parsed object.",
    )


def check_nothing_dials_out() -> Check:
    """The claim every interface rests on, checked across all three of them."""
    name = "No interface opens a connection except the one that is supposed to"
    runner = CliRunner()
    capture = a_capture()
    if capture is None:
        return Check(name, "SKIP", "the sweep corpus is not present")

    import socket

    real_socket = socket.socket
    opened: list[str] = []

    def watching(*args: object, **kwargs: object) -> object:
        if args and args[0] == socket.AF_INET:
            opened.append(str(args))
        return real_socket(*args, **kwargs)  # type: ignore[arg-type]

    # setattr rather than assignment: `socket.socket` is a type, and mypy is right
    # to object to rebinding one by name.
    setattr(socket, "socket", watching)  # noqa: B010
    try:
        runner.invoke(main, ["analyse", str(capture), "--baseline", "default", "--quiet"])
        runner.invoke(main, ["inventory", str(capture)])
        with TestClient(create_app()) as client:
            client.post(
                "/api/v1/analyse",
                files={"file": ("c.pcap", capture.read_bytes(), "application/octet-stream")},
            )
    finally:
        setattr(socket, "socket", real_socket)  # noqa: B010

    if opened:
        return Check(name, "FAIL", f"{len(opened)} outbound socket(s) during passive work")

    # And the one that is supposed to still refuses without authorisation.
    from ipsec_sentinel.probe import AuthorisationError, enumerate_transforms

    try:
        enumerate_transforms("192.0.2.1")
    except AuthorisationError:
        pass
    else:
        return Check(name, "FAIL", "the prober transmitted without authorisation")

    return Check(
        name,
        "PASS",
        "analyse, inventory and the API upload path opened no outbound socket; the "
        "prober still refuses without explicit authorisation",
    )


def check_full_regression(fast: bool) -> Check:
    name = "Full regression green"
    if fast:
        return Check(name, "SKIP", "--fast: run `make verify-all` separately")
    result = subprocess.run(
        ["make", "verify-all"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=7200,
        check=False,
    )
    output = (result.stdout + result.stderr).strip().splitlines()
    unit = next((line for line in output if "passed" in line and "deselected" in line), "")
    integration = next(
        (line for line in reversed(output) if "passed" in line and "deselected" not in line), ""
    )
    if result.returncode != 0:
        return Check(name, "FAIL", "; ".join(output[-4:]))
    return Check(name, "PASS", f"{unit.strip()} / {integration.strip()}")


def main_(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Run the M10 acceptance checklist.")
    parser.add_argument("--fast", action="store_true", help="skip Docker and browser checks")
    parser.add_argument("--only", help="run only checks whose name contains this substring")
    args = parser.parse_args(argv)

    checks = [
        ("cli", check_cli_covers_every_workflow),
        ("api", check_api_security_tests),
        ("dashboard_offline", lambda: check_dashboard_offline(args.fast)),
        ("dashboard_static", check_dashboard_is_self_contained),
        ("watch", lambda: check_watch_detects_weakening(args.fast)),
        ("blind_spot", lambda: check_the_rekey_blind_spot(args.fast)),
        ("no_dial_out", check_nothing_dials_out),
        ("regression", lambda: check_full_regression(args.fast)),
    ]
    selected = [fn for key, fn in checks if not args.only or args.only in key]

    print("M10 — Interfaces complete\n")
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
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main_())
