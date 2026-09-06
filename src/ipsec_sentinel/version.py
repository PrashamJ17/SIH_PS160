"""Tool identity: version and source revision.

A report that cannot say which build produced it is not auditable. Six months later the
question "was this the run before or after the parser fix?" has to have an answer, and
the version alone does not give one — the version changes at release, the finding logic
changes at every commit.

Both lookups fail softly. An installed copy has no git repository, and a checkout may
have no ``git`` binary; neither is an error, and neither should stop a report being
produced. The absence is reported as ``None`` and rendered as "unknown", which is
honest, rather than filled in with a plausible default, which is not.
"""

from __future__ import annotations

import subprocess
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Final

DISTRIBUTION: Final = "ipsec-sentinel"
UNKNOWN_VERSION: Final = "unknown"
REPO_ROOT: Final = Path(__file__).resolve().parents[2]


def tool_version() -> str:
    """The installed distribution version, or ``"unknown"``."""
    try:
        return version(DISTRIBUTION)
    except PackageNotFoundError:
        return UNKNOWN_VERSION


def git_sha(short: bool = True) -> str | None:
    """The current commit, or ``None`` outside a working checkout.

    Never raises: a missing ``git``, a missing repository and a git that returns an
    error all mean the same thing to a caller — the revision is not knowable here.
    """
    argv = ["git", "rev-parse", "--short" if short else "--verify", "HEAD"]
    try:
        result = subprocess.run(
            argv,
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    revision = result.stdout.strip()
    return revision if result.returncode == 0 and revision else None


def git_dirty() -> bool | None:
    """Whether the working tree has uncommitted changes, or ``None`` if unknowable.

    Recorded alongside the SHA because a report produced from a modified checkout was
    not produced by the commit it names, and saying so is the difference between a
    provenance record and a decoration.
    """
    try:
        result = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return bool(result.stdout.strip())


def describe() -> str:
    """A one-line build identity for a report header or ``--version``."""
    revision = git_sha()
    if revision is None:
        return f"{DISTRIBUTION} {tool_version()} (revision unknown)"
    suffix = "-dirty" if git_dirty() else ""
    return f"{DISTRIBUTION} {tool_version()} ({revision}{suffix})"
