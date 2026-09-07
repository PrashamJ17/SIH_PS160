"""The product must work without the test harness beside it.

`testbed/` is the Docker environment that generates the dataset. It is not part of the
distribution: it is excluded from the wheel, from the container image and from the offline
bundle. So a product module that imports from it works perfectly in a checkout and fails
with `ModuleNotFoundError` in every installed copy.

That is exactly what happened. `sentinel remediate` and `sentinel watch` imported
`TunnelConfig` from `testbed.orchestrate.config_gen`, and both were broken in the
container, the wheel and the bundle — while the entire unit suite passed, because the unit
suite runs from a checkout with `testbed/` on the path.

The defect was found by *running the demo*, which is an argument for running demos. This
file is the argument for not needing to.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PRODUCT = REPO_ROOT / "src" / "ipsec_sentinel"

# Packages that exist in this repository but are not shipped with the product.
NOT_DISTRIBUTED = frozenset({"testbed", "tests", "scripts", "demo", "dataset"})


def product_modules() -> list[Path]:
    return sorted(path for path in PRODUCT.rglob("*.py") if "__pycache__" not in path.parts)


def imported_roots(module: Path) -> set[str]:
    """Top-level package names this module imports, at module scope or inside a function."""
    roots: set[str] = set()
    tree = ast.parse(module.read_text(), filename=str(module))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            roots.add(node.module.split(".", 1)[0])
    return roots


class TestNothingShippedImportsWhatIsNotShipped:
    @pytest.mark.parametrize(
        "module", product_modules(), ids=lambda path: str(path.relative_to(PRODUCT))
    )
    def test_the_module_imports_only_distributed_packages(self, module: Path) -> None:
        offending = imported_roots(module) & NOT_DISTRIBUTED
        assert not offending, (
            f"{module.relative_to(REPO_ROOT)} imports {sorted(offending)}, which is not "
            f"part of the distribution; it will fail in the container and the bundle"
        )

    def test_the_forbidden_list_names_directories_that_exist(self) -> None:
        """A guard that names nothing guards nothing."""
        for package in NOT_DISTRIBUTED:
            assert (REPO_ROOT / package).is_dir(), f"{package} is not a directory here"


class TestEveryCommandImportsCleanly:
    """Import each command's module tree with the repository root off `sys.path`.

    Click resolves subcommands lazily, so a broken import inside one of them is invisible
    to `--help` and to any test that only runs `analyse`.
    """

    @pytest.mark.parametrize(
        "module",
        [
            "ipsec_sentinel.analyse",
            "ipsec_sentinel.cli",
            "ipsec_sentinel.collect",
            "ipsec_sentinel.probe",
            "ipsec_sentinel.watch",
            "ipsec_sentinel.remediate.generators.base",
            "ipsec_sentinel.remediate.generators.strongswan",
            "ipsec_sentinel.remediate.generators.libreswan",
            "ipsec_sentinel.remediate.generators.cisco",
            "ipsec_sentinel.remediate.generators.juniper",
            "ipsec_sentinel.remediate.generators.fortigate",
            "ipsec_sentinel.remediate.generators.paloalto",
            "ipsec_sentinel.remediate.observed",
            "ipsec_sentinel.remediate.sequence",
            "ipsec_sentinel.remediate.verify",
            "ipsec_sentinel.report.build",
            "ipsec_sentinel.api.app",
        ],
    )
    def test_it_imports_without_the_repository_on_the_path(self, module: str) -> None:
        result = subprocess.run(
            [sys.executable, "-c", f"import {module}"],
            cwd=REPO_ROOT.parent,  # anywhere but the checkout
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
            env={"PYTHONPATH": "", "PATH": "/usr/bin:/bin"},
        )
        assert result.returncode == 0, f"import {module} failed:\n{result.stderr[-1500:]}"
