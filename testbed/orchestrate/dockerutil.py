"""Minimal Docker exec helper for testbed orchestration."""

from __future__ import annotations

import subprocess


class DockerExecError(RuntimeError):
    """A command inside a container failed."""


def exec_in_container(container: str, *cmd: str, timeout: int = 60) -> str:
    """Run a command in a container and return stdout, raising on failure."""
    result = subprocess.run(
        ["docker", "exec", container, *cmd],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise DockerExecError(
            f"docker exec {container} {' '.join(cmd)} exited {result.returncode}: "
            f"{result.stderr.strip()[:300]}"
        )
    return result.stdout
