"""Thin, well-behaved wrapper around the Docker CLI for integration tests.

Two rules govern everything here, because the Phase 3 sweep runs these paths
thousands of times:

* **Teardown always happens.** Every context manager removes what it created in a
  ``finally`` block. A leaked container or network poisons every subsequent run.
* **Absence is skipped, not failed.** If Docker is unavailable the tests skip with a
  clear reason rather than reporting a false failure.
"""

from __future__ import annotations

import shutil
import subprocess
import time
import uuid
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path

DEFAULT_TIMEOUT = 120


class DockerError(RuntimeError):
    """A docker command failed."""


def docker(
    *args: str,
    timeout: int = DEFAULT_TIMEOUT,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run a docker command, capturing output."""
    result = subprocess.run(
        ["docker", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if check and result.returncode != 0:
        raise DockerError(
            f"docker {' '.join(args)} exited {result.returncode}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
    return result


def docker_available() -> tuple[bool, str]:
    """Return whether a usable Docker daemon is reachable, and why not if it is not."""
    if shutil.which("docker") is None:
        return False, "docker CLI not on PATH"
    try:
        result = docker("info", "--format", "{{.ServerVersion}}", timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"docker info failed: {exc}"
    if result.returncode != 0:
        return False, f"docker daemon unreachable: {result.stderr.strip()[:200]}"
    return True, result.stdout.strip()


def image_exists(tag: str) -> bool:
    return docker("image", "inspect", tag, check=False).returncode == 0


def build_image(tag: str, dockerfile: Path, context: Path, timeout: int = 1800) -> None:
    """Build an image, streaming nothing but raising with full output on failure."""
    docker(
        "build",
        "-f",
        str(dockerfile),
        "-t",
        tag,
        str(context),
        timeout=timeout,
    )


def container_running(name: str) -> bool:
    result = docker("inspect", "-f", "{{.State.Running}}", name, check=False, timeout=30)
    return result.returncode == 0 and result.stdout.strip() == "true"


def force_remove(name: str) -> None:
    """Remove a container, tolerating its absence."""
    docker("rm", "-f", name, check=False, timeout=60)


@contextmanager
def running_container(
    image: str,
    *,
    name: str | None = None,
    privileged: bool = True,
    extra_args: Sequence[str] = (),
    command: Sequence[str] = (),
) -> Iterator[str]:
    """Start a detached container and guarantee its removal.

    Privileged by default: the testbed needs kernel XFRM and network namespaces,
    which is exactly what these containers exist to exercise.
    """
    container = name or f"sentinel-test-{uuid.uuid4().hex[:12]}"
    args = ["run", "-d", "--name", container]
    if privileged:
        args += ["--privileged", "--cap-add=NET_ADMIN"]
    args += [*extra_args, image, *command]
    try:
        docker(*args, timeout=180)
        yield container
    finally:
        force_remove(container)


def wait_for(predicate: Callable[[], bool], timeout: float = 15.0, interval: float = 0.25) -> bool:
    """Poll ``predicate`` until it returns truthy or the timeout elapses."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return bool(predicate())


def compose(
    compose_file: Path,
    project: str,
    *args: str,
    timeout: int = DEFAULT_TIMEOUT,
    check: bool = True,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run `docker compose` against one file under an explicit project name.

    The project name isolates concurrent pairs, which the Step 3.2 sweep depends on.
    """
    argv = ["docker", "compose", "-f", str(compose_file), "-p", project, *args]
    merged = None
    if env is not None:
        import os

        merged = {**os.environ, **env}
    result = subprocess.run(
        argv, capture_output=True, text=True, timeout=timeout, check=False, env=merged
    )
    if check and result.returncode != 0:
        raise DockerError(
            f"{' '.join(argv)} exited {result.returncode}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
    return result


@contextmanager
def compose_project(
    compose_file: Path,
    project: str | None = None,
    env: dict[str, str] | None = None,
    up_timeout: int = 300,
) -> Iterator[str]:
    """Bring a compose project up and guarantee it is torn down.

    Teardown removes volumes and orphans as well as containers: a leaked network
    exhausts the bridge address space and poisons every later run in a sweep.
    """
    name = project or f"sentinel-{uuid.uuid4().hex[:10]}"
    try:
        compose(compose_file, name, "up", "-d", "--wait", timeout=up_timeout, env=env)
        yield name
    finally:
        compose(
            compose_file,
            name,
            "down",
            "-v",
            "--remove-orphans",
            timeout=180,
            check=False,
            env=env,
        )


def network_names() -> list[str]:
    """Every Docker network currently defined."""
    result = docker("network", "ls", "--format", "{{.Name}}", timeout=30)
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def exec_in(container: str, *cmd: str, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    """Run a command inside a container without raising on a non-zero exit."""
    return docker("exec", container, *cmd, timeout=timeout, check=False)
