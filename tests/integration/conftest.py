"""Shared fixtures for integration tests.

Integration tests need a Docker daemon and privileged containers. When those are
absent the whole module skips with a clear reason — a missing daemon is not a test
failure, and reporting it as one would hide real regressions.
"""

from __future__ import annotations

import secrets
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path

import pytest

from testbed.traffic.base import RunContext
from tests.fixtures.dockerctl import (
    build_image,
    compose,
    compose_project,
    docker_available,
    exec_in,
    image_exists,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPOSE_DIR = REPO_ROOT / "testbed" / "compose"
STRONGSWAN_IMAGE = "ipsec-sentinel-strongswan:latest"
TRAFFIC_IMAGE = "ipsec-sentinel-traffic:latest"
PAIR_COMPOSE = COMPOSE_DIR / "pair.yml"


@pytest.fixture(scope="session")
def docker_daemon() -> str:
    available, detail = docker_available()
    if not available:
        pytest.skip(f"Docker unavailable: {detail}")
    return detail


@pytest.fixture(scope="session")
def traffic_image(docker_daemon: str) -> str:  # noqa: ARG001
    """Build the host traffic image once per session if it is not already present.

    ``docker_daemon`` is requested for its skip-if-absent side effect only.
    """
    if not image_exists(TRAFFIC_IMAGE):
        build_image(TRAFFIC_IMAGE, COMPOSE_DIR / "Dockerfile.traffic", COMPOSE_DIR)
    return TRAFFIC_IMAGE


@pytest.fixture(scope="session")
def strongswan_image(docker_daemon: str) -> str:  # noqa: ARG001
    """Build the strongSwan image once per session if it is not already present.

    ``docker_daemon`` is requested for its side effect — it skips the session when no
    daemon is reachable — so the value itself is deliberately unused. That is how
    pytest expresses a fixture dependency, hence the ARG001 suppression.
    """
    if not image_exists(STRONGSWAN_IMAGE):
        build_image(
            STRONGSWAN_IMAGE,
            COMPOSE_DIR / "Dockerfile.strongswan",
            COMPOSE_DIR,
        )
    return STRONGSWAN_IMAGE


@pytest.fixture(scope="session", autouse=True)
def _pair_images(strongswan_image: str, traffic_image: str) -> tuple[str, str]:
    """Ensure both images the pair needs exist before any integration test runs.

    The gateways run the strongSwan image and the hosts run the traffic image. Making
    this autouse means a test that brings up a pair cannot forget one of them and fail
    with an unexplained "image not found" from compose.
    """
    return strongswan_image, traffic_image


@contextmanager
def running_pair(
    out_dir: Path,
    profiles: Sequence[str] = (),
    extra_env: dict[str, str] | None = None,
) -> Iterator[RunContext]:
    """Bring up a pair, establish the tunnel, and yield a RunContext for generators.

    The tunnel is established before the block so traffic tests measure traffic rather
    than negotiation. Tests that need the IKE handshake in the capture must start the
    capture themselves before initiating.
    """
    env = {"SENTINEL_PSK": secrets.token_hex(24), **(extra_env or {})}
    with compose_project(PAIR_COMPOSE, env=env, profiles=profiles) as project:

        def cid(service: str) -> str:
            out = compose(PAIR_COMPOSE, project, "ps", "-q", service).stdout.strip()
            if not out:
                raise RuntimeError(f"no container for service {service}")
            return out

        left = cid("left")
        initiate = exec_in(left, "swanctl", "--initiate", "--child", "net-net", timeout=90)
        if initiate.returncode != 0:
            raise RuntimeError(f"tunnel did not establish: {initiate.stdout}{initiate.stderr}")
        yield RunContext(
            project=project,
            left_gateway=left,
            right_gateway=cid("right"),
            left_host=cid("left_host"),
            right_host=cid("right_host"),
            left_host_ip="10.1.0.10",
            right_host_ip="10.2.0.10",
            out_dir=out_dir,
        )
