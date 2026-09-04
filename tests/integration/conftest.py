"""Shared fixtures for integration tests.

Integration tests need a Docker daemon and privileged containers. When those are
absent the whole module skips with a clear reason — a missing daemon is not a test
failure, and reporting it as one would hide real regressions.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.fixtures.dockerctl import build_image, docker_available, image_exists

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPOSE_DIR = REPO_ROOT / "testbed" / "compose"
STRONGSWAN_IMAGE = "ipsec-sentinel-strongswan:latest"
PAIR_COMPOSE = COMPOSE_DIR / "pair.yml"


@pytest.fixture(scope="session")
def docker_daemon() -> str:
    available, detail = docker_available()
    if not available:
        pytest.skip(f"Docker unavailable: {detail}")
    return detail


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
