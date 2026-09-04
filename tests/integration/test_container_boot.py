"""The strongSwan container boots and stays up (build plan Step 1.1)."""

from __future__ import annotations

import pytest

from tests.fixtures.dockerctl import container_running, docker, running_container, wait_for

pytestmark = pytest.mark.integration


def test_image_builds(strongswan_image: str) -> None:
    """The session fixture builds it; reaching here means the build succeeded."""
    assert docker("image", "inspect", strongswan_image).returncode == 0


def test_swanctl_version_returns_zero(strongswan_image: str) -> None:
    with running_container(strongswan_image) as container:
        assert wait_for(lambda: container_running(container), timeout=20)
        result = docker("exec", container, "swanctl", "--version")
        assert result.returncode == 0
        assert "strongswan" in result.stdout.lower()


def test_charon_is_the_main_process(strongswan_image: str) -> None:
    """The container's lifetime must be the daemon's lifetime."""
    with running_container(strongswan_image) as container:
        assert wait_for(lambda: container_running(container), timeout=20)
        # procps is not in debian bookworm-slim, so read /proc directly rather than
        # adding a package purely to satisfy a test.
        assert wait_for(
            lambda: (
                "charon"
                in docker(
                    "exec",
                    container,
                    "sh",
                    "-c",
                    "cat /proc/[0-9]*/comm 2>/dev/null",
                    check=False,
                ).stdout
            ),
            timeout=20,
        ), "charon is not running inside the container"


def test_vici_socket_appears(strongswan_image: str) -> None:
    """swanctl talks to charon over VICI; Step 1.6 harvests ground truth through it."""
    with running_container(strongswan_image) as container:
        assert wait_for(
            lambda: (
                docker(
                    "exec", container, "test", "-S", "/var/run/charon.vici", check=False
                ).returncode
                == 0
            ),
            timeout=25,
        ), "VICI socket never appeared"


def test_container_still_running_after_five_seconds(strongswan_image: str) -> None:
    """Guards against a daemon that starts, errors and exits immediately."""
    import time

    with running_container(strongswan_image) as container:
        assert wait_for(lambda: container_running(container), timeout=20)
        time.sleep(5)
        assert container_running(container), "container exited within five seconds"


def test_kernel_xfrm_is_reachable_from_the_container(strongswan_image: str) -> None:
    """Phase 1 depends on this; failing here explains any later tunnel failure."""
    with running_container(strongswan_image) as container:
        assert wait_for(lambda: container_running(container), timeout=20)
        result = docker("exec", container, "ip", "xfrm", "state", check=False)
        assert result.returncode == 0, f"ip xfrm state failed: {result.stderr}"


def test_container_stops_cleanly_on_sigterm(strongswan_image: str) -> None:
    """The sweep tears containers down thousands of times; SIGTERM must be handled."""
    with running_container(strongswan_image) as container:
        assert wait_for(lambda: container_running(container), timeout=20)
        docker("stop", "-t", "10", container, timeout=40)
        assert not container_running(container)


# Every primitive the Step 1.5 configuration matrix sweeps over. Nearly all are
# supplied by the openssl plugin, which silently failed to load until
# libstrongswan-standard-plugins was added to the image — leaving 3DES, AES-GCM,
# every HMAC and all ECP groups unavailable. This test exists so that regression
# fails here, loudly, rather than as an unexplained tunnel failure mid-sweep.
REQUIRED_ALGORITHMS = [
    "3DES_CBC",
    "AES_CBC",
    "AES_GCM_16",
    "HMAC_MD5",
    "HMAC_SHA1",
    "HMAC_SHA2_256",
    "HMAC_SHA2_384",
    "MODP_1024",
    "MODP_1536",
    "MODP_2048",
    "ECP_256",
    "ECP_384",
    "CURVE_25519",
]


def test_no_plugin_fails_to_load(strongswan_image: str) -> None:
    with running_container(strongswan_image) as container:
        assert wait_for(lambda: container_running(container), timeout=20)
        logs = docker("logs", container, check=False)
        combined = logs.stdout + logs.stderr
        failures = [ln for ln in combined.splitlines() if "failed to load" in ln.lower()]
        assert not failures, f"plugins failed to load: {failures}"


def test_every_algorithm_the_matrix_needs_is_available(strongswan_image: str) -> None:
    with running_container(strongswan_image) as container:
        assert wait_for(lambda: container_running(container), timeout=20)
        assert wait_for(
            lambda: (
                docker(
                    "exec", container, "test", "-S", "/var/run/charon.vici", check=False
                ).returncode
                == 0
            ),
            timeout=25,
        )
        listing = docker("exec", container, "swanctl", "--list-algs").stdout
        missing = [alg for alg in REQUIRED_ALGORITHMS if alg not in listing]
        assert not missing, f"algorithms missing from the image: {missing}"
