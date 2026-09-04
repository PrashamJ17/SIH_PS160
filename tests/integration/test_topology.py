"""Two-peer topology comes up, connects, and tears down cleanly (Step 1.2)."""

from __future__ import annotations

import pytest

from tests.fixtures.dockerctl import (
    compose,
    compose_project,
    docker,
    exec_in,
    network_names,
)

from .conftest import PAIR_COMPOSE

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("strongswan_image")]


def container_id(project: str, service: str) -> str:
    result = compose(PAIR_COMPOSE, project, "ps", "-q", service)
    cid = result.stdout.strip()
    assert cid, f"no container id for service {service}"
    return cid


def test_pair_comes_up() -> None:
    with compose_project(PAIR_COMPOSE) as project:
        for service in ("left", "right"):
            cid = container_id(project, service)
            state = docker("inspect", "-f", "{{.State.Running}}", cid).stdout.strip()
            assert state == "true", f"{service} is not running"


def test_left_can_ping_right_on_the_transit_network() -> None:
    with compose_project(PAIR_COMPOSE) as project:
        left = container_id(project, "left")
        result = exec_in(left, "ping", "-c", "3", "-W", "5", "10.100.0.3")
        assert result.returncode == 0, f"ping failed:\n{result.stdout}\n{result.stderr}"
        assert "0% packet loss" in result.stdout


def test_peers_have_both_transit_and_protected_addresses() -> None:
    """The site-to-site shape: a gateway address plus a protected subnet behind it."""
    with compose_project(PAIR_COMPOSE) as project:
        left_addrs = exec_in(container_id(project, "left"), "ip", "-4", "addr").stdout
        right_addrs = exec_in(container_id(project, "right"), "ip", "-4", "addr").stdout
        assert "10.100.0.2" in left_addrs
        assert "10.1.0.2" in left_addrs
        assert "10.100.0.3" in right_addrs
        assert "10.2.0.2" in right_addrs


def test_ip_forwarding_is_enabled_on_both_peers() -> None:
    """A gateway that does not forward cannot carry a site-to-site tunnel."""
    with compose_project(PAIR_COMPOSE) as project:
        for service in ("left", "right"):
            cid = container_id(project, service)
            value = exec_in(cid, "cat", "/proc/sys/net/ipv4/ip_forward").stdout.strip()
            assert value == "1", f"{service} has ip_forward={value}"


def test_teardown_leaves_no_orphaned_networks() -> None:
    """A leaked network exhausts the bridge address space and poisons later runs."""
    before = set(network_names())
    with compose_project(PAIR_COMPOSE):
        during = set(network_names())
        assert during - before, "compose created no networks"
    after = set(network_names())
    assert after - before == set(), f"orphaned networks left behind: {after - before}"


def test_teardown_leaves_no_containers() -> None:
    with compose_project(PAIR_COMPOSE) as project:
        captured = project
    remaining = docker(
        "ps",
        "-a",
        "--filter",
        f"label=com.docker.compose.project={captured}",
        "--format",
        "{{.Names}}",
    ).stdout.strip()
    assert remaining == "", f"containers survived teardown: {remaining}"


def test_two_pairs_can_run_concurrently_on_distinct_subnets() -> None:
    """The Step 3.2 sweep runs several pairs at once; the file must support it."""
    second = {
        "TRANSIT_SUBNET": "10.110.0.0/24",
        "LEFT_TRANSIT_IP": "10.110.0.2",
        "RIGHT_TRANSIT_IP": "10.110.0.3",
        "LEFT_PROTECTED_SUBNET": "10.11.0.0/24",
        "LEFT_PROTECTED_IP": "10.11.0.2",
        "LEFT_HOST_IP": "10.11.0.10",
        "RIGHT_PROTECTED_SUBNET": "10.12.0.0/24",
        "RIGHT_PROTECTED_IP": "10.12.0.2",
        "RIGHT_HOST_IP": "10.12.0.10",
    }
    with (
        compose_project(PAIR_COMPOSE) as first_project,
        compose_project(PAIR_COMPOSE, env=second) as second_project,
    ):
        assert first_project != second_project
        a = exec_in(container_id(first_project, "left"), "ping", "-c", "2", "-W", "5", "10.100.0.3")
        b = exec_in(
            container_id(second_project, "left"), "ping", "-c", "2", "-W", "5", "10.110.0.3"
        )
        assert a.returncode == 0, "first pair lost connectivity"
        assert b.returncode == 0, "second pair lost connectivity"
