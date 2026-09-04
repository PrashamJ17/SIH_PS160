"""The first working IPsec tunnel (build plan Step 1.3).

The load-bearing assertion here is not that a tunnel comes up — it is that the
plaintext payload marker does **not** appear on the wire. That is the only evidence
the tunnel is genuinely protecting traffic rather than merely reporting that it is.
"""

from __future__ import annotations

import secrets
import time

import pytest

from tests.fixtures.dockerctl import (
    capture_contains_bytes,
    capture_for,
    compose,
    compose_project,
    exec_in,
    interface_for_ip,
    read_capture,
)

from .conftest import PAIR_COMPOSE

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("strongswan_image")]

LEFT_TRANSIT = "10.100.0.2"
RIGHT_TRANSIT = "10.100.0.3"
LEFT_PROTECTED = "10.1.0.2"
RIGHT_PROTECTED = "10.2.0.2"

# The plan's outer capture filter. Note it excludes ICMP by construction, which also
# excludes the decrypted copies the kernel re-injects on the capturing endpoint —
# capturing on a peer sees inbound packets twice, once as ESP and once decrypted.
OUTER_BPF = "udp port 500 or udp port 4500 or ip proto 50 or ip proto 51"

# A distinctive ICMP payload. If this appears anywhere in the outer capture, the
# traffic was not encrypted.
MARKER_HEX = "a5c3f00d"


def fresh_psk() -> dict[str, str]:
    """A per-run pre-shared key, so no secret is ever committed to the repository."""
    return {"SENTINEL_PSK": secrets.token_hex(24)}


def container_id(project: str, service: str) -> str:
    cid = compose(PAIR_COMPOSE, project, "ps", "-q", service).stdout.strip()
    assert cid, f"no container for service {service}"
    return cid


def initiate(left: str) -> str:
    result = exec_in(left, "swanctl", "--initiate", "--child", "net-net", timeout=90)
    assert result.returncode == 0, f"initiate failed:\n{result.stdout}\n{result.stderr}"
    return result.stdout + result.stderr


def test_tunnel_initiates_successfully() -> None:
    with compose_project(PAIR_COMPOSE, env=fresh_psk()) as project:
        output = initiate(container_id(project, "left"))
        assert "initiate completed successfully" in output


def test_list_sas_shows_an_established_sa() -> None:
    with compose_project(PAIR_COMPOSE, env=fresh_psk()) as project:
        left = container_id(project, "left")
        initiate(left)
        sas = exec_in(left, "swanctl", "--list-sas").stdout
        assert "ESTABLISHED" in sas, f"no established SA:\n{sas}"
        assert "INSTALLED" in sas, f"no installed child SA:\n{sas}"


def test_negotiated_suite_is_the_one_configured() -> None:
    """AES-GCM-256 with DH group 20 — what the hand-written config asked for."""
    with compose_project(PAIR_COMPOSE, env=fresh_psk()) as project:
        left = container_id(project, "left")
        initiate(left)
        sas = exec_in(left, "swanctl", "--list-sas").stdout
        assert "AES_GCM_16" in sas, f"expected AES-GCM:\n{sas}"
        assert "ECP_384" in sas or "ecp384" in sas.lower(), f"expected DH group 20:\n{sas}"


def test_kernel_installed_an_esp_sa_in_tunnel_mode() -> None:
    """The daemon's claim is checked against the kernel's own view."""
    with compose_project(PAIR_COMPOSE, env=fresh_psk()) as project:
        left = container_id(project, "left")
        initiate(left)
        state = exec_in(left, "ip", "xfrm", "state").stdout
        assert "proto esp" in state
        assert "mode tunnel" in state
        assert "rfc4106(gcm(aes))" in state, f"expected AES-GCM AEAD:\n{state}"


def test_traffic_between_protected_subnets_is_esp_and_never_plaintext() -> None:
    """The assertion that matters: ESP on the wire, and the payload marker absent.

    Capture happens on the sending peer's transit interface with the outer filter, so
    only what a passive observer of the link would see is examined.
    """
    with compose_project(PAIR_COMPOSE, env=fresh_psk()) as project:
        left = container_id(project, "left")
        initiate(left)
        transit_iface = interface_for_ip(left, LEFT_TRANSIT)

        capture_for(left, transit_iface, OUTER_BPF, seconds=14, path="/tmp/outer.pcap")
        time.sleep(3)
        ping = exec_in(
            left,
            "ping",
            "-c",
            "5",
            "-W",
            "5",
            "-p",
            MARKER_HEX,
            "-I",
            LEFT_PROTECTED,
            RIGHT_PROTECTED,
            timeout=60,
        )
        assert ping.returncode == 0, f"ping through the tunnel failed:\n{ping.stdout}"
        assert "0% packet loss" in ping.stdout
        time.sleep(13)  # let tcpdump time out, flush and close

        listing = read_capture(left, "/tmp/outer.pcap")
        esp_lines = [ln for ln in listing.splitlines() if "ESP(" in ln]
        assert len(esp_lines) >= 5, f"expected ESP packets on the wire, got:\n{listing}"

        icmp = read_capture(left, "/tmp/outer.pcap", "icmp")
        assert icmp.strip() == "", f"plaintext ICMP present on the transit link:\n{icmp}"

        assert not capture_contains_bytes(left, "/tmp/outer.pcap", MARKER_HEX), (
            "the plaintext ping payload marker was found in the outer capture — "
            "traffic is NOT protected"
        )


def test_marker_would_be_visible_without_the_tunnel() -> None:
    """Control for the test above: prove the marker check can actually fail.

    Without this, a marker assertion that never fires would pass whether or not the
    tunnel encrypts anything.
    """
    with compose_project(PAIR_COMPOSE, env=fresh_psk()) as project:
        left = container_id(project, "left")
        transit_iface = interface_for_ip(left, LEFT_TRANSIT)

        # Ping the peer's transit address directly — no policy covers it, so it goes
        # out in the clear on the same interface.
        capture_for(left, transit_iface, "icmp", seconds=12, path="/tmp/clear.pcap")
        time.sleep(3)
        exec_in(left, "ping", "-c", "3", "-W", "5", "-p", MARKER_HEX, RIGHT_TRANSIT, timeout=60)
        time.sleep(11)

        assert capture_contains_bytes(left, "/tmp/clear.pcap", MARKER_HEX), (
            "the control failed: an unencrypted ping did not expose the marker, so the "
            "encryption assertion proves nothing"
        )
