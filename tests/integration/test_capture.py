"""Dual-tap capture over a live tunnel (build plan Step 1.7)."""

from __future__ import annotations

import secrets
from pathlib import Path

import pytest

from testbed.orchestrate.capture import CaptureError, dual_capture_for_pair, verify_pcap
from tests.fixtures.dockerctl import compose, compose_project, exec_in

from .conftest import PAIR_COMPOSE

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("strongswan_image")]

LEFT_TRANSIT = "10.100.0.2"
LEFT_PROTECTED = "10.1.0.2"
LEFT_HOST = "10.1.0.10"
RIGHT_HOST = "10.2.0.10"


def container_id(project: str, service: str) -> str:
    cid = compose(PAIR_COMPOSE, project, "ps", "-q", service).stdout.strip()
    assert cid, f"no container for {service}"
    return cid


def established(project: str) -> tuple[str, str]:
    left = container_id(project, "left")
    result = exec_in(left, "swanctl", "--initiate", "--child", "net-net", timeout=90)
    assert result.returncode == 0, f"initiate failed: {result.stdout}{result.stderr}"
    return left, container_id(project, "left_host")


def read(container: str, path: str, bpf: str = "") -> str:
    return exec_in(container, "sh", "-c", f"tcpdump -r {path} -n {bpf}".strip()).stdout


@pytest.fixture
def captured(tmp_path: Path) -> tuple[Path, Path, str]:
    """Capture both taps while pinging host-to-host through the tunnel."""
    with compose_project(PAIR_COMPOSE, env={"SENTINEL_PSK": secrets.token_hex(24)}) as project:
        left, left_host = established(project)
        capture = dual_capture_for_pair(left, LEFT_TRANSIT, LEFT_PROTECTED, tmp_path)
        with capture:
            ping = exec_in(left_host, "ping", "-c", "5", "-W", "5", RIGHT_HOST, timeout=60)
            assert ping.returncode == 0, f"ping failed: {ping.stdout}"
        outer, inner = capture.verify()
        assert outer > 0 and inner > 0
        # Copies are read back inside the container too, where tcpdump can filter them.
        yield capture.outer_pcap, capture.inner_pcap, left


def test_outer_pcap_contains_esp_packets(captured: tuple[Path, Path, str]) -> None:
    _, _, container = captured
    listing = read(container, "/tmp/capture_outer.pcap", "'ip proto 50'")
    assert len([ln for ln in listing.splitlines() if "ESP(" in ln]) >= 5, listing


def test_outer_pcap_contains_zero_icmp_echo_packets(captured: tuple[Path, Path, str]) -> None:
    """Plaintext in the outer capture would silently corrupt the entire dataset."""
    _, _, container = captured
    icmp = read(container, "/tmp/capture_outer.pcap", "'icmp'")
    assert icmp.strip() == "", f"plaintext ICMP found in the outer capture:\n{icmp}"


def test_inner_pcap_contains_icmp_echo_packets(captured: tuple[Path, Path, str]) -> None:
    _, _, container = captured
    listing = read(container, "/tmp/capture_inner.pcap", "'icmp'")
    assert "ICMP echo request" in listing, listing


def test_inner_pcap_captures_both_directions(captured: tuple[Path, Path, str]) -> None:
    """A one-directional inner tap would distort every directional flow feature."""
    _, _, container = captured
    requests = read(container, "/tmp/capture_inner.pcap", "'icmp[icmptype]==8'")
    replies = read(container, "/tmp/capture_inner.pcap", "'icmp[icmptype]==0'")
    assert len(requests.strip().splitlines()) >= 4, "no echo requests on the inner tap"
    assert len(replies.strip().splitlines()) >= 4, "no echo replies on the inner tap"


def test_inner_pcap_sees_the_real_host_addresses(captured: tuple[Path, Path, str]) -> None:
    _, _, container = captured
    listing = read(container, "/tmp/capture_inner.pcap", "'icmp'")
    assert LEFT_HOST in listing
    assert RIGHT_HOST in listing


def test_both_files_open_cleanly_in_scapy(captured: tuple[Path, Path, str]) -> None:
    """Reads every packet: a truncated capture opens fine and fails partway through."""
    outer, inner, _ = captured
    assert verify_pcap(outer) > 0
    assert verify_pcap(inner) > 0


def test_both_files_are_non_empty_on_disk(captured: tuple[Path, Path, str]) -> None:
    outer, inner, _ = captured
    assert outer.stat().st_size > 24, "outer pcap has no packets beyond the file header"
    assert inner.stat().st_size > 24, "inner pcap has no packets beyond the file header"


def test_verify_rejects_a_missing_file(tmp_path: Path) -> None:
    with pytest.raises(CaptureError, match="does not exist"):
        verify_pcap(tmp_path / "absent.pcap")


def test_verify_rejects_an_empty_file(tmp_path: Path) -> None:
    empty = tmp_path / "empty.pcap"
    empty.write_bytes(b"")
    with pytest.raises(CaptureError, match="empty"):
        verify_pcap(empty)


def test_verify_rejects_a_corrupt_file(tmp_path: Path) -> None:
    corrupt = tmp_path / "corrupt.pcap"
    corrupt.write_bytes(b"this is not a pcap file at all, not even close")
    with pytest.raises(CaptureError):
        verify_pcap(corrupt)


def test_verify_rejects_a_truncated_capture(
    tmp_path: Path, captured: tuple[Path, Path, str]
) -> None:
    """The exact silent-corruption case: a valid header with a cut-off packet."""
    outer, _, _ = captured
    data = outer.read_bytes()
    truncated = tmp_path / "truncated.pcap"
    truncated.write_bytes(data[: len(data) - 40])
    with pytest.raises(CaptureError):
        verify_pcap(truncated)
