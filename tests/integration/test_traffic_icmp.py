"""ICMP generator over a live tunnel (build plan Step 2.2)."""

from __future__ import annotations

from pathlib import Path

import pytest
from scapy.all import ICMP, IP, PcapReader

from testbed.orchestrate.capture import dual_capture_for_pair
from testbed.traffic.base import TrafficGenerator
from testbed.traffic.icmp import VARIANTS, IcmpGenerator

from .conftest import running_pair

pytestmark = [
    pytest.mark.integration,
    pytest.mark.slow,
    pytest.mark.usefixtures("strongswan_image"),
]

LEFT_TRANSIT = "10.100.0.2"
LEFT_PROTECTED = "10.1.0.2"
DURATION_S = 10


@pytest.fixture(scope="module")
def icmp_run(tmp_path_factory: pytest.TempPathFactory) -> tuple[object, Path, Path]:
    """Run the steady_1s variant for 10 seconds under a dual capture."""
    out = tmp_path_factory.mktemp("icmp")
    with running_pair(out) as ctx:
        gen = IcmpGenerator("steady_1s")
        gen.setup(ctx)
        capture = dual_capture_for_pair(ctx.left_gateway, LEFT_TRANSIT, LEFT_PROTECTED, out)
        with capture:
            outcome = gen.run(DURATION_S)
        gen.teardown()
        return outcome, capture.inner_pcap, capture.outer_pcap


def packets(path: Path) -> list:  # type: ignore[type-arg]
    with PcapReader(str(path)) as reader:
        return list(reader)


def test_generator_satisfies_the_protocol() -> None:
    assert isinstance(IcmpGenerator(), TrafficGenerator)


def test_class_label_is_icmp() -> None:
    assert IcmpGenerator().name == "icmp"


def test_unknown_variant_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown ICMP variant"):
        IcmpGenerator("does_not_exist")


def test_run_before_setup_is_an_error() -> None:
    with pytest.raises(RuntimeError, match="setup"):
        IcmpGenerator().run(1)


def test_result_reports_success(icmp_run: tuple[object, Path, Path]) -> None:
    outcome, _, _ = icmp_run
    assert outcome.success is True, outcome.error  # type: ignore[attr-defined]
    assert outcome.error is None  # type: ignore[attr-defined]


def test_result_counts_the_packets_it_sent(icmp_run: tuple[object, Path, Path]) -> None:
    outcome, _, _ = icmp_run
    assert outcome.packets_sent == DURATION_S  # type: ignore[attr-defined]
    assert outcome.bytes_sent > 0  # type: ignore[attr-defined]


def test_inner_pcap_contains_about_ten_echo_requests(
    icmp_run: tuple[object, Path, Path],
) -> None:
    """One ping per second for ten seconds, allowing the plan's tolerance of two."""
    _, inner, _ = icmp_run
    requests = [p for p in packets(inner) if p.haslayer(ICMP) and p[ICMP].type == 8]
    assert DURATION_S - 2 <= len(requests) <= DURATION_S + 2, (
        f"expected ~{DURATION_S} echo requests, saw {len(requests)}"
    )


def test_outer_esp_count_is_at_least_the_inner_count(
    icmp_run: tuple[object, Path, Path],
) -> None:
    """Every inner packet must have been carried by at least one ESP packet."""
    _, inner, outer = icmp_run
    inner_icmp = [p for p in packets(inner) if p.haslayer(ICMP)]
    esp = [p for p in packets(outer) if p.haslayer(IP) and p[IP].proto == 50]
    assert len(esp) >= len(inner_icmp), f"ESP={len(esp)} < inner ICMP={len(inner_icmp)}"


def test_outer_capture_holds_no_plaintext(icmp_run: tuple[object, Path, Path]) -> None:
    _, _, outer = icmp_run
    assert [p for p in packets(outer) if p.haslayer(ICMP)] == []


def test_variants_differ_in_rate_and_size() -> None:
    """A single rate would let the classifier learn one interval rather than a shape."""
    intervals = {v.interval_s for v in VARIANTS.values()}
    sizes = {v.payload_bytes for v in VARIANTS.values()}
    assert len(intervals) >= 2
    assert len(sizes) >= 3


def test_expected_packet_count_scales_with_rate() -> None:
    assert IcmpGenerator("steady_1s").expected_packets(10) == 10
    assert IcmpGenerator("flood_small").expected_packets(10) == 500
