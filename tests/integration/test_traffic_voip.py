"""VoIP generator over a live tunnel (build plan Step 2.3).

These assertions are the ground truth for the traffic classifier. If the generator
does not produce VoIP-shaped traffic, any model trained on this corpus is worthless —
so they are checked against the captured packets, not against what the generator
claims it sent.
"""

from __future__ import annotations

import itertools
import statistics
from pathlib import Path

import pytest
from scapy.all import IP, UDP, PcapReader

from testbed.orchestrate.capture import dual_capture_for_pair
from testbed.traffic.base import TrafficGenerator
from testbed.traffic.voip import VARIANTS, VoipGenerator

from .conftest import running_pair

pytestmark = [
    pytest.mark.integration,
    pytest.mark.slow,
    pytest.mark.usefixtures("strongswan_image", "traffic_image"),
]

LEFT_TRANSIT = "10.100.0.2"
LEFT_PROTECTED = "10.1.0.2"
LEFT_HOST_IP = "10.1.0.10"
DURATION_S = 8


def _run(variant: str, out: Path) -> tuple[object, Path]:
    with running_pair(out) as ctx:
        gen = VoipGenerator(variant)
        gen.setup(ctx)
        capture = dual_capture_for_pair(ctx.left_gateway, LEFT_TRANSIT, LEFT_PROTECTED, out)
        with capture:
            outcome = gen.run(DURATION_S)
        gen.teardown()
        return outcome, capture.inner_pcap


@pytest.fixture(scope="module")
def g711(tmp_path_factory: pytest.TempPathFactory) -> tuple[object, Path]:
    return _run("g711_20ms", tmp_path_factory.mktemp("voip_g711"))


@pytest.fixture(scope="module")
def g729(tmp_path_factory: pytest.TempPathFactory) -> tuple[object, Path]:
    return _run("g729_20ms", tmp_path_factory.mktemp("voip_g729"))


def rtp_packets(path: Path) -> list:  # type: ignore[type-arg]
    """Media packets only: the RTP ports, both directions."""
    with PcapReader(str(path)) as reader:
        return [
            p for p in reader if p.haslayer(UDP) and {p[UDP].sport, p[UDP].dport} & {40000, 40002}
        ]


def test_generator_satisfies_the_protocol() -> None:
    assert isinstance(VoipGenerator(), TrafficGenerator)


def test_unknown_variant_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown VoIP variant"):
        VoipGenerator("opus")


def test_run_reports_success(g711: tuple[object, Path]) -> None:
    outcome, _ = g711
    assert outcome.success is True, outcome.error  # type: ignore[attr-defined]


def test_inter_arrival_times_cluster_at_twenty_milliseconds(g711: tuple[object, Path]) -> None:
    """The metronome is the signature. 20 ms +/- 5 ms for at least 80% of packets."""
    _, inner = g711
    outbound = [p for p in rtp_packets(inner) if p.haslayer(IP) and p[IP].src == LEFT_HOST_IP]
    assert len(outbound) >= 100, f"too few packets to judge timing: {len(outbound)}"
    times = [float(p.time) for p in outbound]
    gaps_ms = [(b - a) * 1000 for a, b in itertools.pairwise(times)]
    in_band = [g for g in gaps_ms if 15.0 <= g <= 25.0]
    fraction = len(in_band) / len(gaps_ms)
    assert fraction >= 0.80, (
        f"only {fraction:.1%} of inter-arrivals fell in 20ms +/- 5ms "
        f"(median {statistics.median(gaps_ms):.1f} ms)"
    )


def test_g711_payload_sizes_are_near_constant(g711: tuple[object, Path]) -> None:
    """Standard deviation below 10 bytes — a codec emits fixed-size frames."""
    _, inner = g711
    sizes = [len(p[UDP].payload) for p in rtp_packets(inner)]
    assert len(sizes) >= 100
    assert statistics.pstdev(sizes) < 10.0, f"payload sizes vary too much: {set(sizes)}"


def test_g729_mean_payload_is_substantially_smaller_than_g711(
    g711: tuple[object, Path], g729: tuple[object, Path]
) -> None:
    """Same 20 ms interval, eightfold size difference — the reason both variants exist."""
    _, inner_711 = g711
    _, inner_729 = g729
    mean_711 = statistics.mean(len(p[UDP].payload) for p in rtp_packets(inner_711))
    mean_729 = statistics.mean(len(p[UDP].payload) for p in rtp_packets(inner_729))
    assert mean_729 < mean_711 / 2, (
        f"G.729 {mean_729:.0f}B not much smaller than G.711 {mean_711:.0f}B"
    )


def test_traffic_is_roughly_symmetric(g711: tuple[object, Path]) -> None:
    """A call is bidirectional; the forward/backward byte ratio must be near 1."""
    _, inner = g711
    forward = sum(
        len(p) for p in rtp_packets(inner) if p.haslayer(IP) and p[IP].src == LEFT_HOST_IP
    )
    backward = sum(
        len(p) for p in rtp_packets(inner) if p.haslayer(IP) and p[IP].dst == LEFT_HOST_IP
    )
    assert backward > 0, "no return stream — the call is one-directional"
    ratio = forward / backward
    assert 0.7 <= ratio <= 1.4, f"forward/backward byte ratio {ratio:.2f} is not symmetric"


def test_variants_share_an_interval_but_differ_in_size() -> None:
    assert {v.interval_ms for v in VARIANTS.values()} == {20.0}
    assert len({v.media_bytes for v in VARIANTS.values()}) == 2


def test_expected_packet_count_matches_the_packetisation_rate() -> None:
    assert VoipGenerator("g711_20ms").expected_packets(10) == 500
