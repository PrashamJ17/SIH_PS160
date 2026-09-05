"""Video streaming generator over a live tunnel (build plan Step 2.4).

The shape assertions are checked against captured packets. If the generator does not
produce burst-and-idle, downstream-heavy traffic, the streaming class is not what it
claims to be and every model trained on it inherits the error.
"""

from __future__ import annotations

import itertools
from pathlib import Path

import pytest
from scapy.all import IP, TCP, PcapReader

from testbed.orchestrate.capture import dual_capture_for_pair
from testbed.traffic.base import TrafficGenerator
from testbed.traffic.video import VARIANTS, VIDEO_ORIGIN_IP, VideoGenerator

from .conftest import running_pair

pytestmark = [
    pytest.mark.integration,
    pytest.mark.slow,
    pytest.mark.usefixtures("strongswan_image", "traffic_image"),
]

LEFT_TRANSIT = "10.100.0.2"
LEFT_PROTECTED = "10.1.0.2"
LEFT_HOST_IP = "10.1.0.10"
DURATION_S = 60


@pytest.fixture(scope="module")
def video_run(tmp_path_factory: pytest.TempPathFactory) -> tuple[object, Path]:
    out = tmp_path_factory.mktemp("video")
    with running_pair(out, profiles=("video",)) as ctx:
        gen = VideoGenerator("dash_720p", seed=7)
        gen.setup(ctx)
        capture = dual_capture_for_pair(ctx.left_gateway, LEFT_TRANSIT, LEFT_PROTECTED, out)
        with capture:
            outcome = gen.run(DURATION_S)
        gen.teardown()
        return outcome, capture.inner_pcap


def video_packets(path: Path) -> list:  # type: ignore[type-arg]
    with PcapReader(str(path)) as reader:
        return [
            p
            for p in reader
            if p.haslayer(TCP) and p.haslayer(IP) and VIDEO_ORIGIN_IP in (p[IP].src, p[IP].dst)
        ]


def test_generator_satisfies_the_protocol() -> None:
    assert isinstance(VideoGenerator(), TrafficGenerator)


def test_generator_declares_the_origin_it_requires() -> None:
    """requires is how the orchestrator knows to start the sidecar."""
    assert "video" in VideoGenerator().requires


def test_unknown_variant_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown video variant"):
        VideoGenerator("dash_4k")


def test_run_reports_success(video_run: tuple[object, Path]) -> None:
    outcome, _ = video_run
    assert outcome.success is True, outcome.error  # type: ignore[attr-defined]
    assert outcome.bytes_sent > 1_000_000  # type: ignore[attr-defined]


def test_downstream_exceeds_upstream_by_at_least_ten_times(
    video_run: tuple[object, Path],
) -> None:
    """Streaming is overwhelmingly one-directional; a small request pulls a large body."""
    _, inner = video_run
    packets = video_packets(inner)
    down = sum(len(p) for p in packets if p[IP].src == VIDEO_ORIGIN_IP)
    up = sum(len(p) for p in packets if p[IP].dst == VIDEO_ORIGIN_IP)
    assert up > 0, "no upstream requests captured"
    assert down / up >= 10.0, f"downstream/upstream ratio only {down / up:.1f}"


def test_at_least_three_idle_gaps_over_two_seconds(video_run: tuple[object, Path]) -> None:
    """Buffer-then-wait is the signature. A steady stream would be a file download."""
    _, inner = video_run
    times = sorted(float(p.time) for p in video_packets(inner))
    assert len(times) > 50, f"too few packets to judge idleness: {len(times)}"
    gaps = [b - a for a, b in itertools.pairwise(times)]
    long_gaps = [g for g in gaps if g > 2.0]
    assert len(long_gaps) >= 3, (
        f"expected at least 3 idle gaps over 2s, saw {len(long_gaps)} (longest {max(gaps):.1f}s)"
    )


def test_burst_packets_are_predominantly_at_or_near_mtu(
    video_run: tuple[object, Path],
) -> None:
    """Bulk transfer fills segments; a majority of downstream packets ride near the MTU."""
    _, inner = video_run
    downstream = [len(p) for p in video_packets(inner) if p[IP].src == VIDEO_ORIGIN_IP]
    assert len(downstream) > 50
    near_mtu = [size for size in downstream if size >= 1400]
    fraction = len(near_mtu) / len(downstream)
    assert fraction >= 0.6, f"only {fraction:.1%} of downstream packets were near MTU"


def test_variants_differ_in_pacing_or_bitrate() -> None:
    """A single pacing would let the classifier key on one fixed gap length."""
    assert len({(v.rung, v.segment_seconds) for v in VARIANTS.values()}) == 3
