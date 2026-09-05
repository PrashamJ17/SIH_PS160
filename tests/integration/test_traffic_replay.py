"""External PCAP replay over a live tunnel (build plan Step 2.8).

The real corpora require manual download, so these tests use a locally synthesised
stand-in with a realistic mixed-protocol size distribution. What is being tested is
the replay machinery — rewrite, inject, route through the tunnel, preserve the size
distribution — which is identical whatever capture is fed in.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from scapy.all import ICMP, IP, TCP, UDP, Ether, PcapReader, Raw, wrpcap

from testbed.orchestrate.capture import dual_capture_for_pair
from testbed.traffic.base import TrafficGenerator
from testbed.traffic.replay import (
    VARIANTS,
    ReplayGenerator,
    ReplaySourceMissingError,
)

from .conftest import running_pair

pytestmark = [
    pytest.mark.integration,
    pytest.mark.slow,
    pytest.mark.usefixtures("strongswan_image", "traffic_image"),
]

LEFT_TRANSIT = "10.100.0.2"
LEFT_PROTECTED = "10.1.0.2"
SOURCE_PACKETS = 300


def synthesise_source(path: Path) -> list[int]:
    """Build a stand-in external capture with a mixed, realistic size distribution."""
    import random

    rng = random.Random(17)
    packets = []
    for index in range(SOURCE_PACKETS):
        payload = bytes(rng.randrange(256) for _ in range(1))  # placeholder, resized below
        size = rng.choice([40, 60, 90, 140, 300, 576, 900, 1200, 1400])
        payload = b"\x5a" * size
        if index % 7 == 0:
            pkt = Ether() / IP(src="192.168.5.10", dst="93.184.216.34") / UDP() / Raw(payload)
        elif index % 11 == 0:
            pkt = Ether() / IP(src="192.168.5.10", dst="8.8.8.8") / ICMP() / Raw(payload)
        else:
            pkt = Ether() / IP(src="192.168.5.10", dst="93.184.216.34") / TCP() / Raw(payload)
        packets.append(pkt)
    wrpcap(str(path), packets)
    return [len(p) for p in packets]


@pytest.fixture(scope="module")
def replay_run(tmp_path_factory: pytest.TempPathFactory) -> tuple[object, Path, list[int], int]:
    out = tmp_path_factory.mktemp("replay")
    source = out / "external_source.pcap"
    source_sizes = synthesise_source(source)
    with running_pair(out) as ctx:
        gen = ReplayGenerator("cicids2017_benign", source_pcap=source, rate_mbps=5.0)
        gen.setup(ctx)
        capture = dual_capture_for_pair(ctx.left_gateway, LEFT_TRANSIT, LEFT_PROTECTED, out)
        with capture:
            outcome = gen.run(60)
        rewritten = gen.rewritten_packets
        gen.teardown()
        return outcome, out, source_sizes, rewritten


def read_sizes(path: Path, predicate) -> list[int]:  # type: ignore[no-untyped-def]
    with PcapReader(str(path)) as reader:
        return [len(p) for p in reader if predicate(p)]


def test_generator_satisfies_the_protocol() -> None:
    assert isinstance(ReplayGenerator(source_pcap=Path("/x")), TrafficGenerator)


def test_class_label_is_replay() -> None:
    assert ReplayGenerator(source_pcap=Path("/x")).name == "replay"


def test_unknown_variant_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown replay variant"):
        ReplayGenerator("unsw_nb15")


def test_missing_source_fails_with_download_guidance(tmp_path: Path) -> None:
    """External corpora need manual download; the error must say so."""
    from testbed.traffic.base import RunContext

    ctx = RunContext(
        project="p",
        left_gateway="a",
        right_gateway="b",
        left_host="c",
        right_host="d",
        left_host_ip="10.1.0.10",
        right_host_ip="10.2.0.10",
        out_dir=tmp_path,
    )
    gen = ReplayGenerator("cicids2017_benign", source_pcap=tmp_path / "absent.pcap")
    with pytest.raises(ReplaySourceMissingError, match="manual download"):
        gen.setup(ctx)


def test_variants_are_keyed_by_source_dataset() -> None:
    assert {v.dataset_key for v in VARIANTS.values()} == {"cicids2017", "mawi"}


def test_run_succeeds(replay_run: tuple[object, Path, list[int], int]) -> None:
    outcome, _, _, _ = replay_run
    assert outcome.success is True, outcome.error  # type: ignore[attr-defined]


def test_replayed_packet_count_matches_the_source(
    replay_run: tuple[object, Path, list[int], int],
) -> None:
    """Rewriting must not drop packets."""
    outcome, _, source_sizes, rewritten = replay_run
    assert rewritten == len(source_sizes), (
        f"tcprewrite produced {rewritten} packets from {len(source_sizes)}"
    )
    assert abs(outcome.packets_sent - len(source_sizes)) <= 5  # type: ignore[attr-defined]


def test_inner_size_distribution_matches_the_source(
    replay_run: tuple[object, Path, list[int], int],
) -> None:
    """Kolmogorov-Smirnov: the replayed sizes must come from the source distribution.

    Preserving the size distribution is the entire point — it is what makes replayed
    benign traffic authentic inner payload rather than synthetic filler.
    """
    from scipy.stats import ks_2samp

    _, out, source_sizes, _ = replay_run
    inner = read_sizes(
        out / "capture_inner.pcap",
        lambda p: p.haslayer(IP) and p[IP].dst == "10.2.0.10",
    )
    assert len(inner) >= 100, f"too few replayed packets captured: {len(inner)}"
    result = ks_2samp(source_sizes, inner)
    assert result.pvalue > 0.05, (
        f"replayed size distribution differs from the source "
        f"(KS statistic {result.statistic:.3f}, p={result.pvalue:.4f})"
    )


def test_outer_capture_shows_esp_only(
    replay_run: tuple[object, Path, list[int], int],
) -> None:
    """Whatever the payload was, an observer sees only ESP."""
    _, out, _, _ = replay_run
    with PcapReader(str(out / "capture_outer.pcap")) as reader:
        outer = list(reader)
    esp = [p for p in outer if p.haslayer(IP) and p[IP].proto == 50]
    leaked = [p for p in outer if p.haslayer(TCP) or p.haslayer(ICMP)]
    assert len(esp) >= 100, f"expected ESP on the wire, saw {len(esp)}"
    assert leaked == [], "replayed payload leaked into the outer capture in cleartext"
