#!/usr/bin/env python3
"""Measure and compare the traffic shape of every generator.

The M2 acceptance criterion is that the seven classes are visually distinct in an IO
graph. This is the quantitative form of that check: run each generator through a real
tunnel, extract the shape features a classifier would actually see, and report them
side by side. If two classes are indistinguishable here, no model will separate them
later — and the failure is visible as numbers rather than as an impression.

Doubles as the source for the presentation's traffic-shape figure (Step 12.3).
"""

from __future__ import annotations

import argparse
import itertools
import json
import statistics
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from testbed.orchestrate.capture import dual_capture_for_pair  # noqa: E402
from testbed.traffic.base import RunContext  # noqa: E402


@dataclass
class Shape:
    """The features that distinguish one traffic class from another."""

    generator: str
    variant: str
    packets: int
    mean_size: float
    size_stdev: float
    mean_iat_ms: float
    iat_stdev_ms: float
    forward_ratio: float
    idle_fraction: float
    near_mtu_fraction: float
    small_packet_fraction: float


def measure(pcap: Path, near_ip: str) -> tuple[int, float, float, float, float, float, float, float, float]:
    from scapy.layers.inet import IP
    from scapy.utils import PcapReader

    sizes: list[int] = []
    times: list[float] = []
    forward = backward = 0
    with PcapReader(str(pcap)) as reader:
        for packet in reader:
            if not packet.haslayer(IP):
                continue
            sizes.append(len(packet))
            times.append(float(packet.time))
            if packet[IP].src == near_ip:
                forward += len(packet)
            else:
                backward += len(packet)

    if len(sizes) < 2:
        return len(sizes), 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0

    times.sort()
    gaps = [(b - a) * 1000 for a, b in itertools.pairwise(times)]
    span = times[-1] - times[0]
    idle = sum(g for g in gaps if g > 1000.0) / 1000.0
    return (
        len(sizes),
        statistics.mean(sizes),
        statistics.pstdev(sizes),
        statistics.mean(gaps) if gaps else 0.0,
        statistics.pstdev(gaps) if gaps else 0.0,
        forward / max(backward, 1),
        idle / span if span > 0 else 0.0,
        sum(1 for s in sizes if s >= 1400) / len(sizes),
        sum(1 for s in sizes if s < 200) / len(sizes),
    )


def build_generators(replay_source: Path):  # type: ignore[no-untyped-def]
    """Every generator with the compose profile and per-run secret it needs."""
    from testbed.traffic.email import EmailGenerator, generate_mailbox_password
    from testbed.traffic.icmp import IcmpGenerator
    from testbed.traffic.messaging import MessagingGenerator, generate_account_password
    from testbed.traffic.replay import ReplayGenerator
    from testbed.traffic.video import VideoGenerator
    from testbed.traffic.voip import VoipGenerator
    from testbed.traffic.web import WebGenerator

    mail_password = generate_mailbox_password()
    xmpp_password = generate_account_password()
    return [
        (IcmpGenerator("steady_1s"), (), {}),
        (VoipGenerator("g711_20ms"), (), {}),
        (VideoGenerator("dash_720p", seed=7), ("video",), {}),
        (WebGenerator("skimming", seed=11), ("web",), {}),
        (EmailGenerator("smtp_attachment", password=mail_password, seed=5),
         ("mail",), {"MAIL_PASSWORD": mail_password}),
        (MessagingGenerator("chat_active", password=xmpp_password, seed=4),
         ("messaging",), {"XMPP_PASSWORD": xmpp_password}),
        (ReplayGenerator("cicids2017_benign", source_pcap=replay_source), (), {}),
    ]


def synthesise_replay_source(path: Path) -> None:
    import random

    # Imported from the concrete layer modules rather than scapy.all: that module
    # is populated lazily, so the layer classes are invisible to a type checker.
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.l2 import Ether
    from scapy.packet import Raw
    from scapy.utils import wrpcap

    rng = random.Random(23)
    packets = []
    for index in range(400):
        size = rng.choice([40, 60, 90, 140, 300, 576, 900, 1200, 1400])
        layer = UDP() if index % 5 == 0 else TCP()
        packets.append(
            Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
            / IP(src="192.168.5.10", dst="93.184.216.34")
            / layer
            / Raw(b"\x5a" * size)
        )
    wrpcap(str(path), packets)


def main() -> int:
    parser = argparse.ArgumentParser(description="Measure every generator's traffic shape.")
    parser.add_argument("--duration-s", type=int, default=60)
    parser.add_argument("--out", type=Path, default=REPO_ROOT / "reports" / "generator_shapes.json")
    parser.add_argument("--only", nargs="*", default=None,
                        help="measure only these generator names")
    args = parser.parse_args()

    sys.path.insert(0, str(REPO_ROOT / "tests"))
    from tests.integration.conftest import running_pair

    work = REPO_ROOT / "data" / "raw" / "shapes"
    work.mkdir(parents=True, exist_ok=True)
    replay_source = work / "replay_source.pcap"
    synthesise_replay_source(replay_source)

    shapes: list[Shape] = []
    for generator, profiles, extra_env in build_generators(replay_source):
        if args.only and generator.name not in args.only:
            continue
        out_dir = work / generator.name
        out_dir.mkdir(parents=True, exist_ok=True)
        print(f"running {generator.name} for {args.duration_s}s ...", flush=True)
        with running_pair(out_dir, profiles=profiles, extra_env=extra_env) as ctx:
            generator.setup(ctx)
            capture = dual_capture_for_pair(ctx.left_gateway, "10.100.0.2", "10.1.0.2", out_dir)
            with capture:
                outcome = generator.run(args.duration_s)
            generator.teardown()
        if not outcome.success:
            print(f"  FAILED: {outcome.error}", file=sys.stderr)
            return 1
        measured = measure(capture.inner_pcap, "10.1.0.10")
        shapes.append(Shape(generator.name, outcome.variant, *measured))
        print(f"  ok: {measured[0]} packets", flush=True)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps([asdict(s) for s in shapes], indent=2))

    header = (
        f"{'class':<11}{'pkts':>7}{'meanB':>8}{'sdB':>8}{'IATms':>9}"
        f"{'sdIAT':>9}{'fwd/bwd':>9}{'idle':>7}{'~MTU':>7}{'<200B':>7}"
    )
    print("\n" + header)
    print("-" * len(header))
    for s in shapes:
        print(
            f"{s.generator:<11}{s.packets:>7}{s.mean_size:>8.0f}{s.size_stdev:>8.0f}"
            f"{s.mean_iat_ms:>9.1f}{s.iat_stdev_ms:>9.1f}{s.forward_ratio:>9.2f}"
            f"{s.idle_fraction:>7.2f}{s.near_mtu_fraction:>7.2f}{s.small_packet_fraction:>7.2f}"
        )
    print(f"\nwritten to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
