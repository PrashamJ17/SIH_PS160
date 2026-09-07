"""Build ``demo/pcaps/04-estate.pcap`` from the three single-tunnel demo captures.

**What this does and does not do.** The three source captures are real: strongSwan pairs
negotiating in the testbed, carrying real generated traffic. They all ran between the same
two lab addresses, `10.100.0.2` and `10.100.0.3`, because they came off the same testbed
pair one after another.

An estate demo needs an estate. This script rewrites the IP addresses so each capture
represents a different site and merges the three into one file. **Nothing else is
changed** — not a payload, not a timestamp, not a proposal. The findings the merged
capture produces are the findings the three source captures produce, because they are the
same packets.

Addresses come from RFC 5737's documentation ranges, so nothing here can be mistaken for a
real network:

    198.51.100.10  the head-end, shared by all three tunnels
    203.0.113.10   branch-mumbai   ← capture 01, IKEv1 aggressive + 3DES, VoIP
    203.0.113.11   branch-pune     ← capture 02, IKEv1 aggressive + 3DES, email
    203.0.113.12   dc-chennai      ← capture 03, IKEv2 AES-256 + ECP-384, VoIP

The IKE identity payloads in these captures are FQDN-based, not `ID_IPV4_ADDR`, so
rewriting the IP header leaves no payload disagreeing with it.

Run it with::

    python -m demo.build_estate
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final

REPO_ROOT: Final = Path(__file__).resolve().parents[1]
PCAPS: Final = REPO_ROOT / "demo" / "pcaps"
DESTINATION: Final = PCAPS / "04-estate.pcap"

LAB_INITIATOR: Final = "10.100.0.2"
LAB_RESPONDER: Final = "10.100.0.3"
HEAD_END: Final = "198.51.100.10"


@dataclass(frozen=True)
class Site:
    source: str
    address: str
    name: str


SITES: Final = (
    Site("01-worst-ikev1-aggressive-3des-voip.pcap", "203.0.113.10", "branch-mumbai"),
    Site("02-weak-ikev1-aggressive-3des-email.pcap", "203.0.113.11", "branch-pune"),
    Site("03-strong-ikev2-aes256-ecp384-voip.pcap", "203.0.113.12", "dc-chennai"),
)


def rewrite(source: Path, initiator: str, responder: str) -> list[object]:
    """Read a capture and return its packets with the two endpoints renumbered.

    Deleting the checksums makes scapy recompute them on write; leaving the originals
    would produce a capture every tool flags as corrupt.
    """
    from scapy.all import IP, UDP, rdpcap
    from scapy.layers.inet import TCP

    mapping = {LAB_INITIATOR: initiator, LAB_RESPONDER: responder}
    packets = []
    for packet in rdpcap(str(source)):
        if IP in packet:
            packet[IP].src = mapping.get(packet[IP].src, packet[IP].src)
            packet[IP].dst = mapping.get(packet[IP].dst, packet[IP].dst)
            del packet[IP].chksum
            if UDP in packet:
                del packet[UDP].chksum
            if TCP in packet:
                del packet[TCP].chksum
        packets.append(packet)
    return packets


def build(destination: Path = DESTINATION) -> Path:
    from scapy.all import wrpcap

    packets: list[object] = []
    for site in SITES:
        source = PCAPS / site.source
        if not source.is_file():
            raise FileNotFoundError(f"missing demo capture: {source}")
        rewritten = rewrite(source, site.address, HEAD_END)
        print(f"  {site.name:<14} {site.address:<14} {len(rewritten):>5} packets  {site.source}")
        packets += rewritten

    # Chronological, because a merged capture whose timestamps go backwards makes the
    # traffic profile meaningless.
    packets.sort(key=lambda packet: float(packet.time))  # type: ignore[attr-defined]
    destination.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(destination), packets)
    return destination


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DESTINATION)
    arguments = parser.parse_args(argv)

    try:
        written = build(arguments.output)
    except FileNotFoundError as exc:
        print(exc, file=sys.stderr)
        return 1
    print(f"wrote {written} ({written.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
