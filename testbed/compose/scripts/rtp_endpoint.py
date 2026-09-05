#!/usr/bin/env python3
"""A bidirectional RTP endpoint, used to generate VoIP-shaped traffic.

This emits genuine RTP packets — RFC 3550 header followed by fixed-size media — at a
codec's packetisation interval, and receives the peer's stream at the same time. That
produces the shape a real call produces on the wire: small, near-constant-size packets
at a metronomic interval, symmetric in both directions.

It is **not** a softphone. There is no SIP signalling, no jitter buffer and no real
codec; the media payload is synthetic. What it reproduces faithfully is the packet
timing and size distribution, which is the only thing visible through an ESP tunnel and
therefore the only thing the classifier can learn from. This limitation is recorded in
docs/DATASET.md rather than glossed over.
"""

from __future__ import annotations

import argparse
import os
import socket
import struct
import sys
import time

RTP_HEADER_BYTES = 12
RTP_VERSION = 2

# Payload type and samples-per-packet for the codecs modelled here.
CODECS = {
    "g711": {"payload_type": 0, "payload_bytes": 160, "clock_rate": 8000},
    "g729": {"payload_type": 18, "payload_bytes": 20, "clock_rate": 8000},
}


def build_rtp_packet(
    payload_type: int, sequence: int, timestamp: int, ssrc: int, payload: bytes
) -> bytes:
    """Build one RFC 3550 RTP packet."""
    first = RTP_VERSION << 6
    header = struct.pack(
        "!BBHII", first, payload_type & 0x7F, sequence & 0xFFFF, timestamp & 0xFFFFFFFF, ssrc
    )
    return header + payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Bidirectional RTP endpoint.")
    parser.add_argument("--peer", required=True)
    parser.add_argument("--local-port", type=int, required=True)
    parser.add_argument("--peer-port", type=int, required=True)
    parser.add_argument("--codec", choices=sorted(CODECS), default="g711")
    parser.add_argument("--interval-ms", type=float, default=20.0)
    parser.add_argument("--duration-s", type=float, required=True)
    args = parser.parse_args()

    codec = CODECS[args.codec]
    payload = bytes(range(256)) * (codec["payload_bytes"] // 256 + 1)
    payload = payload[: codec["payload_bytes"]]
    samples_per_packet = int(codec["clock_rate"] * args.interval_ms / 1000)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", args.local_port))
    sock.setblocking(False)

    ssrc = int.from_bytes(os.urandom(4), "big")
    sequence = 0
    timestamp = 0
    sent = 0
    received = 0

    interval = args.interval_ms / 1000.0
    start = time.monotonic()
    next_send = start
    deadline = start + args.duration_s

    while time.monotonic() < deadline:
        now = time.monotonic()
        if now >= next_send:
            packet = build_rtp_packet(codec["payload_type"], sequence, timestamp, ssrc, payload)
            try:
                sock.sendto(packet, (args.peer, args.peer_port))
                sent += 1
            except OSError:
                pass
            sequence += 1
            timestamp += samples_per_packet
            # Advance on a fixed grid rather than from "now", so jitter does not
            # accumulate into drift — a real endpoint paces from its own clock.
            next_send += interval

        try:
            while True:
                sock.recv(2048)
                received += 1
        except BlockingIOError:
            pass

        sleep_for = min(next_send - time.monotonic(), 0.002)
        if sleep_for > 0:
            time.sleep(sleep_for)

    sock.close()
    print(
        f"sent={sent} received={received} codec={args.codec} payload_bytes={codec['payload_bytes']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
