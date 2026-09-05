#!/usr/bin/env python3
"""A DASH-style segment player.

Reproduces the traffic shape an adaptive-bitrate player produces: an initial burst
that fills the buffer, then one segment fetched per segment-duration, leaving the link
idle in between. That burst-then-idle rhythm — heavily one-directional, with gaps of
seconds — is what distinguishes streaming from every other class through ESP.

It is a fetcher, not a decoder: no demuxing, no rendering. Only the request schedule
and the response sizes matter once the payload is encrypted.
"""

from __future__ import annotations

import argparse
import random
import sys
import time
import urllib.request


def fetch(url: str, timeout: float) -> int:
    """Fetch one segment, returning the number of bytes read."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return len(response.read())
    except Exception:
        return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="DASH-style segment player.")
    parser.add_argument("--origin", required=True, help="http://host:port")
    parser.add_argument("--rung", default="720p")
    parser.add_argument("--segments", type=int, default=24)
    parser.add_argument("--segment-seconds", type=float, default=4.0)
    parser.add_argument(
        "--buffer-segments",
        type=int,
        default=3,
        help="segments fetched back-to-back before steady state",
    )
    parser.add_argument("--duration-s", type=float, required=True)
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="rotates which segments are fetched, avoiding memorisation",
    )
    args = parser.parse_args()

    rng = random.Random(args.seed)
    # Start at a rotating offset so consecutive runs do not fetch an identical
    # sequence of segment sizes.
    order = list(range(1, args.segments + 1))
    rng.shuffle(order)

    deadline = time.monotonic() + args.duration_s
    total_bytes = 0
    fetched = 0
    index = 0

    # Initial buffering: back-to-back fetches, the burst at the start of playback.
    for _ in range(args.buffer_segments):
        if time.monotonic() >= deadline:
            break
        url = f"{args.origin}/{args.rung}/seg_{order[index % len(order)]}.m4s"
        total_bytes += fetch(url, timeout=30.0)
        fetched += 1
        index += 1

    # Steady state: one segment per segment-duration. The link is idle between them,
    # which is what produces the multi-second gaps the class is recognised by.
    next_fetch = time.monotonic() + args.segment_seconds
    while time.monotonic() < deadline:
        now = time.monotonic()
        if now < next_fetch:
            time.sleep(min(0.2, next_fetch - now))
            continue
        url = f"{args.origin}/{args.rung}/seg_{order[index % len(order)]}.m4s"
        total_bytes += fetch(url, timeout=30.0)
        fetched += 1
        index += 1
        next_fetch += args.segment_seconds

    print(f"segments={fetched} bytes={total_bytes} rung={args.rung}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
