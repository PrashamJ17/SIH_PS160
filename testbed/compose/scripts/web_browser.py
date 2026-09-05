#!/usr/bin/env python3
"""A scripted web browsing session.

Reproduces the sawtooth a browser produces: a small request pulls a large HTML
response, a flurry of asset fetches follows, then the link goes quiet while a human
reads. That request/response asymmetry punctuated by multi-second think time is what
distinguishes browsing from streaming through ESP.

The page order is seeded and rotates between runs. Fetching the same pages every time
would let a classifier memorise one corpus rather than learn the shape of browsing —
trap 4 in the dataset section of the master document.
"""

from __future__ import annotations

import argparse
import random
import re
import sys
import time
import urllib.request

ASSET_PATTERN = re.compile(r'(?:src|href)="([^"]+)"')


def fetch(url: str, timeout: float = 20.0) -> bytes:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return bytes(response.read())
    except Exception:
        return b""


def main() -> int:
    parser = argparse.ArgumentParser(description="Scripted browsing session.")
    parser.add_argument("--origin", required=True)
    parser.add_argument("--pages", type=int, default=24)
    parser.add_argument("--duration-s", type=float, required=True)
    parser.add_argument("--think-min", type=float, default=2.0)
    parser.add_argument("--think-max", type=float, default=8.0)
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args()

    rng = random.Random(args.seed)
    order = list(range(1, args.pages + 1))
    rng.shuffle(order)

    deadline = time.monotonic() + args.duration_s
    visited: list[int] = []
    assets_fetched = 0
    total_bytes = 0
    index = 0

    while time.monotonic() < deadline:
        page = order[index % len(order)]
        index += 1
        body = fetch(f"{args.origin}/page_{page}.html")
        if not body:
            continue
        visited.append(page)
        total_bytes += len(body)

        for asset in ASSET_PATTERN.findall(body.decode("utf-8", "ignore")):
            if time.monotonic() >= deadline:
                break
            data = fetch(f"{args.origin}{asset}")
            total_bytes += len(data)
            assets_fetched += 1

        # Think time: the human reads. This is the gap that makes browsing look
        # nothing like a sustained download.
        think = rng.uniform(args.think_min, args.think_max)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(think, remaining))

    print(
        f"pages={len(visited)} assets={assets_fetched} bytes={total_bytes} "
        f"visited={','.join(str(p) for p in visited)}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
