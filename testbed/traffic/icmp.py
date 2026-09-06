"""ICMP traffic generator.

The simplest generator, and the one whose signature is least ambiguous: perfectly
regular, tiny, symmetric packets. It establishes the pattern the other six follow.

Variants exist because a single ping rate would let the classifier learn "ICMP" as one
fixed inter-arrival time rather than as a shape. ``flood_small`` and ``large_payload``
sit at the extremes of rate and size so the class covers a range.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import ClassVar, Final

from testbed.traffic.base import GenerationResult, RunContext

# IPv4 header + ICMP echo header added to the payload the caller asks for.
ICMP_OVERHEAD_BYTES: Final = 28


@dataclass(frozen=True)
class IcmpVariant:
    """One ICMP shape: how fast, and how large."""

    name: str
    interval_s: float
    payload_bytes: int


VARIANTS: Final[dict[str, IcmpVariant]] = {
    # 56 payload bytes is the conventional ping default and yields a 64-byte packet.
    "steady_1s": IcmpVariant("steady_1s", interval_s=1.0, payload_bytes=56),
    "flood_small": IcmpVariant("flood_small", interval_s=0.02, payload_bytes=8),
    "large_payload": IcmpVariant("large_payload", interval_s=1.0, payload_bytes=1400),
}


class IcmpGenerator:
    """Drive ``ping`` from the left host to the right host through the tunnel."""

    name = "icmp"
    requires: ClassVar[list[str]] = []

    def __init__(self, variant: str = "steady_1s") -> None:
        if variant not in VARIANTS:
            raise ValueError(f"unknown ICMP variant {variant!r}; have {sorted(VARIANTS)}")
        self.variant = VARIANTS[variant]
        self._ctx: RunContext | None = None

    def setup(self, ctx: RunContext) -> None:
        self._ctx = ctx

    def teardown(self) -> None:
        self._ctx = None

    def expected_packets(self, duration_s: int) -> int:
        """How many echo requests ``duration_s`` should produce at this rate."""
        return max(1, int(duration_s / self.variant.interval_s))

    def run(self, duration_s: int) -> GenerationResult:
        if self._ctx is None:
            raise RuntimeError("setup() must be called before run()")

        count = self.expected_packets(duration_s)
        started = datetime.now(UTC)
        completed = subprocess.run(
            [
                "docker",
                "exec",
                self._ctx.source_container,
                "ping",
                "-c",
                str(count),
                "-i",
                str(self.variant.interval_s),
                "-s",
                str(self.variant.payload_bytes),
                "-W",
                "5",
                self._ctx.target_ip,
            ],
            capture_output=True,
            text=True,
            timeout=int(duration_s + 60),
            check=False,
        )
        ended = datetime.now(UTC)

        transmitted, _received = _parse_ping_counts(completed.stdout)
        # ping exits non-zero when any single reply is missing. Under an impairment
        # profile with deliberate loss that is the expected outcome, and a partial run
        # is still usable data — so only a run that sent nothing at all is a failure.
        sent_nothing = transmitted == 0
        detail = completed.stderr.strip() or completed.stdout.strip()
        return GenerationResult(
            generator=self.name,
            variant=self.variant.name,
            packets_sent=transmitted,
            bytes_sent=transmitted * (self.variant.payload_bytes + ICMP_OVERHEAD_BYTES),
            started_at=started,
            ended_at=ended,
            success=not sent_nothing,
            error=(
                f"ping sent no packets (exit {completed.returncode}): {detail[:200]}"
                if sent_nothing
                else None
            ),
        )


def _parse_ping_counts(output: str) -> tuple[int, int]:
    """Extract (transmitted, received) from ping's summary line.

    Returns ``(0, 0)`` when the summary is absent, which is what a ping that never
    ran looks like.
    """
    for line in output.splitlines():
        if "packets transmitted" not in line:
            continue
        parts = line.replace(",", " ").split()
        transmitted = received = 0
        for index, token in enumerate(parts):
            if (
                token == "packets"
                and index + 1 < len(parts)
                and parts[index + 1].startswith("transmitted")
            ):
                transmitted = int(parts[index - 1])
            if token == "received":
                received = int(parts[index - 1])
        return transmitted, received
    return 0, 0
