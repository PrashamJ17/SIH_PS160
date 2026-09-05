"""Video streaming traffic generator.

The shape is burst-and-idle: a player fills its buffer, goes quiet for several
seconds, then bursts again. Heavily one-directional, with most packets at or near the
MTU. Through ESP the payload is invisible, but that rhythm is not, and it is what
distinguishes streaming from every other class.

Content is served by a self-hosted origin behind the right gateway. Nothing reaches
the public internet, so a sweep is reproducible and can run air-gapped — a hard
requirement for the deployments this tool targets.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import ClassVar, Final

from testbed.traffic.base import GenerationResult, RunContext, wait_for_service

DASH_PLAYER: Final = "/opt/sentinel/dash_player.py"
VIDEO_ORIGIN_IP: Final = "10.2.0.20"
VIDEO_ORIGIN_PORT: Final = 80
VIDEO_PROFILE: Final = "video"


@dataclass(frozen=True)
class VideoVariant:
    """One rung of the ABR ladder, plus how the player paces itself."""

    name: str
    rung: str
    segment_seconds: float
    buffer_segments: int


VARIANTS: Final[dict[str, VideoVariant]] = {
    "dash_720p": VideoVariant("dash_720p", rung="720p", segment_seconds=4.0, buffer_segments=3),
    "dash_1080p": VideoVariant("dash_1080p", rung="1080p", segment_seconds=4.0, buffer_segments=3),
    # A shorter segment duration and deeper prebuffer: the same class, paced
    # differently, so the classifier cannot key on one fixed gap length.
    "hls_adaptive": VideoVariant(
        "hls_adaptive", rung="720p", segment_seconds=2.5, buffer_segments=5
    ),
}


class VideoGenerator:
    """Fetch DASH-style segments from the origin on a buffer schedule."""

    name = "video"
    requires: ClassVar[list[str]] = [VIDEO_PROFILE]

    def __init__(self, variant: str = "dash_720p", seed: int | None = None) -> None:
        if variant not in VARIANTS:
            raise ValueError(f"unknown video variant {variant!r}; have {sorted(VARIANTS)}")
        self.variant = VARIANTS[variant]
        self.seed = seed
        self._ctx: RunContext | None = None

    def setup(self, ctx: RunContext) -> None:
        if not wait_for_service(ctx.left_host, VIDEO_ORIGIN_IP, VIDEO_ORIGIN_PORT):
            raise RuntimeError(
                f"the origin at {VIDEO_ORIGIN_IP}:{VIDEO_ORIGIN_PORT} never accepted a connection; "
                "starting anyway would produce a short, sparse capture"
            )
        self._ctx = ctx

    def teardown(self) -> None:
        self._ctx = None

    def expected_gaps(self, duration_s: int) -> int:
        """Idle gaps a run of this length should produce once the buffer is filled."""
        steady = max(0.0, duration_s - self.variant.buffer_segments * 0.5)
        return max(0, int(steady / self.variant.segment_seconds) - 1)

    def run(self, duration_s: int) -> GenerationResult:
        if self._ctx is None:
            raise RuntimeError("setup() must be called before run()")
        ctx = self._ctx

        started = datetime.now(UTC)
        completed = subprocess.run(
            [
                "docker",
                "exec",
                ctx.left_host,
                "python3",
                DASH_PLAYER,
                "--origin",
                f"http://{VIDEO_ORIGIN_IP}:{VIDEO_ORIGIN_PORT}",
                "--rung",
                self.variant.rung,
                "--segment-seconds",
                str(self.variant.segment_seconds),
                "--buffer-segments",
                str(self.variant.buffer_segments),
                "--duration-s",
                str(duration_s),
                *(["--seed", str(self.seed)] if self.seed is not None else []),
            ],
            capture_output=True,
            text=True,
            timeout=duration_s + 120,
            check=False,
        )
        ended = datetime.now(UTC)

        segments, total_bytes = _parse_player(completed.stdout)
        if segments == 0 or total_bytes == 0:
            detail = (completed.stderr.strip() or completed.stdout.strip())[:200]
            return GenerationResult(
                generator=self.name,
                variant=self.variant.name,
                packets_sent=0,
                bytes_sent=0,
                started_at=started,
                ended_at=ended,
                success=False,
                error=f"player fetched no video data (exit {completed.returncode}): {detail}",
            )
        return GenerationResult(
            generator=self.name,
            variant=self.variant.name,
            packets_sent=segments,
            bytes_sent=total_bytes,
            started_at=started,
            ended_at=ended,
            success=True,
        )


def _parse_player(output: str) -> tuple[int, int]:
    """Read ``segments=`` and ``bytes=`` from the player's summary line."""
    segments = total = 0
    for token in output.split():
        if token.startswith("segments="):
            segments = int(token.split("=", 1)[1])
        elif token.startswith("bytes="):
            total = int(token.split("=", 1)[1])
    return segments, total
