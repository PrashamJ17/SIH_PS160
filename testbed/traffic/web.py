"""Web browsing traffic generator.

The shape is a sawtooth: a small request pulls a large HTML response, a flurry of
asset fetches follows, then the link falls quiet while a human reads. Through ESP the
content is invisible; the asymmetry and the multi-second think-time gaps are not.

The page order rotates between runs. Fetching an identical corpus every time would let
the classifier memorise this specific content rather than learn the shape of browsing —
trap 4 in the master document's dataset section, and the reason ``seed`` is part of the
generator's identity rather than an afterthought.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import ClassVar, Final

from testbed.traffic.base import GenerationResult, RunContext, wait_for_service

WEB_BROWSER: Final = "/opt/sentinel/web_browser.py"
WEB_ORIGIN_IP: Final = "10.2.0.21"
WEB_ORIGIN_PORT: Final = 80
WEB_PROFILE: Final = "web"


@dataclass(frozen=True)
class WebVariant:
    """One browsing rhythm: how long a reader lingers between pages."""

    name: str
    think_min_s: float
    think_max_s: float


VARIANTS: Final[dict[str, WebVariant]] = {
    "reading": WebVariant("reading", think_min_s=4.0, think_max_s=12.0),
    "skimming": WebVariant("skimming", think_min_s=2.0, think_max_s=5.0),
}


class WebGenerator:
    """Browse the local corpus with realistic think time between pages."""

    name = "web"
    requires: ClassVar[list[str]] = [WEB_PROFILE]

    def __init__(self, variant: str = "reading", seed: int | None = None) -> None:
        if variant not in VARIANTS:
            raise ValueError(f"unknown web variant {variant!r}; have {sorted(VARIANTS)}")
        self.variant = VARIANTS[variant]
        self.seed = seed
        self.pages_visited: list[int] = []
        """Which corpus pages the last run fetched, so rotation can be verified."""
        self._ctx: RunContext | None = None

    def setup(self, ctx: RunContext) -> None:
        if not wait_for_service(ctx.left_host, ctx.web_origin_ip, WEB_ORIGIN_PORT):
            raise RuntimeError(
                f"the origin at {ctx.web_origin_ip}:{WEB_ORIGIN_PORT} never accepted "
                "a connection; starting anyway would produce a short, sparse capture"
            )
        self._ctx = ctx

    def teardown(self) -> None:
        self._ctx = None

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
                WEB_BROWSER,
                "--origin",
                f"http://{ctx.web_origin_ip}:{WEB_ORIGIN_PORT}",
                "--duration-s",
                str(duration_s),
                "--think-min",
                str(self.variant.think_min_s),
                "--think-max",
                str(self.variant.think_max_s),
                *(["--seed", str(self.seed)] if self.seed is not None else []),
            ],
            capture_output=True,
            text=True,
            timeout=duration_s + 120,
            check=False,
        )
        ended = datetime.now(UTC)

        pages, assets, total_bytes, visited = _parse_browser(completed.stdout)
        self.pages_visited = visited
        if pages == 0:
            detail = (completed.stderr.strip() or completed.stdout.strip())[:200]
            return GenerationResult(
                generator=self.name,
                variant=self.variant.name,
                packets_sent=0,
                bytes_sent=0,
                started_at=started,
                ended_at=ended,
                success=False,
                error=f"browser fetched no pages (exit {completed.returncode}): {detail}",
            )
        return GenerationResult(
            generator=self.name,
            variant=self.variant.name,
            packets_sent=pages + assets,
            bytes_sent=total_bytes,
            started_at=started,
            ended_at=ended,
            success=True,
        )


def _parse_browser(output: str) -> tuple[int, int, int, list[int]]:
    """Read the browser's summary line: pages, assets, bytes, and which pages."""
    pages = assets = total = 0
    visited: list[int] = []
    for token in output.split():
        if token.startswith("pages="):
            pages = int(token.split("=", 1)[1])
        elif token.startswith("assets="):
            assets = int(token.split("=", 1)[1])
        elif token.startswith("bytes="):
            total = int(token.split("=", 1)[1])
        elif token.startswith("visited="):
            raw = token.split("=", 1)[1]
            visited = [int(x) for x in raw.split(",") if x]
    return pages, assets, total, visited
