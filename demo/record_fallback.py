"""Record ``demo/fallback.mp4`` — the demo running, for when the live one will not.

The plan asks for "a recorded video if everything fails". This produces one from a real
run: `run_demo.sh` is executed, its output is captured, and each beat is rendered as a
terminal frame and encoded. **Nothing is re-enacted.** If the demo changes, re-run this
and the video changes with it.

Each beat holds for six seconds, because the point of a fallback is that a presenter
narrates over it at demo pace — a five-second blur of the whole script would be useless
on stage.

Chromium (via Playwright, already a development dependency) does the rendering, and
ffmpeg does the encoding.

    python -m demo.record_fallback
"""

from __future__ import annotations

import argparse
import html
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Final

REPO_ROOT: Final = Path(__file__).resolve().parents[1]
RUNNER: Final = REPO_ROOT / "demo" / "run_demo.sh"
DESTINATION: Final = REPO_ROOT / "demo" / "fallback.mp4"

WIDTH: Final = 1600
HEIGHT: Final = 900
SECONDS_PER_BEAT: Final = 6
ANSI: Final = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

PAGE: Final = """<!DOCTYPE html>
<meta charset="utf-8">
<style>
  html, body {{ margin: 0; background: #12151a; }}
  pre {{
    margin: 0; padding: 26px 30px;
    color: #d6dae0; background: #12151a;
    font: 15px/1.45 Menlo, "DejaVu Sans Mono", monospace;
    white-space: pre-wrap; word-break: break-word;
  }}
  .beat   {{ color: #4fd0e0; font-weight: 700; }}
  .strong {{ color: #f5f7fa; font-weight: 700; }}
  .flag   {{ color: #ff7b72; font-weight: 700; }}
  .ok     {{ color: #6fd08c; font-weight: 700; }}
</style>
<pre>{body}</pre>
"""


def run_demo(output: Path) -> str:
    """Run the demo and return everything it printed."""
    result = subprocess.run(
        [str(RUNNER), "--out", str(output), "--quiet"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=1800,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"run_demo.sh exited {result.returncode}\n"
            f"{result.stdout[-2000:]}{result.stderr[-2000:]}"
        )
    return result.stdout


def decorate(line: str) -> str:
    """Escape a line and give the few structural ones a colour."""
    escaped = html.escape(line)
    if "BEAT" in line:
        return f'<span class="beat">{escaped}</span>'
    if "nobody documented this" in line or "grade F" in line:
        return f'<span class="flag">{escaped}</span>'
    if "Demo complete" in line or "grade A" in line:
        return f'<span class="ok">{escaped}</span>'
    if line.startswith("IPsec Sentinel"):
        return f'<span class="strong">{escaped}</span>'
    return escaped


def frames_from(transcript: str) -> list[str]:
    """One frame per beat: the transcript up to and including that beat's output."""
    lines = [ANSI.sub("", line.rstrip()) for line in transcript.splitlines()]
    rows = HEIGHT // 22 - 2

    boundaries = [index for index, line in enumerate(lines) if "BEAT" in line]
    cuts = [*boundaries[1:], len(lines)]

    pages: list[str] = []
    for cut in cuts:
        window = lines[:cut]
        # Show the tail that fits, so a long beat is readable rather than scrolled away.
        body = "\n".join(decorate(line) for line in window[-rows:])
        pages.append(PAGE.format(body=body))
    return pages


def render(pages: list[str], into: Path) -> list[Path]:
    from playwright.sync_api import sync_playwright

    into.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page(viewport={"width": WIDTH, "height": HEIGHT})
        try:
            for index, markup in enumerate(pages, start=1):
                destination = into / f"frame{index:03d}.png"
                page.set_content(markup)
                page.screenshot(path=str(destination))
                written.append(destination)
        finally:
            browser.close()
    return written


def encode(frames: Path, destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            "ffmpeg",
            "-y",
            "-loglevel",
            "error",
            "-framerate",
            f"1/{SECONDS_PER_BEAT}",
            "-pattern_type",
            "glob",
            "-i",
            str(frames / "*.png"),
            "-c:v",
            "libx264",
            "-pix_fmt",
            "yuv420p",
            "-r",
            "24",
            str(destination),
        ],
        check=True,
        timeout=600,
    )
    return destination


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DESTINATION)
    arguments = parser.parse_args(argv)

    if shutil.which("ffmpeg") is None:
        print("ffmpeg is required to encode the fallback video", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory() as scratch:
        work = Path(scratch)
        print("  running the demo")
        transcript = run_demo(work / "artefacts")

        pages = frames_from(transcript)
        print(f"  rendering {len(pages)} frames")
        render(pages, work / "frames")

        print("  encoding")
        written = encode(work / "frames", arguments.output)

    seconds = len(pages) * SECONDS_PER_BEAT
    print(f"wrote {written} ({written.stat().st_size // 1024} KB, about {seconds}s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
