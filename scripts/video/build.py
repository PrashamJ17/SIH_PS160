"""Compose the demo video: narrate each beat, hold its visual for exactly that long.

Sync is the thing that usually goes wrong in a generated demo. It is solved here by
inverting the usual order: the narration is synthesised first, its true duration is
measured with ffprobe, and the visual is then held for precisely that. Nothing has to be
lined up afterwards because nothing was ever out of line.

Terminal beats reveal their output progressively across the beat, so the video reads as a
command running rather than as a slideshow of finished output.

    python -m scripts.video.build
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Final

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from video import frames
from video.storyboard import BEATS, Beat

REPO: Final = Path(__file__).resolve().parents[2]
TRANSCRIPT: Final = REPO / "demo" / "video-transcript.json"
SHOTS: Final = REPO / "demo" / "video" / "shots"
OUTPUT: Final = REPO / "demo" / "IPsec-Sentinel-demo.mp4"

VOICE: Final = "Daniel"
RATE: Final = 172  # words per minute; the default gallops
FPS: Final = 30
TAIL: Final = 0.7  # a breath after each beat, so cuts do not clip the last word


def narrate(text: str, out: Path) -> float:
    """Synthesise one beat and return how long it actually is."""
    aiff = out.with_suffix(".aiff")
    subprocess.run(
        ["say", "-v", VOICE, "-r", str(RATE), "-o", str(aiff), text],
        check=True,
        timeout=600,
    )
    subprocess.run(
        [
            "ffmpeg",
            "-y",
            "-loglevel",
            "error",
            "-i",
            str(aiff),
            "-af",
            f"apad=pad_dur={TAIL}",
            "-ar",
            "48000",
            "-ac",
            "2",
            str(out),
        ],
        check=True,
        timeout=600,
    )
    aiff.unlink(missing_ok=True)
    probe = subprocess.run(
        ["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", str(out)],
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    return float(probe.stdout.strip())


def beat_frames(
    beat: Beat, transcript: dict, work: Path, duration: float, progress: float
) -> list[tuple[Path, float]]:
    """The images this beat shows, each with how long to hold it."""
    chrome = frames.Chrome(beat.chapter, progress) if beat.chapter else None
    stem = work / beat.key

    if beat.kind == "title":
        return [
            (
                frames.title_card(beat.source, beat.caption, beat.lines, stem.with_suffix(".png")),
                duration,
            )
        ]

    if beat.kind == "statement":
        return [
            (
                frames.statement(beat.source, beat.points, stem.with_suffix(".png"), chrome=chrome),
                duration,
            )
        ]

    if beat.kind == "shot":
        return [
            (
                frames.shot(
                    SHOTS / beat.source,
                    stem.with_suffix(".png"),
                    chrome=chrome,
                    caption=beat.caption,
                    zoom=beat.zoom,
                ),
                duration,
            )
        ]

    step = transcript[beat.source]
    body = step["stdout"] or step["stderr"]
    command = step["command"] or "sentinel"
    # Paths in a recorded command are absolute and temporary; show the readable form.
    command = command.replace(str(REPO) + "/", "").replace(".venv/bin/sentinel", "sentinel")
    command = " ".join(
        part if "/var/folders/" not in part else Path(part).name for part in command.split()
    )

    if not beat.reveal:
        return [
            (
                frames.terminal(
                    command, body, stem.with_suffix(".png"), chrome=chrome, caption=beat.caption
                ),
                duration,
            )
        ]

    # Reveal the output over the first two thirds, then hold what is on screen.
    lines = body.splitlines()
    steps = min(max(len(lines), 1), 14)
    reveal_time = duration * 0.62
    per = reveal_time / steps
    produced: list[tuple[Path, float]] = []
    for index in range(steps):
        shown = round(len(lines) * (index + 1) / steps)
        path = frames.terminal(
            command,
            body,
            work / f"{beat.key}_{index:02d}.png",
            chrome=chrome,
            caption=beat.caption,
            reveal=shown,
        )
        produced.append((path, per))
    produced.append((produced[-1][0], duration - reveal_time))
    return produced


def segment(images: list[tuple[Path, float]], audio: Path, out: Path) -> None:
    listing = out.with_suffix(".txt")
    lines = []
    for path, hold in images:
        lines.append(f"file '{path}'")
        lines.append(f"duration {max(hold, 0.05):.3f}")
    lines.append(f"file '{images[-1][0]}'")  # concat demuxer needs the last one repeated
    listing.write_text("\n".join(lines))

    subprocess.run(
        [
            "ffmpeg",
            "-y",
            "-loglevel",
            "error",
            "-f",
            "concat",
            "-safe",
            "0",
            "-i",
            str(listing),
            "-i",
            str(audio),
            "-c:v",
            "libx264",
            "-preset",
            "medium",
            "-crf",
            "20",
            "-pix_fmt",
            "yuv420p",
            "-r",
            str(FPS),
            "-c:a",
            "aac",
            "-b:a",
            "160k",
            "-shortest",
            "-vf",
            "scale=1920:1080:force_original_aspect_ratio=decrease,"
            "pad=1920:1080:(ow-iw)/2:(oh-ih)/2:color=0x12151a",
            str(out),
        ],
        check=True,
        timeout=1800,
    )


def main() -> int:
    if not TRANSCRIPT.is_file():
        print("run scripts.video.record first", file=sys.stderr)
        return 1
    if not (SHOTS / "02_overview.png").is_file():
        print("run scripts.video.shots first", file=sys.stderr)
        return 1

    transcript = json.loads(TRANSCRIPT.read_text())
    work = Path(tempfile.mkdtemp(prefix="sentinel-video-build-"))
    segments: list[Path] = []
    total = 0.0

    print(f"building {len(BEATS)} beats\n")
    for index, beat in enumerate(BEATS):
        audio = work / f"{beat.key}.m4a"
        duration = narrate(beat.spoken, audio)
        images = beat_frames(beat, transcript, work, duration, index / max(len(BEATS) - 1, 1))
        out = work / f"seg{index:02d}.mp4"
        segment(images, audio, out)
        segments.append(out)
        total += duration
        print(
            f"  {index:>2}  {beat.key:<14} {duration:5.1f}s  "
            f"{len(images):>2} frame(s)  {beat.chapter or '—'}"
        )

    listing = work / "segments.txt"
    listing.write_text("\n".join(f"file '{path}'" for path in segments))
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            "ffmpeg",
            "-y",
            "-loglevel",
            "error",
            "-f",
            "concat",
            "-safe",
            "0",
            "-i",
            str(listing),
            "-c",
            "copy",
            str(OUTPUT),
        ],
        check=True,
        timeout=1800,
    )
    shutil.rmtree(work, ignore_errors=True)

    minutes, seconds = divmod(int(total), 60)
    size = OUTPUT.stat().st_size // 1024 // 1024
    print(f"\nwrote {OUTPUT.relative_to(REPO)}  {minutes}:{seconds:02d}  {size} MB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
