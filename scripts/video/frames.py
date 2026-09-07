"""Render the video's frames: title cards, terminal panels and full-bleed shots.

Drawn with PIL rather than a screen recorder because every frame then has a known size
and the text stays crisp at 1080p — a recording of a terminal window scaled to fit is the
single most common way a demo video ends up unreadable on a projector.

The terminal panels replay the output recorded by :mod:`scripts.video.record`, verbatim.
"""

from __future__ import annotations

import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from PIL import Image, ImageDraw, ImageFont

REPO: Final = Path(__file__).resolve().parents[2]
WIDTH: Final = 1920
HEIGHT: Final = 1080

MONO: Final = "/System/Library/Fonts/Menlo.ttc"
SANS: Final = "/System/Library/Fonts/Supplemental/Arial.ttf"
SANS_BOLD: Final = "/System/Library/Fonts/Supplemental/Arial Bold.ttf"

# The product's own palette, so the video and the dashboard agree.
BG: Final = (18, 21, 26)
PANEL: Final = (24, 29, 37)
INK: Final = (222, 228, 236)
DIM: Final = (140, 155, 170)
NAVY: Final = (31, 73, 125)
ACCENT: Final = (79, 176, 224)
CRITICAL: Final = (234, 123, 112)
HIGH: Final = (224, 145, 84)
MEDIUM: Final = (203, 176, 94)
OK: Final = (92, 195, 137)
WHITE: Final = (255, 255, 255)

SEVERITY: Final = {
    "CRITICAL": CRITICAL,
    "HIGH": HIGH,
    "MEDIUM": MEDIUM,
    "LOW": DIM,
    "INFO": DIM,
}


def font(path: str, size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(path, size)


@dataclass
class Chrome:
    """The persistent band at the bottom: what chapter this is, and how far in."""

    chapter: str
    progress: float = 0.0


def _chrome(draw: ImageDraw.ImageDraw, chrome: Chrome | None) -> None:
    if chrome is None:
        return
    draw.rectangle([(0, HEIGHT - 64), (WIDTH, HEIGHT)], fill=(12, 15, 19))
    draw.text((56, HEIGHT - 46), "IPsec Sentinel", font=font(SANS_BOLD, 21), fill=ACCENT)
    draw.text((250, HEIGHT - 46), chrome.chapter, font=font(SANS, 21), fill=DIM)
    draw.text(
        (WIDTH - 260, HEIGHT - 46), "Team Highlanders · SIH 2026", font=font(SANS, 19), fill=DIM
    )
    draw.rectangle([(0, HEIGHT - 68), (int(WIDTH * chrome.progress), HEIGHT - 64)], fill=ACCENT)


def _canvas(chrome: Chrome | None = None) -> tuple[Image.Image, ImageDraw.ImageDraw]:
    image = Image.new("RGB", (WIDTH, HEIGHT), BG)
    draw = ImageDraw.Draw(image)
    _chrome(draw, chrome)
    return image, draw


def title_card(title: str, subtitle: str, lines: list[str], out: Path) -> Path:
    image, draw = _canvas()
    draw.text((160, 300), title, font=font(SANS_BOLD, 88), fill=WHITE)
    draw.text((160, 412), subtitle, font=font(SANS, 38), fill=ACCENT)
    draw.rectangle([(160, 486), (520, 490)], fill=ACCENT)
    y = 540
    for line in lines:
        draw.text((160, y), line, font=font(SANS, 27), fill=DIM)
        y += 44
    out.parent.mkdir(parents=True, exist_ok=True)
    image.save(out)
    return out


def chapter_card(
    number: str, title: str, blurb: str, out: Path, *, chrome: Chrome | None = None
) -> Path:
    image, draw = _canvas(chrome)
    draw.text((160, 380), number, font=font(SANS_BOLD, 40), fill=ACCENT)
    draw.text((160, 440), title, font=font(SANS_BOLD, 64), fill=WHITE)
    y = 540
    for line in textwrap.wrap(blurb, 68):
        draw.text((160, y), line, font=font(SANS, 30), fill=DIM)
        y += 46
    image.save(out)
    return out


COLUMNS: Final = 118
"""Characters that fit across the panel at 22pt Menlo, measured rather than guessed."""


def _wrap(text: str) -> list[str]:
    """Expand tabs and fold long lines, the way a terminal would.

    Tabs matter: tshark separates its fields with them, and an unexpanded tab renders as
    a missing-glyph box in a TrueType font — which is what the first cut of this video
    showed, on the very first command.
    """
    folded: list[str] = []
    for raw in text.expandtabs(4).splitlines():
        if len(raw) <= COLUMNS:
            folded.append(raw)
            continue
        indent = " " * (len(raw) - len(raw.lstrip()) + 2)
        wrapped = textwrap.wrap(
            raw, COLUMNS, subsequent_indent=indent, break_long_words=True, break_on_hyphens=False
        )
        folded.extend(wrapped or [""])
    return folded


def terminal(
    command: str,
    body: str,
    out: Path,
    *,
    chrome: Chrome | None = None,
    reveal: int | None = None,
    caption: str = "",
) -> Path:
    """A terminal panel showing a real command and however much of its output has run."""
    image, draw = _canvas(chrome)

    top = 96
    bottom = HEIGHT - 150 if caption else HEIGHT - 110
    draw.rounded_rectangle(
        [(72, top), (WIDTH - 72, bottom)], radius=14, fill=PANEL, outline=(46, 56, 68), width=2
    )
    for index, colour in enumerate(((255, 95, 86), (255, 189, 46), (39, 201, 63))):
        draw.ellipse([(102 + index * 26, top + 20), (114 + index * 26, top + 32)], fill=colour)
    draw.text((190, top + 17), "sentinel — demo", font=font(SANS, 19), fill=DIM)

    mono = font(MONO, 22)
    x, y = 106, top + 66
    draw.text((x, y), "$ ", font=mono, fill=OK)
    command_lines = textwrap.wrap(
        command.expandtabs(4),
        COLUMNS - 2,
        subsequent_indent="    ",
        break_long_words=True,
        break_on_hyphens=False,
    ) or [""]
    for part in command_lines:
        draw.text((x + 26, y), part, font=mono, fill=WHITE)
        y += 30
    y += 14

    lines = _wrap(body)
    if reveal is not None:
        lines = lines[:reveal]
    for raw in lines:
        if y > bottom - 44:
            break
        colour = INK
        stripped = raw.strip()
        for name, tone in SEVERITY.items():
            if stripped.startswith(f"[{name}") or f"[{name}" in raw[:14]:
                colour = tone
                break
        else:
            if stripped.startswith("!") or stripped.startswith(("error:", "refusing")):
                colour = CRITICAL
            elif "grade A" in raw or "100/100" in raw:
                colour = OK
            elif "grade F" in raw or "0/100" in raw:
                colour = CRITICAL
            elif raw.startswith("==="):
                colour = ACCENT
        draw.text((x, y), raw, font=mono, fill=colour)
        y += 30

    if reveal is not None and reveal < len(_wrap(body)):
        draw.rectangle([(x, y + 6), (x + 13, y + 26)], fill=INK)

    if caption:
        draw.text((76, bottom + 16), caption, font=font(SANS_BOLD, 26), fill=ACCENT)
    image.save(out)
    return out


def shot(
    path: Path,
    out: Path,
    *,
    chrome: Chrome | None = None,
    caption: str = "",
    zoom: tuple[float, float, float, float] | None = None,
) -> Path:
    """A screenshot, letterboxed onto the canvas, optionally cropped to a region."""
    image, draw = _canvas(chrome)
    picture = Image.open(path).convert("RGB")
    if zoom:
        left, top, right, bottom = zoom
        picture = picture.crop(
            (
                int(picture.width * left),
                int(picture.height * top),
                int(picture.width * right),
                int(picture.height * bottom),
            )
        )

    available_h = HEIGHT - 100 - (110 if caption else 78)
    available_w = WIDTH - 144
    scale = min(available_w / picture.width, available_h / picture.height)
    picture = picture.resize(
        (int(picture.width * scale), int(picture.height * scale)), Image.LANCZOS
    )
    x = (WIDTH - picture.width) // 2
    # Centred in the space available, so a wide, short crop does not sit under a slab of
    # empty background.
    y = 74 + max(0, (available_h - picture.height) // 2)
    draw.rounded_rectangle(
        [(x - 8, y - 8), (x + picture.width + 8, y + picture.height + 8)],
        radius=10,
        fill=(40, 48, 58),
    )
    image.paste(picture, (x, y))
    if caption:
        draw.text((72, y + picture.height + 26), caption, font=font(SANS_BOLD, 27), fill=ACCENT)
    image.save(out)
    return out


def statement(
    headline: str, points: list[tuple[str, str]], out: Path, *, chrome: Chrome | None = None
) -> Path:
    """A claim and the evidence under it."""
    image, draw = _canvas(chrome)
    y = 150
    for line in textwrap.wrap(headline, 52):
        draw.text((150, y), line, font=font(SANS_BOLD, 54), fill=WHITE)
        y += 74
    y += 40
    for value, label in points:
        draw.text((150, y), value, font=font(SANS_BOLD, 46), fill=ACCENT)
        draw.text((470, y + 10), label, font=font(SANS, 30), fill=DIM)
        y += 78
    image.save(out)
    return out
