"""Render the saved .pptx to PNGs so the layout can actually be looked at.

There is no LibreOffice on this machine, and checking a deck by reading the code that
wrote it verifies intentions rather than the artefact. So this re-opens the *saved* file
and draws what is actually in it: every shape at its stored position, its text at its
stored size, and every embedded picture.

It is not a faithful PowerPoint renderer and does not try to be. It is a proofing tool for
the three faults that actually happen when a deck is generated programmatically — a shape
off the slide, two shapes overlapping, and text too long for the box it was put in — and
it reports those as warnings alongside the image.

    python -m scripts.deck.preview
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Final

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle
from PIL import Image
from pptx import Presentation
from pptx.enum.text import PP_ALIGN
from pptx.slide import Slide
from pptx.util import Emu

REPO: Final = Path(__file__).resolve().parents[2]
DECK: Final = REPO / "docs" / "SIH2026-Highlanders-IPsec-Sentinel.pptx"
OUT: Final = REPO / "docs" / "images" / "deck" / "preview"
PT: Final = 12700

# Roughly how wide an Arial character is, as a fraction of its point size. Only used to
# guess at overflow, which is why the threshold below is generous.
CHAR_WIDTH: Final = 0.52


def emu_to_pt(value: Emu | int | None) -> float:
    return (value or 0) / PT


def shape_text(shape: Any) -> str:
    if not shape.has_text_frame:
        return ""
    return " ".join(run.text for para in shape.text_frame.paragraphs for run in para.runs).strip()


def largest_size(shape: Any) -> float:
    sizes = [
        run.font.size.pt
        for para in shape.text_frame.paragraphs
        for run in para.runs
        if run.font.size is not None
    ]
    return max(sizes) if sizes else 12.0


def render(index: int, slide: Slide, width: float, height: float) -> tuple[Path, list[str]]:
    fig, ax = plt.subplots(figsize=(width / 72, height / 72), dpi=110)
    ax.set_xlim(0, width)
    ax.set_ylim(height, 0)
    ax.axis("off")
    ax.add_patch(Rectangle((0, 0), width, height, facecolor="white", edgecolor="#999999"))

    warnings: list[str] = []
    boxes: list[tuple[float, float, float, float, str]] = []

    for raw in slide.shapes:
        # python-pptx resolves `.fill`, `.text_frame` and `.image` on subclasses
        # at runtime; BaseShape declares none, and the body guards before use.
        shape: Any = raw
        x, y = emu_to_pt(shape.left), emu_to_pt(shape.top)
        w, h = emu_to_pt(shape.width), emu_to_pt(shape.height)
        label = shape_text(shape)

        if shape.shape_type == 13 and hasattr(shape, "image"):  # picture
            try:
                image = Image.open(shape.image.blob and __import__("io").BytesIO(shape.image.blob))
                ax.imshow(image, extent=(x, x + w, y + h, y), aspect="auto", zorder=1)
            except Exception:  # pragma: no cover - proofing tool
                ax.add_patch(Rectangle((x, y), w, h, facecolor="#DDDDDD", zorder=1))
        else:
            fill = "#F7F9FB"
            try:
                if shape.fill.type is not None and shape.fill.type == 1:
                    rgb = shape.fill.fore_color.rgb
                    fill = f"#{rgb}"
            except Exception:  # pragma: no cover
                pass
            if label or shape.shape_type is not None:
                ax.add_patch(
                    Rectangle(
                        (x, y), w, h, facecolor=fill, edgecolor="#C3CDD8", linewidth=0.6, zorder=2
                    )
                )

        if label:
            size = largest_size(shape)
            ax.text(
                x + 3,
                y + size,
                label[:96],
                fontsize=size * 0.62,
                color="#17202A",
                va="top",
                zorder=4,
                wrap=True,
            )
            # Overflow guess: how many characters fit on the lines this box allows.
            capacity = max(1, int(w / (size * CHAR_WIDTH))) * max(1, int(h / (size * 1.28)))
            if len(label) > capacity * 1.35:
                warnings.append(
                    f"    text may overflow ({len(label)} chars, ~{capacity} fit): "
                    f"'{label[:48]}...'"
                )

        if x < -1 or y < -1 or x + w > width + 1 or y + h > height + 1:
            warnings.append(
                f"    off-slide: '{label[:40] or shape.shape_type}' "
                f"at ({x:.0f},{y:.0f}) {w:.0f}x{h:.0f}"
            )
        # A text box is as wide as its *text*, not as wide as its frame. The page-centred
        # slide title has a 700pt frame that formally reaches under the logo while the
        # words stop 100pt short of it — five identical false positives, one per slide.
        if label:
            size = largest_size(shape)
            frame: Any = shape.text_frame
            span = min(w, len(label) * size * CHAR_WIDTH)
            align = next(
                (para.alignment for para in frame.paragraphs if para.alignment),
                None,
            )
            if align == PP_ALIGN.CENTER:
                x, w = x + (w - span) / 2, span
            elif align == PP_ALIGN.RIGHT:
                x, w = x + w - span, span
            else:
                w = span
        boxes.append((x, y, w, h, label[:40]))

    # Nothing may overlap a picture — not another picture, and not a text box. The first
    # version checked only picture-against-picture, and a caption then sat 10pt inside a
    # chart's own axis labels on slide 5 without a warning.
    pictures = [b for b in boxes if b[4] == ""]
    for i, (ax0, ay0, aw, ah, _) in enumerate(pictures):
        for bx0, by0, bw, bh, _ in [*pictures[i + 1 :], *[b for b in boxes if b[4]]]:
            overlap_x = min(ax0 + aw, bx0 + bw) - max(ax0, bx0)
            overlap_y = min(ay0 + ah, by0 + bh) - max(ay0, by0)
            if overlap_x > 2 and overlap_y > 2:
                warnings.append(
                    f"    overlap of {overlap_x:.0f}x{overlap_y:.0f}pt: "
                    f"({ax0:.0f},{ay0:.0f}) and ({bx0:.0f},{by0:.0f})"
                )

    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / f"slide{index}.png"
    fig.savefig(path, dpi=110, bbox_inches="tight", pad_inches=0.02)
    plt.close(fig)
    return path, warnings


def main() -> int:
    if not DECK.is_file():
        print(f"no deck at {DECK}", file=sys.stderr)
        return 1
    presentation = Presentation(str(DECK))
    width, height = emu_to_pt(presentation.slide_width), emu_to_pt(presentation.slide_height)
    print(f"{DECK.name}: {width:.0f}x{height:.0f}pt, {len(presentation.slides._sldIdLst)} slides\n")

    total = 0
    for index, slide in enumerate(presentation.slides, start=1):
        path, warnings = render(index, slide, width, height)
        print(f"  slide {index}: {len(slide.shapes)} shapes -> {path.name}")
        for warning in warnings:
            print(warning)
        total += len(warnings)
    print(f"\n{total} layout warning(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
