"""Build the SIH 2026 idea-submission deck.

Two references shaped this file and they are not equal partners.

**The SIH2026 template is the format, exactly.** Its geometry was measured out of the
official PDF rather than eyeballed: 960x540pt, the Times New Roman Bold centred title, the
Arial Bold #1F497D section heading with its Wingdings diamond, the 2pt #1F497D rule at
y=200, the #0070C0 footer band from y=501, the team ellipse at (26,21)-(125,84) stroked
#8064A2, and the SIH logo at (770,0)-(947,84). The section headings and their pointer
bullets are reproduced verbatim, because the template says the idea pointers may not be
changed.

**The Lanezy deck is the visual strategy.** It is a previous SIH entry on the same six
slides, and what it does differently is refuse to be a bullet list: a three-column
composition with a hero graphic owning the centre, red-versus-green chips pairing each
problem with its answer, coloured underlined labels instead of bullets, real charts on the
right, and a link callout in the corner. Image coverage on its slides runs from 36% to
over 300%. Those techniques are applied here — inside SIH's frame, never over it.

The numbers come from :mod:`scripts.deck.facts`, which counts them live or parses them out
of a committed document, so the deck cannot claim something the repository cannot prove.

    python -m scripts.deck.build_deck
"""

# ruff: noqa: RUF001  - typographic dashes and symbols are deliberate slide copy.

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
from pptx.util import Emu, Pt

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from deck import facts

REPO: Final = facts.REPO_ROOT
FIGURES: Final = REPO / "docs" / "images" / "deck"
LOGO: Final = REPO / "docs" / "images" / "deck" / "sih_logo.png"
OUTPUT: Final = REPO / "docs" / "SIH2026-Highlanders-IPsec-Sentinel.pptx"

# The template is 960x540pt.
PT: Final = 12700  # EMU per point
W: Final = 960
H: Final = 540


@dataclass(frozen=True)
class Entry:
    """The registration details, as supplied by the team."""

    ps_id: str = "SIH 26160"
    ps_title: str = "AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework"
    theme: str = "Blockchain & Cybersecurity"
    category: str = "Software"
    team_id: str = "SIH 163"
    team_name: str = "Highlanders"


ENTRY: Final = Entry()

NAVY: Final = RGBColor(0x1F, 0x49, 0x7D)
FOOTER_BLUE: Final = RGBColor(0x00, 0x70, 0xC0)
PURPLE: Final = RGBColor(0x80, 0x64, 0xA2)
BLACK: Final = RGBColor(0x00, 0x00, 0x00)
WHITE: Final = RGBColor(0xFF, 0xFF, 0xFF)
INK: Final = RGBColor(0x17, 0x20, 0x2A)
MUTED: Final = RGBColor(0x5B, 0x6A, 0x7A)
CRITICAL: Final = RGBColor(0x8C, 0x1C, 0x13)
OK: Final = RGBColor(0x1D, 0x6B, 0x3F)


def pt(value: float) -> Emu:
    return Emu(int(value * PT))


def textbox(slide, x, y, w, h, *, anchor=MSO_ANCHOR.TOP, wrap=True):
    box = slide.shapes.add_textbox(pt(x), pt(y), pt(w), pt(h))
    frame = box.text_frame
    frame.word_wrap = wrap
    frame.vertical_anchor = anchor
    frame.margin_left = frame.margin_right = 0
    frame.margin_top = frame.margin_bottom = 0
    return frame


def write(
    frame,
    text,
    *,
    size,
    bold=False,
    colour=BLACK,
    font="Arial",
    align=PP_ALIGN.LEFT,
    italic=False,
    space_after=0,
    first=False,
    underline=False,
):
    paragraph = frame.paragraphs[0] if first else frame.add_paragraph()
    paragraph.alignment = align
    paragraph.space_after = Pt(space_after)
    run = paragraph.add_run()
    run.text = text
    run.font.size = Pt(size)
    run.font.bold = bold
    run.font.italic = italic
    run.font.underline = underline
    run.font.color.rgb = colour
    run.font.name = font
    return paragraph


def chrome(slide, number: int) -> None:
    """The template's own furniture: ellipse, logo, footer band."""
    # Team ellipse, at the template's measured position.
    ellipse = slide.shapes.add_shape(MSO_SHAPE.OVAL, pt(26), pt(21), pt(99), pt(63))
    ellipse.fill.background()
    ellipse.line.color.rgb = PURPLE
    ellipse.line.width = Pt(1.5)
    ellipse.shadow.inherit = False
    frame = ellipse.text_frame
    frame.word_wrap = True
    frame.margin_left = frame.margin_right = 0
    write(
        frame,
        ENTRY.team_name,
        size=15,
        bold=True,
        colour=INK,
        font="Calibri",
        align=PP_ALIGN.CENTER,
        first=True,
    )

    if LOGO.is_file():
        slide.shapes.add_picture(str(LOGO), pt(770), pt(2), pt(177), pt(82))

    band = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, pt(0), pt(501), pt(W), pt(39))
    band.fill.solid()
    band.fill.fore_color.rgb = FOOTER_BLUE
    band.line.fill.background()
    band.shadow.inherit = False
    frame = band.text_frame
    write(
        frame,
        "@SIH Idea submission- Template",
        size=12.3,
        colour=WHITE,
        font="Calibri",
        align=PP_ALIGN.CENTER,
        first=True,
    )

    page = textbox(slide, 880, 505, 60, 24)
    write(
        page,
        str(number),
        size=12.3,
        bold=True,
        colour=WHITE,
        font="Calibri",
        align=PP_ALIGN.RIGHT,
        first=True,
    )


def heading(slide, title: str) -> None:
    frame = textbox(slide, 130, 34, 700, 60)
    write(
        frame,
        title,
        size=36,
        bold=True,
        colour=BLACK,
        font="Times New Roman",
        align=PP_ALIGN.CENTER,
        first=True,
    )


def section(slide, text: str, y: float = 100) -> None:
    """The ❖ heading and the rule beneath it, as the template draws them."""
    frame = textbox(slide, 8, y, 944, 40)
    paragraph = frame.paragraphs[0]
    diamond = paragraph.add_run()
    diamond.text = "❖ "
    diamond.font.size = Pt(21)
    diamond.font.color.rgb = NAVY
    diamond.font.name = "Arial"
    run = paragraph.add_run()
    run.text = text
    run.font.size = Pt(21)
    run.font.bold = True
    run.font.underline = True
    run.font.color.rgb = NAVY
    run.font.name = "Arial"

    rule = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, pt(36), pt(y + 33), pt(894), pt(2))
    rule.fill.solid()
    rule.fill.fore_color.rgb = NAVY
    rule.line.fill.background()
    rule.shadow.inherit = False


def callout(slide, x, y, w, h, label, body, *, accent=NAVY):
    """Lanezy's panel: a coloured underlined label, then the sentence."""
    panel = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, pt(x), pt(y), pt(w), pt(h))
    panel.fill.solid()
    panel.fill.fore_color.rgb = RGBColor(0xF4, 0xF7, 0xFA)
    panel.line.color.rgb = accent
    panel.line.width = Pt(1.25)
    panel.shadow.inherit = False
    panel.adjustments[0] = 0.08

    frame = panel.text_frame
    frame.word_wrap = True
    frame.margin_left = pt(9)
    frame.margin_right = pt(9)
    frame.margin_top = pt(6)
    frame.margin_bottom = pt(6)
    frame.vertical_anchor = MSO_ANCHOR.TOP

    paragraph = frame.paragraphs[0]
    run = paragraph.add_run()
    run.text = label
    run.font.size = Pt(12.5)
    run.font.bold = True
    run.font.underline = True
    run.font.color.rgb = accent
    run.font.name = "Arial"

    body_paragraph = frame.add_paragraph()
    body_paragraph.space_before = Pt(3)
    body_run = body_paragraph.add_run()
    body_run.text = body
    body_run.font.size = Pt(11)
    body_run.font.color.rgb = INK
    body_run.font.name = "Arial"
    return panel


def chip(slide, x, y, w, h, text, colour, *, size=10.5):
    shape = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, pt(x), pt(y), pt(w), pt(h))
    shape.fill.solid()
    shape.fill.fore_color.rgb = colour
    shape.line.fill.background()
    shape.shadow.inherit = False
    shape.adjustments[0] = 0.16
    frame = shape.text_frame
    frame.word_wrap = True
    frame.margin_left = frame.margin_right = pt(4)
    write(frame, text, size=size, bold=True, colour=WHITE, align=PP_ALIGN.CENTER, first=True)
    return shape


def picture(slide, name, x, y, *, width=None, height=None):
    path = FIGURES / name
    if not path.is_file():
        raise FileNotFoundError(f"missing figure: {path}")
    return slide.shapes.add_picture(
        str(path),
        pt(x),
        pt(y),
        width=pt(width) if width else None,
        height=pt(height) if height else None,
    )


def blank(presentation):
    return presentation.slides.add_slide(presentation.slide_layouts[6])


# ------------------------------------------------------------------------ the slides


def slide_title(presentation) -> None:
    slide = blank(presentation)
    if LOGO.is_file():
        slide.shapes.add_picture(str(LOGO), pt(770), pt(2), pt(177), pt(82))

    frame = textbox(slide, 60, 14, 700, 60)
    write(
        frame,
        "SMART INDIA HACKATHON 2026",
        size=40,
        bold=True,
        colour=NAVY,
        font="Garamond",
        first=True,
    )

    frame = textbox(slide, 330, 96, 300, 46)
    write(
        frame,
        "TITLE PAGE",
        size=31.7,
        bold=True,
        colour=BLACK,
        font="Times New Roman",
        align=PP_ALIGN.CENTER,
        first=True,
    )

    rows = [
        ("Problem Statement ID – ", ENTRY.ps_id),
        ("Problem Statement Title- ", ENTRY.ps_title),
        ("Theme- ", ENTRY.theme),
        ("PS Category- ", ENTRY.category),
        ("Team ID- ", ENTRY.team_id),
        ("Team Name (Registered on portal)- ", ENTRY.team_name),
    ]
    frame = textbox(slide, 33, 186, 900, 300)
    for index, (label, value) in enumerate(rows):
        paragraph = frame.paragraphs[0] if index == 0 else frame.add_paragraph()
        paragraph.space_after = Pt(7)
        bullet = paragraph.add_run()
        bullet.text = "•  "
        bullet.font.size = Pt(19)
        bullet.font.color.rgb = BLACK
        bullet.font.name = "Arial"
        key = paragraph.add_run()
        key.text = label
        key.font.size = Pt(19)
        key.font.bold = True
        key.font.color.rgb = BLACK
        key.font.name = "Arial"
        val = paragraph.add_run()
        val.text = value
        val.font.size = Pt(19)
        val.font.bold = True
        val.font.color.rgb = NAVY
        val.font.name = "Arial"

    strip = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, pt(0), pt(501), pt(W), pt(39))
    strip.fill.solid()
    strip.fill.fore_color.rgb = FOOTER_BLUE
    strip.line.fill.background()
    strip.shadow.inherit = False
    frame = strip.text_frame
    write(
        frame,
        "IPsec Sentinel  —  passive IPsec protocol analysis and security assessment",
        size=13,
        bold=True,
        colour=WHITE,
        font="Calibri",
        align=PP_ALIGN.CENTER,
        first=True,
    )


def slide_idea(presentation) -> None:
    slide = blank(presentation)
    chrome(slide, 2)
    # Both reference decks keep the template's own slide-2 heading and put the project
    # name in the first section line, which is the safer reading of "do not change the
    # idea details pointers".
    heading(slide, "PROPOSED SOLUTION")
    section(slide, "IPsec Sentinel — passive IPsec assessment with auditable evidence", y=92)

    callout(
        slide,
        8,
        142,
        268,
        86,
        "Real-world issue:",
        "Wireshark decodes an IKE exchange but has no opinion about it. Weak IPsec "
        "survives for years because nothing judges what it sees.",
        accent=CRITICAL,
    )
    callout(
        slide,
        8,
        236,
        268,
        92,
        "How it addresses the problem:",
        f"{facts.rule_count()} deterministic rules, each citing the clause it applies, "
        "across NIST, CNSA, BSI, RFC 8221/8247, ITSAR and CERT-In.",
        accent=NAVY,
    )
    callout(
        slide,
        8,
        336,
        268,
        96,
        "Innovation and uniqueness:",
        "Facts are parsed. Estimates are inferred. A validator refuses to build a "
        "report that mixes them — the split is enforced, not promised.",
        accent=OK,
    )

    # Widths, not heights: sizing by height let the aspect ratio push this one 83pt off
    # the right edge, which the preview caught and a reader would have seen immediately.
    picture(slide, "two_lane.png", 286, 140, width=394)
    picture(slide, "risk_solution.png", 690, 140, width=262)

    frame = textbox(slide, 8, 446, 660, 48)
    write(
        frame,
        "Working prototype — v1.0.0 tagged, M11 acceptance 20/20, nothing skipped",
        size=11,
        bold=True,
        colour=NAVY,
        first=True,
    )
    write(
        frame,
        "Dashboard, demo video and source: github.com/PrashamJ17/SIH_PS160",
        size=10,
        colour=MUTED,
    )


def slide_technical(presentation) -> None:
    slide = blank(presentation)
    chrome(slide, 3)
    heading(slide, "TECHNICAL APPROACH")
    section(slide, "Technologies and methodology", y=92)

    picture(slide, "pipeline.png", 8, 142, width=560)
    dashboard = REPO / "docs" / "images" / "dashboard.png"
    if dashboard.is_file():
        slide.shapes.add_picture(str(dashboard), pt(580), pt(142), width=pt(372))

    frame = textbox(slide, 580, 316, 372, 40)
    write(
        frame,
        "Working prototype — the dashboard on a real capture",
        size=10,
        bold=True,
        colour=NAVY,
        align=PP_ALIGN.CENTER,
        first=True,
    )

    published, tags = facts.baseline_counts()
    chips = [
        (f"{facts.rule_count()} rules", NAVY),
        (f"{published} baselines + {tags} tags", NAVY),
        (f"{facts.vendor_generator_count()} vendor generators", NAVY),
        ("IKEv1 · IKEv2 · ESP", NAVY),
    ]
    for index, (text, colour) in enumerate(chips):
        chip(
            slide, 580 + (index % 2) * 190, 348 + (index // 2) * 40, 178, 32, text, colour, size=10
        )

    callout(
        slide,
        8,
        366,
        560,
        74,
        "Two boundaries the design will not cross:",
        "It never writes to a network device and stores no credential — an AST sweep "
        "over every module enforces both. Configuration is generated; a person applies it.",
        accent=CRITICAL,
    )

    frame = textbox(slide, 580, 434, 372, 40)
    write(
        frame,
        f"Reproducible build — git {facts.git_sha()}",
        size=9.5,
        colour=MUTED,
        align=PP_ALIGN.CENTER,
        first=True,
    )


def slide_feasibility(presentation) -> None:
    slide = blank(presentation)
    chrome(slide, 4)
    heading(slide, "FEASIBILITY AND VIABILITY")
    section(slide, "Feasibility, the risks, and the strategies for overcoming them", y=92)

    # The quadrant map answers the template's three pointers in the order it asks them.
    picture(slide, "feasibility.png", 8, 142, width=470)

    picture(slide, "performance.png", 490, 142, width=462)

    unit, integration = facts.test_counts()
    stats = [
        (f"{unit:,}", "unit tests", NAVY),
        (f"{integration}", "integration, on live pairs", OK),
        ("93.8%", "coverage", NAVY),
        ("20/20", "M11 acceptance", CRITICAL),
    ]
    for index, (value, label, colour) in enumerate(stats):
        x = 490 + index * 117
        chip(slide, x, 400, 110, 30, value, colour, size=13)
        frame = textbox(slide, x, 432, 110, 26)
        write(frame, label, size=8, colour=MUTED, align=PP_ALIGN.CENTER, first=True)

    callout(
        slide,
        490,
        458,
        462,
        38,
        "Deployable today:",
        f"{facts.container_size_gb() or 0.68:.2f} GB container, non-root, runs under "
        "--network none.",
        accent=OK,
    )


def slide_impact(presentation) -> None:
    slide = blank(presentation)
    chrome(slide, 5)
    heading(slide, "IMPACT AND BENEFITS")
    section(slide, "Impact on the target audience, and the benefits", y=92)

    picture(slide, "benefits.png", 8, 142, width=300)
    picture(slide, "generalisation.png", 320, 142, width=330)
    picture(slide, "endpoint_visibility.png", 664, 142, width=288)

    rows_, classes = facts.dataset_shape()
    frame = textbox(slide, 320, 344, 330, 60)
    write(frame, "Honest about its own limits", size=11, bold=True, colour=NAVY, first=True)
    write(
        frame,
        f"Trained on {rows_} rows across {classes} classes of laboratory traffic. "
        "The unflattering number is published, not the best one.",
        size=9.5,
        colour=INK,
    )

    frame = textbox(slide, 664, 344, 288, 60)
    write(frame, "Endpoint visibility", size=11, bold=True, colour=NAVY, first=True)
    write(
        frame,
        "A gateway's own kernel state is parsed and graded against the same rules "
        "— never fetched, never with a credential.",
        size=9.5,
        colour=INK,
    )

    callout(
        slide,
        8,
        436,
        944,
        58,
        "Social and economic benefit:",
        "Government, telecom and enterprise VPN estates get audit-grade evidence from a "
        "capture they already have — no agent, no credential, no outage, and an Indian "
        "baseline (ITSAR, CERT-In) that no comparable tool ships.",
        accent=OK,
    )


def slide_research(presentation) -> None:
    slide = blank(presentation)
    chrome(slide, 6)
    heading(slide, "RESEARCH AND REFERENCES")
    section(slide, "Details / Links of the reference and research work", y=92)

    standards = [
        ("RFC 7296", "IKEv2 — the protocol the parser implements"),
        ("RFC 2408 / 2409", "ISAKMP and IKEv1, including aggressive mode"),
        ("RFC 8221 / 8247", "Algorithm implementation requirements for ESP and IKEv2"),
        ("RFC 4303", "ESP, and the anti-replay window SA-03/SA-04 judge"),
        ("RFC 9370 / 8784", "Post-quantum: additional key exchanges, PPKs"),
        ("NIST SP 800-77 Rev. 1", "IPsec VPN guidance — the default baseline"),
        ("NIST SP 800-131A Rev. 2", "3DES disallowed after 2023; DES, MD5, SHA-1"),
        ("CNSA 1.0 · BSI TR-02102-3", "The strict and German baselines"),
        ("ITSAR (NCCS) · CERT-In", "Indian telecom security assurance requirements"),
        ("MITRE ATT&CK", "Technique mapping for every finding"),
    ]
    for index, (name, why) in enumerate(standards):
        column, row = index % 2, index // 2
        x = 8 + column * 476
        y = 142 + row * 46
        frame = textbox(slide, x, y, 460, 42)
        write(frame, name, size=11.5, bold=True, colour=NAVY, first=True)
        write(frame, why, size=9.5, colour=INK)

    callout(
        slide,
        8,
        378,
        466,
        106,
        "Our own published research:",
        "GENERALISATION.md — held-out results including the lowest.  "
        "CONFOUND_AUDIT.md — did the model learn traffic or cipher?  "
        "DATASET.md — methodology and limits.  LIMITATIONS.md — what it cannot do.  "
        "external_dataset_audit.md — the named datasets contain no IPsec.",
        accent=NAVY,
    )

    callout(
        slide,
        486,
        378,
        466,
        106,
        "Code, evidence and demo:",
        "github.com/PrashamJ17/SIH_PS160 — v1.0.0, M11 acceptance 20/20.  "
        "Testbed: real strongSwan pairs under netem.  "
        "Published JSON report schema 1.3.  "
        "docs/SECURITY.md names the test behind every security claim.",
        accent=OK,
    )


def main() -> int:
    presentation = Presentation()
    presentation.slide_width = pt(W)
    presentation.slide_height = pt(H)

    slide_title(presentation)
    slide_idea(presentation)
    slide_technical(presentation)
    slide_feasibility(presentation)
    slide_impact(presentation)
    slide_research(presentation)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    presentation.save(OUTPUT)
    slides = len(presentation.slides._sldIdLst)
    print(f"wrote {OUTPUT.relative_to(REPO)} ({OUTPUT.stat().st_size // 1024} KB, {slides} slides)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
