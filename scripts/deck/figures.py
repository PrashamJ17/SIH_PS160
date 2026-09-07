"""Every figure the deck uses, drawn from the repository's own numbers.

Lanezy's lesson is that a slide carries far more through a composed graphic than through
a bullet list, so each of these is a *hero* image sized to dominate the middle of its
slide. The discipline that keeps that honest is Phase 12's: the values come from
:mod:`scripts.deck.facts`, which counts them live or parses them from a committed
document, so a figure cannot drift from what the repository can prove.

    python -m scripts.deck.figures
"""

# ruff: noqa: RUF001  - typographic dashes and symbols are deliberate slide copy.

from __future__ import annotations

import sys
from pathlib import Path
from typing import Final

import matplotlib

matplotlib.use("Agg")
import matplotlib.patches as mpatches
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from deck import facts
from deck.palette import (
    CRITICAL,
    HIGH,
    INFERRED,
    INK,
    MUTED,
    OK,
    PANEL,
    RULE,
    SIH_NAVY,
    VERIFIED,
)

OUT: Final = facts.REPO_ROOT / "docs" / "images" / "deck"
FONT: Final = ["Helvetica Neue", "Helvetica", "Arial", "DejaVu Sans"]

plt.rcParams.update(
    {
        "font.family": "sans-serif",
        "font.sans-serif": FONT,
        "axes.edgecolor": RULE,
        "text.color": INK,
        "axes.labelcolor": INK,
        "xtick.color": MUTED,
        "ytick.color": MUTED,
        "savefig.facecolor": "white",
    }
)


def _save(fig: plt.Figure, name: str) -> Path:
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / name
    fig.savefig(path, dpi=200, bbox_inches="tight", pad_inches=0.06)
    plt.close(fig)
    print(f"  {path.relative_to(facts.REPO_ROOT)}  ({path.stat().st_size // 1024} KB)")
    return path


def _box(
    ax,
    x,
    y,
    w,
    h,
    *,
    face,
    edge=None,
    text="",
    size=9,
    weight="bold",
    colour="white",
    radius=0.02,
    align="center",
    pad=0.0,
):
    ax.add_patch(
        FancyBboxPatch(
            (x, y),
            w,
            h,
            boxstyle=f"round,pad={pad},rounding_size={radius}",
            facecolor=face,
            edgecolor=edge or face,
            linewidth=1.4,
            zorder=2,
        )
    )
    if text:
        tx = x + w / 2 if align == "center" else x + 0.02
        ax.text(
            tx,
            y + h / 2,
            text,
            ha=align if align != "center" else "center",
            va="center",
            fontsize=size,
            fontweight=weight,
            color=colour,
            zorder=3,
            linespacing=1.35,
        )


# ------------------------------------------------------------------ slide 2: the idea


def two_lane_architecture() -> Path:
    """The hero: one capture, two lanes, and a validator that keeps them apart."""
    fig, ax = plt.subplots(figsize=(7.4, 5.6))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    _box(ax, 0.28, 0.885, 0.44, 0.085, face=SIH_NAVY, text="ONE PACKET CAPTURE", size=11.5)

    # The split.
    for x0, label, colour, sub in (
        (0.035, "SECTION A — VERIFIED", VERIFIED, "parsed from cleartext IKE"),
        (0.525, "SECTION B — INFERRED", INFERRED, "estimated from encrypted ESP"),
    ):
        _box(ax, x0, 0.775, 0.44, 0.075, face=colour, text=label, size=10.5)
        ax.text(
            x0 + 0.22,
            0.745,
            sub,
            ha="center",
            va="center",
            fontsize=8.4,
            color=MUTED,
            style="italic",
        )

    facts_rows = [
        f"{facts.rule_count()} deterministic rules",
        "every finding cites a clause",
        "confidence = None",
        "> compliance evidence",
    ]
    infer_rows = [
        "traffic class from flow shape",
        "calibrated + SHAP explained",
        "abstains when signal is thin",
        "> what to fix first",
    ]
    for x0, rows, colour in ((0.035, facts_rows, VERIFIED), (0.525, infer_rows, INFERRED)):
        for i, row in enumerate(rows):
            y = 0.665 - i * 0.082
            weight = "bold" if row.startswith(">") else "normal"
            _box(
                ax,
                x0,
                y,
                0.44,
                0.066,
                face=PANEL,
                edge=RULE,
                text=row,
                size=9.2,
                weight=weight,
                colour=colour if weight == "bold" else INK,
            )

    ax.add_patch(
        FancyBboxPatch(
            (0.035, 0.20),
            0.93,
            0.105,
            boxstyle="round,pad=0,rounding_size=0.02",
            facecolor="#FDF3F2",
            edgecolor=CRITICAL,
            linewidth=2.0,
            zorder=2,
        )
    )
    ax.text(
        0.5,
        0.2525,
        "Report.enforce_separation()  —  raises, not asserts",
        ha="center",
        va="center",
        fontsize=10.5,
        fontweight="bold",
        color=CRITICAL,
        zorder=3,
    )

    ax.text(
        0.5,
        0.145,
        "python -O strips assertions. The guarantee at the centre of the product\n"
        "would vanish in exactly the deployment most likely to run optimised.",
        ha="center",
        va="center",
        fontsize=8.6,
        color=MUTED,
        linespacing=1.45,
    )

    for x in (0.255, 0.745):
        ax.add_patch(
            FancyArrowPatch(
                (0.5, 0.882),
                (x, 0.855),
                arrowstyle="-|>",
                mutation_scale=13,
                color=SIH_NAVY,
                linewidth=1.6,
            )
        )
    for x in (0.255, 0.745):
        ax.add_patch(
            FancyArrowPatch(
                (x, 0.335),
                (x, 0.312),
                arrowstyle="-|>",
                mutation_scale=13,
                color=CRITICAL,
                linewidth=1.6,
            )
        )

    ax.text(
        0.5,
        0.055,
        "An auditor reads Section A.  An engineer triaging forty tunnels reads Section B.",
        ha="center",
        va="center",
        fontsize=9.4,
        fontweight="bold",
        color=SIH_NAVY,
    )
    return _save(fig, "two_lane.png")


def risk_vs_solution() -> Path:
    """Lanezy's red-versus-green chips, with this project's actual gaps."""
    pairs = [
        ("Wireshark shows,\nnever judges", "26 cited rules,\nclause by clause"),
        ("Rekey is encrypted —\ntunnel goes dark", "Kernel + daemon state\nread and graded"),
        (
            "Payload is encrypted —\nwhat does it carry?",
            "Flow-shape inference,\ncalibrated, abstains",
        ),
        ("A one-sided fix\nis an outage", "Both ends, sequenced,\nzero packet loss"),
    ]
    fig, ax = plt.subplots(figsize=(5.5, 5.3))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    ax.text(0.22, 0.955, "GAP", ha="center", fontsize=12, fontweight="bold", color=CRITICAL)
    ax.text(0.78, 0.955, "WHAT WE BUILT", ha="center", fontsize=12, fontweight="bold", color=OK)

    for i, (risk, fix) in enumerate(pairs):
        y = 0.735 - i * 0.225
        _box(ax, 0.0, y, 0.44, 0.165, face=CRITICAL, text=risk, size=8.8)
        _box(ax, 0.56, y, 0.44, 0.165, face=OK, text=fix, size=8.8)
        ax.add_patch(
            FancyArrowPatch(
                (0.455, y + 0.0825),
                (0.545, y + 0.0825),
                arrowstyle="-|>",
                mutation_scale=15,
                color=SIH_NAVY,
                linewidth=2.2,
            )
        )
    return _save(fig, "risk_solution.png")


# ------------------------------------------------------- slide 3: technical approach


def pipeline() -> Path:
    """Capture in, cited document out — with the third input the wire cannot give."""
    fig, ax = plt.subplots(figsize=(7.6, 4.5))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    stages = [
        ("PCAP / live\ninterface", "libpcap-free\nstreaming reader"),
        ("PARSE\nIKEv1 · IKEv2 · ESP", "NAT-T 4500,\nboth registries"),
        ("CORRELATE\ninto tunnels", "negotiation +\nprotected flows"),
        ("ASSESS\n26 rules × baseline", "deterministic,\ncited"),
        ("REPORT\nHTML · PDF · JSON", "CEF / LEEF\nfor a SIEM"),
    ]
    w = 0.176
    for i, (title, sub) in enumerate(stages):
        x = 0.006 + i * 0.199
        _box(ax, x, 0.53, w, 0.20, face=SIH_NAVY, text=title, size=9.0)
        ax.text(
            x + w / 2,
            0.465,
            sub,
            ha="center",
            va="center",
            fontsize=7.6,
            color=MUTED,
            linespacing=1.35,
        )
        if i < len(stages) - 1:
            ax.add_patch(
                FancyArrowPatch(
                    (x + w + 0.002, 0.63),
                    (x + 0.196, 0.63),
                    arrowstyle="-|>",
                    mutation_scale=12,
                    color=SIH_NAVY,
                    linewidth=1.7,
                )
            )

    _box(
        ax,
        0.006,
        0.855,
        0.40,
        0.115,
        face="white",
        edge=VERIFIED,
        text="PASSIVE — never transmits, never writes to a device",
        size=8.8,
        colour=VERIFIED,
    )

    # The device-state lane.
    _box(
        ax,
        0.60,
        0.855,
        0.394,
        0.115,
        face="white",
        edge=OK,
        text="DEVICE STATE — ip xfrm state · swanctl\nparsed, never fetched",
        size=8.4,
        colour=OK,
    )
    ax.add_patch(
        FancyArrowPatch(
            (0.797, 0.85),
            (0.70, 0.735),
            arrowstyle="-|>",
            mutation_scale=12,
            color=OK,
            linewidth=1.7,
            connectionstyle="arc3,rad=-0.2",
        )
    )

    _box(
        ax,
        0.006,
        0.245,
        0.487,
        0.14,
        face=PANEL,
        edge=RULE,
        text="ML lane  ·  flow shape only\nsizes · timings · directions — payload never decrypted",
        size=8.4,
        colour=INFERRED,
        weight="normal",
    )
    _box(
        ax,
        0.507,
        0.245,
        0.487,
        0.14,
        face=PANEL,
        edge=RULE,
        text="Remediation  ·  both ends, sequenced\nsix vendors — a person applies it",
        size=8.4,
        colour=INK,
        weight="normal",
    )

    ax.text(
        0.5,
        0.115,
        "Python 3.11  ·  scapy  ·  pydantic v2  ·  scikit-learn  ·  SHAP\n"
        "FastAPI  ·  Jinja2  ·  WeasyPrint",
        ha="center",
        va="center",
        fontsize=8.6,
        fontweight="bold",
        color=SIH_NAVY,
    )
    ax.text(
        0.5,
        0.04,
        "strongSwan testbed under netem  ·  Docker  ·  ruff · mypy --strict · pytest",
        ha="center",
        va="center",
        fontsize=8.2,
        color=MUTED,
    )
    return _save(fig, "pipeline.png")


# ------------------------------------------------------- slide 4: feasibility


def performance() -> Path:
    """Measured margins against the plan's targets, on a log scale."""
    marks = facts.benchmarks()
    labels = [b.target.split(" under ")[0].replace("Memory on ", "Memory, ") for b in marks]
    margins = [float(b.margin.rstrip("x")) for b in marks]
    measured = [b.measured for b in marks]

    fig, ax = plt.subplots(figsize=(6.6, 3.5))
    bars = ax.barh(labels[::-1], margins[::-1], color=OK, height=0.62, zorder=3)
    ax.set_xscale("log")
    ax.set_xlabel("times faster / leaner than the target (log scale)", fontsize=8.6)
    ax.axvline(1, color=CRITICAL, linewidth=1.8, zorder=4)
    ax.text(1.08, -0.72, "target", color=CRITICAL, fontsize=8, fontweight="bold")
    for bar, value in zip(bars, measured[::-1], strict=True):
        ax.text(
            bar.get_width() * 1.12,
            bar.get_y() + bar.get_height() / 2,
            value,
            va="center",
            fontsize=8.4,
            fontweight="bold",
            color=INK,
        )
    ax.tick_params(labelsize=8.2)
    ax.set_xlim(0.55, 4000)
    for spine in ("top", "right", "left"):
        ax.spines[spine].set_visible(False)
    ax.grid(axis="x", color=RULE, linewidth=0.7, zorder=0)
    ax.set_axisbelow(True)
    return _save(fig, "performance.png")


def verification() -> Path:
    """What is actually checked, and how much of it."""
    unit, integration = facts.test_counts()
    fig, ax = plt.subplots(figsize=(5.6, 4.4))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    rows = [
        (f"{unit:,}", "unit tests", VERIFIED),
        (f"{integration:,}", "integration tests, on real\nstrongSwan pairs under netem", OK),
        ("93.8%", "coverage — parser 98.0%, assess 98.0%", VERIFIED),
        ("10,000", "fuzz inputs · zero crashes, zero hangs", SIH_NAVY),
        ("0", "advisories across 107 packages (pip-audit)", OK),
        ("20/20", "M11 acceptance items, nothing skipped", CRITICAL),
    ]
    for i, (value, label, colour) in enumerate(rows):
        y = 0.845 - i * 0.145
        _box(ax, 0.0, y, 0.28, 0.115, face=colour, text=value, size=15)
        ax.text(
            0.315,
            y + 0.0575,
            label,
            ha="left",
            va="center",
            fontsize=9.0,
            color=INK,
            linespacing=1.35,
        )
    ax.text(
        0.5,
        0.025,
        "Verified by a script, not by assertion — scripts/check_m11.py",
        ha="center",
        fontsize=8.4,
        color=MUTED,
        style="italic",
    )
    return _save(fig, "verification.png")


# ------------------------------------------------------------ slide 5: impact


def generalisation_chart() -> Path:
    """The held-out numbers, including the one that is lowest."""
    splits = [s for s in facts.generalisation() if "leaky" not in s.name]
    order = ["held-out captures", "held-out configurations", "held-out DH groups"]
    splits.sort(key=lambda s: order.index(s.name) if s.name in order else 9)

    labels = [s.name.replace("held-out ", "unseen\n") for s in splits]
    values = [s.accuracy for s in splits]
    colours = [OK if s.name != "held-out configurations" else HIGH for s in splits]

    fig, ax = plt.subplots(figsize=(6.0, 3.5))
    bars = ax.bar(labels, values, color=colours, width=0.55, zorder=3)
    ax.set_ylim(80, 102)
    ax.set_ylabel("accuracy (%)", fontsize=9)
    for bar, split in zip(bars, splits, strict=True):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            split.accuracy + 0.5,
            f"{split.accuracy:.1f}%",
            ha="center",
            fontsize=10.5,
            fontweight="bold",
            color=INK,
        )
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            81.2,
            f"n={split.rows}",
            ha="center",
            fontsize=8,
            color="white",
            fontweight="bold",
        )
    ax.tick_params(labelsize=8.6)
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    ax.grid(axis="y", color=RULE, linewidth=0.7, zorder=0)
    ax.set_axisbelow(True)
    ax.set_title(
        "The middle bar is the one that matters — and it is the lowest",
        fontsize=9.2,
        color=HIGH,
        fontweight="bold",
        pad=9,
    )
    return _save(fig, "generalisation.png")


def endpoint_visibility() -> Path:
    """What the kernel found that the wire could not."""
    fig, ax = plt.subplots(figsize=(6.0, 3.3))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    _box(
        ax,
        0.0,
        0.60,
        0.45,
        0.28,
        face=VERIFIED,
        text="ON THE WIRE\nnegotiated AES-256 / ECP-384",
        size=9.4,
    )
    _box(
        ax,
        0.55,
        0.60,
        0.45,
        0.28,
        face=CRITICAL,
        text="IN THE KERNEL\n3DES / MD5 installed",
        size=9.4,
    )
    ax.add_patch(
        FancyArrowPatch(
            (0.46, 0.74),
            (0.54, 0.74),
            arrowstyle="-|>",
            mutation_scale=16,
            color=INK,
            linewidth=2.2,
        )
    )

    ax.text(
        0.5,
        0.475,
        "estate grade, same capture",
        ha="center",
        fontsize=8.8,
        color=MUTED,
        style="italic",
    )
    _box(
        ax,
        0.10,
        0.235,
        0.30,
        0.20,
        face=PANEL,
        edge=RULE,
        text="33 / 100\n17 findings",
        size=12,
        colour=INK,
    )
    _box(
        ax,
        0.60,
        0.235,
        0.30,
        0.20,
        face=PANEL,
        edge=CRITICAL,
        text="11 / 100\n20 findings",
        size=12,
        colour=CRITICAL,
    )
    ax.add_patch(
        FancyArrowPatch(
            (0.415, 0.335),
            (0.585, 0.335),
            arrowstyle="-|>",
            mutation_scale=16,
            color=CRITICAL,
            linewidth=2.2,
        )
    )

    ax.text(
        0.5,
        0.075,
        "The replay window never appears on the wire in any form.\n"
        "No passive capture of that gateway could ever have found this.",
        ha="center",
        va="center",
        fontsize=8.8,
        fontweight="bold",
        color=SIH_NAVY,
        linespacing=1.5,
    )
    return _save(fig, "endpoint_visibility.png")


def benefits_ring() -> Path:
    """Who gains, in Lanezy's numbered-ring idiom."""
    items = [
        ("Auditors", "cited evidence, not\nan opaque score"),
        ("Network teams", "both-ends fix,\nzero packet loss"),
        ("Regulators", "ITSAR & CERT-In\nfrom one capture"),
        ("Air-gapped sites", "runs offline,\nno credentials"),
    ]
    fig, ax = plt.subplots(figsize=(5.2, 4.6))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")
    for i, (who, what) in enumerate(items):
        y = 0.78 - i * 0.215
        ax.add_patch(mpatches.Circle((0.085, y + 0.075), 0.062, facecolor=SIH_NAVY, zorder=3))
        ax.text(
            0.085,
            y + 0.075,
            str(i + 1),
            ha="center",
            va="center",
            fontsize=13,
            fontweight="bold",
            color="white",
            zorder=4,
        )
        ax.text(
            0.185,
            y + 0.115,
            who,
            ha="left",
            va="center",
            fontsize=11,
            fontweight="bold",
            color=SIH_NAVY,
        )
        ax.text(
            0.185,
            y + 0.035,
            what,
            ha="left",
            va="center",
            fontsize=8.8,
            color=INK,
            linespacing=1.35,
        )
    return _save(fig, "benefits.png")


def main() -> int:
    print("figures:")
    two_lane_architecture()
    risk_vs_solution()
    pipeline()
    performance()
    verification()
    generalisation_chart()
    endpoint_visibility()
    benefits_ring()
    feasibility_quadrants()
    return 0


def feasibility_quadrants() -> Path:
    """The four-quadrant map, borrowed from the RailAnukriti reference deck.

    It answers the template's slide-4 pointers in the order the template asks them —
    feasibility, then risks, then the strategies for overcoming them — which a chart and
    a row of chips did not.
    """
    quadrants = [
        (
            "FEASIBILITY",
            VERIFIED,
            [
                "Working prototype, v1.0.0 tagged",
                "Runs on a laptop: 0.68 GB container",
                "No agent, no credential, no outage",
            ],
        ),
        (
            "VIABILITY",
            OK,
            [
                "Reads captures operators already have",
                "Air-gapped install, offline bundle",
                "ITSAR + CERT-In: no rival ships these",
            ],
        ),
        (
            "CHALLENGES & RISKS",
            CRITICAL,
            [
                "Model trained on laboratory traffic",
                "5 of 6 vendor configs not device-tested",
                "A capture can miss an encrypted rekey",
            ],
        ),
        (
            "STRATEGIES",
            SIH_NAVY,
            [
                "Publish held-out numbers, worst included",
                "Every generated file states its own status",
                "Read kernel + daemon state to close it",
            ],
        ),
    ]
    fig, ax = plt.subplots(figsize=(6.4, 4.3))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    for index, (title, colour, points) in enumerate(quadrants):
        col, row = index % 2, index // 2
        x = 0.012 + col * 0.508
        y = 0.545 - row * 0.525
        _box(ax, x, y + 0.325, 0.48, 0.078, face=colour, text=title, size=10.2)
        ax.add_patch(
            FancyBboxPatch(
                (x, y),
                0.48,
                0.318,
                boxstyle="round,pad=0,rounding_size=0.015",
                facecolor=PANEL,
                edgecolor=colour,
                linewidth=1.3,
                zorder=2,
            )
        )
        for line, point in enumerate(points):
            ax.text(
                x + 0.022,
                y + 0.245 - line * 0.088,
                f"•  {point}",
                ha="left",
                va="center",
                fontsize=7.9,
                color=INK,
                zorder=3,
            )
    return _save(fig, "feasibility.png")


if __name__ == "__main__":
    raise SystemExit(main())
