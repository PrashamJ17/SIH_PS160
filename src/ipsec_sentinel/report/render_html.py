"""Render a report as one self-contained HTML file.

Three requirements shape this module, and each is enforced by a test rather than by
intention.

**Self-contained.** The output loads nothing. No CDN, no external stylesheet, no font,
no script. An assessment is often run on a network with no route to the internet, and a
report whose layout collapses because a stylesheet timed out is not a report. Even the
CVE references are rendered as visible text rather than links: an anchor nobody can
follow is worth less than a URL a reader can copy, and on paper an ``href`` is invisible
anyway.

**Escaped.** Autoescaping is on, and this is a security control rather than a nicety.
Much of what the report prints was read off the wire — vendor ID strings, negotiated
algorithm names, endpoint addresses — and all of it is attacker-controlled. A crafted
IKE vendor ID containing markup would otherwise execute in the browser of whoever opened
the report, which is a fair description of the worst possible outcome for a security
tool. A test crafts exactly that payload.

**Distinguishable.** Section A and Section B are told apart by a heading, a label on
every finding, and an explanatory note — not by colour alone. A reader who prints the
report in greyscale, or who cannot distinguish the two colours, still has to be able to
tell compliance evidence from an estimate.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ipsec_sentinel.models import Severity
from ipsec_sentinel.report.models import Report

TEMPLATE_DIR: Final = Path(__file__).resolve().parent / "templates"
TEMPLATE_NAME: Final = "report.html.j2"

SEVERITY_LABELS: Final[dict[Severity, str]] = {
    Severity.CRITICAL: "Critical",
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
    Severity.INFO: "Informational",
}


def _environment() -> Environment:
    return Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        # Autoescape by extension would miss ``.j2``; naming the extensions explicitly
        # keeps it on for this template. Escaping is the security control here, so it
        # is not left to a default that a later rename could switch off.
        autoescape=select_autoescape(
            enabled_extensions=("html", "j2", "html.j2"),
            default_for_string=True,
            default=True,
        ),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def severity_label(severity: Severity) -> str:
    return SEVERITY_LABELS.get(severity, severity.value)


def human_bytes(count: int) -> str:
    """Bytes in units a reader thinks in. Decimal, because network people count that way."""
    value = float(count)
    for unit in ("B", "kB", "MB", "GB"):
        if value < 1000 or unit == "GB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1000
    return f"{value:.1f} GB"


def hours_summary(hours: list[int]) -> str:
    """Active hours as a phrase, or a plain statement that none were seen."""
    if not hours:
        return "no traffic observed"
    return ", ".join(f"{hour:02d}:00" for hour in hours)


def render_html(report: Report) -> str:
    """Render the report to a complete, standalone HTML document."""
    environment = _environment()
    environment.filters["severity_label"] = severity_label
    environment.filters["human_bytes"] = human_bytes
    environment.filters["hours_summary"] = hours_summary
    return environment.get_template(TEMPLATE_NAME).render(report=report)


def write_html(report: Report, destination: Path) -> Path:
    """Write the rendered report and return the path written."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_html(report), encoding="utf-8")
    return destination
