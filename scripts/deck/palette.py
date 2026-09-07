"""The deck's palette, taken from the product's own stylesheet and the SIH template.

Nothing here is invented: the severity colours are the ones `dashboard/style.css`
already uses for findings, so a CRITICAL chip on a slide is the same red a judge sees
in the dashboard. The two blues are lifted from the official template.
"""

from typing import Final

# From the SIH2026 template itself.
SIH_NAVY: Final = "#1F497D"
SIH_BLUE: Final = "#0070C0"
SIH_PURPLE: Final = "#8064A2"

# From dashboard/style.css — the product's own severity scale.
INK: Final = "#17202A"
MUTED: Final = "#5B6A7A"
RULE: Final = "#D6DDE5"
PANEL: Final = "#F4F7FA"
VERIFIED: Final = "#1C4F82"
INFERRED: Final = "#7A4A12"
CRITICAL: Final = "#8C1C13"
HIGH: Final = "#B8500F"
MEDIUM: Final = "#8A6D1A"
LOW: Final = "#4A5A68"
OK: Final = "#1D6B3F"

PROBLEM: Final = CRITICAL
SOLUTION: Final = OK
