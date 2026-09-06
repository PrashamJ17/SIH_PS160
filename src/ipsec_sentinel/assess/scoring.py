"""Scoring and grading.

A score is a compression of a finding list into one number, and every compression
loses something. What this one is built to preserve is **triage order**: an operator
with forty tunnels and one afternoon needs to know which three to open first, and the
score exists to answer that and nothing else. It is not a measure of risk, because risk
depends on what the tunnel carries, and this tool cannot see inside it.

Weights are 40 / 20 / 8 / 3 / 0, and the specific value of 40 is a deliberate choice
worth defending:

* **Why not 50?** One critical would score 50 and two would score 0. That collapses the
  entire bottom half of the scale into a single step and destroys the distinction
  between "this tunnel has one serious problem" and "this tunnel is systemically
  broken" — which is exactly the distinction an operator triaging an estate needs.
* **Why not 30?** Three criticals would score 10. A tunnel offering DES, 3DES and
  1024-bit MODP should be indistinguishable from the worst configuration possible;
  leaving it a residual score implies a headroom that does not exist.
* **Why 40?** One critical lands on 60 — failing, but visibly recoverable. Two land on
  20 and three floor at 0. The scale degrades in three visible steps, which matches how
  an operator actually sorts work.

Each level is roughly 2.5x the next, so accumulation is meaningful rather than
decorative: five High findings (100) outweigh one Critical (40). That is intended. A
tunnel with five serious weaknesses is in worse shape than one with a single critical
one, and a scoring scheme that hid that would sort the estate wrongly.

Informational findings are weighted zero. They appear in the report because they are
true, not because they cost anything.

**The score is derived from deterministic findings only**, and it inherits their
character: it is reproducible, auditable, and defensible line by line against the
capture. Inferred findings never reach it.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Final

from ipsec_sentinel.models import Finding, Severity, TunnelAssessment

SEVERITY_WEIGHTS: Final[dict[Severity, int]] = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 20,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 0,
}

MAXIMUM_SCORE: Final = 100
MINIMUM_SCORE: Final = 0

# Grade thresholds, inclusive lower bounds. Chosen so that one Critical (score 60)
# lands on D: failing, but distinguishable from a tunnel with several.
GRADE_THRESHOLDS: Final[tuple[tuple[int, str], ...]] = (
    (90, "A"),
    (80, "B"),
    (70, "C"),
    (60, "D"),
    (0, "F"),
)


def grade_for(score: int) -> str:
    """Map a score to its letter grade."""
    for threshold, letter in GRADE_THRESHOLDS:
        if score >= threshold:
            return letter
    return "F"  # pragma: no cover - the final threshold is 0, so this is unreachable


def penalty_for(findings: list[Finding]) -> int:
    """Total weight of a finding list, before flooring."""
    return sum(SEVERITY_WEIGHTS.get(finding.severity, 0) for finding in findings)


def score_tunnel(findings: list[Finding]) -> tuple[int, str]:
    """Score one tunnel from its findings, and grade it.

    Starts at 100, subtracts each finding's weight, floors at 0. Monotonic by
    construction: adding a finding can only subtract, so a score can never improve
    because the tool looked harder.
    """
    score = max(MINIMUM_SCORE, MAXIMUM_SCORE - penalty_for(findings))
    return score, grade_for(score)


@dataclass
class EstateScore:
    """The estate rolled up, with the distribution kept alongside the average.

    The average alone is misleading and dangerously so: forty healthy tunnels and one
    catastrophic one average to a comfortable number, and the one that matters
    disappears. ``worst_tunnel_id`` and ``distribution`` are carried so a caller cannot
    report the mean without also having the shape.
    """

    score: int
    grade: str
    tunnel_count: int
    distribution: dict[str, int] = field(default_factory=dict)
    worst_score: int | None = None
    worst_tunnel_id: str | None = None
    best_score: int | None = None
    weighted: bool = False

    @property
    def failing_count(self) -> int:
        return self.distribution.get("D", 0) + self.distribution.get("F", 0)


def score_estate(
    tunnels: list[TunnelAssessment],
    criticality: dict[str, float] | None = None,
) -> EstateScore:
    """Roll individual tunnel scores into an estate score.

    Weighted by tunnel criticality when supplied, otherwise a plain mean. Criticality
    is the operator's judgement of what a tunnel carries — something this tool cannot
    observe and must not invent — so an unsupplied weight defaults to 1.0 rather than
    to a guess.

    A non-positive total weight falls back to the unweighted mean instead of dividing
    by zero: a caller who marks every tunnel as weight 0 has expressed no preference,
    not a request for an undefined answer.
    """
    if not tunnels:
        return EstateScore(score=MAXIMUM_SCORE, grade=grade_for(MAXIMUM_SCORE), tunnel_count=0)

    distribution = Counter(tunnel.grade for tunnel in tunnels)
    worst = min(tunnels, key=lambda t: t.score)
    best = max(tunnels, key=lambda t: t.score)

    weighted = False
    if criticality:
        weights = [max(0.0, criticality.get(t.tunnel_id, 1.0)) for t in tunnels]
        total_weight = sum(weights)
        if total_weight > 0:
            weighted = True
            mean = sum(t.score * w for t, w in zip(tunnels, weights, strict=True)) / total_weight
        else:
            mean = sum(t.score for t in tunnels) / len(tunnels)
    else:
        mean = sum(t.score for t in tunnels) / len(tunnels)

    score = max(MINIMUM_SCORE, min(MAXIMUM_SCORE, round(mean)))
    return EstateScore(
        score=score,
        grade=grade_for(score),
        tunnel_count=len(tunnels),
        distribution=dict(distribution),
        worst_score=worst.score,
        worst_tunnel_id=worst.tunnel_id,
        best_score=best.score,
        weighted=weighted,
    )
