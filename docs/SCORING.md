# Scoring and grading

## What the score is for

A score compresses a finding list into one number, and every compression loses
something. This one is built to preserve **triage order**: an operator with forty
tunnels and one afternoon needs to know which three to open first.

It is deliberately **not** a measure of risk. Risk depends on what a tunnel carries,
who depends on it, and what an attacker would gain — none of which is visible in a
packet capture. A tool that produced a "risk score" from a handshake would be
inventing the most important input.

## The weights

| Severity | Weight |
|---|---|
| Critical | 40 |
| High | 20 |
| Medium | 8 |
| Low | 3 |
| Informational | 0 |

Score starts at 100, each finding subtracts its weight, the result floors at 0.

## Why 40 for Critical, and not 50 or 30

This is the question a panel asks, so it has an answer.

**Not 50.** One critical would score 50 and two would score 0. That collapses the
entire bottom half of the scale into a single step, destroying the distinction between
*"this tunnel has one serious problem"* and *"this tunnel is systemically broken"* —
which is precisely the distinction triage depends on.

**Not 30.** Three criticals would leave a score of 10. A tunnel offering DES, 3DES and
1024-bit MODP should be indistinguishable from the worst configuration possible.
Leaving it a residual score implies headroom that does not exist.

**40.** One critical lands on 60 — failing, but visibly recoverable. Two land on 20.
Three floor at 0. The scale degrades in three visible steps, which is how an operator
actually sorts work.

## Why the levels are ~2.5x apart

40 : 20 : 8 : 3 is roughly 2.5x per level. That makes accumulation meaningful rather
than decorative — **five High findings (100) outweigh one Critical (40)**.

That is intended. A tunnel with five serious weaknesses is in worse shape than one with
a single critical weakness, and a scheme that hid that would sort the estate wrongly.

## Why Informational is zero

Informational findings appear in the report because they are **true**, not because they
cost anything. Giving them weight would let a tunnel accumulate a failing grade from
observations nobody needs to act on, which trains operators to ignore the score.

## Grades

| Grade | Score |
|---|---|
| A | 90–100 |
| B | 80–89 |
| C | 70–79 |
| D | 60–69 |
| F | 0–59 |

The bands are chosen so a single Critical (60) lands on D: failing, but distinguishable
from a tunnel carrying several.

## Estate scoring

The estate score is the mean of tunnel scores, weighted by tunnel criticality when the
operator supplies it. Criticality is a judgement about what a tunnel carries — not
observable from a capture — so an unsupplied weight defaults to 1.0 rather than to a
guess.

**The mean alone is misleading, and dangerously so.** Forty healthy tunnels and one
catastrophic one average to a comfortable number, and the tunnel that matters
disappears. `EstateScore` therefore carries the grade distribution, the worst score and
the tunnel that holds it, so a caller cannot report the average without also having the
shape.

## What the score inherits

Scores are computed from **deterministic findings only** — every one read from a
documented field at a known offset. The score is therefore reproducible across runs,
auditable, and defensible line by line against the capture that produced it.

Inferred findings, which carry calibrated confidences, never reach the score. Mixing
them in would make a single number that is part measurement and part estimate, and no
reader could tell which parts.
