"""The rule framework: how a parsed fact becomes a finding.

Every rule in this system is deterministic. A rule reads fields the parser took from
the cleartext IKE handshake — a transform ID, a key length, an exchange type — and
either produces a :class:`~ipsec_sentinel.models.Finding` or does not. There is no
scoring, no threshold, no model. That is why every finding a rule emits carries
``confidence=None``, and why the registry refuses to register a rule that would emit
anything else.

This is not a stylistic preference. The whole architecture rests on a reader being able
to look at a finding and know, without checking anything, whether it was read or
guessed. Section A of a report holds findings with no confidence and can be defended
line by line against the capture; Section B holds inferences with calibrated
confidences and is honest about being probabilistic. A single inferred finding leaking
into the deterministic lane would make Section A undefendable, so the guard is enforced
here at the boundary rather than trusted to rule authors.

**A rule that raises must not take the run with it.** A capture that triggers a bug in
one rule still deserves the other forty findings — an analyst with a partial report and
a logged error is far better off than one with a stack trace. Rule failures are caught,
logged with the rule ID, and recorded on the result.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from ipsec_sentinel.logging import get_logger
from ipsec_sentinel.models import Finding, sort_findings
from ipsec_sentinel.parser.correlate import Tunnel

logger = get_logger(__name__)

# The baseline every rule belongs to unless it is explicitly narrowed. A rule with no
# baseline would silently never run, which is the most expensive kind of dead code in
# a security tool: it looks like coverage and is not.
DEFAULT_BASELINE = "default"


@runtime_checkable
class Rule(Protocol):
    """One deterministic check against a tunnel."""

    id: str
    title: str
    severity: object
    standard_ref: str
    attack_technique: str | None
    baselines: list[str]

    def evaluate(self, tunnel: Tunnel) -> Finding | None: ...


class DuplicateRuleError(ValueError):
    """Two rules claim the same ID.

    Fatal at registration rather than tolerated, because rule IDs appear in reports,
    in remediation output and in an auditor's notes. Two rules answering to CRY-03
    would make a finding untraceable to the check that produced it.
    """


class InferredFindingError(ValueError):
    """A deterministic rule emitted a finding carrying a confidence."""


@dataclass
class RuleOutcome:
    """What a rule run produced, including what went wrong.

    Errors are part of the result rather than an exception, so a caller always gets
    the findings that did succeed.
    """

    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    evaluated: int = 0
    skipped: int = 0


class RuleRegistry:
    """Holds the rule set and runs it, in a defined order, without ever aborting."""

    def __init__(self) -> None:
        self._rules: dict[str, Rule] = {}

    def register(self, rule: Rule) -> None:
        """Add a rule, refusing duplicates and rules with no baseline."""
        if rule.id in self._rules:
            raise DuplicateRuleError(
                f"rule ID {rule.id!r} is already registered by "
                f"{type(self._rules[rule.id]).__name__}; IDs appear in reports and in "
                f"remediation output, so two rules answering to one ID would make a "
                f"finding untraceable to the check that produced it"
            )
        if not rule.baselines:
            raise ValueError(
                f"rule {rule.id!r} belongs to no baseline, so it would never run. "
                f"Use [{DEFAULT_BASELINE!r}] if it should always apply."
            )
        self._rules[rule.id] = rule

    def __len__(self) -> int:
        return len(self._rules)

    def __contains__(self, rule_id: object) -> bool:
        return rule_id in self._rules

    @property
    def rules(self) -> list[Rule]:
        """Every registered rule, ordered by ID so runs are reproducible."""
        return [self._rules[key] for key in sorted(self._rules)]

    def baselines(self) -> set[str]:
        return {baseline for rule in self.rules for baseline in rule.baselines}

    def for_baseline(self, baseline: str) -> list[Rule]:
        return [rule for rule in self.rules if baseline in rule.baselines]

    def run(self, tunnel: Tunnel, baseline: str = DEFAULT_BASELINE) -> RuleOutcome:
        """Evaluate every rule in the baseline, surviving any that fail.

        A rule that raises is logged and recorded; the remaining rules still run. A
        rule that returns a finding carrying a confidence is rejected the same way,
        because it has crossed the parse/infer boundary this framework exists to keep.
        """
        outcome = RuleOutcome()
        for rule in self.for_baseline(baseline):
            try:
                finding = rule.evaluate(tunnel)
            except Exception as exc:
                message = f"rule {rule.id} raised {type(exc).__name__}: {exc}"
                logger.error(
                    "rule_failed",
                    extra={
                        "rule_id": rule.id,
                        "error": str(exc),
                        "tunnel": tunnel.tunnel_id,
                    },
                )
                outcome.errors.append(message)
                continue

            outcome.evaluated += 1
            if finding is None:
                outcome.skipped += 1
                continue
            if finding.confidence is not None:
                message = (
                    f"rule {rule.id} returned a finding with a confidence; rules are "
                    f"deterministic by construction and their findings must carry "
                    f"confidence=None, or Section A of the report becomes undefendable"
                )
                logger.error("rule_emitted_inference", extra={"rule_id": rule.id})
                outcome.errors.append(message)
                continue
            outcome.findings.append(finding)

        outcome.findings = sort_findings(outcome.findings)
        return outcome

    def evaluate_all(self, tunnel: Tunnel, baseline: str = DEFAULT_BASELINE) -> list[Finding]:
        """The findings alone, for callers that do not need the error detail."""
        return self.run(tunnel, baseline).findings
