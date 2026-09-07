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

from ipsec_sentinel.assess.baselines.schema import (
    Baseline,
    BaselineError,
    get_baseline,
    load_baselines,
)
from ipsec_sentinel.logging import get_logger
from ipsec_sentinel.models import Finding, Severity, sort_findings
from ipsec_sentinel.parser.correlate import Tunnel

logger = get_logger(__name__)

# The baseline every rule belongs to unless it is explicitly narrowed. A rule with no
# baseline would silently never run, which is the most expensive kind of dead code in
# a security tool: it looks like coverage and is not.
DEFAULT_BASELINE = "default"

# Tags written on the rules themselves, as opposed to the id of a published
# compliance baseline loaded from YAML. Conflating the two namespaces is what made
# `select("nist_800_77r1")` return no rules at all.
BUILTIN_TAGS: frozenset[str] = frozenset({"default", "strict"})


class UnknownBaselineError(ValueError):
    """A baseline was named that is neither a rule tag nor a published baseline."""


@runtime_checkable
class Rule(Protocol):
    """One deterministic check against a tunnel.

    Every member is declared read-only. Rules are frozen dataclasses by design — a
    rule that could be mutated after registration would let one tunnel's evaluation
    change what every later tunnel is checked against — and a protocol declaring bare
    annotations would demand settable attributes that a frozen dataclass cannot
    provide.
    """

    @property
    def id(self) -> str: ...

    @property
    def title(self) -> str: ...

    @property
    def severity(self) -> Severity: ...

    @property
    def standard_ref(self) -> str: ...

    @property
    def remediation_hint(self) -> str: ...

    """Every rule carries one: a Finding cannot be built without it.

    It was absent from this protocol until the ESP path needed to build a Finding from a
    rule it held only as a ``Rule``, which is a good argument for the protocol having
    been incomplete rather than for that path being unusual.
    """

    @property
    def attack_technique(self) -> str | None: ...

    @property
    def baselines(self) -> list[str]: ...

    def evaluate(self, tunnel: Tunnel) -> Finding | None: ...


@runtime_checkable
class BaselineAware(Protocol):
    """A rule whose thresholds come from the baseline rather than from itself.

    "Key shorter than the minimum" is not one check, it is one check per authority:
    CNSA wants 256 bits and NIST wants 128, and writing two rules for that would mean
    two rule IDs, two findings and two remediation lines for one problem. Binding lets
    a single rule carry the policy it is being run under.
    """

    @property
    def id(self) -> str: ...

    def bind(self, baseline: Baseline) -> Rule: ...


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
        """Rules carrying this **tag**. See :meth:`resolve` for the name/tag distinction."""
        return [rule for rule in self.rules if baseline in rule.baselines]

    def resolve(self, baseline: str) -> str | Baseline:
        """Turn a name into the thing that actually selects rules.

        Two different namespaces meet here and used to be conflated. ``default`` and
        ``strict`` are **tags** written on the rules themselves. Everything else is the
        **id of a published compliance baseline**, which selects rules by listing their
        IDs and is loaded from a YAML file.

        Before this existed, a string went straight to tag matching — so
        ``select("nist_800_77r1")`` matched no rule's tag list, returned an **empty rule
        set**, and every capture came back with no findings and a grade of A. A security
        tool that reports a clean bill of health because it ran nothing is the worst
        output it can produce, and nothing about it looks wrong.

        An unrecognised name now raises instead of quietly selecting nothing.
        """
        # A tag any registered rule actually carries is a tag. Only a name that matches
        # nothing at all is an error — which is precisely the case that used to return
        # an empty rule set and a clean bill of health.
        if baseline in BUILTIN_TAGS or baseline in self.baselines():
            return baseline
        try:
            return get_baseline(baseline)
        except BaselineError as exc:
            known = ", ".join(sorted([*BUILTIN_TAGS, *self.baselines(), *load_baselines()]))
            raise UnknownBaselineError(
                f"no baseline {baseline!r}. Known baselines: {known}. "
                f"Refusing to run rather than assess against an empty rule set."
            ) from exc

    def select(self, baseline: str | Baseline) -> list[Rule]:
        """The rules a baseline runs, bound to its thresholds.

        A compliance baseline selects rules by ID, so it is authoritative over the
        rule's own ``baselines`` list — a policy document that names a rule runs it,
        whether or not the rule expected to belong to that policy.
        """
        if isinstance(baseline, str):
            resolved = self.resolve(baseline)
            if isinstance(resolved, str):
                return self.for_baseline(resolved)
            baseline = resolved
        selected = [rule for rule in self.rules if baseline.includes(rule.id)]
        return [
            rule.bind(baseline) if isinstance(rule, BaselineAware) else rule for rule in selected
        ]

    def run(self, tunnel: Tunnel, baseline: str | Baseline = DEFAULT_BASELINE) -> RuleOutcome:
        """Evaluate every rule in the baseline, surviving any that fail.

        A rule that raises is logged and recorded; the remaining rules still run. A
        rule that returns a finding carrying a confidence is rejected the same way,
        because it has crossed the parse/infer boundary this framework exists to keep.

        A compliance baseline's severity overrides are applied to the findings. The
        override changes how urgent *this authority* considers a finding; it never
        changes whether the finding is true, which is why it is applied after evaluation
        rather than handed to the rule.

        The name is resolved **once**, here, and the resolved object is used for both
        rule selection and the overrides. Resolving separately is how a named baseline
        came to select the right rules and then silently skip its own severity
        overrides.
        """
        if isinstance(baseline, str):
            baseline = self.resolve(baseline)
        outcome = RuleOutcome()
        for rule in self.select(baseline):
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
            if not isinstance(baseline, str):
                override = baseline.severity_overrides.get(rule.id)
                if override is not None and override != finding.severity:
                    finding = finding.model_copy(update={"severity": override})
            outcome.findings.append(finding)

        outcome.findings = sort_findings(outcome.findings)
        return outcome

    def evaluate_all(
        self, tunnel: Tunnel, baseline: str | Baseline = DEFAULT_BASELINE
    ) -> list[Finding]:
        """The findings alone, for callers that do not need the error detail."""
        return self.run(tunnel, baseline).findings
