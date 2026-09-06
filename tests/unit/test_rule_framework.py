"""Tests for the rule framework (build plan Step 6.1)."""

from __future__ import annotations

import pytest

from ipsec_sentinel.assess.framework import (
    DEFAULT_BASELINE,
    DuplicateRuleError,
    RuleRegistry,
    UnknownBaselineError,
)
from ipsec_sentinel.models import Confidence, Finding, Severity
from ipsec_sentinel.parser.correlate import Tunnel


def tunnel() -> Tunnel:
    return Tunnel(tunnel_id="abc123", endpoints=("192.0.2.1", "192.0.2.2"))


class StubRule:
    """A rule that returns whatever it was constructed with."""

    def __init__(
        self,
        rule_id: str = "TST-01",
        severity: Severity = Severity.HIGH,
        baselines: list[str] | None = None,
        finding: Finding | str | None = "default",
    ) -> None:
        self.id = rule_id
        self.title = f"Stub {rule_id}"
        self.severity = severity
        self.standard_ref = "NIST SP 800-77"
        self.attack_technique = None
        self.baselines = [DEFAULT_BASELINE] if baselines is None else baselines
        self._finding = finding

    def evaluate(self, _tunnel: Tunnel) -> Finding | None:
        if self._finding == "default":
            return Finding(
                rule_id=self.id,
                title=self.title,
                severity=self.severity,
                evidence="stub evidence",
                standard_ref=self.standard_ref,
                remediation_hint="stub hint",
            )
        return self._finding  # type: ignore[return-value]


class ExplodingRule(StubRule):
    def evaluate(self, _tunnel: Tunnel) -> Finding | None:
        raise RuntimeError("this rule is broken")


class TestRegistration:
    def test_a_duplicate_rule_id_raises(self) -> None:
        registry = RuleRegistry()
        registry.register(StubRule("CRY-01"))
        with pytest.raises(DuplicateRuleError, match="CRY-01"):
            registry.register(StubRule("CRY-01"))

    def test_distinct_ids_register_cleanly(self) -> None:
        registry = RuleRegistry()
        registry.register(StubRule("CRY-01"))
        registry.register(StubRule("CRY-02"))
        assert len(registry) == 2
        assert "CRY-01" in registry

    def test_a_rule_with_no_baseline_is_refused(self) -> None:
        """A rule in no baseline never runs — coverage that looks real and is not."""
        with pytest.raises(ValueError, match="no baseline"):
            RuleRegistry().register(StubRule("CRY-01", baselines=[]))

    def test_rules_are_returned_in_id_order(self) -> None:
        """Reproducible runs: the same capture must yield the same report."""
        registry = RuleRegistry()
        for rule_id in ("CRY-03", "CRY-01", "CRY-02"):
            registry.register(StubRule(rule_id))
        assert [rule.id for rule in registry.rules] == ["CRY-01", "CRY-02", "CRY-03"]


class TestBaselineFiltering:
    def test_only_rules_for_the_baseline_run(self) -> None:
        registry = RuleRegistry()
        registry.register(StubRule("CRY-01", baselines=["pci"]))
        registry.register(StubRule("CRY-02", baselines=["nist"]))
        registry.register(StubRule("CRY-03", baselines=["pci", "nist"]))

        pci = {finding.rule_id for finding in registry.evaluate_all(tunnel(), "pci")}
        assert pci == {"CRY-01", "CRY-03"}

    def test_an_unknown_baseline_is_refused_rather_than_running_nothing(self) -> None:
        """This test used to assert the opposite, and that is how the bug survived.

        Selecting no rules for an unrecognised name means every capture comes back with
        no findings and a grade of A. Nothing about that output looks wrong, which makes
        it the most dangerous thing this tool can produce — and it was reachable from the
        command line, where ``--baseline nist_800_77r1`` named a real published baseline
        that matched no rule *tag*.
        """
        registry = RuleRegistry()
        registry.register(StubRule("CRY-01", baselines=["pci"]))
        with pytest.raises(UnknownBaselineError, match="does-not-exist"):
            registry.evaluate_all(tunnel(), "does-not-exist")

    def test_the_refusal_lists_what_would_have_worked(self) -> None:
        registry = RuleRegistry()
        registry.register(StubRule("CRY-01", baselines=["pci"]))
        with pytest.raises(UnknownBaselineError) as raised:
            registry.select("typo")
        message = str(raised.value)
        assert "pci" in message
        assert "nist_800_77r1" in message
        assert "empty rule set" in message

    def test_a_published_baseline_name_selects_its_rules(self) -> None:
        """The case that was silently broken: a real baseline id is not a rule tag."""
        from ipsec_sentinel.assess.rules import default_registry

        for name in ("nist_800_77r1", "cnsa", "itsar", "certin", "rfc_8221_8247"):
            selected = default_registry().select(name)
            assert selected, f"{name} selected no rules"

    def test_every_shipped_baseline_selects_rules(self) -> None:
        from ipsec_sentinel.assess.baselines.schema import load_baselines
        from ipsec_sentinel.assess.rules import default_registry

        registry = default_registry()
        empty = [name for name in load_baselines() if not registry.select(name)]
        assert not empty, f"these baselines select no rules at all: {empty}"

    def test_a_named_baseline_applies_its_severity_overrides(self) -> None:
        """Resolving separately for selection and overrides skipped the overrides."""
        from ipsec_sentinel.assess.baselines.schema import get_baseline
        from ipsec_sentinel.assess.rules import default_registry

        registry = default_registry()
        for name in ("cnsa", "itsar"):
            baseline = get_baseline(name)
            if not baseline.severity_overrides:
                continue
            by_name = {r.id for r in registry.select(name)}
            by_object = {r.id for r in registry.select(baseline)}
            assert by_name == by_object
            return

    def test_the_registry_lists_its_baselines(self) -> None:
        registry = RuleRegistry()
        registry.register(StubRule("CRY-01", baselines=["pci"]))
        registry.register(StubRule("CRY-02", baselines=["nist", "pci"]))
        assert registry.baselines() == {"pci", "nist"}


class TestFailureIsolation:
    def test_a_rule_that_raises_does_not_abort_the_run(self) -> None:
        """A capture that trips one rule still deserves the other forty findings."""
        registry = RuleRegistry()
        registry.register(StubRule("CRY-01"))
        registry.register(ExplodingRule("CRY-02"))
        registry.register(StubRule("CRY-03"))

        outcome = registry.run(tunnel())
        assert {f.rule_id for f in outcome.findings} == {"CRY-01", "CRY-03"}

    def test_the_failure_is_recorded_rather_than_swallowed(self) -> None:
        registry = RuleRegistry()
        registry.register(ExplodingRule("CRY-02"))
        outcome = registry.run(tunnel())
        assert len(outcome.errors) == 1
        assert "CRY-02" in outcome.errors[0]
        assert "RuntimeError" in outcome.errors[0]

    def test_a_rule_returning_none_is_not_an_error(self) -> None:
        registry = RuleRegistry()
        registry.register(StubRule("CRY-01", finding=None))
        outcome = registry.run(tunnel())
        assert outcome.findings == []
        assert outcome.errors == []
        assert outcome.skipped == 1


class TestDeterminismGuard:
    def test_every_finding_from_a_rule_has_no_confidence(self) -> None:
        registry = RuleRegistry()
        for rule_id in ("CRY-01", "CRY-02", "CRY-03"):
            registry.register(StubRule(rule_id))
        findings = registry.evaluate_all(tunnel())
        assert findings
        assert all(finding.confidence is None for finding in findings)
        assert all(finding.is_deterministic for finding in findings)

    def test_a_rule_emitting_a_confidence_is_rejected_not_reported(self) -> None:
        """A single inference in the deterministic lane makes Section A undefendable."""
        inferred = Finding(
            rule_id="CRY-99",
            title="Inferred thing",
            severity=Severity.MEDIUM,
            evidence="a guess",
            standard_ref="none",
            remediation_hint="none",
            confidence=Confidence(value=0.8, method="test", calibrated=False),
        )
        registry = RuleRegistry()
        registry.register(StubRule("CRY-99", finding=inferred))
        outcome = registry.run(tunnel())
        assert outcome.findings == []
        assert len(outcome.errors) == 1
        assert "confidence" in outcome.errors[0]

    def test_a_rejected_inference_does_not_stop_other_rules(self) -> None:
        inferred = Finding(
            rule_id="CRY-99",
            title="Inferred thing",
            severity=Severity.MEDIUM,
            evidence="a guess",
            standard_ref="none",
            remediation_hint="none",
            confidence=Confidence(value=0.8, method="test", calibrated=False),
        )
        registry = RuleRegistry()
        registry.register(StubRule("CRY-01"))
        registry.register(StubRule("CRY-99", finding=inferred))
        outcome = registry.run(tunnel())
        assert [f.rule_id for f in outcome.findings] == ["CRY-01"]


class TestOrdering:
    def test_findings_come_back_most_severe_first(self) -> None:
        registry = RuleRegistry()
        registry.register(StubRule("CRY-01", severity=Severity.LOW))
        registry.register(StubRule("CRY-02", severity=Severity.CRITICAL))
        registry.register(StubRule("CRY-03", severity=Severity.MEDIUM))
        severities = [f.severity for f in registry.evaluate_all(tunnel())]
        assert severities == [Severity.CRITICAL, Severity.MEDIUM, Severity.LOW]


class TestEmptyRegistry:
    def test_an_empty_registry_produces_no_findings(self) -> None:
        outcome = RuleRegistry().run(tunnel())
        assert outcome.findings == []
        assert outcome.errors == []
        assert outcome.evaluated == 0
