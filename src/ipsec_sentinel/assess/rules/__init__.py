"""The complete rule set, in one place.

Assembled here rather than in each caller because the alternative — every consumer
building its own list — is how a rule ends up implemented, tested in isolation, and
never actually run. :func:`default_registry` is the single answer to "what does this
tool check", and the baseline validation tests assert that every rule in it is claimed
by at least one baseline.
"""

from __future__ import annotations

from ipsec_sentinel.assess.framework import Rule, RuleRegistry
from ipsec_sentinel.assess.rules.coverage import COVERAGE_RULES
from ipsec_sentinel.assess.rules.crypto import CRYPTO_RULES
from ipsec_sentinel.assess.rules.ike import IKE_RULES
from ipsec_sentinel.assess.rules.pqc import PQC_RULES
from ipsec_sentinel.assess.rules.sa import SA_RULES

ALL_RULES: list[Rule] = [
    *CRYPTO_RULES,
    *IKE_RULES,
    *SA_RULES,
    *PQC_RULES,
    *COVERAGE_RULES,
]

ALL_RULE_IDS: frozenset[str] = frozenset(rule.id for rule in ALL_RULES)


def default_registry() -> RuleRegistry:
    """A registry holding every implemented rule.

    A fresh instance each call: a registry is mutable, and a shared one would let a
    caller that registers a custom rule change what every other caller checks.
    """
    registry = RuleRegistry()
    for rule in ALL_RULES:
        registry.register(rule)
    return registry


__all__ = ["ALL_RULES", "ALL_RULE_IDS", "default_registry"]
