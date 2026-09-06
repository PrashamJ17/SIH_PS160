"""The compliance baseline model and loader.

A baseline is a policy document expressed as data: which rules apply, how severe this
authority considers each one, and what thresholds it demands. Keeping them as YAML
rather than code matters for the audience — an auditor can read
``cnsa.yaml`` and check it against the published suite without reading Python, and an
operator can add a house baseline without touching the tool.

**Two of these baselines are interpretations, and the file says so.** ITSAR and CERT-In
are Indian regulatory documents that this project encoded from public description
rather than from a verified copy of the controlling text. Every baseline therefore
carries a ``verified`` flag and a ``provenance`` note, and the reporting layer is
expected to surface them. A compliance claim traceable to an unverified reading is
still useful; one that hides that it is unverified is not.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from ipsec_sentinel.models import Severity

BASELINE_DIR = Path(__file__).parent


class BaselineError(ValueError):
    """A baseline file is missing, malformed, or references something that does not exist."""


class Minimums(BaseModel):
    """Thresholds this authority requires.

    Every field is optional and ``None`` means "this authority does not specify it",
    which is different from zero. A rule bound to an unspecified threshold keeps its
    own default rather than inheriting a silent zero, because a baseline that happens
    to omit a field must not accidentally disable the check.
    """

    model_config = ConfigDict(extra="forbid")

    encryption_key_bits: int | None = Field(default=None, ge=0)
    dh_security_bits: int | None = Field(default=None, ge=0)
    """Required Diffie-Hellman **security strength** in bits, not parameter size.

    Named for the scale it uses because the two are routinely confused: 2048-bit MODP
    is 112-bit strength and 256-bit ECP is 128-bit, so a field called "dh_group_bits"
    invites a comparison that reports the stronger group as the weaker one.
    """
    ike_lifetime_seconds: int | None = Field(default=None, ge=0)
    child_lifetime_seconds: int | None = Field(default=None, ge=0)
    replay_window: int | None = Field(default=None, ge=0)
    require_pfs: bool | None = None
    require_post_quantum: bool | None = None


class Baseline(BaseModel):
    """One compliance baseline: rule selection, severity overrides, thresholds."""

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    authority: str
    reference: str
    description: str
    verified: bool
    """Whether this encoding was checked against the controlling document itself."""
    provenance: str
    """How this baseline was derived, and what a reader should verify independently."""
    rules: list[str] = Field(min_length=1)
    severity_overrides: dict[str, Severity] = Field(default_factory=dict)
    minimums: Minimums = Field(default_factory=Minimums)

    @model_validator(mode="after")
    def _overrides_must_name_selected_rules(self) -> Baseline:
        """A severity override for a rule this baseline does not run does nothing.

        Silently ignoring it would let a typo sit in a compliance document forever,
        looking like policy and having no effect.
        """
        selected = set(self.rules)
        stray = sorted(set(self.severity_overrides) - selected)
        if stray:
            raise ValueError(
                f"baseline {self.id!r} overrides the severity of {stray}, which it does "
                f"not include in `rules`; the override would have no effect"
            )
        return self

    @model_validator(mode="after")
    def _rules_must_be_unique(self) -> Baseline:
        duplicates = sorted({r for r in self.rules if self.rules.count(r) > 1})
        if duplicates:
            raise ValueError(f"baseline {self.id!r} lists {duplicates} more than once")
        return self

    @model_validator(mode="after")
    def _unverified_baselines_must_explain_themselves(self) -> Baseline:
        """An unverified baseline has to say what a reader should check.

        Without this, "verified: false" is a flag nobody can act on.
        """
        if not self.verified and len(self.provenance) < 40:
            raise ValueError(
                f"baseline {self.id!r} is unverified, so its provenance must explain "
                f"how it was derived and what to check against the source"
            )
        return self

    def severity_for(self, rule_id: str, default: Severity) -> Severity:
        """This authority's severity for a rule, or the rule's own."""
        return self.severity_overrides.get(rule_id, default)

    def includes(self, rule_id: str) -> bool:
        return rule_id in self.rules


def _read(path: Path) -> dict[str, Any]:
    try:
        loaded = yaml.safe_load(path.read_text())
    except (OSError, yaml.YAMLError) as exc:
        raise BaselineError(f"{path.name}: {exc}") from exc
    if not isinstance(loaded, dict):
        raise BaselineError(f"{path.name}: expected a mapping at the top level")
    return loaded


def load_baseline_file(path: Path) -> Baseline:
    """Load and validate one baseline file."""
    try:
        return Baseline.model_validate(_read(path))
    except BaselineError:
        raise
    except Exception as exc:
        raise BaselineError(f"{path.name}: {exc}") from exc


def baseline_files() -> list[Path]:
    """Every shipped baseline, excluding the annotated example."""
    return sorted(BASELINE_DIR.glob("*.yaml"))


@lru_cache(maxsize=1)
def load_baselines() -> dict[str, Baseline]:
    """Every shipped baseline, keyed by ID.

    Cached because the files never change at runtime and a report may ask for the same
    baseline for every tunnel in an estate.
    """
    baselines: dict[str, Baseline] = {}
    for path in baseline_files():
        baseline = load_baseline_file(path)
        if baseline.id in baselines:
            raise BaselineError(
                f"two baseline files declare id {baseline.id!r}: {path.name} and an earlier one"
            )
        baselines[baseline.id] = baseline
    return baselines


def get_baseline(baseline_id: str) -> Baseline:
    """Look up one baseline by ID, listing the alternatives when it is not found."""
    baselines = load_baselines()
    if baseline_id not in baselines:
        raise BaselineError(f"unknown baseline {baseline_id!r}; available: {sorted(baselines)}")
    return baselines[baseline_id]


def validate_against_registry(baseline: Baseline, known_rule_ids: set[str]) -> list[str]:
    """Rule IDs a baseline names that no rule implements.

    Returned rather than raised so a caller can report every problem across every
    baseline at once, instead of one per run.
    """
    return sorted(set(baseline.rules) - known_rule_ids)
