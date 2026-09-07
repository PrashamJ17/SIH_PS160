"""The documentation set, checked rather than proof-read (build plan Step 11.6).

Documentation rots the moment it is written by hand and never read again. Three
defences are applied here:

* **`RULES.md` is generated** from the rule registry, and a test regenerates it and
  compares. A rule added without its documentation entry fails the build, which is the
  only mechanism that keeps a 26-row table honest.
* **`LIMITATIONS.md` is checked against the five statements the plan requires.** They are
  the least flattering claims in the project, so they are exactly the ones a later edit
  would soften.
* **Every relative link in every document is resolved.** A broken link in a limitations
  document reads as evasion whether or not it was.

What is deliberately *not* checked is prose quality. A test asserting a document is
well-written is a test that passes when it should not.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from ipsec_sentinel.assess.baselines.schema import load_baselines
from ipsec_sentinel.assess.rules import default_registry
from scripts.generate_rules_doc import render_rules_document

REPO_ROOT = Path(__file__).resolve().parents[2]
DOCS = REPO_ROOT / "docs"

REQUIRED = {
    "README.md": REPO_ROOT / "README.md",
    "ARCHITECTURE.md": DOCS / "ARCHITECTURE.md",
    "DATASET.md": DOCS / "DATASET.md",
    "GENERALISATION.md": DOCS / "GENERALISATION.md",
    "CONFOUND_AUDIT.md": DOCS / "CONFOUND_AUDIT.md",
    "SCORING.md": DOCS / "SCORING.md",
    "RULES.md": DOCS / "RULES.md",
    "SECURITY.md": DOCS / "SECURITY.md",
    "DEPLOYMENT.md": DOCS / "DEPLOYMENT.md",
    "LIMITATIONS.md": DOCS / "LIMITATIONS.md",
}

LINK = re.compile(r"\[[^\]]+\]\((?!https?://|mailto:|#)([^)\s]+)\)")


class TestTheSetIsComplete:
    @pytest.mark.parametrize("name", sorted(REQUIRED))
    def test_the_document_exists(self, name: str) -> None:
        assert REQUIRED[name].is_file(), f"{name} is missing"

    @pytest.mark.parametrize("name", sorted(REQUIRED))
    def test_the_document_is_not_a_stub(self, name: str) -> None:
        """A placeholder file satisfies `is_file` and helps nobody."""
        text = REQUIRED[name].read_text()
        assert len(text) > 1200, f"{name} is {len(text)} characters"
        assert "TODO" not in text, f"{name} contains a TODO"

    @pytest.mark.parametrize("name", sorted(REQUIRED))
    def test_the_document_starts_with_a_heading(self, name: str) -> None:
        assert REQUIRED[name].read_text().lstrip().startswith("#")


class TestEveryLinkResolves:
    @pytest.mark.parametrize("name", sorted(REQUIRED))
    def test_the_relative_links_point_at_files_that_exist(self, name: str) -> None:
        document = REQUIRED[name]
        broken = []
        for target in LINK.findall(document.read_text()):
            path = (document.parent / target.split("#", 1)[0]).resolve()
            if not path.exists():
                broken.append(target)
        assert not broken, f"{name} links to missing files: {broken}"


class TestTheRuleDocumentIsGenerated:
    def test_it_matches_the_registry(self) -> None:
        """A rule added without regenerating this fails here, not in a demo."""
        published = REQUIRED["RULES.md"].read_text()
        assert published == render_rules_document(), (
            "docs/RULES.md is stale; run scripts/generate_rules_doc.py"
        )

    def test_every_rule_appears(self) -> None:
        published = REQUIRED["RULES.md"].read_text()
        for rule in default_registry().rules:
            assert rule.id in published, f"{rule.id} is undocumented"

    def test_every_rule_carries_a_standard_reference(self) -> None:
        """The plan asks for every rule with its standard reference, and a rule that
        cites nothing is an opinion rather than a finding."""
        for rule in default_registry().rules:
            assert rule.standard_ref.strip(), f"{rule.id} cites no standard"
            assert rule.standard_ref in REQUIRED["RULES.md"].read_text(), rule.id

    def test_it_counts_what_it_documents(self) -> None:
        published = REQUIRED["RULES.md"].read_text()
        assert str(len(default_registry().rules)) in published

    def test_every_published_baseline_is_listed(self) -> None:
        published = REQUIRED["RULES.md"].read_text()
        for baseline in load_baselines():
            assert baseline in published, f"baseline {baseline} is undocumented"


class TestLimitationsSaysTheUnflatteringThings:
    """The five statements the build plan requires, each checked for separately."""

    @pytest.fixture(scope="class")
    @staticmethod
    def text() -> str:
        return REQUIRED["LIMITATIONS.md"].read_text().lower()

    def test_it_says_passive_analysis_sees_only_negotiated_sessions(self, text: str) -> None:
        assert "negotiated" in text
        assert "capability" in text, (
            "it must distinguish what was negotiated from what the device supports"
        )

    def test_it_disclaims_accreditation_authority(self, text: str) -> None:
        assert "accredit" in text
        assert "certif" in text

    def test_it_says_governance_is_not_covered(self, text: str) -> None:
        assert "governance" in text

    def test_it_says_the_model_was_trained_on_lab_data(self, text: str) -> None:
        assert "lab" in text
        assert "trained" in text

    def test_it_says_which_vendor_generators_are_only_syntax_validated(self, text: str) -> None:
        assert "syntax" in text
        assert "strongswan" in text
        assert "libreswan" in text

    def test_it_points_at_the_generalisation_numbers(self, text: str) -> None:
        """The held-out numbers are the evidence for the ML caveat."""
        assert "generalisation.md" in text


class TestTheReadmeOrientsAReader:
    @pytest.fixture(scope="class")
    @staticmethod
    def text() -> str:
        return REQUIRED["README.md"].read_text()

    def test_it_says_what_the_tool_is_not(self, text: str) -> None:
        assert "What it is not" in text

    def test_it_carries_a_runnable_quickstart(self, text: str) -> None:
        assert "sentinel analyse" in text

    def test_it_links_to_the_limitations(self, text: str) -> None:
        assert "LIMITATIONS.md" in text

    def test_it_repeats_the_two_load_bearing_claims(self, text: str) -> None:
        lowered = text.lower()
        assert "never writes" in lowered
        assert "credential" in lowered


class TestDeploymentCoversTheSensor:
    @pytest.fixture(scope="class")
    @staticmethod
    def text() -> str:
        return REQUIRED["DEPLOYMENT.md"].read_text().lower()

    @pytest.mark.parametrize("subject", ["mirror port", "tap", "sizing", "platform"])
    def test_it_addresses(self, text: str, subject: str) -> None:
        assert subject in text


class TestArchitectureExplainsTheTwoLanes:
    @pytest.fixture(scope="class")
    @staticmethod
    def text() -> str:
        return REQUIRED["ARCHITECTURE.md"].read_text()

    def test_it_names_both_sections(self, text: str) -> None:
        assert "Section A" in text
        assert "Section B" in text

    def test_it_names_the_validator_that_enforces_the_split(self, text: str) -> None:
        assert "enforce_separation" in text

    def test_it_says_why_the_validator_is_not_an_assert(self, text: str) -> None:
        assert "-O" in text or "python -O" in text
