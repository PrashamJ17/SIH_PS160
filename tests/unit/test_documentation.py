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
from scripts.generate_baselines_doc import render_baselines_document
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
    "COMPLIANCE_BASELINES.md": DOCS / "COMPLIANCE_BASELINES.md",
    "BASELINES.md": DOCS / "BASELINES.md",
    "SECURITY.md": DOCS / "SECURITY.md",
    "DEPLOYMENT.md": DOCS / "DEPLOYMENT.md",
    "LIMITATIONS.md": DOCS / "LIMITATIONS.md",
    "WALKTHROUGH.md": DOCS / "WALKTHROUGH.md",
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


class TestTheWalkthroughIsRunnable:
    """The walkthrough promises every command runs as written. Two things can break that.

    A renamed demo capture is the likelier one: nothing else in the suite reads
    `demo/pcaps`, so a rename would leave the document quietly pointing at a file that no
    longer exists, and the reader finds out instead of the build.
    """

    @pytest.fixture(scope="class")
    @staticmethod
    def text() -> str:
        return REQUIRED["WALKTHROUGH.md"].read_text()

    def test_every_demo_path_it_names_exists(self, text: str) -> None:
        referenced = sorted(set(re.findall(r"demo/[\w./-]+", text)))
        assert referenced, "the walkthrough names no demo file, so this test proves nothing"
        missing = [name for name in referenced if not (REPO_ROOT / name).exists()]
        assert not missing, f"the walkthrough names files that do not exist: {missing}"

    def test_it_covers_the_commands_the_readme_advertises(self, text: str) -> None:
        """A command in the README's table with no worked example is a dead end."""
        for command in ("analyse", "inventory", "remediate", "watch", "scan"):
            assert f"sentinel {command}" in text, (
                f"the walkthrough never shows `sentinel {command}`"
            )

    def test_it_states_the_blind_spot_rather_than_only_the_capability(self, text: str) -> None:
        """The rekey blind spot is the least flattering thing about a passive tool, so it
        is the first thing a rewrite would drop."""
        lowered = text.lower()
        assert "create_child_sa" in lowered
        assert "encrypted" in lowered


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


class TestTheBaselineDocumentIsGenerated:
    """Two senses of "baseline" live in this repository and used to be conflated.

    `docs/BASELINES.md` is about the baselines the ML models must beat. `RULES.md`,
    `ARCHITECTURE.md` and the README all linked to it for "what each authority requires",
    which it has never said a word about. The link resolved, so the link checker passed.
    """

    def test_it_matches_the_definitions(self) -> None:
        published = REQUIRED["COMPLIANCE_BASELINES.md"].read_text()
        assert published == render_baselines_document(), (
            "docs/COMPLIANCE_BASELINES.md is stale; run scripts/generate_baselines_doc.py"
        )

    def test_every_published_baseline_has_a_section(self) -> None:
        published = REQUIRED["COMPLIANCE_BASELINES.md"].read_text()
        for name in load_baselines():
            assert f"`{name}`" in published, f"{name} is undocumented"

    def test_the_unverified_baselines_are_marked_as_such(self) -> None:
        """certin and itsar were encoded from public description, not from a source copy."""
        from ipsec_sentinel.assess.baselines.schema import get_baseline

        published = REQUIRED["COMPLIANCE_BASELINES.md"].read_text()
        unverified = [name for name in load_baselines() if not get_baseline(name).verified]
        assert unverified, "this test assumes at least one baseline is unverified"
        assert "Not verified against a controlling document" in published
        for name in unverified:
            assert name in published

    def test_it_reproduces_the_provenance_rather_than_summarising_it(self) -> None:
        from ipsec_sentinel.assess.baselines.schema import get_baseline

        published = REQUIRED["COMPLIANCE_BASELINES.md"].read_text()
        for name in load_baselines():
            baseline = get_baseline(name)
            if baseline.verified:
                continue
            opening = " ".join(baseline.provenance.split())[:60]
            assert opening in published, f"{name}'s provenance was not carried over"

    def test_the_two_senses_of_baseline_are_distinguished(self) -> None:
        compliance = REQUIRED["COMPLIANCE_BASELINES.md"].read_text()
        assert "BASELINES.md" in compliance, (
            "the compliance document must disambiguate itself from the ML one"
        )

    def test_nothing_points_at_the_ml_document_for_compliance(self) -> None:
        """The defect this class exists for: three documents linked to the wrong file."""
        for name in ("RULES.md", "ARCHITECTURE.md", "README.md"):
            text = REQUIRED[name].read_text()
            for line in text.splitlines():
                if "BASELINES.md" not in line or "COMPLIANCE_BASELINES.md" in line:
                    continue
                lowered = line.lower()
                assert not any(
                    word in lowered for word in ("authority", "authorities", "requires")
                ), f"{name} points at the ML baselines document for compliance: {line.strip()}"
