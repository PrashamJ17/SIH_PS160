"""Grading an installed ESP SA (follows Step 11.8).

Step 11.8 made kernel SA state reach `config_from_state`, but it stopped at reporting:
`3des/md5` printed as neutrally as `aes256/sha256`. These tests drive the wiring that
turns those parameters into graded findings.

**The rules are reused, not reimplemented.** An installed ESP SA genuinely has an
encryption transform and an integrity transform, so it becomes a real `Proposal` and the
existing `ProposalRule.match` predicates run against it unchanged. Writing a second set of
"is this 3DES?" checks is how the IKEv1/IKEv2 registry bug happened three times in this
project; there is one set of names and both paths consult it.

What is *not* reused is the evidence wording. A CRY-05 from the wire says "offered in
proposal 2 of 2"; this one says the algorithm is installed on a named device. The
offered/selected distinction is the point of the crypto rules and must not be blurred by
a code path where nothing was offered at all.

Only rules an ESP SA can actually answer for are run, from an explicit allowlist. An ESP
SA carries no Diffie-Hellman group, so CRY-11 must stay silent rather than fire on an
absence.
"""

from __future__ import annotations

import pytest

from ipsec_sentinel.assess.esp import (
    ESP_PROPOSAL_RULE_IDS,
    assess_esp,
    esp_observed_config,
    proposal_from_esp,
)
from ipsec_sentinel.assess.rules import default_registry
from ipsec_sentinel.assess.rules.crypto import (
    ENCR_3DES_NAMES,
    ENCR_DES_NAMES,
    ENCR_NULL_NAMES,
    INTEG_MD5_NAMES,
)
from ipsec_sentinel.assess.scoring import score_tunnel
from ipsec_sentinel.collect import ESPParameters
from ipsec_sentinel.models import Severity, TransformType


def esp(
    encryption: str = "aes256",
    integrity: str | None = "sha256",
    *,
    keylen: int | None = None,
    aead: bool = False,
    replay_window: int | None = 64,
    mode: str = "tunnel",
) -> ESPParameters:
    return ESPParameters(
        encryption=encryption,
        encryption_keylen=keylen,
        integrity=integrity,
        aead=aead,
        mode=mode,
        replay_window=replay_window,
        spi="0xdeadbeef",
    )


def rule_ids(esp_parameters: ESPParameters, baseline: str = "default") -> set[str]:
    return {
        finding.rule_id
        for finding in assess_esp(esp_parameters, source="gw01", origin="kernel", baseline=baseline)
    }


class TestTheProposalIsBuiltFromRealTransforms:
    """Nothing here is invented: an installed SA has these two algorithms."""

    def test_3des_becomes_a_name_the_rules_already_know(self) -> None:
        proposal = proposal_from_esp(esp("3des", "md5", keylen=192))
        assert proposal is not None
        names = {t.name for t in proposal.transforms if t.type == TransformType.ENCR}
        assert names & ENCR_3DES_NAMES, f"{names} matches no name CRY-05 looks for"

    def test_des_and_null_likewise(self) -> None:
        des = proposal_from_esp(esp("des", "sha1", keylen=64))
        null = proposal_from_esp(esp("null", "sha256"))
        assert des is not None and null is not None
        assert {t.name for t in des.transforms if t.type == TransformType.ENCR} & ENCR_DES_NAMES
        assert {t.name for t in null.transforms if t.type == TransformType.ENCR} & ENCR_NULL_NAMES

    def test_the_integrity_transform_is_carried(self) -> None:
        proposal = proposal_from_esp(esp("aes256", "md5"))
        assert proposal is not None
        names = {t.name for t in proposal.transforms if t.type == TransformType.INTEG}
        assert names & INTEG_MD5_NAMES

    def test_the_key_length_travels_with_the_transform(self) -> None:
        """CRY-09 reads the attribute, not the transform id."""
        proposal = proposal_from_esp(esp("aes256", "sha256", keylen=256))
        assert proposal is not None
        encryption = next(t for t in proposal.transforms if t.type == TransformType.ENCR)
        assert encryption.key_length == 256

    def test_an_aead_sa_carries_no_integrity_transform(self) -> None:
        """It authenticates internally; inventing one would suppress CRY-08 wrongly."""
        proposal = proposal_from_esp(esp("aes256gcm16", None, keylen=256, aead=True))
        assert proposal is not None
        assert not [t for t in proposal.transforms if t.type == TransformType.INTEG]

    def test_an_unmappable_algorithm_yields_no_proposal(self) -> None:
        assert proposal_from_esp(esp("camellia256", "sha256")) is None


class TestInstalledCryptographyIsGraded:
    def test_3des_raises_cry_05(self) -> None:
        assert "CRY-05" in rule_ids(esp("3des", "md5", keylen=192))

    def test_md5_raises_cry_06(self) -> None:
        assert "CRY-06" in rule_ids(esp("3des", "md5", keylen=192))

    def test_des_raises_cry_04(self) -> None:
        assert "CRY-04" in rule_ids(esp("des", "sha1", keylen=64))

    def test_sha1_raises_cry_07(self) -> None:
        assert "CRY-07" in rule_ids(esp("aes256", "sha1", keylen=256))

    def test_null_encryption_raises_cry_12(self) -> None:
        assert "CRY-12" in rule_ids(esp("null", "sha256"))

    def test_a_short_key_raises_cry_09(self) -> None:
        assert "CRY-09" in rule_ids(esp("des", "sha256", keylen=64))

    def test_cbc_without_integrity_raises_cry_08(self) -> None:
        assert "CRY-08" in rule_ids(esp("aes256", None, keylen=256))

    def test_a_sound_sa_raises_nothing(self) -> None:
        assert rule_ids(esp("aes256", "sha256", keylen=256)) == set()

    def test_an_aead_sa_is_not_flagged_for_missing_integrity(self) -> None:
        """AEAD carries its own; CRY-08 firing here would be a false positive."""
        assert "CRY-08" not in rule_ids(esp("aes256gcm16", None, keylen=256, aead=True))


class TestTheReplayWindowIsAssessedFromTheKernel:
    """`sa.py` says the replay window "never appears on the wire in any form".

    The kernel prints it. This is the one place these two rules get a first-hand source.
    """

    def test_a_zero_window_raises_sa_03(self) -> None:
        assert "SA-03" in rule_ids(esp(replay_window=0))

    def test_a_small_window_raises_sa_04(self) -> None:
        assert "SA-04" in rule_ids(esp(replay_window=4))

    def test_an_adequate_window_raises_neither(self) -> None:
        assert rule_ids(esp(replay_window=64)) == set()

    def test_an_unreported_window_raises_neither(self) -> None:
        """Not supplied is not zero, and must not be graded as though it were."""
        assert rule_ids(esp(replay_window=None)) == set()

    def test_the_observed_config_carries_the_window(self) -> None:
        config = esp_observed_config(esp(replay_window=32))
        assert config is not None
        assert config.replay_window == 32
        assert config.anti_replay_enabled is True

    def test_a_zero_window_means_anti_replay_is_off(self) -> None:
        config = esp_observed_config(esp(replay_window=0))
        assert config is not None
        assert config.anti_replay_enabled is False


class TestOnlyRulesAnESPSACanAnswerForRun:
    def test_no_diffie_hellman_finding_is_produced(self) -> None:
        """An ESP SA carries no DH group. CRY-11 must not fire on an absence."""
        found = rule_ids(esp("3des", "md5", keylen=192))
        assert not {rule for rule in found if rule in {"CRY-01", "CRY-02", "CRY-03", "CRY-11"}}

    def test_no_ike_or_pqc_finding_is_produced(self) -> None:
        found = rule_ids(esp("3des", "md5", keylen=192))
        assert not {rule for rule in found if rule.startswith(("IKE-", "PQC-", "PFS-", "OPS-"))}

    def test_every_allowlisted_rule_exists_in_the_registry(self) -> None:
        """An allowlist naming a rule that was renamed silently checks nothing."""
        registered = {rule.id for rule in default_registry().rules}
        assert registered >= ESP_PROPOSAL_RULE_IDS


class TestTheFindingsAreDeterministicAndAttributed:
    def _findings(self) -> list:  # type: ignore[type-arg]
        return assess_esp(esp("3des", "md5", keylen=192), source="gw01", origin="kernel")

    def test_nothing_carries_a_confidence(self) -> None:
        """Read from a device, not inferred. Section A, like a wire-parsed fact."""
        assert all(finding.confidence is None for finding in self._findings())

    def test_the_evidence_names_the_device(self) -> None:
        assert all("gw01" in finding.evidence for finding in self._findings())

    def test_the_evidence_names_the_source(self) -> None:
        assert all("kernel" in finding.evidence for finding in self._findings())

    def test_the_evidence_says_installed_not_offered(self) -> None:
        """The offered/selected distinction is the point of the crypto rules."""
        for finding in self._findings():
            assert "installed" in finding.evidence.lower()
            assert "offered in proposal" not in finding.evidence

    def test_a_daemon_sourced_finding_says_so_instead(self) -> None:
        findings = assess_esp(esp("3des", "md5", keylen=192), source="gw02", origin="daemon")
        assert findings
        assert all("daemon" in finding.evidence for finding in findings)

    def test_every_finding_keeps_its_standard_reference(self) -> None:
        assert all(finding.standard_ref.strip() for finding in self._findings())

    def test_the_title_says_installed_rather_than_offered(self) -> None:
        """The rules are written for the wire, where an algorithm is *offered*.

        Nothing was offered here. Leaving the title alone would put "3DES encryption
        offered" on a finding whose whole evidence is that 3DES is running.
        """
        titles = {finding.rule_id: finding.title for finding in self._findings()}
        assert titles["CRY-05"] == "3DES encryption installed"
        assert titles["CRY-06"] == "MD5 integrity installed"
        assert not any("offered" in title for title in titles.values())

    def test_the_wire_rules_keep_their_own_wording(self) -> None:
        """Rewriting the title here must not reach the registry the wire path uses."""
        from ipsec_sentinel.assess.rules import default_registry

        by_id = {rule.id: rule for rule in default_registry().rules}
        assert by_id["CRY-05"].title == "3DES encryption offered"

    def test_severities_match_the_rules_they_came_from(self) -> None:
        by_id = {finding.rule_id: finding for finding in self._findings()}
        assert by_id["CRY-05"].severity is Severity.CRITICAL
        assert by_id["CRY-06"].severity is Severity.HIGH


class TestItProducesAGrade:
    def test_a_weak_sa_scores_badly(self) -> None:
        findings = assess_esp(esp("3des", "md5", keylen=192, replay_window=0), source="gw01")
        score, grade = score_tunnel(findings)
        assert score < 50
        assert grade in {"D", "E", "F"}

    def test_a_sound_sa_scores_full_marks(self) -> None:
        findings = assess_esp(esp("aes256", "sha256", keylen=256, replay_window=64), source="gw01")
        score, grade = score_tunnel(findings)
        assert (score, grade) == (100, "A")

    def test_scoring_is_monotonic_in_the_number_of_findings(self) -> None:
        weak = assess_esp(esp("3des", "md5", keylen=192, replay_window=0), source="gw01")
        weaker = assess_esp(esp("des", "md5", keylen=64, replay_window=0), source="gw01")
        assert score_tunnel(weaker)[0] <= score_tunnel(weak)[0]


class TestBaselineThresholdsApply:
    def test_cnsa_flags_a_128_bit_key_that_nist_accepts(self) -> None:
        """CRY-10 is the baseline-bound rule; it must bind here too."""
        aes128 = esp("aes128", "sha256", keylen=128)
        assert "CRY-10" not in rule_ids(aes128, baseline="nist_800_77r1")
        assert "CRY-10" in rule_ids(aes128, baseline="cnsa")

    def test_an_unknown_baseline_is_refused(self) -> None:
        from ipsec_sentinel.assess.framework import UnknownBaselineError

        with pytest.raises(UnknownBaselineError):
            assess_esp(esp(), source="gw01", baseline="not_a_baseline")


class TestTheRuleProtocolIsComplete:
    """The ESP path builds a Finding from a rule it holds only as a `Rule`."""

    def test_every_registered_rule_carries_what_a_finding_needs(self) -> None:
        for rule in default_registry().rules:
            assert rule.id
            assert rule.title
            assert rule.standard_ref.strip()
            assert rule.remediation_hint.strip(), f"{rule.id} has no remediation hint"
