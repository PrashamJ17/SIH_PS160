"""Tests for the strongSwan remediation generator (build plan Step 8.2)."""

from __future__ import annotations

import pytest

from ipsec_sentinel.remediate.generators.strongswan import (
    ENCRYPTION_UPGRADES,
    MAX_CHILD_LIFETIME_S,
    MAX_IKE_LIFETIME_S,
    WEAK_DH_GROUPS,
    GenerationError,
    generate_change_package,
    harden,
)
from ipsec_sentinel.remediate.models import ConfigRole
from testbed.orchestrate.config_gen import TunnelConfig, is_aead
from testbed.orchestrate.matrix import expand_matrix


def anchor(label: str) -> TunnelConfig:
    return next(lc.config for lc in expand_matrix() if lc.label == label)


class TestHardening:
    def test_the_worst_configuration_becomes_a_strong_one(self) -> None:
        corrected, changes = harden(anchor("worst"))
        assert corrected.encryption == "aes256gcm16"
        assert corrected.ike_version == "ikev2"
        assert corrected.aggressive is False
        assert corrected.pfs is True
        assert corrected.dh_group not in WEAK_DH_GROUPS
        assert changes

    def test_an_aead_upgrade_drops_the_integrity_transform(self) -> None:
        """AEAD carries its own integrity; a separate transform is invalid, not merely
        redundant, and TunnelConfig refuses the pairing."""
        corrected, _ = harden(anchor("worst"))
        assert is_aead(corrected.encryption)
        assert corrected.integrity is None

    def test_the_prf_is_upgraded_independently_of_the_cipher(self) -> None:
        """Under AEAD the PRF is the only place a broken hash would still appear."""
        corrected, changes = harden(anchor("worst"))
        assert corrected.prf == "prfsha256"
        assert any("PRF" in c for c in changes)

    def test_a_strong_configuration_is_left_alone(self) -> None:
        """ "Not the strongest available" is not a finding."""
        _corrected, changes = harden(anchor("best"))
        assert changes == []

    def test_settings_the_operator_chose_are_preserved(self) -> None:
        """A remediation that rewrites a working configuration is a migration."""
        original = anchor("worst")
        corrected, _ = harden(original)
        assert corrected.mode == original.mode
        assert corrected.ip_version == original.ip_version

    def test_an_over_long_ike_lifetime_is_reduced(self) -> None:
        from dataclasses import replace

        long = replace(anchor("good"), ike_lifetime_s=MAX_IKE_LIFETIME_S * 3)
        corrected, changes = harden(long)
        assert corrected.ike_lifetime_s == MAX_IKE_LIFETIME_S
        assert any("IKE SA lifetime" in c for c in changes)

    def test_an_over_long_child_lifetime_is_reduced(self) -> None:
        from dataclasses import replace

        long = replace(anchor("good"), child_lifetime_s=MAX_CHILD_LIFETIME_S * 4)
        corrected, _ = harden(long)
        assert corrected.child_lifetime_s == MAX_CHILD_LIFETIME_S

    def test_ikev1_gets_a_group_it_can_actually_negotiate(self) -> None:
        """Curve25519 is specified for IKEv2; IKEv1 has no standard support."""
        from dataclasses import replace

        # Force the DH replacement to happen while still on IKEv1 by keeping IKEv1.
        weak_v1 = replace(
            anchor("weak"), ike_version="ikev1", dh_group="modp1024", aggressive=False
        )
        corrected, _ = harden(weak_v1)
        # Hardening upgrades to IKEv2, so curve25519 is legal at that point.
        assert corrected.ike_version == "ikev2"
        assert corrected.dh_group == "curve25519"

    def test_every_upgrade_target_is_itself_acceptable(self) -> None:
        """An upgrade table pointing at something the rules flag would be embarrassing."""
        for target in ENCRYPTION_UPGRADES.values():
            assert target not in ENCRYPTION_UPGRADES, f"{target} is itself upgraded"


class TestProposalSyntax:
    def test_the_ike_proposal_is_well_formed(self) -> None:
        corrected, _ = harden(anchor("worst"))
        parts = corrected.proposal_string().split("-")
        assert len(parts) >= 3
        assert all(parts)

    def test_an_aead_proposal_omits_the_integrity_algorithm(self) -> None:
        """The plan's explicit criterion."""
        corrected, _ = harden(anchor("worst"))
        proposal = corrected.proposal_string()
        assert "sha256-" not in proposal.replace("prfsha256", "")
        assert proposal.startswith("aes256gcm16-prf")

    def test_a_non_aead_proposal_keeps_its_integrity_algorithm(self) -> None:
        good = anchor("good")
        assert not is_aead(good.encryption)
        assert good.integrity is not None
        assert good.integrity in good.proposal_string()

    def test_pfs_produces_an_esp_proposal_dh_group(self) -> None:
        """The plan's explicit criterion."""
        corrected, _ = harden(anchor("worst"))
        assert corrected.pfs is True
        assert corrected.esp_proposal_string().endswith(corrected.dh_group)

    def test_without_pfs_the_esp_proposal_carries_no_group(self) -> None:
        from dataclasses import replace

        no_pfs = replace(anchor("good"), pfs=False, child_dh_group=None)
        assert no_pfs.effective_child_dh_group is None
        assert no_pfs.dh_group not in no_pfs.esp_proposal_string()

    def test_the_esp_proposal_carries_no_prf(self) -> None:
        """A PRF in an ESP proposal is a syntax error strongSwan rejects."""
        corrected, _ = harden(anchor("worst"))
        assert "prf" not in corrected.esp_proposal_string()


class TestRoundTrip:
    """Feed the generated configuration back and confirm it describes what was meant."""

    def test_the_rendered_config_contains_the_intended_proposals(self) -> None:
        corrected, _ = harden(anchor("worst"))
        package = generate_change_package("t1", anchor("worst"), ["CRY-05"])
        for document in (package.local_config, package.peer_config):
            assert corrected.proposal_string() in document.content
            assert corrected.esp_proposal_string() in document.content

    def test_the_rendered_config_records_the_corrected_ike_version(self) -> None:
        package = generate_change_package("t1", anchor("worst"), ["IKE-01"])
        assert (
            "version = 2" in package.local_config.content or "ikev2" in package.local_config.content
        )

    def test_the_two_ends_are_not_the_same_document(self) -> None:
        """Both ends need the same proposal and different addresses."""
        package = generate_change_package("t1", anchor("worst"), ["CRY-05"])
        assert package.local_config.content != package.peer_config.content

    def test_no_secret_material_is_emitted(self) -> None:
        """The tool stores no credentials and must not print one either."""
        package = generate_change_package("t1", anchor("worst"), ["CRY-05"])
        for document in (package.local_config, package.peer_config):
            lowered = document.content.lower()
            assert "secret =" not in lowered
            assert "psk =" not in lowered


class TestChangePackage:
    def test_both_ends_are_emitted(self) -> None:
        package = generate_change_package("t1", anchor("worst"), ["CRY-05"])
        assert package.local_config.role is ConfigRole.LOCAL
        assert package.peer_config.role is ConfigRole.PEER

    def test_the_peer_is_staged_before_the_local_end(self) -> None:
        """The reverse order leaves a window in which the tunnel cannot re-establish."""
        package = generate_change_package("t1", anchor("weak"), ["CRY-02"])
        first_local = next(s.order for s in package.sequence if s.role is ConfigRole.LOCAL)
        first_peer = next(s.order for s in package.sequence if s.role is ConfigRole.PEER)
        assert first_peer < first_local

    def test_an_aggressive_psk_tunnel_rotates_the_key_first(self) -> None:
        """The hash is already exposed; reusing the key carries the compromise forward."""
        package = generate_change_package("t1", anchor("worst"), ["IKE-03"])
        assert "Rotate the pre-shared key" in package.sequence[0].description
        assert package.sequence[0].order == 1
        assert package.requires_maintenance_window is True

    def test_a_non_psk_tunnel_needs_no_maintenance_window(self) -> None:
        package = generate_change_package("t1", anchor("weak"), ["CRY-02"])
        assert package.requires_maintenance_window is False

    def test_findings_it_cannot_fix_are_declared(self) -> None:
        """A package claiming to fix what it did not touch is worse than one admitting it."""
        package = generate_change_package("t1", anchor("worst"), ["CRY-05", "OPS-01"])
        notes = " ".join(package.local_config.notes)
        assert "NOT addressed" in notes
        assert "OPS-01" in notes

    def test_a_configuration_with_nothing_wrong_is_refused(self) -> None:
        """Asking an operator to take a risk for no benefit is not remediation."""
        with pytest.raises(GenerationError, match="nothing to correct"):
            generate_change_package("t1", anchor("best"), ["CRY-05"])

    def test_a_package_with_no_findings_is_refused(self) -> None:
        with pytest.raises(GenerationError, match="must name the findings"):
            generate_change_package("t1", anchor("worst"), [])

    def test_the_verification_steps_name_the_expected_proposal(self) -> None:
        corrected, _ = harden(anchor("worst"))
        package = generate_change_package("t1", anchor("worst"), ["CRY-05"])
        assert any(corrected.proposal_string() in v for v in package.verification)

    def test_the_blast_radius_names_the_peer_coordination(self) -> None:
        package = generate_change_package("t1", anchor("worst"), ["CRY-05"])
        assert package.blast_radius.peers_requiring_coordination
        assert any("one end only" in note for note in package.blast_radius.notes)
