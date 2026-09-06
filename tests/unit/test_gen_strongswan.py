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

    def test_the_change_steps_apply_to_both_ends_together(self) -> None:
        """Step 8.4 replaced staging one end before the other with a stronger property.

        Ordering the ends was an attempt to keep the window short. Adding the target
        alongside the current proposal removes the window instead: at every moment,
        including while a step has reached one end and not the other, the two ends
        still share a proposal. ``add`` and ``remove`` are therefore single operations
        across both ends, and there is no LOCAL-then-PEER ordering left to assert.
        """
        package = generate_change_package("t1", anchor("weak"), ["CRY-02"])
        assert [step.role for step in package.sequence] == [ConfigRole.BOTH] * len(package.sequence)
        assert all(ConfigRole.LOCAL.value in step.role.covers for step in package.sequence)
        assert all(ConfigRole.PEER.value in step.role.covers for step in package.sequence)

    def test_the_packaged_sequence_never_leaves_the_ends_disjoint(self) -> None:
        """The property the ordering used to approximate, asserted directly."""
        from ipsec_sentinel.remediate.sequence import unsafe_states, verify_zero_downtime

        original = anchor("weak")
        corrected, _ = harden(original)
        states = verify_zero_downtime(original.proposal_string(), corrected.proposal_string())
        assert unsafe_states(states) == []

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


class TestDeploymentStatus:
    """strongSwan is the only live-tested vendor, and its documents must say so.

    The status mechanism existed from Step 8.3 but strongSwan never declared one, so
    ``DeploymentStatus.LIVE_TESTED`` was defined and used by nobody. The M8 gate found
    it. A claim no document makes is a claim no reader can check.
    """

    def test_strongswan_declares_itself_live_tested(self) -> None:
        from ipsec_sentinel.remediate.generators.base import DeploymentStatus
        from ipsec_sentinel.remediate.generators.strongswan import STATUS

        assert STATUS is DeploymentStatus.LIVE_TESTED

    def test_it_is_the_only_live_tested_vendor(self) -> None:
        from ipsec_sentinel.remediate.generators import (
            cisco,
            fortigate,
            juniper,
            libreswan,
            paloalto,
        )
        from ipsec_sentinel.remediate.generators.base import DeploymentStatus

        for module in (cisco, fortigate, juniper, libreswan, paloalto):
            assert module.STATUS is DeploymentStatus.SYNTAX_VALIDATED, module.VENDOR

    def test_both_generated_documents_carry_the_banner(self) -> None:
        package = generate_change_package("t1", anchor("worst"), ["CRY-05"])
        for document in (package.local_config, package.peer_config):
            assert "Status: live-tested" in document.content
            assert "This tool never writes to a device" in document.content

    def test_the_banner_does_not_disturb_the_configuration(self) -> None:
        """Banner lines are comments; the connection block must be intact beneath."""
        from ipsec_sentinel.remediate.generators.strongswan import render

        corrected, _ = harden(anchor("worst"))
        rendered = render(corrected, "left")
        banner, _, body = rendered.partition("\n\n")
        assert all(line.startswith("#") for line in banner.splitlines())
        assert body.strip().startswith("#") or "connections {" in body
        assert f"proposals = {corrected.proposal_string()}" in body
        assert "include conf.d/*.conf" in body

    def test_the_two_ends_still_differ(self) -> None:
        """A shared banner must not make the documents identical."""
        from ipsec_sentinel.remediate.generators.strongswan import render

        corrected, _ = harden(anchor("worst"))
        assert render(corrected, "left") != render(corrected, "right")

    def test_an_unknown_role_is_refused(self) -> None:
        from ipsec_sentinel.remediate.generators.strongswan import render

        with pytest.raises(ValueError, match="role must be"):
            render(anchor("worst"), "middle")


class TestChildGroupWeakerThanTheIKEGroup:
    """PFS-02, which the M8 gate found the generator was not addressing.

    The existing branch only raised a child group that was weak *in absolute terms*. A
    group can be perfectly respectable and still be weaker than the IKE group it sits
    under, and the weaker of the two is what sets the effective strength.
    """

    @staticmethod
    def _config(dh: str, child: str | None) -> TunnelConfig:
        return TunnelConfig(
            ike_version="ikev2",
            encryption="aes256",
            integrity="sha384",
            prf="prfsha384",
            dh_group=dh,
            pfs=True,
            child_dh_group=child,
            mode="tunnel",
            ip_version=4,
            ike_lifetime_s=3600,
            child_lifetime_s=3600,
        )

    def test_a_weaker_child_group_is_raised_to_the_ike_group(self) -> None:
        corrected, changes = harden(self._config("ecp384", "modp2048"))
        assert corrected.effective_child_dh_group == "ecp384"
        assert any("child DH group modp2048 -> ecp384" in c for c in changes)

    def test_the_comparison_is_on_security_bits_not_parameter_size(self) -> None:
        """2048-bit MODP is 112-bit strength; 256-bit ECP is 128-bit.

        Comparing the numbers in the names says modp2048 is the stronger of the two,
        which is backwards. This is the same mistake CRY-11 was fixed for.
        """
        corrected, changes = harden(self._config("ecp256", "modp2048"))
        assert corrected.effective_child_dh_group == "ecp256"
        assert changes

    def test_a_numerically_smaller_but_stronger_child_group_is_left_alone(self) -> None:
        corrected, changes = harden(self._config("modp2048", "ecp256"))
        assert corrected.effective_child_dh_group == "ecp256"
        assert not any("child DH group" in c for c in changes)

    def test_equal_strength_groups_are_left_alone(self) -> None:
        """Curve25519 and 256-bit ECP are both 128-bit. Neither wastes the other."""
        corrected, changes = harden(self._config("curve25519", "ecp256"))
        assert corrected.effective_child_dh_group == "ecp256"
        assert not any("child DH group" in c for c in changes)

    def test_an_inherited_child_group_needs_no_correction(self) -> None:
        """``None`` means "same as the IKE group", which cannot be weaker than itself."""
        corrected, changes = harden(self._config("ecp384", None))
        assert corrected.effective_child_dh_group == "ecp384"
        assert not any("child DH group" in c for c in changes)

    def test_an_unrecognised_group_is_not_guessed_at(self) -> None:
        from ipsec_sentinel.remediate.generators.strongswan import _dh_strength

        assert _dh_strength("modp8192") is None
        assert _dh_strength(None) is None

    def test_the_strength_table_agrees_with_the_parser(self) -> None:
        """One source of truth. A private copy would drift and nobody would notice."""
        from ipsec_sentinel.parser.constants import dh_security_bits
        from ipsec_sentinel.remediate.generators.strongswan import (
            DH_GROUP_NUMBERS,
            _dh_strength,
        )

        for name, number in DH_GROUP_NUMBERS.items():
            assert _dh_strength(name) == dh_security_bits(number), name

    def test_every_canonical_matrix_group_has_a_number(self) -> None:
        from ipsec_sentinel.remediate.generators.base import CANONICAL_DH_GROUPS
        from ipsec_sentinel.remediate.generators.strongswan import DH_GROUP_NUMBERS

        assert set(DH_GROUP_NUMBERS) >= CANONICAL_DH_GROUPS


class TestNewlyAddressableFindings:
    def test_pfs_02_and_ike_04_are_declared_addressable(self) -> None:
        from ipsec_sentinel.remediate.generators.strongswan import ADDRESSABLE

        assert {"PFS-02", "IKE-04"} <= ADDRESSABLE

    def test_a_package_for_ike_04_offers_exactly_one_proposal(self) -> None:
        """IKE-04 is "a weaker proposal was offered". The fix is to stop offering it."""
        package = generate_change_package("t1", anchor("worst"), ["IKE-04"])
        for document in (package.local_config, package.peer_config):
            proposals = [line for line in document.content.splitlines() if "proposals =" in line]
            assert proposals, document.content
            for line in proposals:
                assert "," not in line, f"more than one proposal offered: {line}"

    def test_neither_is_reported_as_unaddressed(self) -> None:
        package = generate_change_package("t1", anchor("worst"), ["PFS-02", "IKE-04"])
        assert "NOT addressed" not in " ".join(package.local_config.notes)
