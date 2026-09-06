"""Tests for the vendor configuration generators (build plan Step 8.3).

The plan is explicit that only strongSwan and Libreswan could be live-tested, and that
everything else must be marked "syntax-validated, not deployment-tested" without
overclaiming. This suite enforces that in the output rather than trusting the docs — a
caveat that lives only in a README does not travel with the file an operator pastes
into a change ticket.
"""

from __future__ import annotations

import re

import pytest

from ipsec_sentinel.remediate.generators import (
    cisco,
    fortigate,
    juniper,
    libreswan,
    paloalto,
)
from ipsec_sentinel.remediate.generators.base import (
    CANONICAL_DH_GROUPS,
    CANONICAL_ENCRYPTIONS,
    CANONICAL_INTEGRITIES,
    DeploymentStatus,
    UnsupportedAlgorithmError,
    translate,
)
from ipsec_sentinel.remediate.generators.strongswan import harden
from testbed.orchestrate.config_gen import TunnelConfig
from testbed.orchestrate.matrix import expand_matrix

VENDOR_MODULES = [libreswan, cisco, fortigate, juniper, paloalto]


def anchor(label: str) -> TunnelConfig:
    return next(lc.config for lc in expand_matrix() if lc.label == label)


def hardened(label: str = "worst") -> TunnelConfig:
    return harden(anchor(label))[0]


class TestTranslationRefusesToGuess:
    def test_an_unmapped_algorithm_raises(self) -> None:
        """Emitting the canonical name produces a file the device rejects."""
        with pytest.raises(UnsupportedAlgorithmError, match="cannot express"):
            translate({"a": "x"}, "b", "encryption", "TestVendor")

    def test_the_error_names_what_is_supported(self) -> None:
        with pytest.raises(UnsupportedAlgorithmError, match=r"\['a'\]"):
            translate({"a": "x"}, "b", "encryption", "TestVendor")

    def test_a_mapped_algorithm_translates(self) -> None:
        assert translate({"aes256": "aes-256"}, "aes256", "encryption", "V") == "aes-256"


class TestEveryVendorCoversTheCanonicalSpace:
    """A gap in a mapping table is a document that fails on the device."""

    @pytest.mark.parametrize("module", VENDOR_MODULES, ids=lambda m: m.VENDOR)
    def test_every_canonical_encryption_is_mapped(self, module) -> None:  # type: ignore[no-untyped-def]
        missing = CANONICAL_ENCRYPTIONS - set(module.ENCRYPTION)
        assert not missing, f"{module.VENDOR} cannot express {sorted(missing)}"

    @pytest.mark.parametrize("module", VENDOR_MODULES, ids=lambda m: m.VENDOR)
    def test_every_canonical_integrity_is_mapped(self, module) -> None:  # type: ignore[no-untyped-def]
        missing = CANONICAL_INTEGRITIES - set(module.INTEGRITY)
        assert not missing, f"{module.VENDOR} cannot express {sorted(missing)}"

    @pytest.mark.parametrize("module", VENDOR_MODULES, ids=lambda m: m.VENDOR)
    def test_every_dh_group_gap_is_declared_not_accidental(self, module) -> None:  # type: ignore[no-untyped-def]
        """Some gaps are real: Junos and PAN-OS have no Curve25519 group.

        What must never happen is an *undeclared* gap, which is an unfinished table,
        or a mapping onto an approximate group — Cisco's group 21 is 521-bit ECP, and
        pointing Curve25519 at it would emit a configuration that loads cleanly and
        negotiates something the assessment never asked for.
        """
        missing = CANONICAL_DH_GROUPS - set(module.DH_GROUP)
        undeclared = missing - set(module.UNSUPPORTED)
        assert not undeclared, (
            f"{module.VENDOR} silently omits {sorted(undeclared)}; declare it in "
            f"UNSUPPORTED with the alternative, or add the mapping"
        )

    @pytest.mark.parametrize("module", VENDOR_MODULES, ids=lambda m: m.VENDOR)
    def test_a_declared_gap_names_an_alternative(self, module) -> None:  # type: ignore[no-untyped-def]
        """ "Unsupported" without a next step leaves the operator nowhere to go."""
        for algorithm, alternative in module.UNSUPPORTED.items():
            assert alternative.strip(), f"{module.VENDOR}/{algorithm} has no alternative"

    @pytest.mark.parametrize("module", VENDOR_MODULES, ids=lambda m: m.VENDOR)
    def test_a_declared_gap_is_actually_absent_from_the_table(self, module) -> None:  # type: ignore[no-untyped-def]
        """A gap declared and also mapped is a contradiction the reader cannot resolve."""
        contradictions = set(module.UNSUPPORTED) & set(module.DH_GROUP)
        assert not contradictions, f"{module.VENDOR}: {sorted(contradictions)}"

    @pytest.mark.parametrize("module", VENDOR_MODULES, ids=lambda m: m.VENDOR)
    def test_rendering_an_unsupported_algorithm_refuses_and_suggests(self, module) -> None:  # type: ignore[no-untyped-def]
        """Refusal must be loud and actionable, never a silent approximation."""
        from dataclasses import replace

        if not module.UNSUPPORTED:
            pytest.skip(f"{module.VENDOR} declares no gaps")
        gap = next(iter(module.UNSUPPORTED))
        config = replace(hardened("good"), dh_group=gap, child_dh_group=None)
        with pytest.raises(UnsupportedAlgorithmError) as caught:
            module.render(config)
        assert "cannot express" in str(caught.value)
        assert module.UNSUPPORTED[gap].split()[0] in str(caught.value)

    @pytest.mark.parametrize("module", VENDOR_MODULES, ids=lambda m: m.VENDOR)
    def test_no_dh_mapping_is_an_identity_placeholder(self, module) -> None:  # type: ignore[no-untyped-def]
        """A table mapping a name to itself is usually an unfinished table."""
        identical = [k for k, v in module.DH_GROUP.items() if k == v]
        assert not identical, f"{module.VENDOR} DH mapping looks unfinished: {identical}"

    @pytest.mark.parametrize("module", VENDOR_MODULES, ids=lambda m: m.VENDOR)
    def test_only_strongswan_claims_to_be_live_tested(self, module) -> None:  # type: ignore[no-untyped-def]
        """No device for these vendors exists in this testbed. Claiming otherwise is a lie."""
        assert module.STATUS is DeploymentStatus.SYNTAX_VALIDATED

    @pytest.mark.parametrize("module", VENDOR_MODULES, ids=lambda m: m.VENDOR)
    def test_the_two_ends_differ(self, module) -> None:  # type: ignore[no-untyped-def]
        """A change package whose halves are identical describes one end twice."""
        config = hardened("good")
        assert module.render(config, "left") != module.render(config, "right")

    @pytest.mark.parametrize("module", VENDOR_MODULES, ids=lambda m: m.VENDOR)
    def test_no_credential_is_emitted(self, module) -> None:  # type: ignore[no-untyped-def]
        """The tool stores no credentials and must not print one either."""
        rendered = module.render(hardened("good"))
        assert "CONFIGURE-OUT-OF-BAND" in rendered or "credential" in rendered.lower()
        for leak in ("psksecret abc", "pre-shared-key ascii", 'secret "'):
            assert leak not in rendered

    @pytest.mark.parametrize("module", VENDOR_MODULES, ids=lambda m: m.VENDOR)
    def test_an_invalid_role_is_refused_everywhere(self, module) -> None:  # type: ignore[no-untyped-def]
        with pytest.raises(ValueError, match="role must be"):
            module.render(hardened("good"), role="middle")

    @pytest.mark.parametrize("module", VENDOR_MODULES, ids=lambda m: m.VENDOR)
    def test_lifetimes_reach_the_output(self, module) -> None:  # type: ignore[no-untyped-def]
        config = hardened("good")
        rendered = module.render(config)
        assert str(config.ike_lifetime_s) in rendered
        assert str(config.child_lifetime_s) in rendered


class TestDeploymentStatusIsInTheOutput:
    @pytest.mark.parametrize("module", VENDOR_MODULES, ids=lambda m: m.VENDOR)
    def test_the_rendered_file_states_its_status(self, module) -> None:  # type: ignore[no-untyped-def]
        """The caveat must travel with the file, not live only in a README."""
        rendered = module.render(hardened("good"))
        assert module.STATUS.value in rendered

    @pytest.mark.parametrize("module", VENDOR_MODULES, ids=lambda m: m.VENDOR)
    def test_an_untested_generator_says_it_was_never_loaded(self, module) -> None:  # type: ignore[no-untyped-def]
        if module.STATUS is not DeploymentStatus.SYNTAX_VALIDATED:
            pytest.skip(f"{module.VENDOR} is live-tested")
        rendered = module.render(hardened("good"))
        assert "NOT been loaded" in rendered
        assert "maintenance window" in rendered

    @pytest.mark.parametrize("module", VENDOR_MODULES, ids=lambda m: m.VENDOR)
    def test_every_file_states_the_tool_never_writes_to_a_device(self, module) -> None:  # type: ignore[no-untyped-def]
        assert "never writes to a device" in module.render(hardened("good"))

    def test_libreswan_is_not_claimed_as_live_tested(self) -> None:
        """The testbed runs strongSwan only. Claiming otherwise would be a lie.

        Adding a Libreswan container would make this live-testable and is the obvious
        next step; until it exists, the status stays honest.
        """
        assert libreswan.STATUS is DeploymentStatus.SYNTAX_VALIDATED


class TestLibreswanSyntax:
    def test_the_ike_proposal_uses_a_semicolon_before_the_group(self) -> None:
        rendered = libreswan.proposal(hardened())
        assert ";" in rendered
        assert rendered.split(";")[1].startswith("dh")

    def test_an_aead_proposal_omits_the_integrity_term(self) -> None:
        """Libreswan rejects the combination; it is not merely redundant."""
        proposal = libreswan.proposal(hardened("worst"))
        assert "aes_gcm256" in proposal
        assert "sha2" not in proposal

    def test_a_non_aead_proposal_carries_its_integrity_term(self) -> None:
        good = anchor("good")
        proposal = libreswan.proposal(good)
        assert "-" in proposal.split(";")[0], "encryption-integrity expected"

    def test_the_esp_proposal_carries_a_group_only_with_pfs(self) -> None:
        from dataclasses import replace

        with_pfs = hardened("worst")
        assert ";" in libreswan.esp_proposal(with_pfs)
        without = replace(anchor("good"), pfs=False, child_dh_group=None)
        assert ";" not in libreswan.esp_proposal(without)

    def test_the_config_declares_the_key_exchange_version(self) -> None:
        rendered = libreswan.render(hardened())
        assert re.search(r"^\s+keyexchange=ikev2$", rendered, re.MULTILINE)

    def test_the_config_declares_the_mode(self) -> None:
        rendered = libreswan.render(hardened())
        assert re.search(r"^\s+type=(tunnel|transport)$", rendered, re.MULTILINE)

    def test_lifetimes_are_emitted_with_units(self) -> None:
        rendered = libreswan.render(hardened())
        assert re.search(r"^\s+ikelifetime=\d+s$", rendered, re.MULTILINE)
        assert re.search(r"^\s+salifetime=\d+s$", rendered, re.MULTILINE)

    def test_it_has_a_config_setup_and_a_conn_section(self) -> None:
        rendered = libreswan.render(hardened())
        assert "config setup" in rendered
        assert "conn sentinel-remediated" in rendered

    def test_no_secret_material_is_emitted(self) -> None:
        rendered = libreswan.render(hardened()).lower()
        assert "psk=" not in rendered
        assert "secret=" not in rendered

    def test_the_two_ends_are_mirror_images(self) -> None:
        """A package whose halves are byte-identical describes one end twice."""
        left = libreswan.render(hardened(), role="left")
        right = libreswan.render(hardened(), role="right")
        assert left != right
        assert "leftsubnet=<LOCAL_SUBNET>" in left
        assert "leftsubnet=<PEER_SUBNET>" in right

    def test_addresses_are_placeholders_not_invented(self) -> None:
        """The tool sees endpoints on the wire, never routing intent."""
        rendered = libreswan.render(hardened())
        assert "<PEER_ADDRESS>" in rendered
        assert "<LOCAL_SUBNET>" in rendered

    def test_an_invalid_role_is_refused(self) -> None:
        with pytest.raises(ValueError, match="role must be"):
            libreswan.render(hardened(), role="middle")

    def test_every_line_is_a_comment_a_section_or_an_indented_setting(self) -> None:
        """A crude grammar check, which is what "syntax-validated" actually means."""
        for line in libreswan.render(hardened()).splitlines():
            if not line.strip():
                continue
            assert (
                line.startswith("#")
                or line.startswith("config ")
                or line.startswith("conn ")
                or re.match(r"^\s{4}\S", line)
            ), f"unexpected line: {line!r}"
