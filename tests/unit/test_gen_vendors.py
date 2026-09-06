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

from ipsec_sentinel.remediate.generators import libreswan
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

VENDOR_MODULES = [libreswan]


def anchor(label: str) -> TunnelConfig:
    return next(lc.config for lc in expand_matrix() if lc.label == label)


def hardened(label: str = "worst") -> TunnelConfig:
    return harden(anchor(label))[0]


class TestTranslationRefusesToGuess:
    def test_an_unmapped_algorithm_raises(self) -> None:
        """Emitting the canonical name produces a file the device rejects."""
        with pytest.raises(UnsupportedAlgorithmError, match="no mapping"):
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
    def test_every_canonical_dh_group_is_mapped(self, module) -> None:  # type: ignore[no-untyped-def]
        missing = CANONICAL_DH_GROUPS - set(module.DH_GROUP)
        assert not missing, f"{module.VENDOR} cannot express {sorted(missing)}"

    @pytest.mark.parametrize("module", VENDOR_MODULES, ids=lambda m: m.VENDOR)
    def test_no_mapping_is_an_identity_placeholder(self, module) -> None:  # type: ignore[no-untyped-def]
        """A table that maps a name to itself is usually an unfinished table."""
        identical = [k for k, v in module.DH_GROUP.items() if k == v]
        assert not identical, f"{module.VENDOR} DH mapping looks unfinished: {identical}"


class TestDeploymentStatusIsInTheOutput:
    @pytest.mark.parametrize("module", VENDOR_MODULES, ids=lambda m: m.VENDOR)
    def test_the_rendered_file_states_its_status(self, module) -> None:  # type: ignore[no-untyped-def]
        """The caveat must travel with the file, not live only in a README."""
        rendered = module.render(hardened())
        assert module.STATUS.value in rendered

    @pytest.mark.parametrize("module", VENDOR_MODULES, ids=lambda m: m.VENDOR)
    def test_an_untested_generator_says_it_was_never_loaded(self, module) -> None:  # type: ignore[no-untyped-def]
        if module.STATUS is not DeploymentStatus.SYNTAX_VALIDATED:
            pytest.skip(f"{module.VENDOR} is live-tested")
        rendered = module.render(hardened())
        assert "NOT been loaded" in rendered
        assert "maintenance window" in rendered

    @pytest.mark.parametrize("module", VENDOR_MODULES, ids=lambda m: m.VENDOR)
    def test_every_file_states_the_tool_never_writes_to_a_device(self, module) -> None:  # type: ignore[no-untyped-def]
        assert "never writes to a device" in module.render(hardened())

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
