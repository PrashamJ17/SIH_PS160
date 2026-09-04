"""Tests for the ground-truth harvester (build plan Step 1.6).

Fixtures are real output captured from a live tunnel in this testbed, not invented
text — a parser tested only against text its own author imagined proves very little.
Key material was redacted from the kernel fixture before it was committed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from testbed.orchestrate.config_gen import TunnelConfig
from testbed.orchestrate.groundtruth import (
    KernelSA,
    NegotiatedChild,
    NegotiatedIKE,
    build_manifest,
    compare_intent,
    parse_list_sas,
    parse_xfrm_state,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "harvest"
LIST_SAS = (FIXTURES / "swanctl_list_sas_aes256gcm16_ecp384.txt").read_text()
XFRM_STATE = (FIXTURES / "ip_xfrm_state_aes256gcm16.txt").read_text()


def strong_cfg(**kw: object) -> TunnelConfig:
    base: dict[str, object] = {
        "ike_version": "ikev2",
        "encryption": "aes256gcm16",
        "integrity": None,
        "prf": "prfsha384",
        "dh_group": "ecp384",
        "pfs": True,
        "child_dh_group": "ecp384",
        "mode": "tunnel",
        "ip_version": 4,
        "ike_lifetime_s": 14400,
        "child_lifetime_s": 3600,
    }
    base.update(kw)
    return TunnelConfig(**base)  # type: ignore[arg-type]


class TestParseListSAs:
    def test_ike_sa_fields(self) -> None:
        ike, _ = parse_list_sas(LIST_SAS)
        assert ike.established is True
        assert ike.ike_version == "IKEv2"
        assert ike.encryption == "AES_GCM_16"
        assert ike.encryption_keylen == 256
        assert ike.prf == "PRF_HMAC_SHA2_384"
        assert ike.dh_group == "ECP_384"

    def test_aead_suite_has_no_integrity(self) -> None:
        """Three-part suite means AEAD; a separate integrity algorithm would be wrong."""
        ike, _ = parse_list_sas(LIST_SAS)
        assert ike.integrity is None

    def test_spis_are_extracted(self) -> None:
        ike, _ = parse_list_sas(LIST_SAS)
        assert ike.initiator_spi == "ee7aeab5222057ed"
        assert ike.responder_spi == "1b11ca1a45acd3eb"
        assert len(ike.initiator_spi) == 16, "IKE SPI is 8 bytes / 16 hex chars"

    def test_endpoints_and_nat_traversal(self) -> None:
        ike, _ = parse_list_sas(LIST_SAS)
        assert ike.local_host == "10.100.0.2"
        assert ike.remote_host == "10.100.0.3"
        assert ike.local_port == 4500
        assert ike.nat_t is True, "port 4500 means NAT-T is in play"

    def test_child_sa_fields(self) -> None:
        _, child = parse_list_sas(LIST_SAS)
        assert child is not None
        assert child.installed is True
        assert child.mode == "tunnel"
        assert child.esp_encryption == "AES_GCM_16"
        assert child.esp_keylen == 256
        assert child.reqid == 1

    def test_child_spis_are_four_byte_esp_spis(self) -> None:
        """Distinct from the 8-byte IKE SPI — conflating them is a classic bug."""
        _, child = parse_list_sas(LIST_SAS)
        assert child is not None
        assert child.spi_in == "ce7168b5"
        assert child.spi_out == "c1322710"
        assert len(child.spi_in) == 8

    def test_traffic_selectors(self) -> None:
        _, child = parse_list_sas(LIST_SAS)
        assert child is not None
        assert child.local_ts == "10.1.0.0/24"
        assert child.remote_ts == "10.2.0.0/24"

    def test_non_aead_suite_yields_an_integrity_algorithm(self) -> None:
        text = (
            "net-net: #1, ESTABLISHED, IKEv2, aaaa_i* bbbb_r\n"
            "  local  'left' @ 10.100.0.2[500]\n"
            "  remote 'right' @ 10.100.0.3[500]\n"
            "  AES_CBC-128/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_2048\n"
        )
        ike, _ = parse_list_sas(text)
        assert ike.encryption == "AES_CBC"
        assert ike.encryption_keylen == 128
        assert ike.integrity == "HMAC_SHA2_256_128"
        assert ike.prf == "PRF_HMAC_SHA2_256"
        assert ike.dh_group == "MODP_2048"
        assert ike.nat_t is False


class TestParseListSAsRobustness:
    @pytest.mark.parametrize("text", ["", "\n", "no security associations found\n", "garbage"])
    def test_missing_fields_produce_none_never_a_crash(self, text: str) -> None:
        ike, child = parse_list_sas(text)
        assert ike.established is False
        assert ike.encryption is None
        assert child is None

    def test_connecting_state_is_not_established(self) -> None:
        text = "net-net: #1, CONNECTING, IKEv2, aaaa_i* 0000_r\n"
        ike, _ = parse_list_sas(text)
        assert ike.established is False

    def test_truncated_output_does_not_raise(self) -> None:
        for cut in range(0, len(LIST_SAS), 37):
            parse_list_sas(LIST_SAS[:cut])


class TestParseXfrmState:
    def test_two_directional_sas(self) -> None:
        sas = parse_xfrm_state(XFRM_STATE)
        assert len(sas) == 2, "one SA per direction"

    def test_sa_fields(self) -> None:
        sa = parse_xfrm_state(XFRM_STATE)[0]
        assert sa.src == "10.100.0.2"
        assert sa.dst == "10.100.0.3"
        assert sa.proto == "esp"
        assert sa.spi == "0xc1322710"
        assert sa.reqid == 1
        assert sa.mode == "tunnel"
        assert sa.algorithm == "rfc4106(gcm(aes))"
        assert sa.algorithm_kind == "aead"
        assert sa.icv_bits == 128

    def test_replay_window_is_read(self) -> None:
        windows = {sa.replay_window for sa in parse_xfrm_state(XFRM_STATE)}
        assert windows == {0, 32}

    def test_no_key_material_is_ever_returned(self) -> None:
        """The kernel prints session keys inline; none may reach a returned object."""
        for sa in parse_xfrm_state(XFRM_STATE):
            for value in sa.model_dump().values():
                text = str(value)
                assert "REDACTED" not in text
                assert not (text.startswith("0x") and len(text) > 20)

    def test_non_aead_state_parses(self) -> None:
        text = (
            "src 10.0.0.1 dst 10.0.0.2\n"
            "\tproto esp spi 0xdeadbeef reqid 2 mode transport\n"
            "\treplay-window 64 flag af-unspec\n"
            "\tenc cbc(aes) 0xREDACTED\n"
            "\tauth-trunc hmac(sha256) 0xREDACTED 128\n"
        )
        sa = parse_xfrm_state(text)[0]
        assert sa.mode == "transport"
        assert sa.replay_window == 64
        assert sa.icv_bits == 128

    @pytest.mark.parametrize("text", ["", "\n", "garbage\n", "src only\n"])
    def test_missing_fields_produce_none_never_a_crash(self, text: str) -> None:
        for sa in parse_xfrm_state(text):
            assert isinstance(sa, KernelSA)


class TestIntentComparison:
    def test_matching_negotiation_reports_no_mismatch(self) -> None:
        ike, child = parse_list_sas(LIST_SAS)
        assert compare_intent(strong_cfg(), ike, child) == []

    def test_encryption_disagreement_is_detected(self) -> None:
        ike, child = parse_list_sas(LIST_SAS)
        mismatches = compare_intent(strong_cfg(encryption="3des", integrity="md5"), ike, child)
        assert any("encryption" in m for m in mismatches)

    def test_dh_group_disagreement_is_detected(self) -> None:
        ike, child = parse_list_sas(LIST_SAS)
        assert any(
            "dh_group" in m for m in compare_intent(strong_cfg(dh_group="modp2048"), ike, child)
        )

    def test_mode_disagreement_is_detected(self) -> None:
        ike, child = parse_list_sas(LIST_SAS)
        assert any("mode" in m for m in compare_intent(strong_cfg(mode="transport"), ike, child))

    def test_key_length_disagreement_is_detected(self) -> None:
        ike, child = parse_list_sas(LIST_SAS)
        assert any(
            "key length" in m
            for m in compare_intent(strong_cfg(encryption="aes128gcm16"), ike, child)
        )

    def test_unestablished_sa_is_a_mismatch(self) -> None:
        assert compare_intent(strong_cfg(), NegotiatedIKE(), None) != []


class TestManifest:
    def test_matching_run_sets_the_flag_true(self) -> None:
        manifest = build_manifest(
            strong_cfg(), parse_list_sas(LIST_SAS), parse_xfrm_state(XFRM_STATE)
        )
        assert manifest.negotiation_matched_intent is True
        assert manifest.mismatches == []

    def test_disagreeing_run_sets_the_flag_false(self) -> None:
        """Training on a cell whose labels describe something else poisons the corpus."""
        manifest = build_manifest(
            strong_cfg(dh_group="modp1024"), parse_list_sas(LIST_SAS), parse_xfrm_state(XFRM_STATE)
        )
        assert manifest.negotiation_matched_intent is False
        assert manifest.mismatches

    def test_manifest_records_both_intent_and_reality(self) -> None:
        manifest = build_manifest(
            strong_cfg(), parse_list_sas(LIST_SAS), parse_xfrm_state(XFRM_STATE)
        )
        assert manifest.intent["dh_group"] == "ecp384"
        assert manifest.negotiated_ike is not None
        assert manifest.negotiated_ike.dh_group == "ECP_384"

    def test_manifest_includes_kernel_view(self) -> None:
        manifest = build_manifest(
            strong_cfg(), parse_list_sas(LIST_SAS), parse_xfrm_state(XFRM_STATE)
        )
        assert len(manifest.kernel_sas) == 2

    def test_manifest_round_trips_through_json(self) -> None:
        from testbed.orchestrate.groundtruth import Manifest

        manifest = build_manifest(
            strong_cfg(),
            parse_list_sas(LIST_SAS),
            parse_xfrm_state(XFRM_STATE),
            capture_meta={"duration_s": 60},
        )
        assert Manifest.model_validate_json(manifest.model_dump_json()) == manifest

    def test_manifest_json_contains_no_key_material(self) -> None:
        manifest = build_manifest(
            strong_cfg(), parse_list_sas(LIST_SAS), parse_xfrm_state(XFRM_STATE)
        )
        import re

        assert not re.search(r"0x[0-9a-f]{16,}", manifest.model_dump_json())

    def test_failed_negotiation_still_produces_a_manifest(self) -> None:
        """A failed cell must be recorded, not lost."""
        manifest = build_manifest(strong_cfg(), (NegotiatedIKE(), None), [])
        assert manifest.negotiation_matched_intent is False
        assert manifest.negotiated_child is None

    def test_child_only_manifest_does_not_crash(self) -> None:
        manifest = build_manifest(
            strong_cfg(), (NegotiatedIKE(established=True), NegotiatedChild()), []
        )
        assert manifest.negotiation_matched_intent is False
