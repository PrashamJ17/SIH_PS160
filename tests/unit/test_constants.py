"""Tests for IANA protocol constants and resolvers (build plan Step 0.7).

Pure data with no logic, but an error here silently corrupts every finding
downstream — a mis-mapped transform ID turns a critical finding into a clean bill
of health. So this is tested exhaustively.
"""

from __future__ import annotations

from typing import ClassVar

import pytest

from ipsec_sentinel.models import TransformType
from ipsec_sentinel.parser.constants import (
    ATTRIBUTE_KEY_LENGTH,
    DH_GROUPS,
    ENCR_ALGORITHMS,
    IKE_VERSIONS,
    IKEV1_EXCHANGE_TYPES,
    IKEV2_EXCHANGE_TYPES,
    IKEV2_PAYLOAD_TYPES,
    INTEG_ALGORITHMS,
    KE_LENGTH_TO_GROUP,
    NOTIFY_TYPES,
    PRF_ALGORITHMS,
    TRANSFORM_TYPES,
    KELengthWarning,
    check_ke_length,
    dh_group_bits,
    dh_group_name,
    groups_for_ke_length,
    resolve_transform_name,
)

UNIQUE_VALUE_TABLES = {
    "IKE_VERSIONS": IKE_VERSIONS,
    "IKEV2_EXCHANGE_TYPES": IKEV2_EXCHANGE_TYPES,
    "IKEV1_EXCHANGE_TYPES": IKEV1_EXCHANGE_TYPES,
    "IKEV2_PAYLOAD_TYPES": IKEV2_PAYLOAD_TYPES,
    "TRANSFORM_TYPES": TRANSFORM_TYPES,
    "ENCR_ALGORITHMS": ENCR_ALGORITHMS,
    "INTEG_ALGORITHMS": INTEG_ALGORITHMS,
    "PRF_ALGORITHMS": PRF_ALGORITHMS,
    "NOTIFY_TYPES": NOTIFY_TYPES,
}


class TestTableIntegrity:
    @pytest.mark.parametrize("name", sorted(UNIQUE_VALUE_TABLES))
    def test_no_duplicate_names_within_a_table(self, name: str) -> None:
        """A duplicated name means two IDs resolve identically — silent corruption."""
        table = UNIQUE_VALUE_TABLES[name]
        values = list(table.values())
        assert len(values) == len(set(values)), f"{name} has duplicate names"

    @pytest.mark.parametrize("name", sorted(UNIQUE_VALUE_TABLES))
    def test_keys_are_non_negative_ints(self, name: str) -> None:
        assert all(isinstance(k, int) and k >= 0 for k in UNIQUE_VALUE_TABLES[name])

    def test_dh_group_names_are_unique(self) -> None:
        names = [n for n, _ in DH_GROUPS.values()]
        assert len(names) == len(set(names))

    def test_transform_types_match_the_domain_enum(self) -> None:
        """constants.TRANSFORM_TYPES and models.TransformType must not drift apart."""
        assert set(TRANSFORM_TYPES.values()) == {t.value for t in TransformType}

    def test_attribute_key_length_is_fourteen(self) -> None:
        """Key length is attribute type 14 — the attribute that separates AES-128 from 256."""
        assert ATTRIBUTE_KEY_LENGTH == 14


class TestVersionsAndExchanges:
    def test_ike_versions(self) -> None:
        assert IKE_VERSIONS[0x10] == "IKEv1"
        assert IKE_VERSIONS[0x20] == "IKEv2"

    def test_ikev2_sa_init(self) -> None:
        assert IKEV2_EXCHANGE_TYPES[34] == "IKE_SA_INIT"

    def test_ikev1_aggressive_mode_is_type_four(self) -> None:
        """The highest-value finding the tool can produce."""
        assert IKEV1_EXCHANGE_TYPES[4] == "Aggressive Mode"

    def test_ikev1_main_mode_is_type_two(self) -> None:
        assert "Main Mode" in IKEV1_EXCHANGE_TYPES[2]

    def test_notify_types_carry_the_intelligence_bearing_entries(self) -> None:
        assert NOTIFY_TYPES[17] == "INVALID_KE_PAYLOAD"
        assert NOTIFY_TYPES[16390] == "NAT_DETECTION_SOURCE_IP"
        assert NOTIFY_TYPES[14] == "NO_PROPOSAL_CHOSEN"


class TestResolveTransformName:
    KNOWN: ClassVar[list[tuple[TransformType, int, str]]] = [
        (TransformType.ENCR, 2, "ENCR_DES"),
        (TransformType.ENCR, 3, "ENCR_3DES"),
        (TransformType.ENCR, 11, "ENCR_NULL"),
        (TransformType.ENCR, 12, "ENCR_AES_CBC"),
        (TransformType.ENCR, 13, "ENCR_AES_CTR"),
        (TransformType.ENCR, 18, "ENCR_AES_GCM_8"),
        (TransformType.ENCR, 20, "ENCR_AES_GCM_16"),
        (TransformType.ENCR, 28, "ENCR_CHACHA20_POLY1305"),
        (TransformType.INTEG, 0, "NONE"),
        (TransformType.INTEG, 1, "AUTH_HMAC_MD5_96"),
        (TransformType.INTEG, 2, "AUTH_HMAC_SHA1_96"),
        (TransformType.INTEG, 12, "AUTH_HMAC_SHA2_256_128"),
        (TransformType.INTEG, 14, "AUTH_HMAC_SHA2_512_256"),
        (TransformType.PRF, 1, "PRF_HMAC_MD5"),
        (TransformType.PRF, 2, "PRF_HMAC_SHA1"),
        (TransformType.PRF, 5, "PRF_HMAC_SHA2_256"),
        (TransformType.PRF, 7, "PRF_HMAC_SHA2_512"),
        (TransformType.DH, 2, "1024-bit MODP"),
        (TransformType.DH, 14, "2048-bit MODP"),
        (TransformType.DH, 20, "384-bit ECP"),
        (TransformType.DH, 31, "Curve25519"),
    ]

    @pytest.mark.parametrize(("t_type", "t_id", "expected"), KNOWN)
    def test_known_pairs_resolve(self, t_type: TransformType, t_id: int, expected: str) -> None:
        assert resolve_transform_name(t_type, t_id) == expected

    def test_there_are_at_least_twenty_known_pairs_under_test(self) -> None:
        assert len(self.KNOWN) >= 20

    def test_accepts_the_numeric_transform_type(self) -> None:
        assert resolve_transform_name(1, 3) == "ENCR_3DES"

    @pytest.mark.parametrize(
        ("t_type", "t_id", "expected"),
        [
            (TransformType.ENCR, 99, "UNKNOWN_ENCR_99"),
            (TransformType.INTEG, 250, "UNKNOWN_INTEG_250"),
            (TransformType.PRF, 42, "UNKNOWN_PRF_42"),
            (TransformType.DH, 1024, "UNKNOWN_DH_1024"),
        ],
    )
    def test_unknown_id_returns_a_marker_and_never_raises(
        self, t_type: TransformType, t_id: int, expected: str
    ) -> None:
        assert resolve_transform_name(t_type, t_id) == expected

    def test_unknown_transform_type_never_raises(self) -> None:
        assert resolve_transform_name(200, 7) == "UNKNOWN_TRANSFORM_TYPE_200_7"

    @pytest.mark.parametrize("t_id", [-1, 0, 1, 65535, 2**31])
    def test_never_raises_for_any_integer_id(self, t_id: int) -> None:
        for t_type in TransformType:
            assert isinstance(resolve_transform_name(t_type, t_id), str)


class TestDHGroups:
    def test_group_two_is_1024_bits(self) -> None:
        assert dh_group_bits(2) == 1024

    @pytest.mark.parametrize(
        ("group", "bits"),
        [
            (1, 768),
            (2, 1024),
            (5, 1536),
            (14, 2048),
            (15, 3072),
            (16, 4096),
            (19, 256),
            (20, 384),
            (21, 521),
            (31, 256),
        ],
    )
    def test_group_bit_sizes(self, group: int, bits: int) -> None:
        assert dh_group_bits(group) == bits

    def test_unknown_group_bits_is_none_not_an_error(self) -> None:
        assert dh_group_bits(9999) is None

    def test_unknown_group_name_is_a_marker(self) -> None:
        assert dh_group_name(9999) == "UNKNOWN_DH_9999"

    def test_weak_groups_are_present_so_rules_can_fire_on_them(self) -> None:
        """CRY-01/02/03 depend on groups 1, 2 and 5 being resolvable."""
        for weak in (1, 2, 5):
            assert weak in DH_GROUPS


class TestKELengthCrossCheck:
    """KE length is a consistency check on the declared group, never the source of truth."""

    def test_modp_lengths_map_to_their_groups(self) -> None:
        assert groups_for_ke_length(128) == (2,)
        assert groups_for_ke_length(256) == (14,)

    def test_ecp_lengths_map_to_their_groups(self) -> None:
        assert groups_for_ke_length(64) == (19,)
        assert groups_for_ke_length(32) == (31,)

    def test_the_96_byte_collision_is_represented(self) -> None:
        """768-bit MODP (group 1) and 384-bit ECP (group 20) are both 96 bytes."""
        assert set(groups_for_ke_length(96)) == {1, 20}

    def test_table_maps_length_to_a_tuple_of_candidates(self) -> None:
        assert all(isinstance(v, tuple) and v for v in KE_LENGTH_TO_GROUP.values())

    def test_unknown_length_yields_no_candidates(self) -> None:
        assert groups_for_ke_length(7) == ()

    def test_consistent_length_produces_no_warning(self) -> None:
        import warnings

        with warnings.catch_warnings():
            warnings.simplefilter("error")
            result = check_ke_length(declared_group=14, observed_length=256)
        assert result.consistent is True
        assert result.ambiguous is False

    def test_collision_warns_rather_than_raising(self) -> None:
        """The documented behaviour: a warning, never an exception."""
        with pytest.warns(KELengthWarning, match="ambiguous"):
            result = check_ke_length(declared_group=1, observed_length=96)
        assert result.consistent is True
        assert result.ambiguous is True
        assert set(result.candidate_groups) == {1, 20}

    def test_collision_is_ambiguous_for_either_colliding_group(self) -> None:
        with pytest.warns(KELengthWarning):
            result = check_ke_length(declared_group=20, observed_length=96)
        assert result.consistent is True
        assert result.ambiguous is True

    def test_genuine_mismatch_warns_and_retains_both_values(self) -> None:
        with pytest.warns(KELengthWarning, match="mismatch"):
            result = check_ke_length(declared_group=14, observed_length=128)
        assert result.consistent is False
        assert result.declared_group == 14
        assert result.observed_length == 128
        assert result.candidate_groups == (2,)

    def test_unknown_length_warns_but_does_not_claim_a_mismatch(self) -> None:
        with pytest.warns(KELengthWarning, match="unrecognised"):
            result = check_ke_length(declared_group=14, observed_length=7)
        assert result.candidate_groups == ()
        assert result.consistent is False

    def test_check_never_raises_for_arbitrary_input(self) -> None:
        import warnings

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            for group in (-1, 0, 2, 9999):
                for length in (0, 1, 96, 100_000):
                    assert check_ke_length(group, length).observed_length == length

    def test_every_candidate_group_exists_in_the_dh_table(self) -> None:
        for groups in KE_LENGTH_TO_GROUP.values():
            for g in groups:
                assert g in DH_GROUPS
