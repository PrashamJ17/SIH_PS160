"""Tests for configuration matrix expansion (build plan Step 1.5)."""

from __future__ import annotations

import pytest
import yaml

from testbed.orchestrate.config_gen import is_aead
from testbed.orchestrate.matrix import (
    DEFAULT_MATRIX_PATH,
    MatrixError,
    expand_matrix,
    load_matrix,
)

MATRIX = load_matrix()
EXPANDED = expand_matrix()
CONFIGS = [lc.config for lc in EXPANDED]


class TestMatrixDefinition:
    def test_matrix_file_parses(self) -> None:
        assert isinstance(yaml.safe_load(DEFAULT_MATRIX_PATH.read_text()), dict)

    def test_missing_keys_are_rejected(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        bad = tmp_path / "bad.yaml"
        bad.write_text("ike_versions: [ikev2]\n")
        with pytest.raises(MatrixError, match="missing keys"):
            load_matrix(bad)

    def test_non_mapping_is_rejected(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        bad = tmp_path / "bad.yaml"
        bad.write_text("- just\n- a\n- list\n")
        with pytest.raises(MatrixError, match="mapping"):
            load_matrix(bad)


class TestExpansionSize:
    def test_produces_exactly_the_target_count(self) -> None:
        assert len(CONFIGS) == MATRIX["sampling"]["target_count"]

    def test_all_configs_are_distinct(self) -> None:
        ids = [c.config_id() for c in CONFIGS]
        assert len(ids) == len(set(ids)), "expansion contains duplicates"

    def test_expansion_is_deterministic(self) -> None:
        """A sweep must be resumable, which requires a stable cell list."""
        again = [c.config_id() for c in (lc.config for lc in expand_matrix())]
        assert again == [c.config_id() for c in CONFIGS]


class TestValidity:
    def test_no_aead_cipher_is_paired_with_a_separate_integrity_algorithm(self) -> None:
        for c in CONFIGS:
            if is_aead(c.encryption):
                assert c.integrity is None, f"{c.encryption} paired with {c.integrity}"

    def test_every_non_aead_cipher_has_an_integrity_algorithm(self) -> None:
        for c in CONFIGS:
            if not is_aead(c.encryption):
                assert c.integrity is not None, f"{c.encryption} has no integrity algorithm"

    def test_no_ikev2_config_is_marked_aggressive(self) -> None:
        for c in CONFIGS:
            if c.ike_version == "ikev2":
                assert c.aggressive is False

    def test_curve25519_never_appears_with_ikev1(self) -> None:
        """Curve25519 is specified for IKEv2; an IKEv1 cell would waste a sweep slot."""
        for c in CONFIGS:
            if c.dh_group == "curve25519":
                assert c.ike_version == "ikev2"

    def test_pfs_off_means_no_child_group(self) -> None:
        for c in CONFIGS:
            if not c.pfs:
                assert c.effective_child_dh_group is None

    def test_every_config_renders(self) -> None:
        from testbed.orchestrate.config_gen import render_swanctl_conf

        for c in CONFIGS:
            for role in ("left", "right"):
                rendered = render_swanctl_conf(c, role)  # type: ignore[arg-type]
                assert rendered.count("{") == rendered.count("}")
                assert "proposals = " in rendered


class TestAnchors:
    def test_all_five_anchor_labels_are_present(self) -> None:
        labels = {lc.label for lc in EXPANDED if lc.label}
        assert labels == {"worst", "weak", "medium", "good", "best"}

    def test_worst_anchor_is_the_canonical_bad_config(self) -> None:
        worst = next(lc.config for lc in EXPANDED if lc.label == "worst")
        assert worst.encryption == "3des"
        assert worst.integrity == "md5"
        assert worst.dh_group == "modp1024"
        assert worst.pfs is False
        assert worst.ike_version == "ikev1"
        assert worst.aggressive is True

    def test_best_anchor_is_aead_with_a_modern_group(self) -> None:
        best = next(lc.config for lc in EXPANDED if lc.label == "best")
        assert best.encryption == "aes256gcm16"
        assert best.integrity is None
        assert best.dh_group == "curve25519"
        assert best.pfs is True

    def test_anchors_are_ordered_first(self) -> None:
        assert all(lc.label for lc in EXPANDED[:5])


class TestBalance:
    """The automated guard against the confound trap."""

    def test_every_dh_group_appears_at_least_once(self) -> None:
        present = {c.dh_group for c in CONFIGS}
        assert present == set(MATRIX["dh_groups"]), (
            f"missing DH groups: {set(MATRIX['dh_groups']) - present}"
        )

    def test_every_encryption_appears_with_at_least_two_dh_groups(self) -> None:
        """Otherwise a classifier could read cipher artifacts while appearing to read
        traffic shape — the confound the master document warns is most fatal."""
        by_encryption: dict[str, set[str]] = {}
        for c in CONFIGS:
            by_encryption.setdefault(c.encryption, set()).add(c.dh_group)
        for encryption, groups in by_encryption.items():
            assert len(groups) >= 2, f"{encryption} appears with only {groups}"

    def test_every_encryption_in_the_matrix_is_used(self) -> None:
        expected = {e["name"] for e in MATRIX["encryptions"]}
        assert {c.encryption for c in CONFIGS} == expected

    def test_both_ike_versions_appear(self) -> None:
        assert {c.ike_version for c in CONFIGS} == {"ikev1", "ikev2"}

    def test_both_modes_appear(self) -> None:
        assert {c.mode for c in CONFIGS} == {"tunnel", "transport"}

    def test_pfs_appears_both_on_and_off(self) -> None:
        assert {c.pfs for c in CONFIGS} == {True, False}

    def test_transport_mode_uses_host_traffic_selectors(self) -> None:
        """Transport mode is host-to-host; subnet selectors would not establish."""
        from testbed.orchestrate.config_gen import render_swanctl_conf

        transport = next(c for c in CONFIGS if c.mode == "transport" and c.ip_version == 4)
        rendered = render_swanctl_conf(transport, "left")
        assert "local_ts  = 10.100.0.2/32" in rendered
        assert "10.1.0.0/24" not in rendered


class TestOverConstrainedMatrix:
    def test_impossible_target_fails_loudly(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        """An unreachable target must raise, not loop forever."""
        data = yaml.safe_load(DEFAULT_MATRIX_PATH.read_text())
        data["encryptions"] = [{"name": "aes256gcm16", "aead": True, "keylen": 256}]
        data["dh_groups"] = ["modp2048"]
        data["ike_versions"] = ["ikev2"]
        data["modes"] = ["tunnel"]
        data["pfs"] = [True]
        data["ip_versions"] = [4]
        data["lifetimes"] = {"ike_s": [14400], "child_s": [3600]}
        data["sampling"]["must_include"] = []
        data["sampling"]["target_count"] = 500
        path = tmp_path / "tiny.yaml"
        path.write_text(yaml.safe_dump(data))
        with pytest.raises(MatrixError, match="too constrained"):
            expand_matrix(path)
