"""Tests for compliance baselines (build plan Step 6.6).

The load-bearing test here is `test_cnsa_and_nist_grade_the_same_tunnel_differently`.
Shipping seven baselines that are copies of each other with different names would be
worse than shipping one, because it would let a report claim compliance against an
authority whose requirements were never actually encoded.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from ipsec_sentinel.assess.baselines.schema import (
    BASELINE_DIR,
    Baseline,
    BaselineError,
    baseline_files,
    get_baseline,
    load_baseline_file,
    load_baselines,
    validate_against_registry,
)
from ipsec_sentinel.assess.rules import ALL_RULES, default_registry
from ipsec_sentinel.models import (
    IKEExchange,
    ObservedConfig,
    Proposal,
    Severity,
    Transform,
    TransformType,
)
from ipsec_sentinel.parser.correlate import Tunnel, correlate

BASE = datetime(2026, 9, 6, 12, 0, 0, tzinfo=UTC)

EXPECTED_BASELINES = {
    "nist_800_77r1",
    "rfc_8221_8247",
    "cnsa",
    "bsi_tr02102_3",
    "itsar",
    "certin",
}


def aes128_tunnel() -> Tunnel:
    """AES-128 with a 2048-bit group: fine under NIST, undersized under CNSA."""
    exchange = IKEExchange(
        initiator_spi="11" * 8,
        responder_spi="00" * 8,
        version="IKEv2",
        exchange_type="IKE_SA_INIT",
        proposals_offered=[
            Proposal(
                number=1,
                protocol="IKE",
                transforms=[
                    Transform(type=TransformType.ENCR, id=12, name="ENCR_AES_CBC", key_length=128),
                    Transform(type=TransformType.INTEG, id=12, name="AUTH_HMAC_SHA2_256_128"),
                    Transform(type=TransformType.DH, id=14, name="2048-bit MODP"),
                ],
            )
        ],
        timestamp=BASE,
        src_ip="192.0.2.1",
        dst_ip="192.0.2.2",
    )
    tunnel = correlate([exchange], [])[0]
    tunnel.config = ObservedConfig(pfs_enabled=True, child_lifetime_seconds=21_600)
    return tunnel


class TestSchemaValidation:
    def test_every_shipped_baseline_validates(self) -> None:
        for path in baseline_files():
            assert isinstance(load_baseline_file(path), Baseline), path.name

    def test_the_expected_baselines_are_all_present(self) -> None:
        assert set(load_baselines()) == EXPECTED_BASELINES

    def test_an_unknown_field_is_rejected_rather_than_ignored(self, tmp_path: Path) -> None:
        """A typo in a compliance document must not sit there looking like policy."""
        bad = tmp_path / "bad.yaml"
        bad.write_text(
            yaml.safe_dump(
                {
                    "id": "x",
                    "name": "x",
                    "authority": "x",
                    "reference": "x",
                    "description": "x",
                    "verified": True,
                    "provenance": "x",
                    "rules": ["CRY-01"],
                    "typo_field": 1,
                }
            )
        )
        with pytest.raises(BaselineError, match="typo_field"):
            load_baseline_file(bad)

    def test_a_severity_override_for_an_unselected_rule_is_rejected(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text(
            yaml.safe_dump(
                {
                    "id": "x",
                    "name": "x",
                    "authority": "x",
                    "reference": "x",
                    "description": "x",
                    "verified": True,
                    "provenance": "x",
                    "rules": ["CRY-01"],
                    "severity_overrides": {"CRY-09": "high"},
                }
            )
        )
        with pytest.raises(BaselineError, match="would have no effect"):
            load_baseline_file(bad)

    def test_a_duplicated_rule_id_is_rejected(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text(
            yaml.safe_dump(
                {
                    "id": "x",
                    "name": "x",
                    "authority": "x",
                    "reference": "x",
                    "description": "x",
                    "verified": True,
                    "provenance": "x",
                    "rules": ["CRY-01", "CRY-01"],
                }
            )
        )
        with pytest.raises(BaselineError, match="more than once"):
            load_baseline_file(bad)

    def test_an_empty_rule_list_is_rejected(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text(
            yaml.safe_dump(
                {
                    "id": "x",
                    "name": "x",
                    "authority": "x",
                    "reference": "x",
                    "description": "x",
                    "verified": True,
                    "provenance": "x",
                    "rules": [],
                }
            )
        )
        with pytest.raises(BaselineError):
            load_baseline_file(bad)

    def test_a_malformed_file_raises_a_clear_error(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text("just a string, not a mapping")
        with pytest.raises(BaselineError, match="mapping"):
            load_baseline_file(bad)

    def test_an_unknown_baseline_lists_the_alternatives(self) -> None:
        with pytest.raises(BaselineError, match="available"):
            get_baseline("does-not-exist")


class TestRuleReferencesAreReal:
    def test_every_referenced_rule_id_exists(self) -> None:
        """A baseline naming a rule nobody implemented would silently under-assess."""
        known = {rule.id for rule in ALL_RULES}
        missing: dict[str, list[str]] = {}
        for baseline_id, baseline in load_baselines().items():
            absent = validate_against_registry(baseline, known)
            if absent:
                missing[baseline_id] = absent
        assert not missing, f"baselines reference rules that do not exist: {missing}"

    def test_every_implemented_rule_is_used_by_at_least_one_baseline(self) -> None:
        """A rule in no baseline never runs — coverage that looks real and is not."""
        used = {rid for b in load_baselines().values() for rid in b.rules}
        unused = sorted({rule.id for rule in ALL_RULES} - used)
        assert not unused, f"rules implemented but in no baseline: {unused}"


class TestProvenanceDisclosure:
    def test_every_baseline_declares_whether_it_was_verified(self) -> None:
        for baseline in load_baselines().values():
            assert isinstance(baseline.verified, bool)
            assert baseline.provenance

    def test_the_indian_baselines_are_marked_unverified(self) -> None:
        """They were encoded from public description, not a controlling copy.

        If that ever changes, this test should change with it — deliberately, in a
        commit that says so, rather than by drifting.
        """
        for baseline_id in ("itsar", "certin"):
            assert get_baseline(baseline_id).verified is False

    def test_an_unverified_baseline_must_explain_what_to_check(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text(
            yaml.safe_dump(
                {
                    "id": "x",
                    "name": "x",
                    "authority": "x",
                    "reference": "x",
                    "description": "x",
                    "verified": False,
                    "provenance": "dunno",
                    "rules": ["CRY-01"],
                }
            )
        )
        with pytest.raises(BaselineError, match="provenance must explain"):
            load_baseline_file(bad)

    def test_the_unverified_baselines_say_so_in_capitals(self) -> None:
        """A reader skimming the file must not miss it."""
        for baseline_id in ("itsar", "certin"):
            assert "NOT FROM A VERIFIED COPY" in get_baseline(baseline_id).provenance


class TestBaselinesAreDifferentiated:
    def test_cnsa_and_nist_grade_the_same_tunnel_differently(self) -> None:
        """The test that proves these are policies, not copies with different names."""
        tunnel = aes128_tunnel()
        registry = default_registry()
        cnsa = registry.run(tunnel, get_baseline("cnsa"))
        nist = registry.run(tunnel, get_baseline("nist_800_77r1"))

        cnsa_ids = {f.rule_id for f in cnsa.findings}
        nist_ids = {f.rule_id for f in nist.findings}
        assert cnsa_ids != nist_ids, "CNSA and NIST produced identical findings"
        assert "CRY-10" in cnsa_ids, "CNSA requires 256-bit keys; AES-128 must fail it"
        assert "CRY-10" not in nist_ids, "NIST accepts AES-128"

    def test_cnsa_demands_a_stronger_group_than_nist(self) -> None:
        tunnel = aes128_tunnel()
        registry = default_registry()
        cnsa_ids = {f.rule_id for f in registry.run(tunnel, get_baseline("cnsa")).findings}
        nist_ids = {f.rule_id for f in registry.run(tunnel, get_baseline("nist_800_77r1")).findings}
        assert "CRY-11" in cnsa_ids, "2048-bit MODP is below CNSA's 3072-bit requirement"
        assert "CRY-11" not in nist_ids, "2048-bit MODP meets NIST's requirement"

    def test_no_two_baselines_have_identical_rule_sets_and_thresholds(self) -> None:
        seen: dict[tuple[object, ...], str] = {}
        for baseline_id, baseline in load_baselines().items():
            signature = (
                tuple(sorted(baseline.rules)),
                tuple(sorted(baseline.severity_overrides.items())),
                baseline.minimums.model_dump_json(),
            )
            assert signature not in seen, f"{baseline_id} is identical to {seen.get(signature)}"
            seen[signature] = baseline_id

    def test_severity_overrides_actually_change_a_finding(self) -> None:
        tunnel = aes128_tunnel()
        registry = default_registry()
        cnsa = {f.rule_id: f for f in registry.run(tunnel, get_baseline("cnsa")).findings}
        assert cnsa["CRY-10"].severity is Severity.HIGH, "CNSA raises CRY-10 to high"
        assert cnsa["CRY-11"].severity is Severity.CRITICAL

    def test_an_override_never_changes_whether_a_finding_is_true(self) -> None:
        """Severity is how urgent an authority considers it, not whether it happened."""
        tunnel = aes128_tunnel()
        registry = default_registry()
        cnsa = registry.run(tunnel, get_baseline("cnsa"))
        assert all(f.confidence is None for f in cnsa.findings)


class TestThresholdBinding:
    def test_a_baseline_threshold_replaces_the_rule_default(self) -> None:
        from ipsec_sentinel.assess.rules.sa import SA_02

        assert SA_02.bind(get_baseline("cnsa")).limit == 14_400
        assert SA_02.bind(get_baseline("nist_800_77r1")).limit == 28_800

    def test_an_omitted_threshold_leaves_the_rule_default(self) -> None:
        """Omitted means "this authority does not specify it", not zero."""
        from ipsec_sentinel.assess.rules.sa import SA_02

        rfc = get_baseline("rfc_8221_8247")
        assert rfc.minimums.child_lifetime_seconds is None
        assert SA_02.bind(rfc).limit == SA_02.limit

    def test_a_baseline_runs_only_the_rules_it_selects(self) -> None:
        registry = default_registry()
        selected = {rule.id for rule in registry.select(get_baseline("rfc_8221_8247"))}
        assert selected == set(get_baseline("rfc_8221_8247").rules)
        assert "SA-01" not in selected


class TestITSAR:
    def test_it_loads(self) -> None:
        assert get_baseline("itsar").id == "itsar"

    def test_it_references_at_least_fifteen_rules(self) -> None:
        """The build plan's explicit acceptance criterion."""
        assert len(get_baseline("itsar").rules) >= 15

    def test_it_names_the_issuing_authority(self) -> None:
        assert (
            "NCCS" in get_baseline("itsar").authority
            or "Telecommunications" in get_baseline("itsar").authority
        )

    def test_it_requires_forward_secrecy(self) -> None:
        assert get_baseline("itsar").minimums.require_pfs is True


class TestCustomExample:
    def test_the_example_exists_and_is_not_loaded_as_a_baseline(self) -> None:
        """It ships as documentation; loading it would inject a fake authority."""
        example = BASELINE_DIR / "custom.yaml.example"
        assert example.exists()
        assert "custom" not in load_baselines()

    def test_the_example_is_valid_yaml_that_would_load_if_renamed(self, tmp_path: Path) -> None:
        """A broken template is worse than none — someone will copy it."""
        target = tmp_path / "custom.yaml"
        target.write_text((BASELINE_DIR / "custom.yaml.example").read_text())
        baseline = load_baseline_file(target)
        assert baseline.id == "custom"

    def test_every_rule_the_example_lists_exists(self) -> None:
        target = BASELINE_DIR / "custom.yaml.example"
        baseline = Baseline.model_validate(yaml.safe_load(target.read_text()))
        assert validate_against_registry(baseline, {r.id for r in ALL_RULES}) == []
