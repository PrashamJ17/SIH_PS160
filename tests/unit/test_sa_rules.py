"""Tests for forward secrecy and SA rules PFS-01..SA-04 (build plan Step 6.4).

The recurring assertion in this file is that a rule stays *silent* when its input was
not supplied. Most of what these rules assess is invisible to a passive observer, and a
report asserting "PFS is disabled" because nobody said otherwise would be worse than no
report — an operator would act on it.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from ipsec_sentinel.assess.framework import DEFAULT_BASELINE, RuleRegistry
from ipsec_sentinel.assess.rules.sa import (
    PFS_01,
    PFS_02,
    SA_01,
    SA_02,
    SA_03,
    SA_04,
    SA_RULES,
)
from ipsec_sentinel.models import (
    IKEExchange,
    ObservedConfig,
    Proposal,
    Severity,
    Transform,
    TransformType,
)
from ipsec_sentinel.parser.correlate import Tunnel
from ipsec_sentinel.parser.esp import AssembledFlow

BASE = datetime(2026, 9, 6, 12, 0, 0, tzinfo=UTC)


def exchange(
    dh_group: int = 19, lifetime: int | None = None, version: str = "IKEv2"
) -> IKEExchange:
    return IKEExchange(
        initiator_spi="11" * 8,
        responder_spi="00" * 8,
        version=version,
        exchange_type="IKE_SA_INIT",
        ike_lifetime_seconds=lifetime,
        proposals_offered=[
            Proposal(
                number=1,
                protocol="IKE",
                transforms=[
                    Transform(
                        type=TransformType.ENCR, id=20, name="ENCR_AES_GCM_16", key_length=256
                    ),
                    Transform(type=TransformType.DH, id=dh_group, name=f"group {dh_group}"),
                ],
            )
        ],
        timestamp=BASE,
        src_ip="192.0.2.1",
        dst_ip="192.0.2.2",
    )


def flow(sequences: list[int], spi: str = "aaaaaaaa") -> AssembledFlow:
    return AssembledFlow(
        spi=spi,
        src_ip="192.0.2.1",
        dst_ip="192.0.2.2",
        sizes=[100] * len(sequences),
        sequences=list(sequences),
        timestamps=[BASE + timedelta(milliseconds=i) for i in range(len(sequences))],
    )


def tunnel(
    config: ObservedConfig | None = None,
    ike: IKEExchange | None = None,
    flows: list[AssembledFlow] | None = None,
) -> Tunnel:
    return Tunnel(
        tunnel_id="t1",
        endpoints=("192.0.2.1", "192.0.2.2"),
        ike=ike if ike is not None else exchange(),
        flows=flows or [],
        config=config,
    )


class TestSilenceWithoutInput:
    """Every rule that depends on supplied configuration must say nothing without it."""

    @pytest.mark.parametrize("rule", [PFS_01, PFS_02, SA_02, SA_04], ids=lambda r: r.id)
    def test_no_config_means_no_finding(self, rule) -> None:  # type: ignore[no-untyped-def]
        assert rule.evaluate(tunnel()) is None

    @pytest.mark.parametrize("rule", [PFS_01, PFS_02, SA_02, SA_04], ids=lambda r: r.id)
    def test_an_empty_config_means_no_finding(self, rule) -> None:  # type: ignore[no-untyped-def]
        """Supplied but blank is still "not supplied" for every individual field."""
        assert rule.evaluate(tunnel(config=ObservedConfig())) is None

    def test_sa_03_is_silent_without_config_or_duplicates(self) -> None:
        assert SA_03.evaluate(tunnel(flows=[flow([1, 2, 3, 4])])) is None


class TestPFS01:
    def test_it_fires_when_pfs_is_disabled(self) -> None:
        finding = PFS_01.evaluate(tunnel(config=ObservedConfig(pfs_enabled=False)))
        assert finding is not None
        assert finding.severity is Severity.HIGH
        assert finding.confidence is None

    def test_it_is_silent_when_pfs_is_enabled(self) -> None:
        assert PFS_01.evaluate(tunnel(config=ObservedConfig(pfs_enabled=True))) is None

    def test_the_evidence_names_the_source_as_supplied(self) -> None:
        """A reader must be able to tell a wire fact from a supplied one."""
        finding = PFS_01.evaluate(tunnel(config=ObservedConfig(pfs_enabled=False)))
        assert finding is not None
        assert "operator-supplied configuration" in finding.evidence

    def test_a_custom_source_is_carried_into_the_evidence(self) -> None:
        config = ObservedConfig(pfs_enabled=False, source="swanctl.conf on gw-01")
        finding = PFS_01.evaluate(tunnel(config=config))
        assert finding is not None
        assert "swanctl.conf on gw-01" in finding.evidence


class TestPFS02:
    def test_it_fires_when_the_child_group_is_weaker(self) -> None:
        finding = PFS_02.evaluate(
            tunnel(config=ObservedConfig(child_dh_group=2), ike=exchange(dh_group=19))
        )
        assert finding is not None
        assert finding.severity is Severity.MEDIUM
        assert "group 2" in finding.evidence and "group 19" in finding.evidence

    def test_it_is_silent_when_the_groups_match(self) -> None:
        assert (
            PFS_02.evaluate(
                tunnel(config=ObservedConfig(child_dh_group=19), ike=exchange(dh_group=19))
            )
            is None
        )

    def test_it_is_silent_when_the_child_group_is_stronger(self) -> None:
        assert (
            PFS_02.evaluate(
                tunnel(config=ObservedConfig(child_dh_group=21), ike=exchange(dh_group=14))
            )
            is None
        )

    def test_it_is_silent_when_the_ike_group_is_unknown(self) -> None:
        bare = IKEExchange(
            initiator_spi="11" * 8,
            responder_spi="00" * 8,
            version="IKEv2",
            exchange_type="IKE_SA_INIT",
            timestamp=BASE,
            src_ip="192.0.2.1",
            dst_ip="192.0.2.2",
        )
        assert PFS_02.evaluate(tunnel(config=ObservedConfig(child_dh_group=2), ike=bare)) is None


class TestSA01:
    def test_it_fires_on_a_wire_lifetime_over_24_hours(self) -> None:
        """95,040 s is 26.4 h, and this corpus really contains it."""
        finding = SA_01.evaluate(tunnel(ike=exchange(lifetime=95_040, version="IKEv1")))
        assert finding is not None
        assert "26.4 h" in finding.evidence
        assert "read from the IKE handshake" in finding.evidence

    def test_it_is_silent_on_a_wire_lifetime_under_24_hours(self) -> None:
        assert SA_01.evaluate(tunnel(ike=exchange(lifetime=31_680, version="IKEv1"))) is None

    def test_exactly_24_hours_is_not_over(self) -> None:
        assert SA_01.evaluate(tunnel(ike=exchange(lifetime=86_400, version="IKEv1"))) is None

    def test_it_fires_on_a_supplied_lifetime(self) -> None:
        finding = SA_01.evaluate(tunnel(config=ObservedConfig(ike_lifetime_seconds=172_800)))
        assert finding is not None
        assert "operator-supplied configuration" in finding.evidence

    def test_ikev2_without_a_lifetime_is_silent_not_short(self) -> None:
        """RFC 7296 removed lifetimes from the SA payload; absent is not 'fine'."""
        assert SA_01.evaluate(tunnel(ike=exchange(lifetime=None))) is None

    def test_the_wire_takes_precedence_over_configuration(self) -> None:
        """What the peers actually negotiated beats what a document claims."""
        finding = SA_01.evaluate(
            tunnel(
                ike=exchange(lifetime=95_040, version="IKEv1"),
                config=ObservedConfig(ike_lifetime_seconds=3600),
            )
        )
        assert finding is not None
        assert "read from the IKE handshake" in finding.evidence


class TestSA02:
    def test_it_fires_over_eight_hours(self) -> None:
        finding = SA_02.evaluate(tunnel(config=ObservedConfig(child_lifetime_seconds=36_000)))
        assert finding is not None
        assert finding.severity is Severity.LOW

    def test_it_is_silent_at_eight_hours(self) -> None:
        assert SA_02.evaluate(tunnel(config=ObservedConfig(child_lifetime_seconds=28_800))) is None


class TestSA03:
    def test_it_fires_when_configuration_says_anti_replay_is_off(self) -> None:
        finding = SA_03.evaluate(tunnel(config=ObservedConfig(anti_replay_enabled=False)))
        assert finding is not None
        assert finding.severity is Severity.MEDIUM

    def test_it_is_silent_when_anti_replay_is_on_and_nothing_duplicated(self) -> None:
        assert (
            SA_03.evaluate(
                tunnel(config=ObservedConfig(anti_replay_enabled=True), flows=[flow([1, 2, 3])])
            )
            is None
        )

    def test_it_fires_on_observed_duplicate_sequence_numbers(self) -> None:
        """The build plan's explicit observable trigger."""
        finding = SA_03.evaluate(tunnel(flows=[flow([1, 2, 3, 3, 4])]))
        assert finding is not None
        assert "duplicate ESP sequence number" in finding.evidence

    def test_the_observed_case_is_worded_as_observation_not_conclusion(self) -> None:
        """A passive observer cannot tell a replay from network duplication."""
        finding = SA_03.evaluate(tunnel(flows=[flow([1, 2, 2, 3])]))
        assert finding is not None
        assert "consistent with" in finding.evidence
        assert "cannot distinguish" in finding.evidence
        assert "confirm against the device configuration" in finding.evidence

    def test_the_evidence_counts_the_duplicates_and_names_the_spi(self) -> None:
        finding = SA_03.evaluate(tunnel(flows=[flow([1, 1, 1, 2], spi="deadbeef")]))
        assert finding is not None
        assert "deadbeef" in finding.evidence
        assert "2 duplicate" in finding.evidence

    def test_duplicates_across_several_flows_are_one_finding(self) -> None:
        finding = SA_03.evaluate(
            tunnel(flows=[flow([1, 1], spi="aaaaaaaa"), flow([5, 5], spi="bbbbbbbb")])
        )
        assert finding is not None
        assert "2 flow(s)" in finding.evidence


class TestSA04:
    def test_it_fires_on_a_small_window(self) -> None:
        finding = SA_04.evaluate(tunnel(config=ObservedConfig(replay_window=32)))
        assert finding is not None
        assert finding.severity is Severity.LOW

    def test_it_is_silent_at_the_recommended_window(self) -> None:
        assert SA_04.evaluate(tunnel(config=ObservedConfig(replay_window=64))) is None

    def test_it_is_silent_when_anti_replay_is_off_entirely(self) -> None:
        """The window is irrelevant when the check is off; two findings imply two fixes."""
        config = ObservedConfig(replay_window=8, anti_replay_enabled=False)
        assert SA_04.evaluate(tunnel(config=config)) is None
        assert SA_03.evaluate(tunnel(config=config)) is not None


class TestGeneralProperties:
    def test_all_rules_register_cleanly(self) -> None:
        registry = RuleRegistry()
        for rule in SA_RULES:
            registry.register(rule)
        assert len(registry) == 6

    def test_no_rule_fires_on_a_bare_orphan_tunnel(self) -> None:
        orphan = Tunnel(tunnel_id="x", endpoints=("192.0.2.1", "192.0.2.2"))
        for rule in SA_RULES:
            assert rule.evaluate(orphan) is None, rule.id

    def test_every_finding_is_deterministic(self) -> None:
        registry = RuleRegistry()
        for rule in SA_RULES:
            registry.register(rule)
        rich = tunnel(
            config=ObservedConfig(
                pfs_enabled=False,
                child_dh_group=2,
                child_lifetime_seconds=36_000,
                replay_window=16,
            ),
            ike=exchange(dh_group=19, lifetime=95_040, version="IKEv1"),
            flows=[flow([1, 1, 2])],
        )
        findings = registry.evaluate_all(rich, DEFAULT_BASELINE)
        assert len(findings) == 6
        assert all(f.confidence is None for f in findings)

    def test_every_rule_carries_a_citation_and_remediation(self) -> None:
        for rule in SA_RULES:
            assert rule.standard_ref, rule.id
            assert rule.remediation_hint, rule.id
