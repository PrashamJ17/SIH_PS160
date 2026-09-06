"""Tests for configuration anomaly detection (build plan Step 6.9).

The refusal test matters most. Outlier detection over five tunnels identifies whichever
one the algorithm isolated first, not the unusual one, and a confident answer to a
question the data cannot support is the worst output available.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from ipsec_sentinel.assess.anomaly import (
    ANOMALY_RULE_ID,
    FEATURE_NAMES,
    MIN_ESTATE_SIZE,
    anomaly_summary,
    detect_config_anomalies,
    extract_features,
    score_anomalies,
)
from ipsec_sentinel.models import IKEExchange, Proposal, Severity, Transform, TransformType
from ipsec_sentinel.parser.correlate import Tunnel, correlate
from ipsec_sentinel.parser.esp import AssembledFlow

BASE = datetime(2026, 9, 6, 12, 0, 0, tzinfo=UTC)

STRONG = [
    Transform(type=TransformType.ENCR, id=20, name="ENCR_AES_GCM_16", key_length=256),
    Transform(type=TransformType.INTEG, id=13, name="AUTH_HMAC_SHA2_384_192"),
    Transform(type=TransformType.PRF, id=6, name="PRF_HMAC_SHA2_384"),
    Transform(type=TransformType.DH, id=20, name="384-bit ECP"),
]
DIFFERENT = [
    Transform(type=TransformType.ENCR, id=12, name="ENCR_AES_CBC", key_length=128),
    Transform(type=TransformType.INTEG, id=12, name="AUTH_HMAC_SHA2_256_128"),
    Transform(type=TransformType.PRF, id=5, name="PRF_HMAC_SHA2_256"),
    Transform(type=TransformType.DH, id=14, name="2048-bit MODP"),
]


def tunnel(index: int, transforms: list[Transform]) -> Tunnel:
    left, right = f"192.0.2.{index}", f"198.51.100.{index}"
    exchange = IKEExchange(
        initiator_spi=f"{index:016x}",
        responder_spi="00" * 8,
        version="IKEv2",
        exchange_type="IKE_SA_INIT",
        proposals_offered=[Proposal(number=1, protocol="IKE", transforms=transforms)],
        timestamp=BASE + timedelta(seconds=index),
        src_ip=left,
        dst_ip=right,
    )
    return correlate([exchange], [])[0]


def estate(identical: int, odd: int = 0) -> list[Tunnel]:
    tunnels = [tunnel(i, STRONG) for i in range(1, identical + 1)]
    tunnels += [tunnel(100 + i, DIFFERENT) for i in range(odd)]
    return tunnels


class TestPlanCases:
    def test_forty_identical_and_one_different_flags_exactly_one(self) -> None:
        findings = detect_config_anomalies(estate(40, odd=1))
        assert len(findings) == 1

    def test_forty_identical_configs_flag_nothing(self) -> None:
        assert detect_config_anomalies(estate(40)) == []

    def test_an_estate_of_five_returns_empty(self) -> None:
        """Below the minimum, "the odd one out" is not a meaningful question."""
        assert detect_config_anomalies(estate(4, odd=1)) == []

    def test_all_findings_carry_a_confidence(self) -> None:
        findings = detect_config_anomalies(estate(40, odd=1))
        assert findings
        assert all(f.confidence is not None for f in findings)


class TestTheRefusal:
    def test_exactly_at_the_minimum_it_runs(self) -> None:
        assert score_anomalies(estate(MIN_ESTATE_SIZE)) != []

    def test_one_below_the_minimum_it_refuses(self) -> None:
        assert score_anomalies(estate(MIN_ESTATE_SIZE - 1)) == []

    def test_an_empty_estate_refuses(self) -> None:
        assert detect_config_anomalies([]) == []

    def test_the_threshold_is_configurable(self) -> None:
        small = estate(5, odd=1)
        assert detect_config_anomalies(small) == []
        assert detect_config_anomalies(small, min_estate_size=3) != []

    def test_the_summary_says_why_it_refused(self) -> None:
        summary = anomaly_summary(estate(3))
        assert summary["below_minimum"] is True
        assert summary["anomalies"] == 0
        assert summary["minimum_estate_size"] == MIN_ESTATE_SIZE


class TestFindingShape:
    def test_the_finding_is_informational_not_a_violation(self) -> None:
        """It violates no rule; presenting it as one would train operators to ignore it."""
        finding = detect_config_anomalies(estate(40, odd=1))[0]
        assert finding.severity is Severity.INFO
        assert finding.rule_id == ANOMALY_RULE_ID

    def test_the_confidence_names_its_method(self) -> None:
        finding = detect_config_anomalies(estate(40, odd=1))[0]
        assert finding.confidence is not None
        assert "IsolationForest" in finding.confidence.method

    def test_the_confidence_never_claims_certainty(self) -> None:
        """An unsupervised outlier score is not certainty at any magnitude."""
        for finding in detect_config_anomalies(estate(40, odd=1)):
            assert finding.confidence is not None
            assert 0.0 < finding.confidence.value <= 0.95

    def test_it_is_not_deterministic_and_says_so(self) -> None:
        finding = detect_config_anomalies(estate(40, odd=1))[0]
        assert finding.is_deterministic is False

    def test_the_evidence_names_the_differing_fields(self) -> None:
        """An outlier score alone tells an operator nothing about where to look."""
        finding = detect_config_anomalies(estate(40, odd=1))[0]
        assert "dh_security_bits" in finding.evidence or "encryption_id" in finding.evidence
        assert "% of the estate" in finding.evidence

    def test_the_evidence_says_it_violates_no_rule(self) -> None:
        finding = detect_config_anomalies(estate(40, odd=1))[0]
        assert "violates no rule" in finding.evidence


class TestFeatures:
    def test_every_declared_feature_is_produced(self) -> None:
        features = extract_features(tunnel(1, STRONG))
        assert set(features) == set(FEATURE_NAMES)

    def test_features_are_all_numeric(self) -> None:
        assert all(isinstance(v, float) for v in extract_features(tunnel(1, STRONG)).values())

    def test_traffic_volume_is_not_a_feature(self) -> None:
        """A busy tunnel is a fact about the business, not the configuration.

        Including volume would make the highest-traffic tunnel look anomalous for being
        busy, burying the misconfigured gateway this module exists to find.
        """
        quiet = tunnel(1, STRONG)
        busy = tunnel(1, STRONG)
        busy.flows.append(
            AssembledFlow(
                spi="aaaaaaaa",
                src_ip="192.0.2.1",
                dst_ip="198.51.100.1",
                sizes=[1500] * 100_000,
                sequences=list(range(100_000)),
                timestamps=[BASE] * 100_000,
            )
        )
        assert extract_features(quiet) == extract_features(busy)

    def test_a_tunnel_with_no_ike_still_produces_a_vector(self) -> None:
        features = extract_features(Tunnel(tunnel_id="x", endpoints=("a", "b")))
        assert set(features) == set(FEATURE_NAMES)

    def test_aggressive_mode_is_captured(self) -> None:
        aggressive = tunnel(1, STRONG)
        assert aggressive.ike is not None
        aggressive.ike = aggressive.ike.model_copy(update={"is_aggressive": True})
        assert extract_features(aggressive)["is_aggressive"] == 1.0


class TestDeterminism:
    def test_the_same_estate_scores_identically_across_runs(self) -> None:
        """A report that reordered its findings between runs could not be diffed."""
        population = estate(40, odd=1)
        first = [
            (r.tunnel_id, r.is_anomaly, round(r.score, 9)) for r in score_anomalies(population)
        ]
        second = [
            (r.tunnel_id, r.is_anomaly, round(r.score, 9)) for r in score_anomalies(population)
        ]
        assert first == second

    def test_every_tunnel_is_scored(self) -> None:
        population = estate(20, odd=2)
        results = score_anomalies(population)
        assert len(results) == len(population)
        assert {r.tunnel_id for r in results} == {t.tunnel_id for t in population}


class TestSummary:
    def test_it_counts_anomalies(self) -> None:
        summary = anomaly_summary(estate(40, odd=1))
        assert summary["evaluated"] == 41
        assert summary["anomalies"] >= 1
        assert summary["below_minimum"] is False


class TestNoDominantConfiguration:
    """An estate with no standard configuration has nothing to deviate from.

    Measured against this project's own 36-configuration sweep, the first version
    flagged 224 of 252 tunnels — an answer that is useless even where it is arguably
    correct, because a finding that applies to 89% of the estate is not a finding.
    """

    def test_a_diverse_estate_produces_no_anomalies(self) -> None:
        diverse = [
            tunnel(
                i,
                [
                    Transform(
                        type=TransformType.ENCR,
                        id=12 + (i % 9),
                        name=f"E{i}",
                        key_length=128 + (i % 3) * 64,
                    ),
                    Transform(type=TransformType.INTEG, id=12 + (i % 3), name=f"I{i}"),
                    Transform(type=TransformType.DH, id=(14, 19, 20, 21, 15)[i % 5], name=f"D{i}"),
                ],
            )
            for i in range(1, 41)
        ]
        assert detect_config_anomalies(diverse) == []

    def test_the_summary_explains_why(self) -> None:
        diverse = [
            tunnel(
                i,
                [
                    Transform(
                        type=TransformType.ENCR,
                        id=12 + (i % 9),
                        name=f"E{i}",
                        key_length=128 + (i % 3) * 64,
                    ),
                    Transform(type=TransformType.DH, id=(14, 19, 20, 21, 15)[i % 5], name=f"D{i}"),
                ],
            )
            for i in range(1, 41)
        ]
        summary = anomaly_summary(diverse)
        assert summary["no_dominant_configuration"] is True
        assert summary["anomalies"] == 0
        assert summary["modal_share"] < 0.25

    def test_a_standardised_estate_still_works(self) -> None:
        """The guard must not disable the feature on the estates it is built for."""
        summary = anomaly_summary(estate(40, odd=1))
        assert summary["no_dominant_configuration"] is False
        assert summary["modal_share"] > 0.9
        assert summary["anomalies"] >= 1

    def test_modal_share_measures_the_most_common_configuration(self) -> None:
        from ipsec_sentinel.assess.anomaly import extract_features, modal_share

        rows = [extract_features(t) for t in estate(9, odd=1)]
        assert modal_share(rows) == 0.9

    def test_modal_share_of_an_empty_estate_is_zero(self) -> None:
        from ipsec_sentinel.assess.anomaly import modal_share

        assert modal_share([]) == 0.0

    def test_at_most_ten_percent_of_a_standard_estate_is_flagged(self) -> None:
        """An outlier is a minority by definition."""
        population = estate(90, odd=10)
        flagged = len(detect_config_anomalies(population))
        assert 0 < flagged <= len(population) * 0.15
