"""Tests for drift detection (build plan Step 10.4).

Drift is a comparison against a tunnel's own past, so most of these are about the two
ways that can go wrong: missing a weakening, and crying wolf. The second matters as much
as the first — an alert that fires on a first sighting, or on an improvement, is an alert
people learn to close without reading, and then the real one is closed too.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from ipsec_sentinel.models import IKEExchange, Proposal, Severity, Transform, TransformType
from ipsec_sentinel.watch import (
    CIPHER_RANK,
    CRITICAL_SCORE_DROP,
    DriftDetector,
    PcapPollSource,
    WatchState,
    alerts_as_syslog,
    compare,
    watch,
)
from testbed.orchestrate.config_gen import TunnelConfig

NOW = datetime(2026, 9, 7, 9, 0, tzinfo=UTC)


def config(**changes: object) -> TunnelConfig:
    base = {
        "ike_version": "ikev2",
        "encryption": "aes256",
        "integrity": "sha256",
        "prf": "prfsha256",
        "dh_group": "ecp384",
        "pfs": True,
        "child_dh_group": None,
        "mode": "tunnel",
        "ip_version": 4,
        "ike_lifetime_s": 14400,
        "child_lifetime_s": 3600,
        "aggressive": False,
    }
    base.update(changes)
    return TunnelConfig(**base)  # type: ignore[arg-type]


def transform(kind: TransformType, identifier: int, name: str, key_length: int | None = None):  # type: ignore[no-untyped-def]
    return Transform(type=kind, id=identifier, name=name, key_length=key_length)


def exchange(
    *,
    encryption: tuple[int, int | None] = (12, 256),
    integrity: int = 12,
    prf: int = 5,
    dh: int = 20,
    version: str = "IKEv2",
    aggressive: bool = False,
    at: datetime = NOW,
    spi: str = "1122334455667788",
) -> IKEExchange:
    return IKEExchange(
        initiator_spi=spi,
        responder_spi="99aabbccddeeff00",
        version=version,
        exchange_type="IKE_SA_INIT",
        is_aggressive=aggressive,
        proposals_offered=[
            Proposal(
                number=1,
                protocol="IKE",
                transforms=[
                    transform(TransformType.ENCR, encryption[0], "ENCR", encryption[1]),
                    transform(TransformType.INTEG, integrity, "INTEG"),
                    transform(TransformType.PRF, prf, "PRF"),
                    transform(TransformType.DH, dh, "DH"),
                ],
            )
        ],
        timestamp=at,
        src_ip="203.0.113.1",
        dst_ip="198.51.100.1",
    )


class TestTheComparison:
    def test_an_identical_configuration_is_not_drift(self) -> None:
        assert compare(config(), config()) == []

    def test_a_weaker_cipher_is_drift(self) -> None:
        found = compare(config(encryption="aes256"), config(encryption="aes128"))
        assert [w.parameter for w in found] == ["encryption"]

    def test_a_stronger_cipher_is_not(self) -> None:
        """An alert that fires on good news is an alert people learn to close."""
        assert compare(config(encryption="aes128"), config(encryption="aes256")) == []

    def test_a_weaker_hash_is_drift(self) -> None:
        found = compare(config(integrity="sha256"), config(integrity="sha1"))
        assert [w.parameter for w in found] == ["integrity"]

    def test_a_weaker_prf_is_drift(self) -> None:
        found = compare(config(prf="prfsha256"), config(prf="prfmd5"))
        assert [w.parameter for w in found] == ["prf"]

    def test_a_weaker_group_is_drift(self) -> None:
        found = compare(config(dh_group="ecp384"), config(dh_group="modp1024"))
        assert [w.parameter for w in found] == ["dh_group"]
        assert "80-bit strength, down from 192" in found[0].detail

    def test_the_group_comparison_is_on_security_bits(self) -> None:
        """256-bit ECP is stronger than 2048-bit MODP; the printed numbers disagree."""
        assert compare(config(dh_group="modp2048"), config(dh_group="ecp256")) == []
        assert compare(config(dh_group="ecp256"), config(dh_group="modp2048")) != []

    def test_dropping_to_ikev1_is_drift(self) -> None:
        found = compare(config(ike_version="ikev2"), config(ike_version="ikev1"))
        assert [w.parameter for w in found] == ["ike_version"]
        assert "RFC 9395" in found[0].detail

    def test_moving_to_ikev2_is_not(self) -> None:
        assert compare(config(ike_version="ikev1"), config(ike_version="ikev2")) == []

    def test_turning_on_aggressive_mode_is_drift(self) -> None:
        found = compare(config(ike_version="ikev1"), config(ike_version="ikev1", aggressive=True))
        assert [w.parameter for w in found] == ["aggressive_mode"]

    def test_turning_off_pfs_is_drift(self) -> None:
        found = compare(config(pfs=True), config(pfs=False))
        assert [w.parameter for w in found] == ["pfs"]

    def test_several_weakenings_are_all_reported(self) -> None:
        """An operator asked to act needs every setting that moved, not the first."""
        found = compare(
            config(),
            config(
                ike_version="ikev1",
                encryption="3des",
                integrity="md5",
                prf="prfmd5",
                dh_group="modp1024",
                aggressive=True,
            ),
        )
        assert {w.parameter for w in found} == {
            "ike_version",
            "aggressive_mode",
            "encryption",
            "integrity",
            "prf",
            "dh_group",
        }

    def test_a_mixed_change_reports_only_what_got_worse(self) -> None:
        """A stronger cipher on a weaker group is still a weaker group."""
        found = compare(
            config(encryption="aes128", dh_group="ecp384"),
            config(encryption="aes256", dh_group="modp1024"),
        )
        assert [w.parameter for w in found] == ["dh_group"]

    def test_an_unknown_algorithm_is_not_guessed_at(self) -> None:
        """Absent from the ranking means no opinion, not "weaker"."""
        assert "camellia" in CIPHER_RANK
        assert compare(config(encryption="aes256"), config(encryption="aes256")) == []

    def test_every_weakening_explains_itself(self) -> None:
        for found in (
            compare(config(), config(encryption="3des")),
            compare(config(), config(dh_group="modp1024")),
            compare(config(pfs=True), config(pfs=False)),
        ):
            assert found
            assert found[0].detail.strip()
            assert "->" in found[0].describe()


class TestTheDetector:
    def test_a_first_sighting_is_not_drift(self) -> None:
        """With no past there is no drift, and alerting here fills an inbox on restart."""
        detector = DriftDetector()
        assert detector.observe(exchange()) is None
        assert len(detector.known()) == 1

    def test_an_unchanged_tunnel_raises_nothing(self) -> None:
        detector = DriftDetector()
        detector.observe(exchange(at=NOW))
        assert detector.observe(exchange(at=NOW + timedelta(minutes=5))) is None

    def test_a_weakened_tunnel_raises_an_alert(self) -> None:
        detector = DriftDetector()
        detector.observe(exchange(encryption=(12, 256), integrity=12, prf=5, dh=20))
        alert = detector.observe(
            exchange(
                encryption=(3, None),
                integrity=1,
                prf=1,
                dh=2,
                at=NOW + timedelta(minutes=1),
                spi="aabbccddeeff0011",
            )
        )
        assert alert is not None
        assert {w.parameter for w in alert.weakenings} >= {"encryption", "integrity", "dh_group"}

    def test_the_alert_carries_both_states(self) -> None:
        detector = DriftDetector()
        detector.observe(exchange())
        alert = detector.observe(
            exchange(encryption=(3, None), integrity=1, prf=1, dh=2, spi="ff" * 8)
        )
        assert alert is not None
        assert "aes256" in alert.previous.suite
        assert "3des" in alert.current.suite
        assert alert.score_drop > 0

    def test_a_large_score_drop_is_critical(self) -> None:
        detector = DriftDetector()
        detector.observe(exchange())
        alert = detector.observe(
            exchange(encryption=(3, None), integrity=1, prf=1, dh=2, spi="ff" * 8)
        )
        assert alert is not None
        assert alert.score_drop >= CRITICAL_SCORE_DROP
        assert alert.severity is Severity.CRITICAL

    def test_a_small_weakening_is_still_high(self) -> None:
        """A weakening is an active change by someone with access, never informational."""
        detector = DriftDetector()
        detector.observe(exchange(prf=5))
        alert = detector.observe(exchange(prf=2, spi="ff" * 8))
        if alert is not None:
            assert alert.severity in (Severity.HIGH, Severity.CRITICAL)

    def test_tunnels_are_tracked_by_endpoint_not_by_id(self) -> None:
        """A tunnel id derives from the negotiation, so it changes exactly when the
        configuration does — which is when the previous state must still be findable."""
        detector = DriftDetector()
        detector.observe(exchange(spi="1111111111111111"))
        alert = detector.observe(
            exchange(encryption=(3, None), integrity=1, prf=1, dh=2, spi="2222222222222222")
        )
        assert alert is not None
        assert len(detector.known()) == 1

    def test_an_unreadable_exchange_is_ignored_not_crashed_on(self) -> None:
        empty = exchange()
        empty.proposals_offered = []
        assert DriftDetector().observe(empty) is None

    def test_a_strengthened_tunnel_is_recorded_but_not_alerted(self) -> None:
        detector = DriftDetector()
        detector.observe(exchange(encryption=(3, None), integrity=1, prf=1, dh=2))
        assert detector.observe(exchange(spi="ff" * 8)) is None
        known = list(detector.known().values())
        assert "aes256" in known[0].suite


class TestTheSource:
    def test_a_missing_file_yields_nothing(self, tmp_path: Path) -> None:
        assert PcapPollSource(tmp_path / "absent.pcap").poll() == []

    def test_an_empty_file_yields_nothing(self, tmp_path: Path) -> None:
        target = tmp_path / "empty.pcap"
        target.write_bytes(b"")
        assert PcapPollSource(target).poll() == []

    def test_a_truncated_file_is_survived(self, tmp_path: Path) -> None:
        """A file being appended to can be read mid-packet; the next poll gets it."""
        target = tmp_path / "partial.pcap"
        target.write_bytes(b"\xd4\xc3\xb2\xa1\x02\x00")
        assert PcapPollSource(target).poll() == []

    def test_an_exchange_is_yielded_once(self, tmp_path: Path) -> None:
        from tests.fixtures.builders import build_ike_sa_init, build_pcap, build_udp_frame

        payload = build_ike_sa_init(
            [
                Proposal(
                    number=1,
                    protocol="IKE",
                    transforms=[
                        transform(TransformType.ENCR, 12, "ENCR_AES_CBC", 256),
                        transform(TransformType.DH, 20, "384-bit ECP"),
                    ],
                )
            ]
        )
        target = tmp_path / "one.pcap"
        target.write_bytes(build_pcap([build_udp_frame(payload)]))

        source = PcapPollSource(target)
        first = source.poll()
        assert len(first) >= 1
        assert source.poll() == [], "the same negotiation was yielded twice"


class TestTheWatchLoop:
    def test_it_yields_alerts_as_they_are_detected(self) -> None:
        class Scripted:
            def __init__(self) -> None:
                self.batches = [
                    [exchange()],
                    [exchange(encryption=(3, None), integrity=1, prf=1, dh=2, spi="ff" * 8)],
                ]

            def poll(self) -> list[IKEExchange]:
                return self.batches.pop(0) if self.batches else []

            def close(self) -> None:
                return None

        state = WatchState()
        alerts = list(watch(Scripted(), poll_s=0.0, until=0.5, state=state))
        assert len(alerts) == 1
        assert state.exchanges == 2
        assert state.alerts == alerts

    def test_a_callback_is_invoked(self) -> None:
        seen: list[object] = []

        class Scripted:
            def __init__(self) -> None:
                self.batches = [
                    [exchange()],
                    [exchange(encryption=(3, None), integrity=1, prf=1, dh=2, spi="ff" * 8)],
                ]

            def poll(self) -> list[IKEExchange]:
                return self.batches.pop(0) if self.batches else []

            def close(self) -> None:
                return None

        list(watch(Scripted(), poll_s=0.0, until=0.5, on_alert=seen.append))
        assert len(seen) == 1

    def test_a_quiet_source_produces_nothing(self) -> None:
        class Silent:
            def poll(self) -> list[IKEExchange]:
                return []

            def close(self) -> None:
                return None

        assert list(watch(Silent(), poll_s=0.0, until=0.3)) == []


class TestSIEMOutput:
    def test_a_drift_alert_renders_as_syslog(self) -> None:
        detector = DriftDetector()
        detector.observe(exchange())
        alert = detector.observe(
            exchange(encryption=(3, None), integrity=1, prf=1, dh=2, spi="ff" * 8)
        )
        assert alert is not None
        lines = alerts_as_syslog([alert])
        assert len(lines) == 1
        assert "DRIFT-01" in lines[0]
        assert lines[0].startswith("<")

    def test_the_alert_is_a_section_a_finding(self) -> None:
        """The comparison is arithmetic over two parsed negotiations. No model, no
        confidence — it belongs in Section A."""
        detector = DriftDetector()
        detector.observe(exchange())
        alert = detector.observe(
            exchange(encryption=(3, None), integrity=1, prf=1, dh=2, spi="ff" * 8)
        )
        assert alert is not None
        assert 'assurance="verified"' in alerts_as_syslog([alert])[0]

    def test_nothing_to_report_renders_nothing(self) -> None:
        assert alerts_as_syslog([]) == []


class TestSurvivingARestart:
    """A watcher that forgets treats the next sighting as a first sighting.

    That is the one moment an operator most needs an alert, so losing history is not a
    small degradation — it is a silent failure of the whole feature.
    """

    def test_state_round_trips(self, tmp_path: Path) -> None:
        detector = DriftDetector()
        detector.observe(exchange())
        saved = detector.save(tmp_path / "watch.json")

        restored = DriftDetector()
        assert restored.load(saved) == 1
        assert restored.known().keys() == detector.known().keys()
        before = next(iter(detector.known().values()))
        after = next(iter(restored.known().values()))
        assert after.suite == before.suite
        assert after.score == before.score

    def test_drift_is_detected_across_a_restart(self, tmp_path: Path) -> None:
        """The property that matters, not the serialisation."""
        first = DriftDetector()
        first.observe(exchange())
        first.save(tmp_path / "watch.json")

        second = DriftDetector()
        second.load(tmp_path / "watch.json")
        alert = second.observe(
            exchange(encryption=(3, None), integrity=1, prf=1, dh=2, spi="ff" * 8)
        )
        assert alert is not None, "a restarted watcher missed the weakening"
        assert "aes256" in alert.previous.suite

    def test_a_restored_sighting_carries_no_fabricated_exchange(self, tmp_path: Path) -> None:
        """Inventing a wire message would make a reconstruction look like an observation."""
        detector = DriftDetector()
        detector.observe(exchange())
        detector.save(tmp_path / "watch.json")
        restored = DriftDetector()
        restored.load(tmp_path / "watch.json")
        assert next(iter(restored.known().values())).exchange is None

    def test_a_missing_state_file_is_not_an_error(self, tmp_path: Path) -> None:
        assert DriftDetector().load(tmp_path / "absent.json") == 0

    def test_an_unreadable_state_file_is_ignored_not_fatal(self, tmp_path: Path) -> None:
        """Losing the history costs one comparison; refusing to start costs every one."""
        broken = tmp_path / "broken.json"
        broken.write_text("{not json")
        assert DriftDetector().load(broken) == 0

    def test_a_state_file_from_another_version_is_ignored(self, tmp_path: Path) -> None:
        """Guessing at an older layout could restore a wrong past and invent drift."""
        import json

        target = tmp_path / "old.json"
        target.write_text(json.dumps({"version": 999, "tunnels": []}))
        assert DriftDetector().load(target) == 0

    def test_saving_is_atomic(self, tmp_path: Path) -> None:
        """A kill mid-write must leave the previous state, not a truncated file."""
        detector = DriftDetector()
        detector.observe(exchange())
        target = tmp_path / "watch.json"
        detector.save(target)
        detector.save(target)
        assert target.exists()
        assert not list(tmp_path.glob("*.partial"))


class TestSeedingFromAPreviousAudit:
    def test_a_capture_supplies_the_past(self, tmp_path: Path) -> None:
        from tests.fixtures.builders import build_ike_sa_init, build_pcap, build_udp_frame

        strong = Proposal(
            number=1,
            protocol="IKE",
            transforms=[
                transform(TransformType.ENCR, 12, "ENCR_AES_CBC", 256),
                transform(TransformType.INTEG, 12, "AUTH_HMAC_SHA2_256_128"),
                transform(TransformType.PRF, 5, "PRF_HMAC_SHA2_256"),
                transform(TransformType.DH, 20, "384-bit ECP"),
            ],
        )
        audit = tmp_path / "audit.pcap"
        audit.write_bytes(build_pcap([build_udp_frame(build_ike_sa_init([strong]))]))

        detector = DriftDetector()
        assert detector.seed_from_capture(audit) >= 1
        assert detector.known()

    def test_a_capture_with_nothing_readable_seeds_nothing(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty.pcap"
        from tests.fixtures.builders import build_pcap

        empty.write_bytes(build_pcap([]))
        assert DriftDetector().seed_from_capture(empty) == 0


class TestStalenessIsStated:
    """An empty alert log and a quiet network look identical unless something says which."""

    def test_a_recently_seen_tunnel_is_not_stale(self) -> None:
        detector = DriftDetector()
        detector.observe(exchange(at=datetime.now(UTC)))
        assert detector.stale(older_than_s=3600) == []

    def test_a_long_silent_tunnel_is_reported(self) -> None:
        detector = DriftDetector()
        detector.observe(exchange(at=datetime.now(UTC) - timedelta(days=3)))
        stale = detector.stale(older_than_s=3600)
        assert len(stale) == 1
        assert stale[0].silent_for_s > 3600

    def test_the_wording_does_not_claim_the_tunnel_is_unchanged(self) -> None:
        """Silence is an absence of evidence, and must not read as evidence of absence."""
        detector = DriftDetector()
        detector.observe(exchange(at=datetime.now(UTC) - timedelta(days=2)))
        described = detector.stale(older_than_s=60)[0].describe()
        assert "unverified" in described
        assert "not confirmed unchanged" in described

    def test_the_quietest_tunnel_is_reported_first(self) -> None:
        detector = DriftDetector()
        now = datetime.now(UTC)
        detector.observe(exchange(at=now - timedelta(hours=2)))
        second = exchange(at=now - timedelta(days=5), spi="ff" * 8)
        second.src_ip, second.dst_ip = "10.0.0.1", "10.0.0.2"
        detector.observe(second)
        stale = detector.stale(older_than_s=3600)
        assert len(stale) == 2
        assert stale[0].silent_for_s > stale[1].silent_for_s
