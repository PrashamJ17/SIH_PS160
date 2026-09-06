"""Live drift detection (build plan Step 10.4).

This is the scenario from the pitch, run for real: a tunnel that was strong is replaced
with a weak one between the same two endpoints, and the watcher notices without anyone
asking it to look.

It is the failure an audit cannot catch. An assessment run today says the estate is
sound; the gateway is swapped under warranty on Friday and the vendor default comes back
up; traffic flows, nobody is paged, and the next assessment is three months away. What is
being tested is the gap between those three months and sixty seconds.

The deadline is asserted rather than assumed. A watcher that eventually notices is not a
watcher, and the plan's number — sixty seconds — is the one an operator was promised.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from pathlib import Path

import pytest

from ipsec_sentinel.models import IKEExchange
from ipsec_sentinel.watch import DriftDetector, PcapPollSource, watch
from testbed.orchestrate.config_gen import TunnelConfig
from testbed.orchestrate.matrix import expand_matrix
from tests.fixtures.dockerctl import exec_in
from tests.fixtures.livepair import LivePair, live_pair

pytestmark = [
    pytest.mark.integration,
    pytest.mark.slow,
    pytest.mark.usefixtures("strongswan_image", "traffic_image"),
]

DRIFT_DEADLINE_S = 60.0
SETTLE_S = 3


def anchor(label: str) -> TunnelConfig:
    return next(lc.config for lc in expand_matrix() if lc.label == label)


class DockerIkeSource:
    """An :class:`ExchangeSource` fed by a capture running inside the gateway.

    The watcher runs on the host and the traffic is on a Docker network the host cannot
    reach, so the capture is copied out on each poll. In a deployment this role is played
    by ``LiveInterfaceSource``, which reads a local interface directly; the container hop
    exists only because the testbed's wire is inside Docker.
    """

    def __init__(self, pair: LivePair, destination: Path) -> None:
        self.pair = pair
        self.destination = destination
        self._reader = PcapPollSource(destination)

    def poll(self) -> list[IKEExchange]:
        self.pair.fetch_capture(self.destination)
        return self._reader.poll()

    def close(self) -> None:
        return None


class TestDriftIsNoticed:
    def test_a_tunnel_that_weakens_raises_an_alert_within_sixty_seconds(
        self, tmp_path: Path
    ) -> None:
        """Strong tunnel, then a weak one between the same endpoints."""
        strong = anchor("good")  # aes256-sha384-prfsha384-ecp384
        weak = anchor("weak")  # aes128-sha1-prfsha1-modp1024

        # The capture starts before the first handshake. A rekey would not do: it is
        # carried in CREATE_CHILD_SA and its SA payload is encrypted, so IKE_SA_INIT is
        # the only exchange whose parameters a passive watcher can read.
        with live_pair(strong, ike_capture=True) as pair:
            time.sleep(SETTLE_S)

            source = DockerIkeSource(pair, tmp_path / "ike.pcap")
            detector = DriftDetector()

            # Establish the baseline: whatever is on the wire now is this tunnel's past.
            for exchange in source.poll():
                assert detector.observe(exchange) is None, "a first sighting is not drift"
            assert detector.known(), "the strong negotiation was not captured"
            baseline = next(iter(detector.known().values()))
            assert "aes256" in baseline.suite, baseline.suite

            # The change: someone replaces the configuration with a weaker one.
            changed_at = time.monotonic()
            pair.set_config(weak)
            pair.load()
            assert pair.initiate().returncode == 0

            alert = next(
                iter(watch(source, detector=detector, poll_s=2.0, until=DRIFT_DEADLINE_S)),
                None,
            )
            elapsed = time.monotonic() - changed_at

        assert alert is not None, (
            f"no drift alert within {DRIFT_DEADLINE_S:.0f}s of the configuration being "
            f"weakened; the watcher did not notice"
        )
        assert elapsed <= DRIFT_DEADLINE_S, f"took {elapsed:.1f}s"
        assert "aes256" in alert.previous.suite
        assert "aes128" in alert.current.suite
        assert {w.parameter for w in alert.weakenings} >= {"integrity", "dh_group"}
        assert alert.score_drop >= 0
        print(f"\ndrift detected {elapsed:.1f}s after the change: {alert.summary()[:160]}")

    def test_an_unchanged_tunnel_raises_nothing(self, tmp_path: Path) -> None:
        """The other half of the claim: it must not cry wolf on a stable estate.

        A watcher that alerts on a tunnel nobody touched is one whose alerts get muted,
        and then the real one is muted too.
        """
        with live_pair(anchor("good"), ike_capture=True) as pair:
            time.sleep(SETTLE_S)

            source = DockerIkeSource(pair, tmp_path / "ike.pcap")
            detector = DriftDetector()
            for exchange in source.poll():
                detector.observe(exchange)

            # Re-establish the same configuration several times. Each is a fresh
            # IKE_SA_INIT the watcher can read, and none of them changed anything.
            for _ in range(3):
                exec_in(pair.left, "swanctl", "--terminate", "--ike", "net-net", timeout=120)
                time.sleep(1)
                assert pair.initiate().returncode == 0
                time.sleep(2)

            alerts = list(watch(source, detector=detector, poll_s=1.0, until=15.0))

        assert alerts == [], f"drift reported on an unchanged tunnel: {alerts}"

    def test_a_tunnel_that_strengthens_raises_nothing(self, tmp_path: Path) -> None:
        """Recorded, not alerted. An alert on good news teaches people to close alerts."""
        with live_pair(anchor("weak"), ike_capture=True) as pair:
            time.sleep(SETTLE_S)

            source = DockerIkeSource(pair, tmp_path / "ike.pcap")
            detector = DriftDetector()
            for exchange in source.poll():
                detector.observe(exchange)
            before = next(iter(detector.known().values()))

            pair.set_config(anchor("good"))
            pair.load()
            assert pair.initiate().returncode == 0

            alerts = list(watch(source, detector=detector, poll_s=2.0, until=25.0))
            after = next(iter(detector.known().values()))

        assert alerts == [], f"strengthening was reported as drift: {alerts}"
        assert "aes128" in before.suite
        assert "aes256" in after.suite, "the new state was not recorded"


class TestTheAlertIsUsable:
    def test_it_names_what_changed_and_reaches_a_siem(self, tmp_path: Path) -> None:
        from ipsec_sentinel.watch import alerts_as_syslog

        with live_pair(anchor("good"), ike_capture=True) as pair:
            time.sleep(SETTLE_S)

            source = DockerIkeSource(pair, tmp_path / "ike.pcap")
            detector = DriftDetector()
            for exchange in source.poll():
                detector.observe(exchange)

            pair.set_config(anchor("worst"))
            pair.load()
            pair.initiate()

            alert = next(
                iter(watch(source, detector=detector, poll_s=2.0, until=DRIFT_DEADLINE_S)),
                None,
            )

        assert alert is not None
        summary = alert.summary()
        assert "->" in summary
        assert alert.previous.suite in summary
        assert alert.current.suite in summary

        line = alerts_as_syslog([alert])[0]
        assert "DRIFT-01" in line
        assert 'assurance="verified"' in line
        assert len(line.encode()) <= 1024

    def test_the_detected_time_is_when_it_was_noticed(self, tmp_path: Path) -> None:
        """Distinct from the exchange timestamp, which is when it happened on the wire."""
        with live_pair(anchor("good"), ike_capture=True) as pair:
            time.sleep(SETTLE_S)
            source = DockerIkeSource(pair, tmp_path / "ike.pcap")
            detector = DriftDetector()
            for exchange in source.poll():
                detector.observe(exchange)

            pair.set_config(anchor("worst"))
            pair.load()
            pair.initiate()
            alert = next(
                iter(watch(source, detector=detector, poll_s=2.0, until=DRIFT_DEADLINE_S)),
                None,
            )

        assert alert is not None
        assert alert.detected_at >= alert.current.seen_at
        assert alert.detected_at <= datetime.now(UTC)


class TestTheLimitationIsMitigated:
    """A tunnel's parameters are readable only at IKE_SA_INIT. These close the gaps.

    The narrow version of the limit is benign: a config change only takes effect when a
    new IKE SA is built, and building one is an IKE_SA_INIT. The dangerous version is a
    watcher that has no memory of the strong past — because then the weak tunnel is a
    first sighting, and a first sighting is deliberately not drift.
    """

    def test_a_fresh_watcher_seeded_from_the_last_audit_still_catches_drift(
        self, tmp_path: Path
    ) -> None:
        """The gap that matters: the change happened before the watcher started."""
        audit = tmp_path / "audit.pcap"

        # The last audit: a strong tunnel, captured.
        with live_pair(anchor("good"), ike_capture=True) as pair:
            time.sleep(SETTLE_S)
            pair.fetch_capture(audit)
        assert audit.exists() and audit.stat().st_size > 0

        seeded = DriftDetector()
        assert seeded.seed_from_capture(audit) >= 1, "the audit capture seeded nothing"
        remembered = next(iter(seeded.known().values()))
        assert "aes256" in remembered.suite, remembered.suite

        # Weeks later: a different tunnel between the same endpoints, and a watcher that
        # was not running when it changed.
        with live_pair(anchor("weak"), ike_capture=True) as pair:
            time.sleep(SETTLE_S)
            source = DockerIkeSource(pair, tmp_path / "now.pcap")
            alert = next(
                iter(watch(source, detector=seeded, poll_s=2.0, until=DRIFT_DEADLINE_S)),
                None,
            )

        assert alert is not None, (
            "a watcher seeded from the previous audit did not notice the weakening; "
            "without seeding this is the case that reads as a first sighting"
        )
        assert "aes256" in alert.previous.suite
        assert "aes128" in alert.current.suite

    def test_the_same_watcher_without_a_seed_reports_nothing(self, tmp_path: Path) -> None:
        """The control, and the reason seeding exists.

        With no past, the weak tunnel is a first sighting and no alert fires. That is
        correct behaviour and it is exactly the blind spot ``--since`` closes.
        """
        with live_pair(anchor("weak"), ike_capture=True) as pair:
            time.sleep(SETTLE_S)
            source = DockerIkeSource(pair, tmp_path / "cold.pcap")
            alerts = list(watch(source, detector=DriftDetector(), poll_s=1.0, until=12.0))
        assert alerts == []

    def test_a_restarted_watcher_keeps_its_baseline(self, tmp_path: Path) -> None:
        """Persisted state, exercised against real captures rather than constructed ones."""
        state = tmp_path / "watch-state.json"

        with live_pair(anchor("good"), ike_capture=True) as pair:
            time.sleep(SETTLE_S)
            source = DockerIkeSource(pair, tmp_path / "first.pcap")
            detector = DriftDetector()
            for exchange in source.poll():
                detector.observe(exchange)
            assert detector.known(), "nothing was observed to remember"
            detector.save(state)

        # A new process, with only the file to go on.
        restarted = DriftDetector()
        assert restarted.load(state) >= 1

        with live_pair(anchor("worst"), ike_capture=True) as pair:
            time.sleep(SETTLE_S)
            source = DockerIkeSource(pair, tmp_path / "second.pcap")
            alert = next(
                iter(watch(source, detector=restarted, poll_s=2.0, until=DRIFT_DEADLINE_S)),
                None,
            )

        assert alert is not None, "a restarted watcher lost its baseline and missed the drift"
        assert alert.weakenings

    def test_a_silent_tunnel_is_reported_as_unverified(self, tmp_path: Path) -> None:
        """The honest complement: silence is not evidence the tunnel is unchanged."""
        with live_pair(anchor("good"), ike_capture=True) as pair:
            time.sleep(SETTLE_S)
            source = DockerIkeSource(pair, tmp_path / "quiet.pcap")
            detector = DriftDetector()
            for exchange in source.poll():
                detector.observe(exchange)

        assert detector.known()
        stale = detector.stale(older_than_s=0)
        assert stale, "a tunnel not seen since should be reported as unverified"
        assert "unverified" in stale[0].describe()
        assert "not confirmed unchanged" in stale[0].describe()
