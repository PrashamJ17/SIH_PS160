"""Read real device state from a live pair (Step 10.4b).

The unit tests parse a sample with fake keys. This parses what a real Linux kernel and a
real strongSwan actually print, which is the only way to know the parsers match the
format rather than match each other.

The key-material assertion is repeated here against **real session keys**. A sample with
fake keys proves the regex drops the field it was pointed at; only real output proves it
drops the field the kernel actually emits.
"""

from __future__ import annotations

import re
import time

import pytest

from ipsec_sentinel.collect import config_from_state, parse_list_sas, parse_xfrm_state
from ipsec_sentinel.watch import DriftDetector
from testbed.orchestrate.config_gen import TunnelConfig
from testbed.orchestrate.matrix import expand_matrix
from tests.fixtures.dockerctl import exec_in
from tests.fixtures.livepair import LivePair, live_pair

pytestmark = [
    pytest.mark.integration,
    pytest.mark.slow,
    pytest.mark.usefixtures("strongswan_image", "traffic_image"),
]


def anchor(label: str) -> TunnelConfig:
    return next(lc.config for lc in expand_matrix() if lc.label == label)


def device_state(pair: LivePair, source: str = "left"):  # type: ignore[no-untyped-def]
    """What the gateway says about itself, read from the container."""
    from datetime import UTC, datetime

    from ipsec_sentinel.collect import DeviceState

    sas = exec_in(pair.left, "swanctl", "--list-sas", timeout=60).stdout
    xfrm = exec_in(pair.left, "ip", "xfrm", "state", timeout=60).stdout
    ike, child = parse_list_sas(sas)
    return (
        DeviceState(
            source=source,
            collected_at=datetime.now(UTC),
            ike=ike,
            child=child,
            kernel_sas=tuple(parse_xfrm_state(xfrm)),
        ),
        xfrm,
    )


class TestAgainstRealKernelOutput:
    def test_no_real_session_key_survives_parsing(self) -> None:
        """`ip xfrm state` prints keys inline. None may reach a parsed object.

        Run against real keys, not a sample: a fixture proves the regex drops the field
        it was aimed at, and only the kernel's own output proves it drops the field the
        kernel emits.
        """
        with live_pair(anchor("good")) as pair:
            time.sleep(2)
            state, raw = device_state(pair)

        blobs = set(re.findall(r"0x[0-9a-f]{20,}", raw))
        assert blobs, "the kernel printed no key material; this test would prove nothing"

        serialised = " ".join(sa.model_dump_json() for sa in state.kernel_sas)
        serialised += repr(state) + state.describe()
        leaked = [b for b in blobs if b in serialised or b[2:] in serialised]
        assert not leaked, f"{len(leaked)} key blob(s) reached a parsed object"

    def test_the_algorithms_are_read_from_real_output(self) -> None:
        with live_pair(anchor("good")) as pair:
            time.sleep(2)
            state, _ = device_state(pair)

        assert state.ike is not None
        assert state.ike.established is True
        assert state.ike.encryption == "AES_CBC"
        assert state.ike.encryption_keylen == 256
        assert state.ike.dh_group == "ECP_384"
        assert len(state.kernel_sas) == 2, "one SA per direction"
        assert all(sa.proto == "esp" for sa in state.kernel_sas)

    def test_the_reported_state_reconstructs_to_the_configured_suite(self) -> None:
        """The oracle: the pair was configured from a TunnelConfig this must recover."""
        configured = anchor("good")
        with live_pair(configured) as pair:
            time.sleep(2)
            state, _ = device_state(pair)

        recovered = config_from_state(state)
        assert recovered is not None
        assert recovered.proposal_string() == configured.proposal_string()  # type: ignore[union-attr]

    def test_the_endpoints_are_read(self) -> None:
        with live_pair(anchor("good")) as pair:
            time.sleep(2)
            state, _ = device_state(pair)
        assert state.endpoints == ("10.100.0.2", "10.100.0.3")


class TestDriftFromStateWithoutTheWire:
    """The rekey blind spot, closed. No capture involved anywhere in this test."""

    def test_a_weakening_is_detected_from_device_state_alone(self) -> None:
        detector = DriftDetector()

        with live_pair(anchor("good")) as pair:
            time.sleep(2)
            before, _ = device_state(pair)
            assert detector.observe_state(before) is None, "a first sighting is not drift"

            pair.set_config(anchor("weak"))
            pair.load()
            assert pair.initiate().returncode == 0
            time.sleep(3)
            after, _ = device_state(pair)
            alert = detector.observe_state(after)

        assert alert is not None, "the weakening was not detected from state"
        assert "aes256" in alert.previous.suite
        assert "aes128" in alert.current.suite
        assert {w.parameter for w in alert.weakenings} >= {"encryption", "integrity", "dh_group"}

    def test_the_state_sighting_is_not_scored_or_mistaken_for_an_observation(self) -> None:
        detector = DriftDetector()
        with live_pair(anchor("good")) as pair:
            time.sleep(2)
            state, _ = device_state(pair)
            detector.observe_state(state)

        sighting = next(iter(detector.known().values()))
        assert sighting.score is None, "a tunnel with no negotiation must not score 100"
        assert sighting.exchange is None, "state is not a wire observation"

    def test_an_unchanged_device_reports_nothing(self) -> None:
        detector = DriftDetector()
        with live_pair(anchor("good")) as pair:
            time.sleep(2)
            for _ in range(3):
                state, _ = device_state(pair)
                detector.observe_state(state)
                time.sleep(1)
        assert len(detector.known()) == 1
