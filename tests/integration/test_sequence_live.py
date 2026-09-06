"""Execute the zero-downtime sequence on a live pair (build plan Step 8.4).

The unit tests prove the sequence is safe *in the model*. This proves the model
describes strongSwan. It runs the four steps against two real peers while a ping runs
across the tunnel throughout, and asserts the ping loses nothing.

Two controls keep that assertion honest, because "0% packet loss" is exactly what a
ping that measured nothing also reports:

* :class:`TestTheNaiveApproachIsWorse` performs the obvious replacement instead and
  asserts the same measurement *does* see loss. A meter that cannot read non-zero is
  not evidence.
* :func:`test_a_state_with_no_common_proposal_really_does_fail` puts the two ends into
  the state the simulation calls unsafe and shows the negotiation genuinely fails —
  tying the modelled property to an observable outcome rather than an assumption.

One finding from building this is baked into the sequence itself: on strongSwan 5.9.8
an established SA keeps the configuration it was created with, so ``swanctl --rekey``
after a reload renegotiates the *old* proposal and the change silently does nothing.
:class:`TestRekeyDoesNotAdoptNewConfiguration` pins that behaviour, because it is the
reason step 2 initiates a second SA instead of rekeying, and if a future strongSwan
changes it we want to be told rather than to keep carrying the workaround.
"""

from __future__ import annotations

import time

import pytest

from ipsec_sentinel.remediate.generators.strongswan import harden
from ipsec_sentinel.remediate.sequence import STEP_COUNT, build_sequence, verify_zero_downtime
from testbed.orchestrate.config_gen import TunnelConfig
from testbed.orchestrate.matrix import expand_matrix
from tests.fixtures.dockerctl import exec_in
from tests.fixtures.livepair import (
    MIN_CONTROL_OUTAGE_S,
    MIN_PROBE_COVERAGE,
    SETTLE_S,
    live_pair,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.slow,
    pytest.mark.usefixtures("strongswan_image", "traffic_image"),
]


def anchor(label: str) -> TunnelConfig:
    return next(lc.config for lc in expand_matrix() if lc.label == label)


def transition() -> tuple[TunnelConfig, TunnelConfig]:
    """A weak configuration and its hardened form, both IKEv2.

    The proposal is the only thing that changes. An IKE version change is a different
    and larger operation, and mixing it in would leave it unclear which part of the
    sequence a failure belonged to.
    """
    current = anchor("weak")
    target, changes = harden(current)
    assert changes, "the weak anchor should have something to correct"
    assert current.ike_version == target.ike_version == "ikev2"
    assert current.proposal_string() != target.proposal_string()
    return current, target


def both_lists(current: TunnelConfig, target: TunnelConfig) -> tuple[str, str]:
    """Proposal lists offering the target first and the current as a fallback."""
    return (
        f"{target.proposal_string()},{current.proposal_string()}",
        f"{target.esp_proposal_string()},{current.esp_proposal_string()}",
    )


# ---------------------------------------------------------------------------- the run


class TestTheSequenceRunsWithoutLosingAPacket:
    def test_the_full_sequence_holds_the_tunnel_up_throughout(self) -> None:
        """The demo moment: four steps, a live pair, and a ping that loses nothing."""
        current, target = transition()
        steps = build_sequence(current.proposal_string(), target.proposal_string())
        assert len(steps) == STEP_COUNT
        verify_zero_downtime(current.proposal_string(), target.proposal_string())

        with live_pair(current) as pair:
            before = pair.sa_carrying(current)
            assert before is not None, f"expected the weak proposal, saw {pair.sas()}"

            with pair.reachability() as measured:
                # Step 1 — add the target alongside the current on both ends.
                pair.set_proposals(*both_lists(current, target))
                pair.load()
                time.sleep(1)
                assert pair.sa_carrying(current) is not None, (
                    "reloading the configuration disturbed the running SA; step 1 is "
                    "supposed to be inert"
                )

                # Step 2 — establish a second SA on the target, then retire the old.
                assert pair.initiate().returncode == 0
                time.sleep(SETTLE_S)
                migrated = pair.sa_carrying(target)
                assert migrated is not None, (
                    "the new SA did not negotiate the target proposal; step 2 says to "
                    f"stop here rather than continue. SAs: {pair.sas()}"
                )
                stale = pair.sa_carrying(current)
                assert stale is not None and stale.ike_id != migrated.ike_id
                pair.terminate(stale.ike_id)
                time.sleep(SETTLE_S)

                # Step 3 — remove the current proposal from both ends.
                pair.set_proposals(target.proposal_string(), target.esp_proposal_string())
                pair.load()
                time.sleep(1)

                # Step 4 — still established, on the target alone.
                remaining = pair.sas()
                assert len(remaining) == 1, f"expected one SA, saw {remaining}"
                assert remaining[0].carries(target)
                assert pair.sa_carrying(current) is None

            result = measured[0]

        print(f"\nzero-downtime sequence: {result.summary()}")
        assert result.coverage > MIN_PROBE_COVERAGE, (
            f"the probe watched only {result.measured_s:.1f}s of a {result.block_s:.1f}s "
            f"change, so it was not looking during part of it and its verdict says "
            f"nothing about that part: {result.summary()}"
        )
        assert result.lost == 0, f"the sequence dropped traffic: {result.summary()}"
        assert result.longest_outage_s == 0.0, (
            f"the tunnel was unreachable during the change: {result.summary()}"
        )

    def test_both_ends_agree_on_the_result(self) -> None:
        """A change applied to one end only is the failure the sequence exists to avoid."""
        current, target = transition()
        with live_pair(current) as pair:
            pair.set_proposals(*both_lists(current, target))
            pair.load()
            assert pair.initiate().returncode == 0
            time.sleep(SETTLE_S)
            migrated = pair.sa_carrying(target)
            assert migrated is not None
            stale = pair.sa_carrying(current)
            assert stale is not None
            pair.terminate(stale.ike_id)
            time.sleep(SETTLE_S)

            for end in (pair.left, pair.right):
                sas = pair.sas(end)
                assert len(sas) == 1, f"{end} sees {sas}"
                assert sas[0].carries(target), f"{end} did not move to the target: {sas[0]}"
                assert sas[0].esp_algorithms, f"{end} has no child SA installed"


class TestTheNaiveApproachIsWorse:
    """The negative control. Without it, "0% loss" could mean the meter is broken."""

    def test_replacing_the_proposal_outright_loses_packets(self) -> None:
        current, target = transition()
        with live_pair(current) as pair:
            with pair.reachability() as measured:
                time.sleep(2)
                # No add-alongside step: replace on both ends, then force the new
                # configuration to take effect the only way that remains.
                pair.set_proposals(target.proposal_string(), target.esp_proposal_string())
                pair.load()
                exec_in(pair.left, "swanctl", "--terminate", "--ike", "net-net", timeout=120)
                time.sleep(SETTLE_S)
                assert pair.initiate().returncode == 0
                time.sleep(SETTLE_S)
                assert pair.sa_carrying(target) is not None
            result = measured[0]

        print(f"\nnaive replacement: {result.summary()}")
        assert result.coverage > MIN_PROBE_COVERAGE, result.summary()
        assert result.longest_outage_s >= MIN_CONTROL_OUTAGE_S, (
            f"the naive replacement caused no sustained outage, so this measurement "
            f"has not been shown to detect one at all; without that the zero-loss "
            f"result above proves nothing: {result.summary()}"
        )
        assert result.lost > 0, result.summary()


def test_a_state_with_no_common_proposal_really_does_fail() -> None:
    """The modelled unsafe state, reproduced on real peers.

    ``simulate`` calls a state unsafe when the two ends share no proposal. This puts
    them in exactly that state and shows the negotiation fails, which is what ties the
    model to something observable.
    """
    current, target = transition()
    with live_pair(current) as pair:
        exec_in(pair.left, "swanctl", "--terminate", "--ike", "net-net", timeout=120)
        time.sleep(1)
        # The local end offers only the target; the peer still offers only the current.
        pair.set_proposals(target.proposal_string(), target.esp_proposal_string())
        pair.load(both_ends=False)
        attempt = pair.initiate()

        assert attempt.returncode != 0, (
            "the two ends share no proposal, so this must not establish; it did"
        )
        assert "NO_PROPOSAL_CHOSEN" in attempt.stdout + attempt.stderr, (
            f"expected a proposal mismatch, got: {(attempt.stdout + attempt.stderr)[-500:]}"
        )


class TestRekeyDoesNotAdoptNewConfiguration:
    """Why step 2 initiates instead of rekeying.

    Pinned as a test rather than a comment: it is a behavioural claim about strongSwan
    that the sequence depends on, and if a later release changes it we should find out
    from a failing test rather than by keeping a workaround forever.
    """

    def test_a_rekey_after_a_reload_renegotiates_the_old_proposal(self) -> None:
        current, target = transition()
        with live_pair(current) as pair:
            pair.set_proposals(*both_lists(current, target))
            pair.load()
            time.sleep(1)
            for kind in ("ike", "child"):
                result = exec_in(
                    pair.left, "swanctl", "--rekey", f"--{kind}", "net-net", timeout=120
                )
                assert result.returncode == 0, result.stderr[:300]
                time.sleep(SETTLE_S)

            assert pair.sa_carrying(target) is None, (
                "strongSwan now adopts reloaded proposals on rekey — the sequence can "
                "be simplified to a rekey, and this test should be replaced"
            )
            assert pair.sa_carrying(current) is not None
