"""Tests for zero-downtime change sequencing (build plan Step 8.4).

The load-bearing test is `test_no_intermediate_state_leaves_the_ends_without_a_common
_proposal`, and its companion proving the check can fail. A safety property asserted
against only safe inputs proves nothing.
"""

from __future__ import annotations

import pytest

from ipsec_sentinel.remediate.models import ConfigRole
from ipsec_sentinel.remediate.sequence import (
    STEP_COUNT,
    ProposalState,
    SequenceError,
    build_sequence,
    naive_sequence_states,
    simulate,
    unsafe_states,
    verify_zero_downtime,
)

CURRENT = "3des-md5-modp1024"
TARGET = "aes256gcm16-curve25519"


class TestSequenceShape:
    def test_the_sequence_has_exactly_four_steps(self) -> None:
        assert len(build_sequence(CURRENT, TARGET)) == STEP_COUNT

    def test_the_steps_are_numbered_in_order(self) -> None:
        orders = [step.order for step in build_sequence(CURRENT, TARGET)]
        assert orders == [1, 2, 3, 4]

    def test_every_step_names_which_ends_it_applies_to(self) -> None:
        """The plan's explicit criterion. "The other one" at 2 a.m. edits the wrong box."""
        for step in build_sequence(CURRENT, TARGET):
            assert step.role in (ConfigRole.LOCAL, ConfigRole.PEER, ConfigRole.BOTH)
            assert step.role.covers

    def test_the_add_and_remove_steps_apply_to_both_ends(self) -> None:
        steps = build_sequence(CURRENT, TARGET)
        assert steps[0].role is ConfigRole.BOTH
        assert steps[2].role is ConfigRole.BOTH

    def test_step_one_offers_both_proposals(self) -> None:
        """The plan's criterion: step 1's configuration contains both."""
        step = build_sequence(CURRENT, TARGET)[0]
        assert CURRENT in step.action
        assert TARGET in step.action

    def test_step_three_offers_only_the_target(self) -> None:
        """The plan's criterion: step 3's configuration contains only the target."""
        step = build_sequence(CURRENT, TARGET)[2]
        assert f"'{TARGET}'" in step.action
        assert f"'{CURRENT}, {TARGET}'" not in step.action

    def test_no_step_expects_disruption(self) -> None:
        """That is the whole claim; a step admitting downtime falsifies it."""
        assert all(s.expected_disruption_s == 0 for s in build_sequence(CURRENT, TARGET))

    def test_step_two_warns_against_continuing_on_failure(self) -> None:
        """Step 3 is only safe because step 2 proved the target is in use."""
        step = build_sequence(CURRENT, TARGET)[1]
        assert "stop here" in step.description

    def test_step_two_warns_against_rekeying_the_existing_sa(self) -> None:
        """Measured, not assumed: a rekey renegotiates the old proposal.

        ``tests/integration/test_sequence_live.py`` demonstrates this on strongSwan
        5.9.8 — after reloading a new proposal list, rekeying the IKE SA, rekeying the
        child SA, and reauthenticating all come back on the *old* proposal, so a
        sequence built around a rekey would leave the tunnel unchanged while looking
        like it had worked.
        """
        step = build_sequence(CURRENT, TARGET)[1]
        assert "Do not rekey" in step.description
        assert "Initiate the connection again" in step.action

    def test_step_two_says_how_to_pick_the_sa_to_retire(self) -> None:
        """Two SAs coexist at that moment and the listing puts the newest first.

        Retiring "the first one" would delete the SA that just moved to the target and
        silently roll the change back.
        """
        assert "not by its position" in build_sequence(CURRENT, TARGET)[1].action

    def test_an_identical_proposal_is_refused(self) -> None:
        with pytest.raises(SequenceError, match="identical"):
            build_sequence(TARGET, TARGET)

    def test_an_empty_proposal_is_refused(self) -> None:
        with pytest.raises(SequenceError, match="must be named"):
            build_sequence("", TARGET)


class TestTheSafetyProperty:
    def test_no_intermediate_state_leaves_the_ends_without_a_common_proposal(self) -> None:
        """The property that makes the sequence zero-downtime.

        Simulated over every state including the half-applied ones — a step reaches one
        end before the other, and those are the states a four-step narrative glosses
        over.
        """
        states = simulate(CURRENT, TARGET)
        assert unsafe_states(states) == [], [s.describe() for s in unsafe_states(states)]

    def test_the_simulation_covers_partially_applied_states(self) -> None:
        """Atomic states alone would miss the window a bad ordering opens."""
        labels = [state.label for state in simulate(CURRENT, TARGET)]
        assert any("local end only" in label for label in labels)
        assert sum("only" in label for label in labels) >= 2

    def test_every_state_is_checked_from_the_initial_one(self) -> None:
        states = simulate(CURRENT, TARGET)
        assert states[0].label == "initial"
        assert states[0].local == (CURRENT,)
        assert states[-1].local == (TARGET,)
        assert states[-1].peer == (TARGET,)

    def test_verify_returns_the_states_it_checked(self) -> None:
        assert len(verify_zero_downtime(CURRENT, TARGET)) == len(simulate(CURRENT, TARGET))

    def test_the_check_can_fail(self) -> None:
        """The naive replace-both-ends approach must be caught.

        Without this, the safety assertion is only ever run against input that cannot
        fail it, and proves nothing.
        """
        unsafe = unsafe_states(naive_sequence_states(CURRENT, TARGET))
        assert unsafe, "the naive sequence should pass through a disjoint state"
        assert "local end only" in unsafe[0].label

    def test_a_disjoint_state_reports_no_common_proposal(self) -> None:
        state = ProposalState("test", ("A",), ("B",))
        assert state.is_safe is False
        assert state.common == ()
        assert "NO COMMON PROPOSAL" in state.describe()

    def test_a_shared_state_reports_the_overlap(self) -> None:
        state = ProposalState("test", ("A", "B"), ("B",))
        assert state.is_safe is True
        assert state.common == ("B",)


class TestGeneratorIntegration:
    """The change package must carry the verified sequence, not a hand-written one."""

    @staticmethod
    def _package(label: str, findings: list[str]):  # type: ignore[no-untyped-def]
        from ipsec_sentinel.remediate.generators.strongswan import generate_change_package
        from testbed.orchestrate.matrix import expand_matrix

        config = next(lc.config for lc in expand_matrix() if lc.label == label)
        return generate_change_package("t1", config, findings)

    def test_a_package_carries_the_four_step_sequence(self) -> None:
        package = self._package("weak", ["CRY-02"])
        assert len(package.sequence) == STEP_COUNT

    def test_a_package_expects_no_disruption(self) -> None:
        package = self._package("weak", ["CRY-02"])
        assert package.total_expected_disruption_s == 0

    def test_an_aggressive_psk_package_rotates_the_key_first(self) -> None:
        """The hash is already exposed; rotating after the transition carries it forward."""
        package = self._package("worst", ["IKE-03"])
        assert len(package.sequence) == STEP_COUNT + 1
        assert package.sequence[0].order == 1
        assert "Rotate the pre-shared key" in package.sequence[0].description
        assert package.sequence[0].reversible is False

    def test_the_rotation_does_not_disturb_the_step_ordering(self) -> None:
        package = self._package("worst", ["IKE-03"])
        assert [s.order for s in package.sequence] == [1, 2, 3, 4, 5]

    def test_the_packaged_sequence_is_itself_zero_downtime(self) -> None:
        """Simulate the transition the package actually describes."""
        from ipsec_sentinel.remediate.generators.strongswan import harden
        from testbed.orchestrate.matrix import expand_matrix

        original = next(lc.config for lc in expand_matrix() if lc.label == "weak")
        corrected, _ = harden(original)
        states = verify_zero_downtime(original.proposal_string(), corrected.proposal_string())
        assert all(state.is_safe for state in states)
