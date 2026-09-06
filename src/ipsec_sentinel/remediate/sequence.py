"""Zero-downtime change sequencing.

Changing an IPsec proposal is not editing a setting; it is renegotiating a contract
between two parties who must agree at every instant. The obvious approach — edit both
ends to the new proposal — has a window in which one end offers only the new proposal
and the other only the old, and in that window the tunnel cannot re-establish. It is
not a long window, and that is what makes it dangerous: the change appears to work, and
the outage arrives at the next rekey, hours later, with nothing obviously connecting
the two.

The safe pattern is four steps:

1. **Add** the target proposal alongside the current one, on both ends.
2. **Migrate** onto the target and retire the old SA.
3. **Remove** the old proposal from both ends.
4. **Verify** the tunnel is still established on the target alone.

What makes it safe is not the ordering of the steps but a property of every state
between them: **the two ends always share at least one proposal**. This module models
that explicitly and :func:`simulate` walks every intermediate state — including the
partially-applied ones, where a step has reached one end and not yet the other, which
are the states an operator actually passes through and the ones a four-step narrative
tends to gloss over.

Step 2 is not a rekey, and that distinction is measured rather than assumed. On
strongSwan 5.9.8 an established SA holds the configuration it was created with:
after reloading a new proposal list, ``swanctl --rekey`` — of the IKE SA, of the
child SA, and reauthentication with ``make_before_break`` — all renegotiate the
*old* proposal. The tunnel stays up and the change appears to have been applied,
which is the dangerous part: step 3 would then remove the old proposal from the
configuration while the live SA is still using it. Establishing a *second* SA from
the reloaded configuration is what actually adopts it, and the two coexist without
dropping a packet while the old one is retired.

The negative control matters as much as the sequence. :func:`naive_sequence_states`
builds the obvious replace-both-ends approach and the tests assert that the simulation
*catches* it. A safety check that cannot fail proves nothing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from ipsec_sentinel.remediate.models import ChangeStep, ConfigRole

STEP_COUNT: Final = 4


class SequenceError(ValueError):
    """A sequence could not be built, or would drop the tunnel."""


@dataclass(frozen=True)
class ProposalState:
    """What each end offers at one moment."""

    label: str
    local: tuple[str, ...]
    peer: tuple[str, ...]

    @property
    def common(self) -> tuple[str, ...]:
        """Proposals both ends will accept. Empty means the tunnel cannot establish."""
        return tuple(p for p in self.local if p in self.peer)

    @property
    def is_safe(self) -> bool:
        return bool(self.common)

    def describe(self) -> str:
        verdict = f"common {list(self.common)}" if self.is_safe else "NO COMMON PROPOSAL"
        return f"{self.label}: local {list(self.local)} / peer {list(self.peer)} — {verdict}"


def build_sequence(current: str, target: str) -> list[ChangeStep]:
    """The four-step zero-downtime transition from ``current`` to ``target``.

    Steps 1 and 3 carry :attr:`ConfigRole.BOTH` because each is a single operation an
    operator performs across both ends. Splitting them would imply an ordering between
    the ends that neither exists nor is required — what matters is that the *add*
    completes before the *remove* begins.
    """
    if not current or not target:
        raise SequenceError("both the current and target proposals must be named")
    if current == target:
        raise SequenceError(
            f"the current and target proposals are identical ({current!r}); there is "
            f"nothing to sequence"
        )

    return [
        ChangeStep(
            order=1,
            role=ConfigRole.BOTH,
            description=(
                f"Add {target} alongside the existing {current} on both ends. Both "
                f"proposals are offered, so the tunnel keeps negotiating {current} "
                f"until it is told otherwise."
            ),
            action=(
                f"Set the proposal list to '{current}, {target}' on both peers and "
                f"reload the configuration. Do not restart the SA."
            ),
            expected_disruption_s=0,
        ),
        ChangeStep(
            order=2,
            role=ConfigRole.BOTH,
            description=(
                f"Establish a second SA under the reloaded configuration, confirm it "
                f"negotiated {target}, then retire the SA still running {current}. Do "
                f"not rekey the existing SA: a running SA keeps the configuration it "
                f"was established with, so a rekey renegotiates {current} and the "
                f"change silently does nothing. This is the point of no return — if "
                f"the new SA does not report {target}, stop here and investigate "
                f"rather than continuing to step 3."
            ),
            action=(
                f"Initiate the connection again so a second SA is built from the "
                f"reloaded configuration. Confirm on both ends that it reports "
                f"{target}, then delete the SA still reporting {current} — identify "
                f"it by its algorithms, not by its position in the SA list."
            ),
            expected_disruption_s=0,
        ),
        ChangeStep(
            order=3,
            role=ConfigRole.BOTH,
            description=(
                f"Remove {current} from both ends, leaving {target} alone. Safe only "
                f"because step 2 proved the tunnel is already running on {target}."
            ),
            action=(
                f"Set the proposal list to '{target}' on both peers and reload. Do not "
                f"restart the SA."
            ),
            expected_disruption_s=0,
        ),
        ChangeStep(
            order=4,
            role=ConfigRole.BOTH,
            description=(
                f"Confirm the tunnel is still established on {target} with the weak "
                f"proposal gone, and that traffic is still passing."
            ),
            action=(
                "Confirm the SA is installed and carrying traffic, and that the "
                "proposal list no longer contains the removed algorithm."
            ),
            expected_disruption_s=0,
        ),
    ]


def simulate(current: str, target: str) -> list[ProposalState]:
    """Every state the estate passes through, including partial application.

    A four-step narrative describes what an operator intends; this describes what is
    actually true between the keystrokes. Steps 1 and 3 each reach one end before the
    other, and those half-applied states are where a bad ordering shows up.
    """
    both = (current, target)
    return [
        ProposalState("initial", (current,), (current,)),
        ProposalState("step 1, applied to the local end only", both, (current,)),
        ProposalState("step 1 complete, both ends offer both", both, both),
        ProposalState("step 2, a second SA established on the target", both, both),
        ProposalState("step 2, the old SA retired", both, both),
        ProposalState("step 3, removed from the local end only", (target,), both),
        ProposalState("step 3 complete, both ends offer the target", (target,), (target,)),
        ProposalState("step 4, verified", (target,), (target,)),
    ]


def naive_sequence_states(current: str, target: str) -> list[ProposalState]:
    """The obvious approach, for comparison: replace the proposal on each end in turn.

    Exists so the safety check has something it must reject. A test that only ever sees
    safe input proves nothing about the check.
    """
    return [
        ProposalState("initial", (current,), (current,)),
        ProposalState("replaced on the local end only", (target,), (current,)),
        ProposalState("replaced on both ends", (target,), (target,)),
    ]


def unsafe_states(states: list[ProposalState]) -> list[ProposalState]:
    """States in which the two ends share no proposal, so the tunnel cannot establish."""
    return [state for state in states if not state.is_safe]


def verify_zero_downtime(current: str, target: str) -> list[ProposalState]:
    """Simulate the sequence and refuse it if any state would drop the tunnel."""
    states = simulate(current, target)
    unsafe = unsafe_states(states)
    if unsafe:
        raise SequenceError(
            "this sequence passes through a state with no common proposal, so the "
            "tunnel would drop: " + "; ".join(s.describe() for s in unsafe)
        )
    return states
