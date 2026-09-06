"""Close the remediation loop against a real capture (build plan Step 8.6).

The unit tests feed :func:`verify_remediation` proposals built by hand. This feeds it
proposals a real strongSwan negotiated and a real parser read off the wire, which is the
only way to find out whether the two agree about what a proposal *is*. They did not, at
first: see the note in :mod:`ipsec_sentinel.remediate.verify` about the field that was
never populated.

It walks the Step 8.4 sequence on a live pair with a capture running throughout, and
checks the verdict at each stage. All four outcomes appear in one run, in the order an
operator meets them:

* before the change - the weak proposal is still being negotiated -> ``FAILED``
* after step 2 - the target is in use, the old proposal is still offered -> ``PARTIAL``
* after step 3, before the next negotiation - nothing new to read -> ``PENDING``
* after the next negotiation - the old proposal is gone -> ``VERIFIED``, finding closed

The third and fourth are the point. Removing a proposal from a configuration file is not
observable until the peers next negotiate, so a fix is *pending* until the wire confirms
it. Anything that closed the finding at step 3 would be reporting the configuration, not
the tunnel.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from pathlib import Path

import pytest

from ipsec_sentinel.models import IKEExchange, Proposal
from ipsec_sentinel.parser.correlate import Negotiation, group_negotiations
from ipsec_sentinel.parser.pcap import extract_ike_exchanges
from ipsec_sentinel.remediate.generators.strongswan import harden
from ipsec_sentinel.remediate.verify import VerificationStatus, describe, verify_remediation
from testbed.orchestrate.config_gen import TunnelConfig
from testbed.orchestrate.matrix import expand_matrix
from tests.fixtures.livepair import SETTLE_S, live_pair

pytestmark = [
    pytest.mark.integration,
    pytest.mark.slow,
    pytest.mark.usefixtures("strongswan_image", "traffic_image"),
]

FINDINGS = ["CRY-02", "CRY-06"]


def anchor(label: str) -> TunnelConfig:
    return next(lc.config for lc in expand_matrix() if lc.label == label)


def transition() -> tuple[TunnelConfig, TunnelConfig]:
    current = anchor("weak")
    target, changes = harden(current)
    assert changes
    assert current.ike_version == target.ike_version == "ikev2"
    return current, target


def both_lists(current: TunnelConfig, target: TunnelConfig) -> tuple[str, str]:
    return (
        f"{target.proposal_string()},{current.proposal_string()}",
        f"{target.esp_proposal_string()},{current.esp_proposal_string()}",
    )


def negotiations(exchanges: list[IKEExchange]) -> list[Negotiation]:
    """Negotiations that carry an agreed proposal, oldest first.

    The parser yields one exchange per IKE *message*; a single IKEv2 setup is four or
    more of them. Only IKE_SA_INIT carries SA payloads in the clear, and it takes both
    directions of it to answer the question: the initiator's message holds the offer
    list, the responder's reply holds the one proposal it chose.
    """
    grouped = [n for n in group_negotiations(exchanges) if n.accepted_proposal is not None]
    return sorted(grouped, key=lambda negotiation: negotiation.started_at)


def messages(found: list[Negotiation]) -> list[IKEExchange]:
    """Flatten back to the message stream ``verify_remediation`` takes."""
    return [message for negotiation in found for message in negotiation.messages]


def read_negotiations(out_dir: Path) -> list[Negotiation]:
    return negotiations(extract_ike_exchanges(out_dir / "capture_outer.pcap"))


class TestTheLoopClosesOnObservedEvidence:
    def test_all_four_verdicts_appear_in_one_real_change(self, tmp_path: Path) -> None:
        current, target = transition()
        marks: dict[str, datetime] = {}

        with live_pair(current, capture_to=tmp_path) as pair:
            time.sleep(1)
            marks["change_started"] = datetime.now(UTC)

            # Step 1 - offer both proposals on both ends.
            pair.set_proposals(*both_lists(current, target))
            pair.load()
            time.sleep(1)

            # Step 2 - build a second SA from the reloaded configuration.
            assert pair.initiate().returncode == 0
            time.sleep(SETTLE_S)
            migrated = pair.sa_carrying(target)
            assert migrated is not None, f"step 2 did not reach the target: {pair.sas()}"
            stale = pair.sa_carrying(current)
            assert stale is not None
            pair.terminate(stale.ike_id)
            time.sleep(SETTLE_S)
            marks["step_2_done"] = datetime.now(UTC)

            # Step 3 - remove the old proposal. Nothing observable happens yet.
            pair.set_proposals(target.proposal_string(), target.esp_proposal_string())
            pair.load()
            time.sleep(1)
            marks["step_3_done"] = datetime.now(UTC)

            # The next negotiation is what makes the removal visible. In a deployment
            # that is the natural rekey; here it is brought forward so the test does
            # not wait out an SA lifetime.
            assert pair.initiate().returncode == 0
            time.sleep(SETTLE_S)
            confirming = [sa for sa in pair.sas() if sa.carries(target)]
            assert len(confirming) == 2, f"expected the old and new target SAs: {pair.sas()}"
            pair.terminate(min(sa.ike_id for sa in confirming))
            time.sleep(1)

        found = read_negotiations(tmp_path)
        assert len(found) >= 3, (
            f"expected the initial handshake and two later negotiations, read "
            f"{[describe(n.accepted_proposal) for n in found if n.accepted_proposal]}"
        )

        initial = found[0]
        assert initial.accepted_proposal is not None
        weak_proposal: Proposal = initial.accepted_proposal

        after_change = [n for n in found if n.started_at >= marks["change_started"]]
        assert after_change, "the step 2 negotiation is missing from the capture"
        migrated_negotiation = after_change[0]
        assert migrated_negotiation.accepted_proposal is not None
        target_proposal: Proposal = migrated_negotiation.accepted_proposal

        # Anchor both proposals on their algorithms, so neither is defined circularly
        # by the verdict it is about to produce.
        assert "SHA2_256" in describe(target_proposal), describe(target_proposal)
        assert "SHA2" not in describe(weak_proposal), describe(weak_proposal)

        # --- before the change: still negotiating the weak proposal --------------
        before = verify_remediation(
            "live", target_proposal, initial.messages, findings_addressed=FINDINGS
        )
        assert before.status is VerificationStatus.FAILED, before.evidence
        assert before.findings_still_open == FINDINGS

        # --- after step 2: target in use, old proposal still offered -------------
        # Only what had been observed by the end of step 2. Passing the whole capture
        # would hand it the confirming negotiation from step 3 as well, and the verdict
        # would be about the finished change rather than the half-finished one.
        through_step_2 = [n for n in found if n.started_at <= marks["step_2_done"]]
        partial = verify_remediation(
            "live",
            target_proposal,
            messages(through_step_2),
            findings_addressed=FINDINGS,
            superseded=[weak_proposal],
            changed_at=marks["change_started"],
        )
        assert partial.status is VerificationStatus.PARTIAL, (
            f"expected the old proposal to still be on offer after step 2: {partial.evidence}"
        )
        assert partial.residual_offers, partial.evidence
        assert partial.findings_closed == []

        # --- after step 3, before the next negotiation: nothing to read ----------
        before_confirmation = [n for n in found if n.started_at <= marks["step_3_done"]]
        pending = verify_remediation(
            "live",
            target_proposal,
            messages(before_confirmation),
            findings_addressed=FINDINGS,
            superseded=[weak_proposal],
            changed_at=marks["step_3_done"],
        )
        assert pending.status is VerificationStatus.PENDING, pending.evidence
        assert pending.findings_still_open == FINDINGS

        # --- after the confirming negotiation: closed ----------------------------
        verified = verify_remediation(
            "live",
            target_proposal,
            messages(found),
            findings_addressed=FINDINGS,
            superseded=[weak_proposal],
            changed_at=marks["step_3_done"],
        )
        assert verified.status is VerificationStatus.VERIFIED, verified.evidence
        assert verified.findings_closed == FINDINGS
        assert verified.findings_still_open == []
        assert verified.residual_offers == []

    def test_the_offer_list_is_what_changes_between_the_two_verdicts(self, tmp_path: Path) -> None:
        """The accepted proposal is identical either side of step 3.

        Which is the whole reason ``PARTIAL`` exists: a verifier reading the agreed
        proposal alone sees no difference between a tunnel that is still downgradeable
        and one that is not.
        """
        current, target = transition()
        with live_pair(current, capture_to=tmp_path) as pair:
            pair.set_proposals(*both_lists(current, target))
            pair.load()
            assert pair.initiate().returncode == 0
            time.sleep(SETTLE_S)
            stale = pair.sa_carrying(current)
            assert stale is not None
            pair.terminate(stale.ike_id)
            time.sleep(SETTLE_S)

            pair.set_proposals(target.proposal_string(), target.esp_proposal_string())
            pair.load()
            time.sleep(1)
            assert pair.initiate().returncode == 0
            time.sleep(SETTLE_S)

        found = read_negotiations(tmp_path)
        assert len(found) >= 3
        both_offered, target_only = found[-2], found[-1]

        assert both_offered.accepted_proposal is not None
        assert target_only.accepted_proposal is not None
        assert describe(both_offered.accepted_proposal) == describe(
            target_only.accepted_proposal
        ), "the accepted proposal should be unchanged; only the offer list differs"

        offered_before = both_offered.representative.proposals_offered
        offered_after = target_only.representative.proposals_offered
        assert len(offered_before) > len(offered_after), (
            f"step 3 should have shrunk the offer list: "
            f"{len(offered_before)} then {len(offered_after)}"
        )
