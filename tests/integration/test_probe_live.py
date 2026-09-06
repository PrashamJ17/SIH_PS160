"""Active transform enumeration against a live strongSwan (build plan Step 10.1).

The unit tests round-trip the encoder through this project's own parser, which proves
the two agree with each other and nothing more. A frame both halves of one codebase like
can still be one a real IKE daemon drops without a word — and a dropped frame is reported
as "no response", which reads as a filtered target rather than as our own bug. That
failure mode is the reason this test exists.

The responder here is configured with a known proposal, so the enumeration has an oracle:
that exact proposal must be accepted, and everything else must be refused. A prober that
reported everything as refused would pass a weaker test.
"""

from __future__ import annotations

import time

import pytest

from ipsec_sentinel.probe import (
    DEFAULT_CANDIDATES,
    Candidate,
    build_ike_sa_init,
    interpret_reply,
    weak_acceptances,
)
from testbed.orchestrate.config_gen import TunnelConfig
from testbed.orchestrate.matrix import expand_matrix
from tests.fixtures.livepair import LivePair, live_pair

pytestmark = [
    pytest.mark.integration,
    pytest.mark.slow,
    pytest.mark.usefixtures("strongswan_image", "traffic_image"),
]

RIGHT_TRANSIT = "10.100.0.3"

# The responder's configuration, and the candidate that exactly matches it.
RESPONDER_LABEL = "medium"  # aes128-sha256-prfsha256-modp2048
MATCHING = Candidate(encryption=12, integrity=12, prf=5, dh_group=14, key_length=128)
WEAK = Candidate(encryption=3, integrity=1, prf=1, dh_group=2)


def anchor(label: str) -> TunnelConfig:
    return next(lc.config for lc in expand_matrix() if lc.label == label)


def probe(pair: LivePair, candidate: Candidate) -> bytes | None:
    return pair.send_datagram(build_ike_sa_init(candidate), RIGHT_TRANSIT)


class TestAgainstALiveResponder:
    def test_the_configured_proposal_is_accepted(self) -> None:
        """The oracle: this responder is configured for exactly this proposal."""
        with live_pair(anchor(RESPONDER_LABEL)) as pair:
            reply = probe(pair, MATCHING)
            assert reply is not None, "strongSwan did not answer a well-formed probe"
            outcome = interpret_reply(reply, MATCHING)
        assert outcome.accepted is True, outcome.summary()
        assert outcome.negotiated is not None
        ids = {t.type.value if t.type else "?": t.id for t in outcome.negotiated.transforms}
        assert ids["ENCR"] == MATCHING.encryption
        assert ids["INTEG"] == MATCHING.integrity
        assert ids["DH"] == MATCHING.dh_group

    def test_a_weak_proposal_is_refused(self) -> None:
        with live_pair(anchor(RESPONDER_LABEL)) as pair:
            reply = probe(pair, WEAK)
            assert reply is not None, "strongSwan did not answer a well-formed probe"
            outcome = interpret_reply(reply, WEAK)
        assert outcome.accepted is False
        assert outcome.verdict == "rejected", outcome.summary()

    def test_every_default_candidate_gets_an_answer(self) -> None:
        """A frame the daemon cannot parse is dropped silently and reads as a filtered port.

        Every probe drawing a reply is what shows the encoding is right — the acceptance
        decisions are the responder's business, but the answer arriving is ours.
        """
        answered: list[Candidate] = []
        unanswered: list[Candidate] = []
        with live_pair(anchor(RESPONDER_LABEL)) as pair:
            for candidate in DEFAULT_CANDIDATES:
                time.sleep(0.2)
                if probe(pair, candidate) is None:
                    unanswered.append(candidate)
                else:
                    answered.append(candidate)
        assert not unanswered, (
            f"strongSwan ignored {len(unanswered)} probe(s), which means the frames are "
            f"malformed: {[c.describe() for c in unanswered]}"
        )
        assert len(answered) == len(DEFAULT_CANDIDATES)

    def test_the_enumeration_discriminates(self) -> None:
        """Accepted and refused, on one responder, in one run.

        A prober that answered "refused" to everything would pass a test that only
        checked refusals, and would be useless.
        """
        outcomes = []
        with live_pair(anchor(RESPONDER_LABEL)) as pair:
            for candidate in (MATCHING, *DEFAULT_CANDIDATES[:3]):
                time.sleep(0.2)
                reply = probe(pair, candidate)
                assert reply is not None
                outcomes.append(interpret_reply(reply, candidate))

        accepted = [o for o in outcomes if o.accepted]
        refused = [o for o in outcomes if not o.accepted]
        assert accepted, "nothing was accepted; the prober cannot tell the two apart"
        assert refused, "nothing was refused; the prober cannot tell the two apart"
        assert accepted[0].candidate == MATCHING

    def test_a_weak_responder_reveals_what_listening_would_not(self) -> None:
        """The reason active probing exists at all.

        A gateway configured for a weak proposal accepts it, and ``weak_acceptances``
        surfaces that. Passive observation of a capture in which the gateway happened to
        negotiate something strong would never show it.
        """
        weak_config = anchor("worst")
        assert (weak_config.encryption, weak_config.integrity, weak_config.dh_group) == (
            "3des",
            "md5",
            "modp1024",
        ), "the 'worst' anchor changed; this candidate no longer matches it"
        with live_pair(weak_config.with_(ike_version="ikev2", aggressive=False)) as pair:
            reply = probe(pair, WEAK)
            assert reply is not None
            outcome = interpret_reply(reply, WEAK)

        assert outcome.accepted is True, (
            f"a responder configured for 3DES/MD5/MODP-1024 refused it: {outcome.summary()}"
        )
        assert len(weak_acceptances([outcome])) == 1


class TestTheProbeIsHarmless:
    def test_the_tunnel_still_works_after_probing(self) -> None:
        """A half-open IKE_SA_INIT must not disturb an established SA.

        Worth asserting because the tool tells operators this is safe on a healthy
        device, and that claim should rest on something.
        """
        with live_pair(anchor(RESPONDER_LABEL)) as pair:
            before = pair.sas()
            assert before, "the tunnel did not establish"
            for candidate in DEFAULT_CANDIDATES:
                time.sleep(0.2)
                probe(pair, candidate)
            time.sleep(2)
            after = pair.sas()

        assert len(after) == len(before)
        assert {sa.ike_id for sa in after} == {sa.ike_id for sa in before}
        assert all(sa.esp_algorithms for sa in after), "a child SA was lost"
