"""Tests for active IKE transform enumeration (build plan Step 10.1).

Three things are being checked, in order of how badly they would matter.

**The gate.** This is the only module in the project that transmits, so the test that
matters most is that it refuses to without explicit authorisation, and that nothing in
the analysis path can reach it.

**The encoder.** A frame that a responder cannot parse produces silence, and silence is
reported as "no response" — which reads as "the target is filtered" rather than "we sent
rubbish". Every candidate is round-tripped through this project's own parser, and
``tests/integration/test_probe_live.py`` puts the same frames in front of a real
strongSwan.

**The interpretation.** No response, a rejection, and a wrong-group notify are three
different answers, and only one of them says anything about the target's acceptance
policy. Conflating them in the safe-looking direction would report a device that accepts
3DES as silent.
"""

from __future__ import annotations

import socket
import threading
from pathlib import Path

import pytest

from ipsec_sentinel.parser.message import parse_ike_message
from ipsec_sentinel.probe import (
    AUTHORISATION_REQUIRED,
    DEFAULT_CANDIDATES,
    KE_LENGTHS,
    AuthorisationError,
    Candidate,
    ProbeError,
    build_ike_sa_init,
    enumerate_transforms,
    interpret_reply,
    probe_once,
    weak_acceptances,
)

WEAK = Candidate(encryption=3, integrity=1, prf=1, dh_group=2)
STRONG = Candidate(encryption=20, integrity=0, prf=5, dh_group=31, key_length=256)
# The proposal the captured replies were produced against.
MATCHING = Candidate(encryption=12, integrity=12, prf=5, dh_group=14, key_length=128)


class TestTheAuthorisationGate:
    """The gate lives in the library, not only in the CLI."""

    def test_enumeration_refuses_without_authorisation(self) -> None:
        with pytest.raises(AuthorisationError):
            enumerate_transforms("192.0.2.1")

    def test_the_refusal_explains_what_is_being_asked(self) -> None:
        with pytest.raises(AuthorisationError) as raised:
            enumerate_transforms("192.0.2.1")
        message = str(raised.value)
        assert "permission from whoever operates it" in message
        assert "--i-have-authorisation" in message

    def test_the_warning_names_the_operational_risk(self) -> None:
        assert "OT networks" in AUTHORISATION_REQUIRED
        assert "indistinguishable from an attack" in AUTHORISATION_REQUIRED

    def test_authorisation_is_not_the_default_of_any_parameter(self) -> None:
        import inspect

        signature = inspect.signature(enumerate_transforms)
        assert signature.parameters["authorised"].default is False

    def test_no_analysis_module_imports_the_prober(self) -> None:
        """A passive lane that can reach this module is one that eventually will."""
        import ast
        from pathlib import Path

        root = Path(__file__).resolve().parents[2] / "src" / "ipsec_sentinel"
        passive = [
            root / "analyse.py",
            *(root / "parser").glob("*.py"),
            *(root / "assess").rglob("*.py"),
            *(root / "report").glob("*.py"),
            *(root / "remediate").rglob("*.py"),
        ]
        offenders = []
        for path in passive:
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and (node.module or "").endswith("probe"):
                    offenders.append(path.name)
                elif isinstance(node, ast.Import):
                    offenders += [path.name for a in node.names if a.name.endswith(".probe")]
        assert not offenders, f"the passive lane imports the prober: {sorted(set(offenders))}"

    def test_an_authorised_enumeration_with_no_candidates_is_refused(self) -> None:
        with pytest.raises(ProbeError, match="no candidates"):
            enumerate_transforms("192.0.2.1", authorised=True, candidates=())


class TestTheEncoder:
    @pytest.mark.parametrize("candidate", DEFAULT_CANDIDATES, ids=lambda c: c.describe())
    def test_every_default_candidate_encodes_and_parses(self, candidate: Candidate) -> None:
        parsed = parse_ike_message(build_ike_sa_init(candidate))
        assert parsed.header.exchange_type_name == "IKE_SA_INIT"
        assert not parsed.errors, parsed.errors
        assert parsed.proposals

    @pytest.mark.parametrize("candidate", DEFAULT_CANDIDATES, ids=lambda c: c.describe())
    def test_the_frame_offers_exactly_what_was_asked_for(self, candidate: Candidate) -> None:
        """A prober that offers something other than the candidate answers the wrong question."""
        parsed = parse_ike_message(build_ike_sa_init(candidate))
        transforms = {t.type.value if t.type else "?": t for t in parsed.proposals[0].transforms}
        assert transforms["ENCR"].id == candidate.encryption
        assert transforms["INTEG"].id == candidate.integrity
        assert transforms["PRF"].id == candidate.prf
        assert transforms["DH"].id == candidate.dh_group
        assert transforms["ENCR"].key_length == candidate.key_length

    @pytest.mark.parametrize("candidate", DEFAULT_CANDIDATES, ids=lambda c: c.describe())
    def test_the_key_exchange_length_corroborates_the_group(self, candidate: Candidate) -> None:
        """A wrong length is rejected for the wrong reason, which reads as a policy answer.

        Checked with the parser's own cross-check rather than by comparing the inferred
        group, because a 96-byte payload is both 768-bit MODP and 384-bit ECP — a
        collision the parser documents and an equality test would trip over.
        """
        from ipsec_sentinel.parser.constants import check_ke_length

        check = check_ke_length(candidate.dh_group, KE_LENGTHS[candidate.dh_group])
        assert check.consistent, check.message

    def test_the_probe_and_the_parser_agree_about_key_exchange_lengths(self) -> None:
        """One source of truth. A private copy would drift and nobody would notice."""
        from ipsec_sentinel.parser.constants import KE_LENGTH_TO_GROUP

        for group, length in KE_LENGTHS.items():
            assert group in KE_LENGTH_TO_GROUP.get(length, ()), (
                f"group {group} encodes a {length}-byte KE payload, which the parser "
                f"reads as {KE_LENGTH_TO_GROUP.get(length)}"
            )

    def test_the_declared_length_matches_the_frame(self) -> None:
        """RFC 7296 section 3.1: the length field is at offset 24 and covers the whole message.

        A responder that finds it wrong drops the datagram silently, which this tool
        would report as "no response" — a filtered target rather than its own bug.
        """
        frame = build_ike_sa_init(WEAK)
        assert int.from_bytes(frame[24:28], "big") == len(frame)

    def test_it_is_an_initiator_message_with_no_responder_spi(self) -> None:
        frame = build_ike_sa_init(WEAK)
        parsed = parse_ike_message(frame)
        assert parsed.header.is_initiator is True
        assert parsed.header.is_response is False
        assert parsed.header.responder_spi == "00" * 8
        assert parsed.header.message_id == 0

    def test_each_probe_uses_a_fresh_initiator_spi(self) -> None:
        """A repeated SPI is a retransmission to the responder, not a new question."""
        seen = {parse_ike_message(build_ike_sa_init(WEAK)).header.initiator_spi for _ in range(20)}
        assert len(seen) == 20

    def test_a_supplied_spi_is_used(self) -> None:
        parsed = parse_ike_message(build_ike_sa_init(WEAK, initiator_spi=b"\x11" * 8))
        assert parsed.header.initiator_spi == "11" * 8

    def test_a_wrong_length_spi_is_refused(self) -> None:
        with pytest.raises(ProbeError, match="8 bytes"):
            build_ike_sa_init(WEAK, initiator_spi=b"\x01\x02")

    def test_an_unknown_group_is_refused_rather_than_guessed(self) -> None:
        with pytest.raises(ProbeError, match="no key exchange length known"):
            build_ike_sa_init(Candidate(encryption=12, integrity=2, prf=2, dh_group=99))

    def test_every_group_in_the_defaults_has_a_length(self) -> None:
        assert {c.dh_group for c in DEFAULT_CANDIDATES} <= set(KE_LENGTHS)

    def test_an_aead_candidate_carries_no_separate_integrity(self) -> None:
        """AES-GCM authenticates; offering INTEG alongside it is a different proposal."""
        parsed = parse_ike_message(build_ike_sa_init(STRONG))
        integ = [t for t in parsed.proposals[0].transforms if t.type and t.type.value == "INTEG"]
        assert [t.id for t in integ] == [0]


REPLIES = Path(__file__).resolve().parents[1] / "fixtures" / "probe_replies"


def real_reply(name: str) -> bytes:
    """A reply a real strongSwan actually sent, captured from the testbed.

    Recorded rather than synthesised. A hand-built reply tests this project's
    understanding of the format against itself; these test it against the daemon the
    tool will meet.
    """
    return (REPLIES / f"{name}.bin").read_bytes()


class TestInterpretingARealReply:
    """Against bytes strongSwan 5.9.8 sent in response to these exact probes."""

    def test_an_accepted_proposal_is_recognised(self) -> None:
        outcome = interpret_reply(real_reply("accepted"), MATCHING)
        assert outcome.accepted is True
        assert outcome.verdict == "accepted"
        assert outcome.negotiated is not None
        assert outcome.detail == "the responder selected this proposal"

    def test_the_negotiated_proposal_is_the_one_offered(self) -> None:
        outcome = interpret_reply(real_reply("accepted"), MATCHING)
        assert outcome.negotiated is not None
        ids = {t.type.value if t.type else "?": t.id for t in outcome.negotiated.transforms}
        assert ids["ENCR"] == MATCHING.encryption
        assert ids["DH"] == MATCHING.dh_group

    def test_a_refusal_is_recognised(self) -> None:
        outcome = interpret_reply(real_reply("rejected"), WEAK)
        assert outcome.accepted is False
        assert outcome.verdict == "rejected"

    def test_an_unacceptable_group_is_refused_outright(self) -> None:
        """strongSwan answers NO_PROPOSAL_CHOSEN, not INVALID_KE_PAYLOAD.

        INVALID_KE_PAYLOAD is for a proposal the responder *would* accept offered with
        the wrong group. When the whole proposal is unacceptable — as here — it is
        simply refused, and reading the two as the same thing would report "the
        responder wants a different group" about a device that wants a different
        everything.
        """
        outcome = interpret_reply(real_reply("wrong_group"), STRONG)
        assert outcome.verdict == "rejected"

    def test_a_refusal_is_never_read_as_an_acceptance(self) -> None:
        for name in ("rejected", "wrong_group"):
            assert interpret_reply(real_reply(name), WEAK).accepted is False

    def test_an_unparseable_reply_is_not_an_acceptance(self) -> None:
        outcome = interpret_reply(b"\x00\x01\x02", WEAK)
        assert outcome.accepted is False
        assert outcome.verdict == "unreadable"

    def test_an_empty_reply_is_not_an_acceptance(self) -> None:
        assert interpret_reply(b"", WEAK).accepted is False

    def test_the_round_trip_time_is_carried_through(self) -> None:
        outcome = interpret_reply(real_reply("accepted"), MATCHING, round_trip_ms=12.5)
        assert outcome.round_trip_ms == 12.5

    def test_the_summary_names_the_verdict_and_the_candidate(self) -> None:
        summary = interpret_reply(real_reply("rejected"), WEAK).summary()
        assert "REJECTED" in summary
        assert "ENCR_3DES" in summary


class TestSending:
    def test_a_silent_target_is_no_response_not_a_rejection(self) -> None:
        """A filtered port and a refused proposal are different answers."""
        outcome = probe_once("127.0.0.1", WEAK, port=_closed_udp_port(), timeout_s=0.5)
        assert outcome.verdict == "no-response"
        assert outcome.accepted is False
        assert "no conclusion about acceptance" in outcome.detail

    def test_a_responder_that_answers_is_read(self) -> None:
        from ipsec_sentinel.models import Proposal, Transform, TransformType
        from tests.fixtures.builders import build_ike_sa_init as build_response

        offered = Proposal(
            number=1,
            protocol="IKE",
            transforms=[
                Transform(type=TransformType.ENCR, id=12, name="ENCR_AES_CBC", key_length=128),
                Transform(type=TransformType.DH, id=2, name="1024-bit MODP"),
            ],
        )
        with _udp_responder(build_response([offered])) as port:
            outcome = probe_once("127.0.0.1", WEAK, port=port, timeout_s=3.0)
        assert outcome.accepted is True
        assert outcome.round_trip_ms is not None

    def test_an_unresolvable_host_does_not_raise(self) -> None:
        outcome = probe_once("no-such-host.invalid", WEAK, timeout_s=1.0)
        assert outcome.accepted is False
        assert outcome.verdict == "no-response"

    def test_enumeration_probes_every_candidate(self) -> None:
        port = _closed_udp_port()
        outcomes = enumerate_transforms(
            "127.0.0.1",
            authorised=True,
            candidates=DEFAULT_CANDIDATES[:3],
            port=port,
            timeout_s=0.2,
            gap_s=0.0,
        )
        assert len(outcomes) == 3
        assert [o.candidate for o in outcomes] == list(DEFAULT_CANDIDATES[:3])


class TestWeakAcceptances:
    @staticmethod
    def _accepted(candidate: Candidate) -> object:
        from ipsec_sentinel.probe import ProbeOutcome

        return ProbeOutcome(candidate=candidate, accepted=True, verdict="accepted")

    @staticmethod
    def _rejected(candidate: Candidate) -> object:
        from ipsec_sentinel.probe import ProbeOutcome

        return ProbeOutcome(candidate=candidate, accepted=False, verdict="rejected")

    def test_an_accepted_weak_cipher_is_reported(self) -> None:
        weak = weak_acceptances([self._accepted(WEAK)])  # type: ignore[list-item]
        assert len(weak) == 1

    def test_a_rejected_weak_cipher_is_not(self) -> None:
        """The point is what the device accepts, not what it was asked."""
        assert weak_acceptances([self._rejected(WEAK)]) == []  # type: ignore[list-item]

    def test_an_accepted_strong_proposal_is_not_reported(self) -> None:
        assert weak_acceptances([self._accepted(STRONG)]) == []  # type: ignore[list-item]

    def test_a_weak_group_alone_is_enough(self) -> None:
        aes_on_modp1024 = Candidate(encryption=12, integrity=12, prf=5, dh_group=2, key_length=256)
        assert len(weak_acceptances([self._accepted(aes_on_modp1024)])) == 1  # type: ignore[list-item]


def _closed_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


class _udp_responder:  # noqa: N801 — used as a context manager
    """Answer one datagram with a canned reply."""

    def __init__(self, reply: bytes) -> None:
        self.reply = reply
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = int(self.sock.getsockname()[1])
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self) -> None:
        self.sock.settimeout(5.0)
        try:
            _, addr = self.sock.recvfrom(65535)
            self.sock.sendto(self.reply, addr)
        except OSError:
            return

    def __enter__(self) -> int:
        self.thread.start()
        return self.port

    def __exit__(self, *exc: object) -> None:
        self.thread.join(timeout=5.0)
        self.sock.close()
