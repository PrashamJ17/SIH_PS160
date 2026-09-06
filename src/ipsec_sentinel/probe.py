"""Active IKE transform enumeration.

**This is the only module in the project that transmits.** Everything else reads a
capture. That distinction is the product's central claim, so the gate is here in the
library rather than only in the command line: :func:`enumerate_transforms` raises unless
the caller passes ``authorised=True``, and no analysis path imports this module at all.
A future contributor who wires it into the passive lane has to do so deliberately.

What it does and why it is worth the exception: a passive observer sees the proposals a
peer *offered during the sessions that happened to be captured*, which is a lower bound
on what that peer will accept. A gateway that negotiated AES-GCM this morning may still
accept 3DES from a peer that offers nothing else, and no amount of listening reveals
that. Enumeration asks directly, one proposal at a time, and the answer is the device's
actual acceptance policy.

What it does **not** do: it never completes a handshake. Each probe sends one
IKE_SA_INIT and reads the reply. The key exchange value is random data of the correct
length for the group — the responder answers with its chosen proposal, or with
NO_PROPOSAL_CHOSEN, before that value is ever used. Nothing is authenticated, no SA is
created, and the half-open exchange expires on the responder's own timer.

Active probing is unsafe on production OT networks and the caller is told so. The IKE
daemons on industrial gateways are not always robust, and a rejected proposal is logged
at the far end as a failed negotiation — which looks like an attack to whoever reads
those logs, because it is the same thing an attacker would do.
"""

from __future__ import annotations

import secrets
import socket
import time
from dataclasses import dataclass
from typing import Final

from ipsec_sentinel.models import Proposal
from ipsec_sentinel.parser.constants import (
    DH_GROUPS,
    ENCR_ALGORITHMS,
    INTEG_ALGORITHMS,
    PRF_ALGORITHMS,
)
from ipsec_sentinel.parser.message import ParsedMessage, parse_ike_message
from ipsec_sentinel.parser.reader import ParseError

IKE_PORT: Final = 500
IKEV2_VERSION: Final = 0x20
IKE_SA_INIT: Final = 34
FLAG_INITIATOR: Final = 0x08

PAYLOAD_NONE: Final = 0
PAYLOAD_SA: Final = 33
PAYLOAD_KE: Final = 34
PAYLOAD_NONCE: Final = 40

PROTOCOL_IKE: Final = 1
LAST_SUBSTRUCTURE: Final = 0
MORE_TRANSFORMS: Final = 3

TRANSFORM_TYPE_ENCR: Final = 1
TRANSFORM_TYPE_PRF: Final = 2
TRANSFORM_TYPE_INTEG: Final = 3
TRANSFORM_TYPE_DH: Final = 4

# RFC 7296 section 3.3.5: attribute format bit set means the value is inline (TV), and
# attribute type 14 is the key length in bits.
ATTRIBUTE_KEY_LENGTH: Final = 0x800E

NONCE_BYTES: Final = 32
DEFAULT_TIMEOUT_S: Final = 2.0
DEFAULT_GAP_S: Final = 0.2

# Length of the key exchange data for each group, in bytes. Tabulated rather than
# derived: for MODP it is the modulus size, but for ECP it is *two* coordinates
# (RFC 5903), so a single formula would send a half-length payload for every elliptic
# group and every probe would be rejected for the wrong reason.
KE_LENGTHS: Final[dict[int, int]] = {
    1: 96,
    2: 128,
    5: 192,
    14: 256,
    15: 384,
    16: 512,
    19: 64,
    20: 96,
    21: 132,
    31: 32,
}


class AuthorisationError(PermissionError):
    """Active probing was attempted without explicit authorisation."""


class ProbeError(RuntimeError):
    """A probe could not be constructed or sent."""


@dataclass(frozen=True)
class Candidate:
    """One complete proposal to offer."""

    encryption: int
    integrity: int
    prf: int
    dh_group: int
    key_length: int | None = None

    def describe(self) -> str:
        encryption = ENCR_ALGORITHMS.get(self.encryption, f"ENCR_{self.encryption}")
        if self.key_length:
            encryption = f"{encryption}-{self.key_length}"
        integrity = INTEG_ALGORITHMS.get(self.integrity, f"INTEG_{self.integrity}")
        prf = PRF_ALGORITHMS.get(self.prf, f"PRF_{self.prf}")
        group = DH_GROUPS.get(self.dh_group, (f"group {self.dh_group}", 0))[0]
        return f"{encryption}/{integrity}/{prf}/{group}"


@dataclass(frozen=True)
class ProbeOutcome:
    """What the far end said about one candidate."""

    candidate: Candidate
    accepted: bool
    verdict: str
    """One of: accepted, rejected, wrong-group, no-response, unreadable."""

    detail: str = ""
    negotiated: Proposal | None = None
    round_trip_ms: float | None = None

    def summary(self) -> str:
        marker = "ACCEPTED" if self.accepted else self.verdict.upper()
        return (
            f"{marker:<12} {self.candidate.describe()}{f' — {self.detail}' if self.detail else ''}"
        )


# The proposals worth asking about: the ones a baseline forbids, and enough strong ones
# to tell "this device only accepts good crypto" from "this device is not answering".
DEFAULT_CANDIDATES: Final[tuple[Candidate, ...]] = (
    Candidate(encryption=3, integrity=1, prf=1, dh_group=2),  # 3DES/MD5/MODP-1024
    Candidate(encryption=3, integrity=2, prf=2, dh_group=2),  # 3DES/SHA1/MODP-1024
    Candidate(encryption=12, integrity=2, prf=2, dh_group=2, key_length=128),
    Candidate(encryption=12, integrity=2, prf=2, dh_group=14, key_length=128),
    Candidate(encryption=12, integrity=12, prf=5, dh_group=14, key_length=128),
    Candidate(encryption=12, integrity=12, prf=5, dh_group=14, key_length=256),
    Candidate(encryption=12, integrity=13, prf=6, dh_group=20, key_length=256),
    Candidate(encryption=12, integrity=12, prf=5, dh_group=19, key_length=256),
    Candidate(encryption=20, integrity=0, prf=5, dh_group=19, key_length=256),
    Candidate(encryption=20, integrity=0, prf=5, dh_group=31, key_length=256),
)


def _attribute(key_length: int) -> bytes:
    return ATTRIBUTE_KEY_LENGTH.to_bytes(2, "big") + key_length.to_bytes(2, "big")


def _transform(
    transform_type: int, transform_id: int, *, last: bool, key_length: int | None = None
) -> bytes:
    attributes = _attribute(key_length) if key_length else b""
    body = (
        transform_type.to_bytes(1, "big") + b"\x00" + transform_id.to_bytes(2, "big") + attributes
    )
    length = 4 + len(body)
    header = (LAST_SUBSTRUCTURE if last else MORE_TRANSFORMS).to_bytes(1, "big")
    return header + b"\x00" + length.to_bytes(2, "big") + body


def _sa_payload(candidate: Candidate) -> bytes:
    transforms = [
        _transform(
            TRANSFORM_TYPE_ENCR,
            candidate.encryption,
            last=False,
            key_length=candidate.key_length,
        ),
        _transform(TRANSFORM_TYPE_PRF, candidate.prf, last=False),
        _transform(TRANSFORM_TYPE_INTEG, candidate.integrity, last=False),
        _transform(TRANSFORM_TYPE_DH, candidate.dh_group, last=True),
    ]
    joined = b"".join(transforms)
    proposal_body = (
        b"\x01"  # proposal number 1
        + PROTOCOL_IKE.to_bytes(1, "big")
        + b"\x00"  # SPI size: none, as required for IKE in an IKE_SA_INIT
        + len(transforms).to_bytes(1, "big")
        + joined
    )
    proposal_length = 4 + len(proposal_body)
    proposal = (
        LAST_SUBSTRUCTURE.to_bytes(1, "big")
        + b"\x00"
        + proposal_length.to_bytes(2, "big")
        + proposal_body
    )
    return proposal


def _payload(next_payload: int, body: bytes) -> bytes:
    return next_payload.to_bytes(1, "big") + b"\x00" + (4 + len(body)).to_bytes(2, "big") + body


def build_ike_sa_init(candidate: Candidate, initiator_spi: bytes | None = None) -> bytes:
    """Encode one IKE_SA_INIT offering exactly this proposal.

    The key exchange value is random data of the length the group requires. It is never
    used: the responder selects a proposal, or refuses, before deriving anything from
    it, and no reply this tool sends could complete the exchange.
    """
    if candidate.dh_group not in KE_LENGTHS:
        raise ProbeError(
            f"no key exchange length known for DH group {candidate.dh_group}; add it to "
            f"KE_LENGTHS rather than guessing, since a wrong length is rejected for the "
            f"wrong reason"
        )
    spi = initiator_spi or secrets.token_bytes(8)
    if len(spi) != 8:
        raise ProbeError(f"an initiator SPI is 8 bytes, got {len(spi)}")

    sa = _payload(PAYLOAD_KE, _sa_payload(candidate))
    ke_body = (
        candidate.dh_group.to_bytes(2, "big")
        + b"\x00\x00"
        + secrets.token_bytes(KE_LENGTHS[candidate.dh_group])
    )
    ke = _payload(PAYLOAD_NONCE, ke_body)
    nonce = _payload(PAYLOAD_NONE, secrets.token_bytes(NONCE_BYTES))

    body = sa + ke + nonce
    header = (
        spi
        + b"\x00" * 8
        + PAYLOAD_SA.to_bytes(1, "big")
        + IKEV2_VERSION.to_bytes(1, "big")
        + IKE_SA_INIT.to_bytes(1, "big")
        + FLAG_INITIATOR.to_bytes(1, "big")
        + (0).to_bytes(4, "big")
        + (28 + len(body)).to_bytes(4, "big")
    )
    return header + body


def interpret_reply(
    reply: bytes, candidate: Candidate, round_trip_ms: float | None = None
) -> ProbeOutcome:
    """Read a responder's answer to one probe.

    Public and separate from the sending, so the judgement can be tested against replies
    a real strongSwan produced rather than only against ones this project made up.
    """
    try:
        parsed = parse_ike_message(reply)
    except ParseError as exc:
        return ProbeOutcome(
            candidate=candidate,
            accepted=False,
            verdict="unreadable",
            detail=f"the reply could not be parsed: {exc}",
            round_trip_ms=round_trip_ms,
        )
    return _interpret(parsed, candidate, round_trip_ms)


def _interpret(
    parsed: ParsedMessage, candidate: Candidate, elapsed_ms: float | None
) -> ProbeOutcome:
    notifies = {notify.upper() for notify in parsed.notifies}
    if "NO_PROPOSAL_CHOSEN" in notifies:
        return ProbeOutcome(
            candidate=candidate,
            accepted=False,
            verdict="rejected",
            detail="the responder refused this proposal",
            round_trip_ms=elapsed_ms,
        )
    if "INVALID_KE_PAYLOAD" in notifies:
        return ProbeOutcome(
            candidate=candidate,
            accepted=False,
            verdict="wrong-group",
            detail=(
                "the responder wants a different Diffie-Hellman group; the rest of the "
                "proposal was not judged"
            ),
            round_trip_ms=elapsed_ms,
        )
    if parsed.proposals:
        return ProbeOutcome(
            candidate=candidate,
            accepted=True,
            verdict="accepted",
            detail="the responder selected this proposal",
            negotiated=parsed.proposals[0],
            round_trip_ms=elapsed_ms,
        )
    return ProbeOutcome(
        candidate=candidate,
        accepted=False,
        verdict="unreadable",
        detail=f"a reply arrived with no proposal and no notify: {sorted(notifies)}",
        round_trip_ms=elapsed_ms,
    )


def probe_once(
    host: str,
    candidate: Candidate,
    *,
    port: int = IKE_PORT,
    timeout_s: float = DEFAULT_TIMEOUT_S,
) -> ProbeOutcome:
    """Offer one proposal and report what came back.

    A silent responder is reported as ``no-response`` rather than as a rejection. The
    two are different: a filtered port, a host that is down and a device that refused
    the proposal all produce no packet, and only the last says anything about its
    acceptance policy.
    """
    datagram = build_ike_sa_init(candidate)
    started = time.monotonic()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout_s)
        try:
            sock.sendto(datagram, (host, port))
            reply, _ = sock.recvfrom(65535)
        except TimeoutError:
            return ProbeOutcome(
                candidate=candidate,
                accepted=False,
                verdict="no-response",
                detail=(
                    "nothing came back within the timeout. A filtered port, a host that "
                    "is down and a refused proposal all look like this, so no conclusion "
                    "about acceptance can be drawn"
                ),
            )
        except OSError as exc:
            return ProbeOutcome(
                candidate=candidate, accepted=False, verdict="no-response", detail=str(exc)
            )
    return interpret_reply(reply, candidate, (time.monotonic() - started) * 1000)


AUTHORISATION_REQUIRED: Final = (
    "Active probing transmits to the target and must not be run without permission "
    "from whoever operates it. Pass authorised=True (or --i-have-authorisation on the "
    "command line) to confirm you have it. On production and OT networks, probing can "
    "disturb a fragile IKE daemon and will appear in the far end's logs as a failed "
    "negotiation, which is indistinguishable from an attack."
)


def enumerate_transforms(
    host: str,
    *,
    authorised: bool = False,
    candidates: tuple[Candidate, ...] = DEFAULT_CANDIDATES,
    port: int = IKE_PORT,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    gap_s: float = DEFAULT_GAP_S,
) -> list[ProbeOutcome]:
    """Offer each candidate in turn and report which the target accepts.

    Refuses without ``authorised=True``. The gate is here rather than only in the CLI
    because this is the one function in the project that transmits, and a library that
    can be made to transmit by an ordinary-looking call is a library that eventually
    will be.

    ``gap_s`` spaces the probes out. Back-to-back IKE_SA_INITs from one source look like
    a flood to a rate limiter, and being throttled would make a device that accepts a
    weak proposal report as silent — the wrong answer in the dangerous direction.
    """
    if not authorised:
        raise AuthorisationError(AUTHORISATION_REQUIRED)
    if not candidates:
        raise ProbeError("no candidates to probe with")

    outcomes: list[ProbeOutcome] = []
    for index, candidate in enumerate(candidates):
        if index and gap_s:
            time.sleep(gap_s)
        outcomes.append(probe_once(host, candidate, port=port, timeout_s=timeout_s))
    return outcomes


def weak_acceptances(outcomes: list[ProbeOutcome]) -> list[ProbeOutcome]:
    """Accepted proposals that a modern baseline would refuse.

    The point of the exercise: a device that negotiated something strong during the
    capture, and still accepts this, has an acceptance policy its observed sessions did
    not reveal.
    """
    weak_encryption = {1, 2, 3, 5, 6, 7, 8, 11}  # DES, 3DES, RC5, IDEA, CAST, Blowfish, NULL
    weak_integrity = {1}  # HMAC-MD5
    weak_groups = {1, 2, 5}  # 768-, 1024- and 1536-bit MODP
    return [
        outcome
        for outcome in outcomes
        if outcome.accepted
        and (
            outcome.candidate.encryption in weak_encryption
            or outcome.candidate.integrity in weak_integrity
            or outcome.candidate.dh_group in weak_groups
        )
    ]
