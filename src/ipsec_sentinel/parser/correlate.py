"""Link IKE negotiations to the ESP flows they produced.

Correlation is what turns two unrelated lists into an inventory. On its own, an IKE
exchange says what was agreed and an ESP flow says what was carried; together they say
"this tunnel, between these gateways, negotiated 3DES and moved 40 MB". Only the
combination is actionable.

Two design decisions here are load-bearing.

**A negotiation is a group of messages, not one message.** A single IKEv2 tunnel setup
is at least IKE_SA_INIT and IKE_AUTH in both directions — four messages, and often more
with fragmentation or retries. Treating each message as its own tunnel would report a
single tunnel four to nine times over, which in an inventory is not a cosmetic error:
it is the difference between "you have 12 tunnels" and "you have 80". Messages are
grouped by initiator SPI, which is constant across a negotiation and changes on rekey.

**Unmatched flows are a finding, not an error.** ESP with no preceding IKE means either
the negotiation happened before the capture started or the tunnel is long-lived and was
never renegotiated. Both are worth reporting, and both are common in real captures,
where the analyst starts capturing on an already-running network. Discarding those
flows would silently hide the tunnels most likely to be forgotten and unpatched — which
are exactly the ones worth finding.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Final

from ipsec_sentinel.models import IKEExchange, ObservedConfig, Proposal
from ipsec_sentinel.parser.esp import AssembledFlow

# An initiator cannot know the responder's SPI when it sends the first message, so
# an all-zero responder SPI marks that message as the initiator's opening offer.
ZERO_SPI: Final = "00" * 8


def _transform_signature(proposal: Proposal) -> frozenset[tuple[str, int, int | None]]:
    """Identify a proposal by its transforms, ignoring its number.

    The responder renumbers the proposal it accepts, so comparing numbers would report
    every accepted proposal as a different one.
    """
    return frozenset(
        (str(transform.type), transform.id, transform.key_length)
        for transform in proposal.transforms
    )


def canonical_address(address: str) -> str:
    """Canonicalise an IP address, leaving anything unparseable untouched.

    IPv6 has many spellings of one address — ``2001:db8::1``, ``2001:0db8:0000::0001``
    and ``2001:DB8::1`` are the same host. Comparing them as strings would file one
    tunnel under three identities, and an operator's documented-tunnel list would then
    never match what was observed.
    """
    try:
        return str(ip_address(address))
    except ValueError:
        return address


def _sort_key(address: str) -> tuple[int, int, str]:
    """Order addresses numerically within a family, not lexicographically.

    As strings, ``192.0.2.10`` sorts before ``192.0.2.9``. That is stable, so it would
    work as a key — but it produces an inventory ordered in a way that looks broken to
    the person reading it, and the point of this file is a list an operator trusts.
    """
    try:
        parsed = ip_address(canonical_address(address))
    except ValueError:
        return (2, 0, address)
    return (parsed.version, int(parsed), "")


def endpoint_pair(left: str, right: str) -> tuple[str, str]:
    """A direction-independent, canonical endpoint key.

    Sorted, because a tunnel between A and B is the same tunnel as one between B and
    A, and an inventory that lists it twice is wrong in a way an operator notices
    immediately.
    """
    first, second = canonical_address(left), canonical_address(right)
    return (first, second) if _sort_key(first) <= _sort_key(second) else (second, first)


@dataclass
class Negotiation:
    """Every IKE message belonging to one IKE SA, in time order."""

    initiator_spi: str
    endpoints: tuple[str, str]
    messages: list[IKEExchange] = field(default_factory=list)

    @property
    def started_at(self) -> datetime:
        return min(message.timestamp for message in self.messages)

    @property
    def representative(self) -> IKEExchange:
        """The message an assessment should read.

        The earliest one carrying proposals — the initiator's offer is the full list of
        what this peer is willing to accept, which is the attack surface. A later
        message carries only the single chosen proposal and would understate it.
        """
        with_proposals = [m for m in self.messages if m.proposals_offered]
        pool = with_proposals or self.messages
        return min(pool, key=lambda m: m.timestamp)

    @property
    def is_aggressive(self) -> bool:
        return any(message.is_aggressive for message in self.messages)

    @property
    def response(self) -> IKEExchange | None:
        """The responder's message carrying its chosen proposal, if it was captured.

        Identified by a non-zero responder SPI: the initiator cannot know that value
        when it sends the first message, so a message carrying one came from the
        responder or later in the exchange. The responder's IKE_SA_INIT reply carries
        exactly the proposal it accepted, which is how "offered but not selected" can
        be said with certainty rather than guessed.
        """
        for message in sorted(self.messages, key=lambda m: m.timestamp):
            if message.responder_spi != ZERO_SPI and message.proposals_offered:
                return message
        return None

    @property
    def accepted_proposal(self) -> Proposal | None:
        """The proposal the responder chose, or None if the reply was not captured."""
        response = self.response
        if response is None or not response.proposals_offered:
            return None
        return response.proposals_offered[0]

    def was_accepted(self, proposal: Proposal) -> bool | None:
        """Whether this offered proposal is the one the responder chose.

        ``None`` when the responder's reply was not captured — the honest answer, and
        different from "no". A rule that reported "offered but not selected" on a
        capture that simply started too late would be asserting something it cannot
        know.
        """
        accepted = self.accepted_proposal
        if accepted is None:
            return None
        return _transform_signature(proposal) == _transform_signature(accepted)


@dataclass
class Tunnel:
    """One tunnel: the negotiation that created it and the flows it carried.

    Either half may be missing, and each absence means something specific — see
    :attr:`is_orphan` and :attr:`negotiation_only`.
    """

    tunnel_id: str
    endpoints: tuple[str, str]
    ike: IKEExchange | None = None
    negotiation: Negotiation | None = None
    flows: list[AssembledFlow] = field(default_factory=list)
    config: ObservedConfig | None = None
    """Configuration the operator supplied for this tunnel, if any.

    Kept here because a Tunnel is "everything known about this tunnel", and some of
    what is worth knowing cannot be read from packets. Absent by default.
    """

    @property
    def is_orphan(self) -> bool:
        """ESP with no negotiation in the capture.

        Not an error: the tunnel predates the capture, or is long-lived. Both are worth
        reporting, and a long-lived tunnel nobody has renegotiated is exactly the kind
        that is still running a cipher chosen years ago.
        """
        return self.ike is None

    @property
    def negotiation_only(self) -> bool:
        """A negotiation with no ESP behind it: it failed, or the tunnel sat idle."""
        return self.ike is not None and not self.flows

    @property
    def packet_count(self) -> int:
        return sum(flow.packet_count for flow in self.flows)

    @property
    def byte_count(self) -> int:
        return sum(flow.byte_count for flow in self.flows)

    @property
    def first_seen(self) -> datetime | None:
        candidates = [flow.first_seen for flow in self.flows]
        if self.negotiation is not None:
            candidates.append(self.negotiation.started_at)
        return min(candidates) if candidates else None

    @property
    def last_seen(self) -> datetime | None:
        candidates = [flow.last_seen for flow in self.flows]
        if self.negotiation is not None:
            candidates.append(max(m.timestamp for m in self.negotiation.messages))
        return max(candidates) if candidates else None


def _tunnel_id(endpoints: tuple[str, str], discriminator: str) -> str:
    """A stable, short identifier.

    Hashed rather than sequential so that the same tunnel keeps the same ID across
    runs and across captures — an inventory diffed between Monday and Friday must be
    able to say "this is the same tunnel", and a positional index cannot.
    """
    digest = hashlib.sha256(f"{endpoints[0]}|{endpoints[1]}|{discriminator}".encode())
    return digest.hexdigest()[:12]


def group_negotiations(exchanges: list[IKEExchange]) -> list[Negotiation]:
    """Group IKE messages into negotiations by initiator SPI.

    The initiator SPI is constant for the life of an IKE SA and changes when the peers
    rekey, which is precisely the boundary a tunnel inventory should draw.
    """
    negotiations: dict[str, Negotiation] = {}
    for exchange in exchanges:
        existing = negotiations.get(exchange.initiator_spi)
        if existing is None:
            existing = Negotiation(
                initiator_spi=exchange.initiator_spi,
                endpoints=endpoint_pair(exchange.src_ip, exchange.dst_ip),
            )
            negotiations[exchange.initiator_spi] = existing
        existing.messages.append(exchange)
    return list(negotiations.values())


def correlate(exchanges: list[IKEExchange], flows: list[AssembledFlow]) -> list[Tunnel]:
    """Match ESP flows to the negotiations that created them.

    Matching is on the endpoint pair plus temporal ordering: a flow belongs to the most
    recent negotiation between the same endpoints that began at or before the flow's
    first packet. Causality is the whole constraint — ESP cannot precede the exchange
    that produced its keys — and using it makes a rekey fall out naturally, since flows
    after the rekey attach to the newer negotiation.
    """
    negotiations = group_negotiations(exchanges)
    by_endpoints: dict[tuple[str, str], list[Negotiation]] = {}
    for negotiation in negotiations:
        by_endpoints.setdefault(negotiation.endpoints, []).append(negotiation)
    for group in by_endpoints.values():
        group.sort(key=lambda n: n.started_at)

    assigned: dict[str, Tunnel] = {}
    for negotiation in negotiations:
        tunnel_id = _tunnel_id(negotiation.endpoints, negotiation.initiator_spi)
        assigned[tunnel_id] = Tunnel(
            tunnel_id=tunnel_id,
            endpoints=negotiation.endpoints,
            ike=negotiation.representative,
            negotiation=negotiation,
        )

    orphans: dict[tuple[str, str], Tunnel] = {}
    for flow in flows:
        endpoints = endpoint_pair(flow.src_ip, flow.dst_ip)
        candidates = [
            negotiation
            for negotiation in by_endpoints.get(endpoints, [])
            if negotiation.started_at <= flow.first_seen
        ]
        if candidates:
            chosen = candidates[-1]
            assigned[_tunnel_id(endpoints, chosen.initiator_spi)].flows.append(flow)
            continue
        orphan = orphans.get(endpoints)
        if orphan is None:
            orphan = Tunnel(tunnel_id=_tunnel_id(endpoints, "orphan"), endpoints=endpoints)
            orphans[endpoints] = orphan
        orphan.flows.append(flow)

    tunnels = list(assigned.values()) + list(orphans.values())
    # A tunnel always has a negotiation or a flow, so first_seen is never actually
    # None — but the fallback is timezone-aware anyway, because comparing an aware
    # datetime with a naive one raises rather than sorting wrongly, and a sort that
    # raises on a corner case is a worse failure than one that orders it arbitrarily.
    tunnels.sort(key=lambda t: (t.first_seen or datetime.max.replace(tzinfo=UTC), t.tunnel_id))
    return tunnels
