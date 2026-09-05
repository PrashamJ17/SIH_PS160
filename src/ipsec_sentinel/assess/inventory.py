"""The tunnel inventory: what is actually running, and what nobody wrote down.

The build plan calls this the feature that delivers value in hour four, and the reason
is that it answers a question most organisations genuinely cannot answer about
themselves. Site-to-site VPNs accumulate. They are built for a project, a partner, a
migration; the project ends and the tunnel does not. Years later it is still carrying
traffic, still terminating on a gateway nobody patches, still using the cipher that was
reasonable when it was configured.

Everything here is deterministic. An inventory entry is assembled from parsed IKE
fields and counted ESP packets; nothing is inferred, and no entry carries a confidence
score. "Undocumented" is a set difference between what was observed and what the
operator supplied — not a judgement about whether a tunnel *ought* to exist.

The mirror case is reported too. A tunnel on the documented list that was never
observed is either decommissioned and never removed from the list, or down right now.
The tool cannot tell which, and says so rather than guessing.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from ipsec_sentinel.parser.correlate import Tunnel, canonical_address, endpoint_pair


class InventoryStatus(StrEnum):
    """How an observed tunnel relates to the operator's documented list."""

    DOCUMENTED = "documented"
    UNDOCUMENTED = "undocumented"
    UNKNOWN = "unknown"
    """No documented list was supplied, so the question was not asked."""


class KnownTunnel(BaseModel):
    """A tunnel the operator says should exist.

    Supplied by the operator, so the endpoints arrive in whatever form a human typed
    them. They are canonicalised on the way in, because a documented list that fails
    to match observed traffic over a spelling of an IPv6 address would flag every
    tunnel as undocumented and destroy trust in the whole report.
    """

    endpoints: tuple[str, str]
    name: str | None = None
    owner: str | None = None

    def normalised(self) -> tuple[str, str]:
        return endpoint_pair(*self.endpoints)


class InventoryEntry(BaseModel):
    """One observed tunnel, as an operator needs to see it."""

    tunnel_id: str
    endpoints: tuple[str, str]
    status: InventoryStatus
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    packet_count: int = Field(default=0, ge=0)
    byte_count: int = Field(default=0, ge=0)
    ike_version: str | None = None
    exchange_type: str | None = None
    negotiated_suite: str | None = None
    is_aggressive: bool = False
    orphan: bool = False
    negotiation_only: bool = False
    documented_name: str | None = None
    documented_owner: str | None = None

    @property
    def is_undocumented(self) -> bool:
        return self.status is InventoryStatus.UNDOCUMENTED


class Inventory(BaseModel):
    """Every observed tunnel, plus the documented ones that were not seen."""

    entries: list[InventoryEntry] = Field(default_factory=list)
    unobserved: list[KnownTunnel] = Field(default_factory=list)
    documented_list_supplied: bool = False

    @property
    def undocumented(self) -> list[InventoryEntry]:
        return [entry for entry in self.entries if entry.is_undocumented]

    @property
    def orphans(self) -> list[InventoryEntry]:
        return [entry for entry in self.entries if entry.orphan]

    def __len__(self) -> int:
        return len(self.entries)


def describe_suite(tunnel: Tunnel) -> str | None:
    """The negotiated suite as a single readable string, or None if unknown.

    Reads the first proposal only. An entry in an inventory table needs one line, and
    the full offer list — which is what the assessment engine cares about — would not
    fit in one. That is a presentation choice, not a loss: the offer list is carried
    intact on the exchange and Phase 6 reads it from there.
    """
    if tunnel.ike is None or not tunnel.ike.proposals_offered:
        return None
    transforms = tunnel.ike.proposals_offered[0].transforms
    if not transforms:
        return None
    parts = [
        f"{transform.name}-{transform.key_length}"
        if transform.key_length is not None
        else transform.name
        for transform in transforms
    ]
    return " / ".join(parts)


def build_inventory(tunnels: list[Tunnel], known: list[KnownTunnel] | None = None) -> Inventory:
    """Build the inventory, flagging anything the operator did not document.

    With no documented list the status is ``UNKNOWN`` rather than ``DOCUMENTED``: the
    question was not asked, and answering it "documented" by default would let a
    report claim clearance it never checked for.
    """
    documented: dict[tuple[str, str], KnownTunnel] = {}
    if known is not None:
        for entry in known:
            documented[entry.normalised()] = entry

    entries: list[InventoryEntry] = []
    observed: set[tuple[str, str]] = set()
    for tunnel in tunnels:
        endpoints = endpoint_pair(*tunnel.endpoints)
        observed.add(endpoints)
        match = documented.get(endpoints)
        if known is None:
            status = InventoryStatus.UNKNOWN
        elif match is not None:
            status = InventoryStatus.DOCUMENTED
        else:
            status = InventoryStatus.UNDOCUMENTED

        entries.append(
            InventoryEntry(
                tunnel_id=tunnel.tunnel_id,
                endpoints=endpoints,
                status=status,
                first_seen=tunnel.first_seen,
                last_seen=tunnel.last_seen,
                packet_count=tunnel.packet_count,
                byte_count=tunnel.byte_count,
                ike_version=tunnel.ike.version if tunnel.ike else None,
                exchange_type=tunnel.ike.exchange_type if tunnel.ike else None,
                negotiated_suite=describe_suite(tunnel),
                is_aggressive=tunnel.ike.is_aggressive if tunnel.ike else False,
                orphan=tunnel.is_orphan,
                negotiation_only=tunnel.negotiation_only,
                documented_name=match.name if match else None,
                documented_owner=match.owner if match else None,
            )
        )

    unobserved = (
        [entry for key, entry in documented.items() if key not in observed]
        if known is not None
        else []
    )
    return Inventory(
        entries=entries,
        unobserved=unobserved,
        documented_list_supplied=known is not None,
    )


def known_from_endpoints(pairs: list[tuple[str, str]]) -> list[KnownTunnel]:
    """Convenience for building a documented list from bare endpoint pairs."""
    return [KnownTunnel(endpoints=(canonical_address(a), canonical_address(b))) for a, b in pairs]
