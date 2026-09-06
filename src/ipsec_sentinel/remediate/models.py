"""The remediation change package: what to change, in what order, and how to undo it.

Two invariants are enforced by the model rather than described in a comment, because
both are the kind of mistake that produces a confident, well-formatted document which
takes a tunnel down.

**Both ends are mandatory.** IPsec is a negotiation between two peers. A proposal
changed at one end and not the other does not degrade — it fails to establish, and the
tunnel drops at the next rekey rather than immediately, which is worse because the
change looks successful for hours. A :class:`ChangePackage` therefore cannot be
constructed with only a local configuration; ``peer_config`` is required, and where the
far end is administered by someone else that is precisely the fact the operator needs
surfaced before they start.

**A change without a rollback is not a change, it is a gamble.** ``rollback`` and
``sequence`` are both non-empty by construction. So is ``verification``: a step nobody
can check is indistinguishable from one that silently did nothing.

**Nothing here applies a configuration.** This module produces documents. The tool
generates configurations and humans apply them — the entire remediation lane is
deliberately inert, and a test asserts that no module in it imports a transport that
could reach a device.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Final

from pydantic import BaseModel, Field, model_validator


# Whose device an action touches. Named rather than free text because "the other one" in
# a change document at 2 a.m. is how the wrong box gets edited.
class ConfigRole(StrEnum):
    LOCAL = "local"
    PEER = "peer"
    BOTH = "both"
    """A step applied to both ends before the next one begins.

    Needed because the zero-downtime pattern is four steps, not eight: "add the target
    proposal alongside the current one on both ends" is one operation an operator
    performs, and splitting it into two would imply an ordering between the ends that
    does not exist and is not required.
    """

    @property
    def covers(self) -> frozenset[str]:
        """Which ends this role actually touches."""
        if self is ConfigRole.BOTH:
            return frozenset({ConfigRole.LOCAL.value, ConfigRole.PEER.value})
        return frozenset({self.value})


class ChangeRisk(StrEnum):
    """How much of the estate a change can disturb if it goes wrong."""

    NONE = "none"
    SINGLE_TUNNEL = "single_tunnel"
    MULTIPLE_TUNNELS = "multiple_tunnels"
    GATEWAY_WIDE = "gateway_wide"


class DeviceConfig(BaseModel):
    """A configuration document for one end of one tunnel.

    ``content`` is text an operator reads and applies themselves. It is never executed,
    never uploaded, and never sent anywhere by this system.
    """

    role: ConfigRole
    vendor: str = Field(min_length=1)
    device_hint: str = Field(min_length=1)
    """How the operator identifies this device — a hostname, an address, a label."""
    filename: str = Field(min_length=1)
    content: str = Field(min_length=1)
    notes: list[str] = Field(default_factory=list)


class ChangeStep(BaseModel):
    """One ordered action in a zero-downtime sequence."""

    order: int = Field(ge=1)
    role: ConfigRole
    description: str = Field(min_length=1)
    action: str = Field(min_length=1)
    reversible: bool = True
    expected_disruption_s: int = Field(default=0, ge=0)


class BlastRadius(BaseModel):
    """What else this change can disturb.

    Reported so an operator can decide *when* to act, which is usually the question
    they actually have. A change that is safe in isolation and unsafe at 09:00 is still
    unsafe at 09:00.
    """

    risk: ChangeRisk
    tunnels_affected: int = Field(ge=0)
    peers_requiring_coordination: list[str] = Field(default_factory=list)
    estimated_disruption_s: int = Field(default=0, ge=0)
    notes: list[str] = Field(default_factory=list)


class ChangePackage(BaseModel):
    """Everything needed to make one tunnel's remediation safe to carry out."""

    tunnel_id: str = Field(min_length=1)
    findings_addressed: list[str] = Field(min_length=1)
    local_config: DeviceConfig
    peer_config: DeviceConfig
    sequence: list[ChangeStep] = Field(min_length=1)
    verification: list[str] = Field(min_length=1)
    rollback: list[str] = Field(min_length=1)
    blast_radius: BlastRadius
    requires_maintenance_window: bool = False
    generated_at: datetime | None = None

    @model_validator(mode="after")
    def _configs_must_be_for_opposite_ends(self) -> ChangePackage:
        """Two configurations for the same end are not a both-ends change.

        The failure this catches is a generator bug that produces the local document
        twice — which passes every "peer_config is present" check while leaving the far
        end untouched, and so drops the tunnel at the next rekey.
        """
        if self.local_config.role is ConfigRole.BOTH or self.peer_config.role is ConfigRole.BOTH:
            raise ValueError(
                "a configuration document belongs to one end; ConfigRole.BOTH describes "
                "a change *step*, not a file"
            )
        if self.local_config.role is not ConfigRole.LOCAL:
            raise ValueError(
                f"local_config carries role {self.local_config.role!r}; a change package "
                f"needs one document for each end"
            )
        if self.peer_config.role is not ConfigRole.PEER:
            raise ValueError(
                f"peer_config carries role {self.peer_config.role!r}; a change package "
                f"needs one document for each end"
            )
        return self

    @model_validator(mode="after")
    def _sequence_must_be_ordered_and_cover_both_ends(self) -> ChangePackage:
        """An ordered sequence that skips an end cannot be zero-downtime.

        IPsec rekeys with whatever both peers currently accept. A sequence touching only
        one end either fails immediately or, worse, appears to succeed until the SA
        expires.
        """
        orders = [step.order for step in self.sequence]
        if orders != sorted(orders):
            raise ValueError(
                f"change steps are out of order ({orders}); the sequence is the "
                f"zero-downtime guarantee and cannot be shuffled"
            )
        if len(set(orders)) != len(orders):
            raise ValueError(f"change steps share an order number ({orders})")
        covered: set[str] = set()
        for step in self.sequence:
            covered |= step.role.covers
        if covered != {ConfigRole.LOCAL.value, ConfigRole.PEER.value}:
            raise ValueError(
                f"the sequence touches only {sorted(covered)}; an IPsec change applied "
                f"to one end drops the tunnel at the next rekey"
            )
        return self

    @property
    def is_reversible(self) -> bool:
        """Whether every step can be undone individually."""
        return all(step.reversible for step in self.sequence)

    @property
    def total_expected_disruption_s(self) -> int:
        return sum(step.expected_disruption_s for step in self.sequence)

    def summary(self) -> str:
        window = " (maintenance window required)" if self.requires_maintenance_window else ""
        return (
            f"{self.tunnel_id}: {len(self.findings_addressed)} finding(s), "
            f"{len(self.sequence)} step(s), ~{self.total_expected_disruption_s}s "
            f"disruption, risk {self.blast_radius.risk.value}{window}"
        )


# Transports that could reach a device. The remediation lane must import none of them:
# this tool produces documents and humans apply them. Asserted by a test rather than
# left to review, because the prohibition is easy to violate helpfully.
FORBIDDEN_TRANSPORTS: Final[frozenset[str]] = frozenset(
    {
        "paramiko",
        "netmiko",
        "fabric",
        "pexpect",
        "telnetlib",
        "napalm",
        "scrapli",
        "asyncssh",
    }
)
