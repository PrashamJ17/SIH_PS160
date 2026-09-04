"""Core domain models shared by every module.

One rule governs this file, and the whole project rests on it:

    **Facts are parsed. Estimates are inferred.**

Anything read from the cleartext IKE handshake — cipher, integrity algorithm, PRF,
DH group, IKE version, aggressive mode, SPIs — is deterministic, and its
:attr:`Finding.confidence` is ``None``. Anything derived from encrypted traffic —
tunnel vs transport mode, in-tunnel application type, configuration anomalies — is
inferred, and carries a calibrated :class:`Confidence`.

The two lanes never mix. ``confidence is None`` is therefore not an incidental default
but the load-bearing signal that routes a finding into Section A (compliance-grade
evidence) or Section B (intelligence) of the report.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Final

from pydantic import BaseModel, Field, model_validator


class Severity(StrEnum):
    """Finding severity, ordered most urgent first by :attr:`rank`."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"

    @property
    def rank(self) -> int:
        """Sort key: 0 is the most urgent, so ``CRITICAL`` sorts first."""
        return _SEVERITY_RANK[self]


_SEVERITY_RANK: Final[dict[Severity, int]] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class TransformType(StrEnum):
    """The five negotiable transform families in an IKE proposal."""

    ENCR = "ENCR"
    PRF = "PRF"
    INTEG = "INTEG"
    DH = "DH"
    ESN = "ESN"


class Confidence(BaseModel):
    """A calibrated confidence in an inference.

    Only ever attached to **inferred** facts, never to parsed ones. ``method`` is
    mandatory because an estimate whose provenance is unstated is not auditable.
    """

    value: float = Field(ge=0.0, le=1.0)
    method: str
    abstained: bool = False


class Transform(BaseModel):
    """One negotiable algorithm choice inside a proposal.

    ``key_length`` comes from the transform's *attribute* level, not its ID. Parsing
    only to the transform level cannot tell AES-128 from AES-256, since both are
    transform ID 12 with different attributes.
    """

    type: TransformType
    id: int
    name: str
    key_length: int | None = None


class Proposal(BaseModel):
    """One complete algorithm suite offered or accepted in an SA payload."""

    number: int
    protocol: str
    transforms: list[Transform] = Field(default_factory=list)


class IKEExchange(BaseModel):
    """A parsed IKE negotiation. Every field here is a fact read off the wire.

    ``proposals_offered`` holds **every** proposal, not just the accepted one: the
    offer list is the real attack surface, since a gateway advertising 3DES will
    accept 3DES from a peer that offers only that.
    """

    initiator_spi: str
    responder_spi: str
    version: str
    exchange_type: str
    is_aggressive: bool = False
    proposals_offered: list[Proposal] = Field(default_factory=list)
    proposal_accepted: Proposal | None = None
    ke_group_from_length: int | None = None
    vendor_ids: list[str] = Field(default_factory=list)
    notifies: list[str] = Field(default_factory=list)
    timestamp: datetime
    src_ip: str
    dst_ip: str


class ESPFlow(BaseModel):
    """One direction of one ESP security association.

    ``spi`` is the **4-byte** ESP SPI rendered as hex — a different field from the
    8-byte IKE SPI in :class:`IKEExchange`, which identifies a negotiation session
    rather than a data SA.
    """

    spi: str
    src_ip: str
    dst_ip: str
    packet_count: int = Field(ge=0)
    byte_count: int = Field(ge=0)
    first_seen: datetime
    last_seen: datetime
    sequence_gaps: int = Field(default=0, ge=0)
    replay_suspected: bool = False


class Finding(BaseModel):
    """A single assessment result.

    ``confidence is None`` means the finding was **parsed** and is deterministic;
    a non-None confidence means it was **inferred**. See :attr:`is_deterministic`.
    """

    rule_id: str
    title: str
    severity: Severity
    evidence: str
    standard_ref: str
    attack_technique: str | None = None
    remediation_hint: str
    confidence: Confidence | None = None

    @property
    def is_deterministic(self) -> bool:
        """True when this finding is a parsed fact rather than an inference."""
        return self.confidence is None


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Return findings ordered most severe first, stably, without mutating the input."""
    return sorted(findings, key=lambda f: f.severity.rank)


Grade = Annotated[str, Field(pattern=r"^[A-F]$")]


class TunnelAssessment(BaseModel):
    """Everything known about one tunnel: parsed facts, inferences, and findings."""

    tunnel_id: str
    endpoints: tuple[str, str]
    ike: IKEExchange | None = None
    esp_flows: list[ESPFlow] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    score: int = Field(ge=0, le=100)
    grade: Grade
    inferred_mode: str | None = None
    inferred_mode_confidence: Confidence | None = None
    inferred_traffic: str | None = None
    inferred_traffic_confidence: Confidence | None = None

    @model_validator(mode="after")
    def _inferences_must_carry_confidence(self) -> TunnelAssessment:
        """Every inference carries a confidence, and every confidence has a value.

        This is the model-level guard on the parse/infer split: an inferred mode or
        traffic class stated without a calibrated confidence would be indistinguishable
        from a parsed fact downstream, which is exactly the confusion the architecture
        exists to prevent.
        """
        for field, conf_field in (
            ("inferred_mode", "inferred_mode_confidence"),
            ("inferred_traffic", "inferred_traffic_confidence"),
        ):
            value = getattr(self, field)
            confidence = getattr(self, conf_field)
            if (value is None) != (confidence is None):
                raise ValueError(
                    f"{field} and {conf_field} must be set together: an inference without "
                    f"a confidence is indistinguishable from a parsed fact "
                    f"(got {field}={value!r}, {conf_field}={confidence!r})"
                )
        return self
