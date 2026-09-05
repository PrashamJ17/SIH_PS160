"""The contract every traffic generator implements.

The orchestrator treats generators uniformly: it hands each one a :class:`RunContext`
describing the pair it is running against, asks it to run for a duration, and records
a :class:`GenerationResult`. Nothing in the sweep needs to know whether it is driving
a ping or a VoIP call.

``TrafficGenerator.name`` is not decoration — it becomes the **ML class label** for
every flow captured while that generator ran. Two generators sharing a name would
merge two classes; a name that misdescribes what was generated mislabels the corpus.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, Field, model_validator


@dataclass(frozen=True)
class RunContext:
    """Everything a generator needs to know about the pair it runs against.

    Generators drive the **hosts**, not the gateways: traffic a gateway originates
    never crosses its own protected interface and so is invisible to the inner tap,
    which would leave every flow labelled from half a conversation.
    """

    project: str
    left_gateway: str
    right_gateway: str
    left_host: str
    right_host: str
    left_host_ip: str
    right_host_ip: str
    out_dir: Path


class GenerationResult(BaseModel):
    """What one generator run produced.

    A Pydantic model rather than a plain dataclass because the success/error
    relationship is an invariant worth enforcing: a run that reports failure without
    saying why is not diagnosable months later when a sweep cell is being explained.
    """

    generator: str
    variant: str
    packets_sent: int = Field(ge=0)
    bytes_sent: int = Field(ge=0)
    started_at: datetime
    ended_at: datetime
    success: bool
    error: str | None = None

    @property
    def duration_s(self) -> float:
        return (self.ended_at - self.started_at).total_seconds()

    @model_validator(mode="after")
    def _failure_must_explain_itself(self) -> GenerationResult:
        if not self.success and not self.error:
            raise ValueError(
                "a failed GenerationResult must carry a non-empty error explaining why"
            )
        if self.success and self.error:
            raise ValueError(
                f"a successful GenerationResult must not carry an error, got {self.error!r}"
            )
        return self

    @model_validator(mode="after")
    def _times_must_be_ordered(self) -> GenerationResult:
        if self.ended_at < self.started_at:
            raise ValueError(
                f"ended_at {self.ended_at.isoformat()} precedes "
                f"started_at {self.started_at.isoformat()}"
            )
        return self


@runtime_checkable
class TrafficGenerator(Protocol):
    """One application traffic class the sweep can drive through a tunnel."""

    name: str
    """The ML class label for every flow captured while this generator ran."""

    requires: list[str]
    """Extra containers or services this generator needs beyond the pair itself."""

    def setup(self, ctx: RunContext) -> None:
        """Prepare to run against this pair. Must be safe to call once per cell."""
        ...

    def run(self, duration_s: int) -> GenerationResult:
        """Generate traffic for roughly ``duration_s`` seconds."""
        ...

    def teardown(self) -> None:
        """Release anything ``setup`` acquired. Must be safe to call after a failure."""
        ...
