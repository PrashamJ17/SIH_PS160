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

import subprocess
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import ClassVar, Protocol, runtime_checkable

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

    # Sidecar addresses travel with the context rather than living as module constants
    # in each generator, because the sweep runs several pairs concurrently and each
    # slot gets its own subnets. Defaults are slot 0, which is what a single pair uses.
    # The gateway's address on the protected side, needed by anything that must
    # address the gateway itself rather than a host behind it.
    left_protected_ip: str = "10.1.0.2"
    video_origin_ip: str = "10.2.0.20"
    web_origin_ip: str = "10.2.0.21"
    mail_origin_ip: str = "10.2.0.22"
    xmpp_origin_ip: str = "10.2.0.23"


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


def wait_for_service(
    container: str,
    host: str,
    port: int,
    timeout_s: float = 120.0,
    interval_s: float = 0.5,
    *,
    expect_banner: bool = False,
    probe: str | None = None,
) -> bool:
    """Block until ``host:port`` is ready to converse, from inside ``container``.

    Compose's ``--wait`` only waits for a container to be *running*, not for the
    service inside it to be listening. Without this, a generator can start talking to
    a sidecar that is still initialising and produce a short, sparse capture — which
    does not fail loudly, it just yields a thin cell that quietly weakens the corpus.

    A bare TCP connect is not always enough. Postfix and Dovecot accept a connection
    slightly before they will serve one, so ``expect_banner`` additionally reads the
    greeting; ``probe`` sends a string first, for protocols where the client speaks
    first. Waiting only for the port is what let a loaded sweep hand a generator a
    socket that then timed out mid-session.

    The budget is generous because Prosody and Postfix are far slower to become ready
    than nginx, and slower still when several pairs have run back to back.
    """
    if expect_banner or probe:
        send = repr(probe.encode()) if probe else "None"
        script = (
            "import socket,sys\n"
            "s=socket.socket(); s.settimeout(3)\n"
            f"rc=s.connect_ex(({host!r}, {port}))\n"
            "sys.exit(1) if rc else None\n"
            f"payload={send}\n"
            "s.sendall(payload) if payload else None\n"
            "sys.exit(0 if s.recv(64) else 1)"
        )
    else:
        script = (
            "import socket,sys\n"
            "s=socket.socket(); s.settimeout(2)\n"
            f"sys.exit(0 if s.connect_ex(({host!r}, {port})) == 0 else 1)"
        )

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        result = subprocess.run(
            ["docker", "exec", container, "python3", "-c", script],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if result.returncode == 0:
            return True
        time.sleep(interval_s)
    return False


@runtime_checkable
class TrafficGenerator(Protocol):
    """One application traffic class the sweep can drive through a tunnel."""

    name: str
    """The ML class label for every flow captured while this generator ran.

    Left as an instance-variable declaration deliberately: implementations assign it
    plainly (``name = "icmp"``), which mypy infers as an instance variable and which a
    ClassVar declaration here would then reject.
    """

    requires: ClassVar[list[str]]
    """Extra containers or services this generator needs beyond the pair itself.

    Declared ClassVar because every implementation must be: a mutable list as a plain
    class attribute is a shared-state bug (RUF012), and a Protocol member declared as
    an instance variable cannot be satisfied by a ClassVar implementation.
    """

    def setup(self, ctx: RunContext) -> None:
        """Prepare to run against this pair. Must be safe to call once per cell."""
        ...

    def run(self, duration_s: int) -> GenerationResult:
        """Generate traffic for roughly ``duration_s`` seconds."""
        ...

    def teardown(self) -> None:
        """Release anything ``setup`` acquired. Must be safe to call after a failure."""
        ...
