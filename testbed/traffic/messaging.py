"""Messaging traffic generator — an XMPP shape proxy.

**This is XMPP, not WhatsApp, and the corpus must never say otherwise.** WhatsApp
cannot be scripted and no public corpus of it exists. XMPP is used because the traffic
*shape* it produces — small, sporadic, bidirectional stanzas separated by
human-length pauses — is the shape consumer messaging produces, and through ESP the
shape is the only thing an observer can see.

Naming the substitution is a scoring asset, not a weakness: a team that says "this is
XMPP standing in for messaging" is more credible than one that claims a WhatsApp
corpus it cannot possibly have. The disclosure belongs in docs/DATASET.md as well as
here.

Traffic is genuine XMPP against a real Prosody server, driven by slixmpp.
"""

from __future__ import annotations

import secrets
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import ClassVar, Final

from testbed.traffic.base import GenerationResult, RunContext, wait_for_service

XMPP_CLIENT: Final = "/opt/sentinel/xmpp_client.py"
XMPP_ORIGIN_IP: Final = "10.2.0.23"
XMPP_PORT: Final = 5222
XMPP_DOMAIN: Final = "testbed.local"
MESSAGING_PROFILE: Final = "messaging"

#: Stated in the class docstring and in docs/DATASET.md. Read by the dataset card.
PROXY_DISCLOSURE: Final = (
    "Messaging traffic is XMPP (Prosody + slixmpp) used as a shape proxy. It is not "
    "WhatsApp, Signal or any specific consumer messenger, none of which can be "
    "scripted or lawfully captured for a public corpus."
)


@dataclass(frozen=True)
class MessagingVariant:
    """One conversational rhythm."""

    name: str
    gap_min_s: float
    gap_max_s: float


VARIANTS: Final[dict[str, MessagingVariant]] = {
    "chat_active": MessagingVariant("chat_active", gap_min_s=1.0, gap_max_s=4.0),
    "chat_idle": MessagingVariant("chat_idle", gap_min_s=4.0, gap_max_s=12.0),
}


def generate_account_password() -> str:
    """A fresh XMPP account password for one run; never stored."""
    return secrets.token_hex(16)


class MessagingGenerator:
    """Run a two-party XMPP conversation across the tunnel."""

    name = "messaging"
    requires: ClassVar[list[str]] = [MESSAGING_PROFILE]
    proxy_disclosure: ClassVar[str] = PROXY_DISCLOSURE

    def __init__(
        self, variant: str = "chat_active", password: str | None = None, seed: int | None = None
    ) -> None:
        if variant not in VARIANTS:
            raise ValueError(f"unknown messaging variant {variant!r}; have {sorted(VARIANTS)}")
        self.variant = VARIANTS[variant]
        self.password = password
        self.seed = seed
        self._ctx: RunContext | None = None

    def setup(self, ctx: RunContext) -> None:
        if not self.password:
            raise RuntimeError(
                "the XMPP account password must be supplied; it is generated per run "
                "and passed to both the sidecar and this generator"
            )
        if not wait_for_service(ctx.left_host, ctx.xmpp_origin_ip, XMPP_PORT):
            raise RuntimeError(
                f"the sidecar at {ctx.xmpp_origin_ip}:{XMPP_PORT} never accepted "
                "a connection; starting anyway would produce a short, sparse capture"
            )
        self._ctx = ctx

    def teardown(self) -> None:
        self._ctx = None

    def _client_argv(
        self, container: str, jid: str, peer: str, duration_s: int, seed: int | None
    ) -> list[str]:
        return [
            "docker",
            "exec",
            container,
            "python3",
            XMPP_CLIENT,
            "--jid",
            f"{jid}@{XMPP_DOMAIN}",
            "--password",
            str(self.password),
            "--peer",
            f"{peer}@{XMPP_DOMAIN}",
            "--server",
            XMPP_ORIGIN_IP,
            "--port",
            str(XMPP_PORT),
            "--duration-s",
            str(duration_s),
            "--gap-min",
            str(self.variant.gap_min_s),
            "--gap-max",
            str(self.variant.gap_max_s),
            *(["--seed", str(seed)] if seed is not None else []),
        ]

    def run(self, duration_s: int) -> GenerationResult:
        if self._ctx is None:
            raise RuntimeError("setup() must be called before run()")
        ctx = self._ctx

        started = datetime.now(UTC)
        # The far party runs slightly longer so it is present for the whole
        # conversation; a peer that leaves early would make the tail one-directional.
        bob = subprocess.Popen(
            self._client_argv(
                ctx.right_host,
                "bob",
                "alice",
                duration_s + 4,
                None if self.seed is None else self.seed + 1,
            ),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        alice = subprocess.Popen(
            self._client_argv(ctx.left_host, "alice", "bob", duration_s, self.seed),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            alice_out, alice_err = alice.communicate(timeout=duration_s + 120)
            bob_out, _bob_err = bob.communicate(timeout=duration_s + 120)
        except subprocess.TimeoutExpired:
            alice.kill()
            bob.kill()
            return GenerationResult(
                generator=self.name,
                variant=self.variant.name,
                packets_sent=0,
                bytes_sent=0,
                started_at=started,
                ended_at=datetime.now(UTC),
                success=False,
                error="XMPP clients did not exit within the timeout",
            )
        ended = datetime.now(UTC)

        alice_sent, alice_received, alice_bytes = _parse_client(alice_out)
        bob_sent, _bob_received, bob_bytes = _parse_client(bob_out)
        exchanged = alice_sent + bob_sent
        if exchanged == 0 or alice_received == 0:
            detail = (alice_err.strip() or alice_out.strip())[:250]
            return GenerationResult(
                generator=self.name,
                variant=self.variant.name,
                packets_sent=0,
                bytes_sent=0,
                started_at=started,
                ended_at=ended,
                success=False,
                error=f"no two-way conversation took place: {detail}",
            )
        return GenerationResult(
            generator=self.name,
            variant=self.variant.name,
            packets_sent=exchanged,
            bytes_sent=alice_bytes + bob_bytes,
            started_at=started,
            ended_at=ended,
            success=True,
        )


def _parse_client(output: str) -> tuple[int, int, int]:
    """Read sent, received and body bytes from a client's summary line."""
    sent = received = body_bytes = 0
    for token in output.split():
        if token.startswith("sent="):
            sent = int(token.split("=", 1)[1])
        elif token.startswith("received="):
            received = int(token.split("=", 1)[1])
        elif token.startswith("bytes="):
            body_bytes = int(token.split("=", 1)[1])
    return sent, received, body_bytes
