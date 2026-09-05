"""Email traffic generator.

Email's contribution to the corpus is a shape almost nothing else has: long idleness
punctuated by discrete, self-contained bursts. A message goes out or a client polls,
and then the link is quiet for seconds. Streaming bursts are sustained and VoIP never
stops; mail does neither.

Traffic is genuine SMTP and IMAP against real Postfix and Dovecot, using the standard
library's ``smtplib`` and ``imaplib`` — the corpus contains actual protocol exchanges
rather than something shaped to resemble them.
"""

from __future__ import annotations

import secrets
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import ClassVar, Final

from testbed.traffic.base import GenerationResult, RunContext

MAIL_CLIENT: Final = "/opt/sentinel/mail_client.py"
MAIL_ORIGIN_IP: Final = "10.2.0.22"
MAIL_PROFILE: Final = "mail"
MAIL_USER: Final = "tester"


@dataclass(frozen=True)
class EmailVariant:
    """One mail behaviour: what is exchanged, and how long the gaps are."""

    name: str
    mode: str
    idle_min_s: float
    idle_max_s: float


VARIANTS: Final[dict[str, EmailVariant]] = {
    "smtp_small": EmailVariant("smtp_small", mode="smtp_small", idle_min_s=3.0, idle_max_s=8.0),
    "smtp_attachment": EmailVariant(
        "smtp_attachment", mode="smtp_attachment", idle_min_s=4.0, idle_max_s=10.0
    ),
    "imap_sync": EmailVariant("imap_sync", mode="imap_sync", idle_min_s=5.0, idle_max_s=12.0),
}


def generate_mailbox_password() -> str:
    """A fresh mailbox password for one run.

    Generated rather than stored: no credential belongs in this repository or in an
    image, and the mail sidecar reads it from the environment exactly as the tunnel
    reads its PSK.
    """
    return secrets.token_hex(16)


class EmailGenerator:
    """Send mail and poll a mailbox across the tunnel."""

    name = "email"
    requires: ClassVar[list[str]] = [MAIL_PROFILE]

    def __init__(
        self, variant: str = "smtp_small", password: str | None = None, seed: int | None = None
    ) -> None:
        if variant not in VARIANTS:
            raise ValueError(f"unknown email variant {variant!r}; have {sorted(VARIANTS)}")
        self.variant = VARIANTS[variant]
        self.password = password
        self.seed = seed
        self.largest_burst_bytes = 0
        self._ctx: RunContext | None = None

    def setup(self, ctx: RunContext) -> None:
        if not self.password:
            raise RuntimeError(
                "the mailbox password must be supplied; it is generated per run and "
                "passed to both the sidecar and this generator"
            )
        self._ctx = ctx

    def teardown(self) -> None:
        self._ctx = None

    def run(self, duration_s: int) -> GenerationResult:
        if self._ctx is None:
            raise RuntimeError("setup() must be called before run()")
        ctx = self._ctx

        started = datetime.now(UTC)
        completed = subprocess.run(
            [
                "docker",
                "exec",
                ctx.left_host,
                "python3",
                MAIL_CLIENT,
                "--host",
                MAIL_ORIGIN_IP,
                "--user",
                MAIL_USER,
                "--password",
                str(self.password),
                "--mode",
                self.variant.mode,
                "--duration-s",
                str(duration_s),
                "--idle-min",
                str(self.variant.idle_min_s),
                "--idle-max",
                str(self.variant.idle_max_s),
                *(["--seed", str(self.seed)] if self.seed is not None else []),
            ],
            capture_output=True,
            text=True,
            timeout=duration_s + 180,
            check=False,
        )
        ended = datetime.now(UTC)

        exchanges, total_bytes, largest = _parse_client(completed.stdout)
        self.largest_burst_bytes = largest
        if exchanges == 0:
            detail = (completed.stderr.strip() or completed.stdout.strip())[:250]
            return GenerationResult(
                generator=self.name,
                variant=self.variant.name,
                packets_sent=0,
                bytes_sent=0,
                started_at=started,
                ended_at=ended,
                success=False,
                error=f"no mail exchanges completed (exit {completed.returncode}): {detail}",
            )
        return GenerationResult(
            generator=self.name,
            variant=self.variant.name,
            packets_sent=exchanges,
            bytes_sent=total_bytes,
            started_at=started,
            ended_at=ended,
            success=True,
        )


def _parse_client(output: str) -> tuple[int, int, int]:
    """Read exchanges, total bytes and largest single burst from the summary line."""
    exchanges = total = largest = 0
    for token in output.split():
        if token.startswith("exchanges="):
            exchanges = int(token.split("=", 1)[1])
        elif token.startswith("bytes="):
            total = int(token.split("=", 1)[1])
        elif token.startswith("largest="):
            largest = int(token.split("=", 1)[1])
    return exchanges, total, largest
