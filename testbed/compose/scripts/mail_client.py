#!/usr/bin/env python3
"""Genuine SMTP and IMAP client traffic against the testbed mail sidecar.

Uses the standard library's ``smtplib`` and ``imaplib`` against real Postfix and
Dovecot servers, so the corpus contains actual protocol exchanges rather than
something shaped to resemble them.

The shape email contributes to the corpus is long idleness punctuated by discrete
bursts — a message goes out, or a client polls, and then nothing happens for a while.
That is quite unlike streaming's sustained bursts or VoIP's metronome.
"""

from __future__ import annotations

import argparse
import imaplib
import random
import smtplib
import sys
import time
from email.message import EmailMessage


def send_message(
    host: str,
    sender: str,
    recipient: str,
    body_bytes: int,
    attachment_bytes: int,
    rng: random.Random,
) -> int:
    """Send one message, returning the approximate bytes handed to SMTP."""
    message = EmailMessage()
    message["From"] = sender
    message["To"] = recipient
    message["Subject"] = f"testbed message {rng.randrange(10**6)}"
    message.set_content("x" * body_bytes)
    if attachment_bytes > 0:
        message.add_attachment(
            rng.randbytes(attachment_bytes),
            maintype="application",
            subtype="octet-stream",
            filename=f"attachment_{rng.randrange(1000)}.bin",
        )
    raw = message.as_bytes()
    # Short per-operation timeout: a stalled session must fail fast and let the
    # loop retry, rather than consuming the cell's whole duration.
    with smtplib.SMTP(host, 25, timeout=20) as smtp:
        smtp.send_message(message)
    return len(raw)


def poll_mailbox(host: str, user: str, password: str) -> int:
    """Log in, select INBOX and fetch what is there. Returns bytes fetched."""
    fetched = 0
    with imaplib.IMAP4(host, 143) as imap:
        imap.login(user, password)
        imap.select("INBOX")
        _typ, data = imap.search(None, "ALL")
        ids = data[0].split()
        for message_id in ids[-5:]:
            _typ, payload = imap.fetch(message_id, "(RFC822)")
            for part in payload:
                if isinstance(part, tuple) and part[1]:
                    fetched += len(part[1])
        imap.logout()
    return fetched


def main() -> int:
    parser = argparse.ArgumentParser(description="SMTP/IMAP traffic client.")
    parser.add_argument("--host", required=True)
    parser.add_argument("--user", default="tester")
    parser.add_argument("--password", required=True)
    parser.add_argument("--domain", default="testbed.local")
    parser.add_argument(
        "--mode", choices=["smtp_small", "smtp_attachment", "imap_sync"], required=True
    )
    parser.add_argument("--duration-s", type=float, required=True)
    parser.add_argument("--idle-min", type=float, default=3.0)
    parser.add_argument("--idle-max", type=float, default=9.0)
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args()

    rng = random.Random(args.seed)
    recipient = f"{args.user}@{args.domain}"
    sender = f"sender@{args.domain}"

    deadline = time.monotonic() + args.duration_s
    sent = 0
    total_bytes = 0
    largest_burst = 0

    # imap_sync needs something in the mailbox before polling is meaningful.
    if args.mode == "imap_sync":
        for _ in range(3):
            total_bytes += send_message(args.host, sender, recipient, 2048, 0, rng)
            sent += 1

    while time.monotonic() < deadline:
        try:
            if args.mode == "smtp_small":
                size = send_message(args.host, sender, recipient, rng.randrange(512, 8192), 0, rng)
            elif args.mode == "smtp_attachment":
                # Comfortably above the 100 KB the class is expected to show.
                size = send_message(
                    args.host,
                    sender,
                    recipient,
                    1024,
                    rng.randrange(150_000, 900_000),
                    rng,
                )
            else:
                size = poll_mailbox(args.host, args.user, args.password)
            sent += 1
            total_bytes += size
            largest_burst = max(largest_burst, size)
        except Exception as exc:
            print(f"warning: {type(exc).__name__}: {exc}", file=sys.stderr)

        # Long idle between exchanges: the shape that distinguishes mail from
        # everything else in the corpus.
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(rng.uniform(args.idle_min, args.idle_max), remaining))

    print(f"exchanges={sent} bytes={total_bytes} largest={largest_burst} mode={args.mode}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
