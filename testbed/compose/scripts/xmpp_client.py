#!/usr/bin/env python3
"""An XMPP chat participant, used as a documented shape proxy for messaging.

Uses slixmpp against a real Prosody server, so the corpus contains genuine XMPP.

**This is not WhatsApp and does not claim to be.** WhatsApp cannot be scripted, and
no public corpus of it exists. XMPP is used because its traffic *shape* — small,
sporadic, bidirectional stanzas separated by human-length pauses — is the shape
consumer messaging produces, and shape is the only thing an observer can see through
ESP. The substitution is stated in docs/DATASET.md rather than glossed over.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import random
import sys

import slixmpp


class Chatter(slixmpp.ClientXMPP):  # type: ignore[misc]
    """Sends short messages to a peer at irregular intervals while receiving theirs."""

    def __init__(
        self,
        jid: str,
        password: str,
        peer: str,
        duration_s: float,
        gap_min: float,
        gap_max: float,
        seed: int | None,
    ) -> None:
        super().__init__(jid, password)
        self.peer = peer
        self.duration_s = duration_s
        self.gap_min = gap_min
        self.gap_max = gap_max
        self.rng = random.Random(seed)
        self.sent = 0
        self.received = 0
        self.bytes_sent = 0
        self.add_event_handler("session_start", self.on_session_start)
        self.add_event_handler("message", self.on_message)

    async def on_session_start(self, _event: object) -> None:
        self.send_presence()
        # The roster is not required to exchange messages; a failure fetching it must
        # not abort the conversation.
        with contextlib.suppress(Exception):
            await self.get_roster()
        await self.chat_loop()

    def on_message(self, message: slixmpp.Message) -> None:
        if message["type"] in ("chat", "normal"):
            self.received += 1

    async def chat_loop(self) -> None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.duration_s
        while loop.time() < deadline:
            # Short, varied bodies: a chat line, not a file transfer.
            body = "".join(
                self.rng.choice("abcdefghijklmnopqrstuvwxyz .,?!")
                for _ in range(self.rng.randrange(8, 180))
            )
            self.send_message(mto=self.peer, mbody=body, mtype="chat")
            self.sent += 1
            self.bytes_sent += len(body)
            remaining = deadline - loop.time()
            if remaining <= 0:
                break
            # Human-length pauses, deliberately irregular.
            await asyncio.sleep(min(self.rng.uniform(self.gap_min, self.gap_max), remaining))
        # disconnect() is a coroutine in slixmpp 1.8. Calling it without awaiting
        # schedules nothing, the connection never closes, and process(forever=False)
        # blocks on a disconnection that will never arrive — the client then hangs
        # until something kills it.
        await self.disconnect()


def main() -> int:
    parser = argparse.ArgumentParser(description="XMPP chat participant.")
    parser.add_argument("--jid", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--peer", required=True)
    parser.add_argument("--server", required=True)
    parser.add_argument("--port", type=int, default=5222)
    parser.add_argument("--duration-s", type=float, required=True)
    parser.add_argument("--gap-min", type=float, default=1.5)
    parser.add_argument("--gap-max", type=float, default=7.0)
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args()

    client = Chatter(
        args.jid,
        args.password,
        args.peer,
        args.duration_s,
        args.gap_min,
        args.gap_max,
        args.seed,
    )
    # The link is already inside an IPsec tunnel; layering TLS on top would hide the
    # very traffic shape this corpus exists to capture.
    client.connect(
        (args.server, args.port), use_ssl=False, force_starttls=False, disable_starttls=True
    )
    try:
        client.process(forever=False)
    except Exception as exc:
        print(f"warning: {type(exc).__name__}: {exc}", file=sys.stderr)

    print(f"sent={client.sent} received={client.received} bytes={client.bytes_sent}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
