"""The demo video's beats: what is said, and what is on screen while it is said.

Written as data so the narration and the visual for a beat cannot drift apart, and so the
running order can be changed without touching the compositor.

Narration is spelled for a synthesiser rather than for a reader — "three-D-E-S" instead of
"3DES" — because a text-to-speech voice reading "3DES" produces something no judge will
recognise. The `spoken` field is what is said; `caption` is what is written on screen.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final, Literal


@dataclass(frozen=True)
class Beat:
    key: str
    chapter: str
    spoken: str
    kind: Literal["title", "chapter", "terminal", "shot", "statement"]
    # Visual payload, interpreted by the compositor according to `kind`.
    source: str = ""
    caption: str = ""
    zoom: tuple[float, float, float, float] | None = None
    reveal: bool = False
    lines: list[str] = field(default_factory=list)
    points: list[tuple[str, str]] = field(default_factory=list)


BEATS: Final[list[Beat]] = [
    Beat(
        key="title",
        chapter="",
        kind="title",
        source="IPsec Sentinel",
        caption="Passive IPsec protocol analysis and security assessment",
        lines=[
            "Smart India Hackathon 2026  ·  Problem Statement SIH 26160",
            "Theme: Blockchain & Cybersecurity",
            "Team Highlanders  ·  SIH 163",
            "",
            "Everything in this video is the software running. Nothing is re-enacted.",
        ],
        spoken=(
            "IPsec Sentinel, from team Highlanders, for Smart India Hackathon twenty twenty-six, "
            "problem statement twenty-six one sixty. It is a passive I P sec V P N protocol "
            "analyser and security assessment framework. Everything you are about to see is the "
            "software actually running. Nothing here is a mock-up."
        ),
    ),
    Beat(
        key="tshark",
        chapter="1 · The gap",
        kind="terminal",
        source="tshark",
        caption="Every field is here. Nothing here is a judgement.",
        reveal=True,
        spoken=(
            "Here is a packet capture from a V P N gateway, opened in tshark, the tool every "
            "network engineer already has. Every field is present. Exchange type four is "
            "I K E version one, Aggressive Mode. What tshark will not tell you is that Aggressive "
            "Mode leaks a crackable hash of the pre-shared key to anyone listening, which "
            "standard forbids it, or what to put in its place. That gap, between visible and "
            "judged, is what we built."
        ),
    ),
    Beat(
        key="analyse_worst",
        chapter="2 · One command",
        kind="terminal",
        source="analyse_worst",
        caption="Grade F — and every finding cites the clause it comes from",
        reveal=True,
        spoken=(
            "The same capture. One command. Grade F, zero out of one hundred, nine findings. "
            "Every one of them cites the clause it comes from. Three D E S, against nist eight "
            "hundred, one thirty one A, which disallowed it after twenty twenty-three. "
            "A ten twenty-four bit Diffie Hellman group. M D five. Aggressive Mode with a "
            "pre-shared key. These are not opinions. Each was read off the wire, and an auditor "
            "can check every citation."
        ),
    ),
    Beat(
        key="inventory",
        chapter="3 · The estate",
        kind="terminal",
        source="inventory",
        caption="Two tunnels are documented. The wire has three.",
        reveal=True,
        spoken=(
            "One tunnel is a demo. Here is an estate: three sites, checked against the operator's "
            "own documented tunnel list. Two of them are documented. The wire has three. That "
            "third tunnel is in nobody's asset register, and it is the weakest of the three."
        ),
    ),
    Beat(
        key="dashboard",
        chapter="4 · The dashboard",
        kind="shot",
        source="02_overview.png",
        caption="The same analysis, in the browser",
        zoom=(0.0, 0.0, 1.0, 0.62),
        spoken=(
            "The same analysis in a browser. Drop a capture in, and the estate grade comes back "
            "with the findings behind it. This is the real dashboard, served under a content "
            "security policy with no inline script at all."
        ),
    ),
    Beat(
        key="findings",
        chapter="4 · The dashboard",
        kind="shot",
        source="04_findings.png",
        caption="Section A — verified. Cited, and carrying no confidence value.",
        zoom=(0.0, 0.12, 1.0, 0.78),
        spoken=(
            "Here are the findings. Each one carries its severity, the evidence read off the wire, "
            "the standard it applies, and what to do about it."
        ),
    ),
    Beat(
        key="shap",
        chapter="5 · The inference",
        kind="shot",
        source="09_detail.png",
        caption="Encrypted payload. Packet size, timing and direction — nothing else.",
        zoom=(0.10, 0.885, 0.92, 1.0),
        spoken=(
            "So what is that tunnel carrying? The payload is encrypted, and we never decrypt it. "
            "What the model reads is packet size, timing and direction. Nothing else. It says "
            "email, at a confidence of zero point nine nine. And it says why: the packet rate, the "
            "average gap between packets, the timing irregularity. Those are the fingerprints of a "
            "mail session. It is a calibrated classifier, and it abstains when the signal is thin. "
            "A short capture returns insufficient signal rather than a guess."
        ),
    ),
    Beat(
        key="separation",
        chapter="6 · Facts and estimates",
        kind="statement",
        source="Facts are parsed. Estimates are inferred.",
        points=[
            ("Section A", "read off the wire · cites a clause · no confidence value"),
            ("Section B", "estimated by a model · always carries a confidence"),
            ("raises", "enforce_separation() — not an assert, which -O would strip"),
        ],
        spoken=(
            "Now the part that matters most. Findings sit in Section A: parsed from the wire, each "
            "citing a clause, with no confidence value anywhere. The inference sits in Section B, "
            "and always carries one. A validator refuses to build a report that mixes them. And it "
            "raises rather than asserting, because python dash O strips assertions, and the "
            "guarantee at the centre of this product would vanish in exactly the deployment most "
            "likely to run optimised."
        ),
    ),
    Beat(
        key="wrong_format",
        chapter="7 · When it goes wrong",
        kind="terminal",
        source="wrong_format",
        caption="Wireshark saves pcapng by default. The error says so, in one line.",
        spoken=(
            "Real deployments fail. Wireshark saves p cap n g by default, and this parser reads "
            "p cap. Hand it the wrong file and it says so in one line, naming the file and the "
            "reason. It does not crash, and it does not quietly hand back an empty report."
        ),
    ),
    Beat(
        key="device_state",
        chapter="8 · The anomaly",
        kind="terminal",
        source="device_state",
        caption="The wire said AES-256. The kernel says 3DES is what is installed.",
        reveal=True,
        spoken=(
            "Here is a harder failure. On the wire, this tunnel negotiated A E S two fifty-six. "
            "But the gateway's own kernel says something different: three D E S with M D five is "
            "what is actually installed. The tool reads that state. It parses it, it never fetches "
            "it, and it needs no credential. Then it grades it against the same rules, and the "
            "estate falls from thirty-three out of a hundred to eleven. It also found the "
            "anti-replay window switched off, and that setting never appears on the wire in any "
            "form. No passive capture of that gateway could ever have found it."
        ),
    ),
    Beat(
        key="remediate",
        chapter="9 · Auto-remediation",
        kind="terminal",
        source="remediate",
        caption="Both ends, sequenced, with its assumptions stated",
        reveal=True,
        spoken=(
            "Detected. Now corrected. The tool generates the change package itself: configuration "
            "for both ends, because a one-sided I P sec change is an outage. It is reconstructed "
            "from what the peer actually negotiated, not from what a document claims it runs. And "
            "it is sequenced, with the assumptions it had to make written at the top. Applied in "
            "this order, a proposal change costs zero packet loss, measured on a live strongSwan "
            "pair in the integration suite."
        ),
    ),
    Beat(
        key="config",
        chapter="9 · Auto-remediation",
        kind="terminal",
        source="config",
        caption="Generated configuration — and no secret anywhere in it",
        spoken=(
            "This is the file an engineer pastes into a change ticket. Note what is not in it: "
            "there is no key, and no secret. The tool generates configuration. A person applies it."
        ),
    ),
    Beat(
        key="after",
        chapter="10 · Recovery",
        kind="terminal",
        source="analyse_after",
        caption="Grade A — because the fix is on the wire, not because a box was ticked",
        reveal=True,
        spoken=(
            "And verification closes the loop. Re-analyse the same estate after the fix: grade A, "
            "one hundred out of one hundred. The finding is closed because the fix is visible on "
            "the wire, not because somebody ticked a box. What is left is the post-quantum note, "
            "which is the next thing to plan for rather than a defect to fix today."
        ),
    ),
    Beat(
        key="pqc",
        chapter="11 · Post-quantum",
        kind="shot",
        source="07_pqc.png",
        caption="Harvest-now, decrypt-later — graded per tunnel",
        zoom=(0.0, 0.10, 1.0, 0.72),
        spoken=(
            "Post-quantum readiness is graded for every tunnel. Traffic captured today can be "
            "stored and decrypted later, so this is about traffic already on the wire, not only "
            "about future sessions."
        ),
    ),
    Beat(
        key="boundaries",
        chapter="12 · What it will not do",
        kind="terminal",
        source="scan_refusal",
        caption="Asked to probe without authorisation, it refuses",
        spoken=(
            "Two things it will not do. It never writes to a network device. There is no S S H "
            "client, no NETCONF client, and a test walks the syntax tree of every module to keep "
            "it that way. And it stores no credential, because it never authenticates to anything. "
            "Ask it to probe a host without authorisation, and it refuses."
        ),
    ),
    Beat(
        key="close",
        chapter="",
        kind="statement",
        source="Built to be checked, not believed.",
        points=[
            ("2,613", "unit tests"),
            ("306", "integration tests, on real strongSwan pairs"),
            ("93.8%", "coverage · 10,000 fuzz inputs, zero crashes"),
            ("20 / 20", "release checklist — nothing skipped"),
            ("0.68 GB", "container, non-root, runs air-gapped"),
        ],
        spoken=(
            "Two thousand six hundred and thirteen unit tests. Three hundred and six integration "
            "tests, on real strongSwan pairs. Ninety-four percent coverage. Ten thousand fuzz "
            "inputs with zero crashes. Twenty out of twenty on the release checklist, with nothing "
            "skipped. It runs air-gapped, in a container, as a non-root user. "
            "IPsec Sentinel, from team Highlanders. Thank you."
        ),
    ),
]
