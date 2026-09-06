#!/usr/bin/env python3
"""Compare this parser against Wireshark's, message by message.

Independent confirmation is the strongest correctness evidence available here. Every
other test in the parser suite checks the parser against fixtures this project wrote,
which proves internal consistency and nothing about whether the RFCs were read
correctly. tshark is a decades-old dissector maintained by people who have seen far
more real IKE than this project ever will; where the two disagree, the burden of proof
is on this one.

The filter is ``isakmp``, not ``ike`` — Wireshark's dissector predates the IKEv2 name
and never adopted it, and ``-Y ike`` silently matches nothing.

One awkwardness worth knowing about: tshark's JSON output emits genuinely duplicate
object keys, one per repeated field, so a naive ``json.loads`` keeps only the last of
them and a message with four transforms appears to have one. Everything below is read
through an ordered pair list for that reason.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from ipsec_sentinel.models import IKEExchange  # noqa: E402
from ipsec_sentinel.parser.constants import TRANSFORM_TYPES  # noqa: E402
from ipsec_sentinel.parser.pcap import extract_ike_exchanges  # noqa: E402

TSHARK_TIMEOUT_S: Final = 300

# tshark names the transform ID field after the transform's type.
TF_ID_FIELDS: Final[dict[str, int]] = {
    "isakmp.tf.id.encr": 1,
    "isakmp.tf.id.prf": 2,
    "isakmp.tf.id.integ": 3,
    "isakmp.tf.id.dh": 4,
    "isakmp.tf.id.esn": 5,
}

# IKEv1 attribute classes, mapped onto the transform types this project projects them
# onto so the two sides can be compared at all.
V1_ATTR_TO_TRANSFORM_TYPE: Final[dict[str, int]] = {
    "isakmp.ike.attr.encryption_algorithm": 1,
    "isakmp.ike.attr.hash_algorithm": 3,
    "isakmp.ike.attr.group_description": 4,
}

TYPE_NAME_TO_NUMBER: Final[dict[str, int]] = {
    name: number for number, name in TRANSFORM_TYPES.items()
}


class TsharkUnavailableError(RuntimeError):
    """tshark is not installed or not runnable."""


@dataclass(frozen=True)
class MessageSummary:
    """The facts both parsers can be held to, for one IKE message."""

    version_major: int
    exchange_type: int
    transforms: tuple[tuple[int, int], ...] = ()
    key_lengths: tuple[int, ...] = ()

    def describe(self) -> str:
        pairs = ", ".join(f"{TRANSFORM_TYPES.get(t, t)}={i}" for t, i in self.transforms)
        return (
            f"v{self.version_major} exchange={self.exchange_type} "
            f"transforms=[{pairs}] key_lengths={list(self.key_lengths)}"
        )


@dataclass
class Discrepancy:
    """One disagreement, with both sides quoted."""

    index: int
    field_name: str
    tshark: object
    sentinel: object

    def __str__(self) -> str:
        return (
            f"  message {self.index}: {self.field_name}\n"
            f"    tshark:   {self.tshark}\n"
            f"    sentinel: {self.sentinel}"
        )


@dataclass
class ComparisonResult:
    pcap: Path
    tshark_messages: list[MessageSummary] = field(default_factory=list)
    sentinel_messages: list[MessageSummary] = field(default_factory=list)
    discrepancies: list[Discrepancy] = field(default_factory=list)

    @property
    def agrees(self) -> bool:
        return not self.discrepancies


def tshark_available() -> bool:
    try:
        subprocess.run(["tshark", "--version"], capture_output=True, timeout=30, check=True)
    except (OSError, subprocess.SubprocessError):
        return False
    return True


def _run_tshark(pcap: Path) -> Any:
    try:
        result = subprocess.run(
            ["tshark", "-r", str(pcap), "-Y", "isakmp", "-T", "json"],
            capture_output=True,
            text=True,
            timeout=TSHARK_TIMEOUT_S,
            check=False,
        )
    except OSError as exc:
        raise TsharkUnavailableError(f"tshark could not be run: {exc}") from exc
    if result.returncode != 0:
        raise TsharkUnavailableError(
            f"tshark exited {result.returncode} on {pcap}: {result.stderr.strip()[:400]}"
        )
    if not result.stdout.strip():
        return []
    # Duplicate keys are the whole point; keep the pairs rather than a dict.
    return json.loads(result.stdout, object_pairs_hook=lambda pairs: pairs)


def _leaves(node: Any) -> Iterator[tuple[str, Any]]:
    """Yield every (key, scalar) leaf in document order, duplicates intact."""
    if isinstance(node, list):
        for item in node:
            if isinstance(item, tuple) and len(item) == 2 and isinstance(item[0], str):
                key, value = item
                if isinstance(value, list | tuple):
                    yield from _leaves(value)
                else:
                    yield key, value
            else:
                yield from _leaves(item)


def _summarise_tshark_packet(packet: Any) -> MessageSummary | None:
    leaves = list(_leaves(packet))
    if not any(key.startswith("isakmp.") for key, _ in leaves):
        return None

    version_major = 0
    exchange_type = -1
    transforms: list[tuple[int, int]] = []
    key_lengths: list[int] = []

    for key, value in leaves:
        if key == "isakmp.version":
            version_major = int(str(value), 16) >> 4
        elif key == "isakmp.exchangetype":
            exchange_type = int(value)
        elif key in TF_ID_FIELDS:
            # The transform type comes from the field name, so tshark's own
            # ``isakmp.tf.type`` is redundant here and is deliberately not read.
            transforms.append((TF_ID_FIELDS[key], int(value)))
        elif key in V1_ATTR_TO_TRANSFORM_TYPE:
            transforms.append((V1_ATTR_TO_TRANSFORM_TYPE[key], int(value)))
        elif key in ("isakmp.ike2.attr.key_length", "isakmp.ike.attr.key_length"):
            key_lengths.append(int(value))

    return MessageSummary(
        version_major=version_major,
        exchange_type=exchange_type,
        transforms=tuple(sorted(transforms)),
        key_lengths=tuple(sorted(key_lengths)),
    )


def tshark_summary(pcap: Path) -> list[MessageSummary]:
    """Summarise every ISAKMP message tshark finds in the capture."""
    summaries: list[MessageSummary] = []
    for packet in _run_tshark(pcap):
        summary = _summarise_tshark_packet(packet)
        if summary is not None:
            summaries.append(summary)
    return summaries


def _summarise_exchange(exchange: IKEExchange) -> MessageSummary:
    transforms: list[tuple[int, int]] = []
    key_lengths: list[int] = []
    for proposal in exchange.proposals_offered:
        for transform in proposal.transforms:
            if transform.type is None:
                continue
            number = TYPE_NAME_TO_NUMBER.get(str(transform.type))
            if number is None:
                continue
            transforms.append((number, transform.id))
            if transform.key_length is not None:
                key_lengths.append(transform.key_length)
    return MessageSummary(
        version_major=1 if exchange.version == "IKEv1" else 2,
        exchange_type=_exchange_number(exchange),
        transforms=tuple(sorted(transforms)),
        key_lengths=tuple(sorted(key_lengths)),
    )


def _exchange_number(exchange: IKEExchange) -> int:
    """Recover the numeric exchange type from the model's resolved name.

    The model stores the name because that is what a report shows; tshark reports the
    number. Names are reversed through the same tables that produced them rather than
    re-parsing, so a table change cannot make the two sides disagree spuriously.
    """
    from ipsec_sentinel.parser.constants import (
        IKEV1_EXCHANGE_TYPES,
        IKEV2_EXCHANGE_TYPES,
    )

    table = IKEV1_EXCHANGE_TYPES if exchange.version == "IKEv1" else IKEV2_EXCHANGE_TYPES
    for number, name in table.items():
        if name == exchange.exchange_type:
            return number
    return -1


def sentinel_summary(pcap: Path) -> list[MessageSummary]:
    return [_summarise_exchange(exchange) for exchange in extract_ike_exchanges(pcap)]


def compare(pcap: Path) -> ComparisonResult:
    """Compare both parsers on one capture."""
    result = ComparisonResult(pcap=pcap)
    result.tshark_messages = tshark_summary(pcap)
    result.sentinel_messages = sentinel_summary(pcap)

    if len(result.tshark_messages) != len(result.sentinel_messages):
        result.discrepancies.append(
            Discrepancy(
                index=-1,
                field_name="message count",
                tshark=len(result.tshark_messages),
                sentinel=len(result.sentinel_messages),
            )
        )
        return result

    for index, (expected, actual) in enumerate(
        zip(result.tshark_messages, result.sentinel_messages, strict=True)
    ):
        for name in ("version_major", "exchange_type", "transforms", "key_lengths"):
            left = getattr(expected, name)
            right = getattr(actual, name)
            if left != right:
                result.discrepancies.append(
                    Discrepancy(index=index, field_name=name, tshark=left, sentinel=right)
                )
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcaps", nargs="+", type=Path)
    parser.add_argument("--quiet", action="store_true", help="only report disagreements")
    args = parser.parse_args(argv)

    if not tshark_available():
        print("tshark is not installed; cannot run the parity check", file=sys.stderr)
        return 2

    total = agreed = 0
    for pcap in args.pcaps:
        result = compare(pcap)
        total += 1
        if result.agrees:
            agreed += 1
            if not args.quiet:
                print(f"OK   {pcap} ({len(result.tshark_messages)} messages agree)")
            continue
        print(f"FAIL {pcap}")
        for discrepancy in result.discrepancies:
            print(discrepancy)

    print(f"\n{agreed}/{total} captures agree with tshark")
    return 0 if agreed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
