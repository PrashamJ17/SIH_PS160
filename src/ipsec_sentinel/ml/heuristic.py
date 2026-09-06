"""A deliberately crude baseline for mode inference — the bar the model must beat.

This exists to be beaten, and it is written before any model so that the comparison is
honest. A machine-learned classifier that cannot outperform twenty lines of arithmetic
does not justify its training cost, its opacity, or the confidence interval it forces a
reader to reason about. Establishing the bar afterwards invites choosing a bar the model
already clears.

**The physical signal.** Tunnel mode encapsulates the entire inner IP packet, so every
protected packet carries a full inner IP header that transport mode does not: 20 bytes
for IPv4, 40 for IPv6. That offset is present in every packet of the flow, which makes
the *smallest* packet the most informative observation — a bare TCP ACK is 40 bytes of
inner packet, and whether it arrives as 40 or 60 bytes of ESP payload is the whole
distinction. Large packets are useless here, because they are clamped to the MTU either
way.

**Why the confidence is crude and says so.** The offset is small, ESP padding rounds
sizes to the cipher's block size, and a flow whose smallest packet is not a bare ACK
gives no signal at all. The returned confidence reflects how far the observation is from
the decision boundary and nothing more. It is not calibrated, it is not a probability,
and :func:`infer_mode_heuristic` names it ``crude`` for that reason.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

# The inner IP header tunnel mode adds and transport mode does not.
TUNNEL_OVERHEAD_IPV4: Final = 20
TUNNEL_OVERHEAD_IPV6: Final = 40

# ESP framing on the wire: SPI (4) + sequence (4) + IV (16 for a 128-bit block cipher)
# + pad length (1) + next header (1) + ICV (16). Approximate by construction — the IV
# and ICV both vary with the negotiated algorithm, which a passive observer does not
# know for certain.
ESP_FRAMING_OVERHEAD: Final = 42

# The smallest inner packet worth reasoning about: a bare TCP ACK.
BARE_ACK_BYTES: Final = 40

# Band around each expected floor within which an observation counts as a match. Wide
# enough to absorb block padding (up to 15 bytes for AES-CBC) plus the IV/ICV variation
# above.
MATCH_TOLERANCE: Final = 24

MODE_TUNNEL: Final = "tunnel"
MODE_TRANSPORT: Final = "transport"
MODE_UNKNOWN: Final = "unknown"


@dataclass(frozen=True)
class ModeEstimate:
    """A mode guess, its crude confidence, and the reasoning behind it."""

    mode: str
    confidence: float
    rationale: str

    def as_tuple(self) -> tuple[str, float]:
        return self.mode, self.confidence


def expected_floor(mode: str, ipv6: bool = False) -> int:
    """The smallest ESP packet size a bare ACK would produce under this mode."""
    overhead = TUNNEL_OVERHEAD_IPV6 if ipv6 else TUNNEL_OVERHEAD_IPV4
    inner = BARE_ACK_BYTES + (overhead if mode == MODE_TUNNEL else 0)
    return inner + ESP_FRAMING_OVERHEAD


def infer_mode_heuristic(flow_features: dict[str, float], ipv6: bool = False) -> tuple[str, float]:
    """Guess tunnel or transport mode from a flow's size distribution.

    Returns ``(mode, crude_confidence)``. The mode is ``"unknown"`` with confidence 0
    whenever the observation cannot distinguish the two — an empty flow, or a smallest
    packet far from both floors, which happens whenever the flow never carried a bare
    acknowledgement. Guessing there would be worse than abstaining: this baseline
    exists to be compared against, and a baseline that inflates its own coverage makes
    the comparison meaningless.
    """
    return estimate_mode(flow_features, ipv6=ipv6).as_tuple()


def estimate_mode(flow_features: dict[str, float], ipv6: bool = False) -> ModeEstimate:
    """The full estimate, including why it decided what it did."""
    packet_count = flow_features.get("packet_count", 0.0)
    smallest = flow_features.get("size_min", 0.0)

    if packet_count <= 0 or smallest <= 0:
        return ModeEstimate(MODE_UNKNOWN, 0.0, "no packets to measure")

    tunnel_floor = expected_floor(MODE_TUNNEL, ipv6)
    transport_floor = expected_floor(MODE_TRANSPORT, ipv6)

    to_tunnel = abs(smallest - tunnel_floor)
    to_transport = abs(smallest - transport_floor)

    if min(to_tunnel, to_transport) > MATCH_TOLERANCE:
        return ModeEstimate(
            MODE_UNKNOWN,
            0.0,
            f"smallest packet {smallest:.0f} B is {min(to_tunnel, to_transport):.0f} B "
            f"from either floor (tunnel {tunnel_floor}, transport {transport_floor}); "
            f"this flow probably never carried a bare acknowledgement",
        )

    separation = abs(tunnel_floor - transport_floor)
    if to_tunnel < to_transport:
        mode, distance = MODE_TUNNEL, to_tunnel
    else:
        mode, distance = MODE_TRANSPORT, to_transport

    # Confidence falls off with distance from the chosen floor, and is capped well
    # below certainty because a 20-byte offset under padding is never conclusive.
    confidence = max(0.0, min(0.75, 1.0 - (distance / separation)))
    return ModeEstimate(
        mode,
        confidence,
        f"smallest packet {smallest:.0f} B is {distance:.0f} B from the {mode} floor "
        f"({expected_floor(mode, ipv6)} B) and {max(to_tunnel, to_transport):.0f} B "
        f"from the other",
    )


def heuristic_accuracy(
    rows: list[tuple[dict[str, float], str]], ipv6: bool = False
) -> dict[str, float]:
    """Score the heuristic against labelled rows.

    Reports coverage separately from accuracy. A baseline that abstains on 90% of rows
    and is right on the rest is not a 100%-accurate baseline, and collapsing the two
    into one number would flatter it into looking like a bar worth clearing.
    """
    total = len(rows)
    if total == 0:
        return {"total": 0, "answered": 0, "coverage": 0.0, "accuracy": 0.0}

    answered = 0
    correct = 0
    for features, truth in rows:
        mode, _confidence = infer_mode_heuristic(features, ipv6=ipv6)
        if mode == MODE_UNKNOWN:
            continue
        answered += 1
        if mode == truth:
            correct += 1
    return {
        "total": float(total),
        "answered": float(answered),
        "coverage": answered / total,
        "accuracy": (correct / answered) if answered else 0.0,
    }
