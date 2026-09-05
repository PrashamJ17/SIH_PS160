"""Network impairment profiles.

Without impairment the classifier learns this lab's unnaturally clean network and
collapses on anything real. Every inter-arrival feature it relies on is a property of
the path as much as of the application, and a path with no delay, no jitter and no
loss does not exist outside a testbed.

Impairment is applied to **both** gateways' transit interfaces. ``tc netem`` shapes
egress only, so impairing one end delays one direction and leaves a round trip half
untouched — which is not what any real link does.
"""

from __future__ import annotations

import subprocess
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True)
class ImpairmentProfile:
    """One path characterisation: delay, jitter, loss and an optional rate cap."""

    name: str
    delay_ms: int
    jitter_ms: int
    loss_pct: float
    rate_mbit: int | None

    @property
    def is_clean(self) -> bool:
        """True when the profile asks for no shaping at all."""
        return (
            self.delay_ms == 0
            and self.jitter_ms == 0
            and self.loss_pct == 0.0
            and self.rate_mbit is None
        )

    def netem_args(self) -> list[str]:
        """The ``tc`` netem arguments this profile expands to."""
        args: list[str] = ["netem"]
        if self.delay_ms > 0:
            args += ["delay", f"{self.delay_ms}ms"]
            if self.jitter_ms > 0:
                args += [f"{self.jitter_ms}ms", "distribution", "normal"]
        if self.loss_pct > 0:
            args += ["loss", f"{self.loss_pct}%"]
        if self.rate_mbit is not None:
            args += ["rate", f"{self.rate_mbit}mbit"]
        return args

    def expected_min_rtt_ms(self) -> float:
        """Round-trip delay this profile should introduce across both directions."""
        return 2.0 * self.delay_ms


PROFILES: Final[list[ImpairmentProfile]] = [
    ImpairmentProfile("clean", 0, 0, 0.0, None),
    ImpairmentProfile("lan", 1, 0, 0.0, 1000),
    ImpairmentProfile("wan_good", 20, 2, 0.1, 100),
    ImpairmentProfile("wan_poor", 80, 15, 1.0, 10),
    ImpairmentProfile("satellite", 300, 30, 2.0, 5),
]

PROFILES_BY_NAME: Final[dict[str, ImpairmentProfile]] = {p.name: p for p in PROFILES}


class ImpairmentError(RuntimeError):
    """An impairment could not be applied."""


def profile(name: str) -> ImpairmentProfile:
    if name not in PROFILES_BY_NAME:
        raise ValueError(f"unknown impairment profile {name!r}; have {sorted(PROFILES_BY_NAME)}")
    return PROFILES_BY_NAME[name]


def _tc(container: str, *args: str, check: bool) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["docker", "exec", container, "tc", *args],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if check and result.returncode != 0:
        raise ImpairmentError(
            f"tc {' '.join(args)} in {container} exited {result.returncode}: "
            f"{result.stderr.strip()[:200]}"
        )
    return result


def clear(container: str, interface: str) -> None:
    """Remove any root qdisc. Idempotent: removing nothing is not an error.

    Idempotence matters because teardown runs in a ``finally`` block that may execute
    after a failure that already removed the qdisc — and a sweep that aborts on a
    double-clear would leave containers running.
    """
    _tc(container, "qdisc", "del", "dev", interface, "root", check=False)


def apply_profile(endpoints: Sequence[tuple[str, str]], impairment: ImpairmentProfile) -> None:
    """Apply an impairment to every (container, interface) pair.

    A clean profile clears instead of shaping, so "clean" genuinely means an unshaped
    path rather than netem with zeroed parameters.
    """
    for container, interface in endpoints:
        clear(container, interface)
        if impairment.is_clean:
            continue
        _tc(
            container,
            "qdisc",
            "add",
            "dev",
            interface,
            "root",
            *impairment.netem_args(),
            check=True,
        )


@contextmanager
def impaired(
    endpoints: Sequence[tuple[str, str]], impairment: ImpairmentProfile
) -> Iterator[ImpairmentProfile]:
    """Apply an impairment for the duration of a block, always removing it after.

    A leaked qdisc silently distorts every subsequent cell in a sweep, and the
    resulting corpus would carry timing labels that describe a path nobody configured.
    """
    try:
        apply_profile(endpoints, impairment)
        yield impairment
    finally:
        for container, interface in endpoints:
            clear(container, interface)


def active_qdisc(container: str, interface: str) -> str:
    """The root qdisc currently on an interface, for verification."""
    return _tc(container, "qdisc", "show", "dev", interface, check=False).stdout.strip()
