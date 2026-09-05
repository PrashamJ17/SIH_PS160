"""Construct any generator by name, with the sidecars and secrets it needs.

The sweep works from a plan of names, not objects, so a cell can be described in a
state file, skipped on resume, and reconstructed identically afterwards. Anything a
generator needs beyond its own arguments — a compose profile, a per-run password —
is produced here rather than in the runner, so adding a generator does not mean
editing the orchestrator.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from testbed.traffic.base import TrafficGenerator
from testbed.traffic.email import EmailGenerator, generate_mailbox_password
from testbed.traffic.icmp import IcmpGenerator
from testbed.traffic.messaging import MessagingGenerator, generate_account_password
from testbed.traffic.replay import ReplayGenerator
from testbed.traffic.video import VideoGenerator
from testbed.traffic.voip import VoipGenerator
from testbed.traffic.web import WebGenerator


@dataclass(frozen=True)
class GeneratorSpec:
    """How to build one generator class, and what the environment must supply."""

    name: str
    variants: tuple[str, ...]
    build: Callable[..., TrafficGenerator] = field(repr=False)
    profiles: tuple[str, ...] = ()
    secret_env: str | None = None
    secret_factory: Callable[[], str] | None = None
    needs_replay_source: bool = False


def _icmp(variant: str, **_: object) -> TrafficGenerator:
    return IcmpGenerator(variant)


def _voip(variant: str, **_: object) -> TrafficGenerator:
    return VoipGenerator(variant)


def _video(variant: str, seed: int | None = None, **_: object) -> TrafficGenerator:
    return VideoGenerator(variant, seed=seed)


def _web(variant: str, seed: int | None = None, **_: object) -> TrafficGenerator:
    return WebGenerator(variant, seed=seed)


def _email(
    variant: str, seed: int | None = None, secret: str | None = None, **_: object
) -> TrafficGenerator:
    return EmailGenerator(variant, password=secret, seed=seed)


def _messaging(
    variant: str, seed: int | None = None, secret: str | None = None, **_: object
) -> TrafficGenerator:
    return MessagingGenerator(variant, password=secret, seed=seed)


def _replay(variant: str, replay_source: Path | None = None, **_: object) -> TrafficGenerator:
    return ReplayGenerator(variant, source_pcap=replay_source)


SPECS: Final[dict[str, GeneratorSpec]] = {
    "icmp": GeneratorSpec("icmp", ("steady_1s", "flood_small", "large_payload"), build=_icmp),
    "voip": GeneratorSpec("voip", ("g711_20ms", "g729_20ms"), build=_voip),
    "video": GeneratorSpec(
        "video", ("dash_720p", "dash_1080p", "hls_adaptive"), profiles=("video",), build=_video
    ),
    "web": GeneratorSpec("web", ("reading", "skimming"), profiles=("web",), build=_web),
    "email": GeneratorSpec(
        "email",
        ("smtp_small", "smtp_attachment", "imap_sync"),
        profiles=("mail",),
        secret_env="MAIL_PASSWORD",
        secret_factory=generate_mailbox_password,
        build=_email,
    ),
    "messaging": GeneratorSpec(
        "messaging",
        ("chat_active", "chat_idle"),
        profiles=("messaging",),
        secret_env="XMPP_PASSWORD",
        secret_factory=generate_account_password,
        build=_messaging,
    ),
    "replay": GeneratorSpec(
        "replay",
        ("cicids2017_benign", "mawi_sample"),
        needs_replay_source=True,
        build=_replay,
    ),
}

GENERATOR_NAMES: Final[tuple[str, ...]] = tuple(SPECS)


@dataclass(frozen=True)
class BuiltGenerator:
    """A generator plus everything the runner must arrange around it."""

    generator: TrafficGenerator
    profiles: tuple[str, ...]
    env: dict[str, str]


def spec(name: str) -> GeneratorSpec:
    if name not in SPECS:
        raise ValueError(f"unknown generator {name!r}; have {sorted(SPECS)}")
    return SPECS[name]


def variants_of(name: str) -> Sequence[str]:
    return spec(name).variants


def build_generator(
    name: str,
    variant: str | None = None,
    *,
    seed: int | None = None,
    replay_source: Path | None = None,
) -> BuiltGenerator:
    """Build a generator by name, minting any per-run secret it needs.

    Secrets are generated here and returned in ``env`` so the same value reaches both
    the sidecar and the client. Nothing is stored, and nothing is reused between cells.
    """
    generator_spec = spec(name)
    chosen = variant or generator_spec.variants[0]
    if chosen not in generator_spec.variants:
        raise ValueError(
            f"unknown variant {chosen!r} for {name}; have {list(generator_spec.variants)}"
        )

    env: dict[str, str] = {}
    secret: str | None = None
    if generator_spec.secret_env and generator_spec.secret_factory:
        secret = generator_spec.secret_factory()
        env[generator_spec.secret_env] = secret

    if generator_spec.needs_replay_source and replay_source is None:
        raise ValueError(f"{name} requires a replay source capture")

    generator = generator_spec.build(
        variant=chosen, seed=seed, secret=secret, replay_source=replay_source
    )
    return BuiltGenerator(generator, generator_spec.profiles, env)
