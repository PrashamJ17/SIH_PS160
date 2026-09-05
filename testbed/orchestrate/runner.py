"""Run one complete sweep cell: configuration x generator x impairment.

Every cell is independent and self-cleaning. Teardown happens in a ``finally`` block
without exception, because a leaked container or netem qdisc does not fail the cell
that leaked it — it silently distorts every cell that follows, and in a sweep of
thousands that is a corpus-wide fault with no obvious cause.

One ordering detail is load-bearing: **capture starts before the tunnel is
established.** The IKE handshake happens exactly once, during initiation, and it is
the entire input to the deterministic parser lane. Capturing after it produces cells
full of ESP with no negotiation to read — which looks perfectly healthy until Phase 4
discovers there is nothing to parse.
"""

from __future__ import annotations

import contextlib
import secrets
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from pydantic import BaseModel, Field

from testbed.orchestrate.capture import dual_capture_for_pair, verify_pcap
from testbed.orchestrate.config_gen import TunnelConfig, render_swanctl_conf
from testbed.orchestrate.groundtruth import build_manifest, harvest_swanctl, harvest_xfrm_state
from testbed.orchestrate.netem import ImpairmentProfile, apply_profile, clear
from testbed.traffic.base import RunContext
from testbed.traffic.registry import build_generator

REPO_ROOT: Final = Path(__file__).resolve().parents[2]
PAIR_COMPOSE: Final = REPO_ROOT / "testbed" / "compose" / "pair.yml"

LEFT_TRANSIT: Final = "10.100.0.2"
RIGHT_TRANSIT: Final = "10.100.0.3"
LEFT_PROTECTED: Final = "10.1.0.2"
LEFT_HOST_IP: Final = "10.1.0.10"
RIGHT_HOST_IP: Final = "10.2.0.10"


class RunOutcome(BaseModel):
    """What one cell produced, whether or not it succeeded."""

    cell_id: str
    config_id: str
    generator: str
    variant: str
    impairment: str
    success: bool
    error: str | None = None
    outer_pcap: str | None = None
    inner_pcap: str | None = None
    manifest_path: str | None = None
    negotiation_matched_intent: bool = False
    outer_packets: int = 0
    inner_packets: int = 0
    started_at: datetime
    ended_at: datetime
    details: dict[str, Any] = Field(default_factory=dict)


@dataclass(frozen=True)
class CellSpec:
    """The identity of one cell, independent of how it is executed."""

    config: TunnelConfig
    generator: str
    variant: str
    impairment: str
    repeat: int = 0

    @property
    def cell_id(self) -> str:
        """Stable across processes, so a resumed sweep skips exactly what it ran."""
        return (
            f"{self.config.config_id()}_{self.generator}_{self.variant}"
            f"_{self.impairment}_r{self.repeat}"
        )


def _compose(
    project: str,
    *args: str,
    env: dict[str, str],
    profiles: tuple[str, ...] = (),
    timeout: int = 420,
) -> str:
    import os

    argv = ["docker", "compose", "-f", str(PAIR_COMPOSE), "-p", project]
    for profile in profiles:
        argv += ["--profile", profile]
    argv += list(args)
    result = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        env={**os.environ, **env},
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"docker compose {' '.join(args)} exited {result.returncode}: "
            f"{result.stderr.strip()[:400]}"
        )
    return result.stdout


def _exec(container: str, *cmd: str, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "exec", container, *cmd],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _purge(project: str) -> None:
    """Remove anything still carrying this project's compose labels.

    Belt and braces after `compose down`: a service behind a profile can survive
    teardown if the profile is not active on that call, and one surviving container
    pins its network, whose subnet then collides with the next cell.
    """
    label = f"label=com.docker.compose.project={project}"
    listed = subprocess.run(
        ["docker", "ps", "-aq", "--filter", label],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    for container in listed.stdout.split():
        subprocess.run(
            ["docker", "rm", "-f", container],
            capture_output=True,
            timeout=60,
            check=False,
        )
    nets = subprocess.run(
        ["docker", "network", "ls", "-q", "--filter", label],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    for network in nets.stdout.split():
        subprocess.run(
            ["docker", "network", "rm", network],
            capture_output=True,
            timeout=60,
            check=False,
        )


def run_cell(
    cell: CellSpec,
    impairment: ImpairmentProfile,
    duration_s: int,
    out_dir: Path,
    *,
    replay_source: Path | None = None,
    seed: int | None = None,
    slot_env: dict[str, str] | None = None,
    addresses: Any = None,
) -> RunOutcome:
    """Execute one cell end to end and return its outcome.

    Never raises for an operational failure: a cell that cannot establish a tunnel is
    a recorded result, not an exception, because the sweep must continue and the
    failure itself is data about that configuration.

    ``slot_env`` and ``addresses`` place this cell in one concurrency slot's private
    subnets. Omitting them uses slot 0, which is what a single pair uses.
    """
    started = datetime.now(UTC)
    out_dir.mkdir(parents=True, exist_ok=True)
    project = f"sentinel-cell-{uuid.uuid4().hex[:10]}"
    conf_dir = Path(tempfile.mkdtemp(prefix="sentinel-cell-"))

    def failure(message: str, **details: Any) -> RunOutcome:
        return RunOutcome(
            cell_id=cell.cell_id,
            config_id=cell.config.config_id(),
            generator=cell.generator,
            variant=cell.variant,
            impairment=cell.impairment,
            success=False,
            error=message[:600],
            started_at=started,
            ended_at=datetime.now(UTC),
            details=details,
        )

    try:
        built = build_generator(
            cell.generator, cell.variant, seed=seed, replay_source=replay_source
        )
    except Exception as exc:
        return failure(f"could not build generator: {type(exc).__name__}: {exc}")

    # The rendered traffic selectors must match the slot's subnets, or the tunnel
    # comes up and then carries nothing.
    topology = None
    if addresses is not None:
        from testbed.orchestrate.config_gen import Topology

        topology = Topology(
            left_transit=addresses.left_transit,
            right_transit=addresses.right_transit,
            left_subnet=addresses.left_subnet,
            right_subnet=addresses.right_subnet,
        )
    (conf_dir / "left.conf").write_text(render_swanctl_conf(cell.config, "left", topology))
    (conf_dir / "right.conf").write_text(render_swanctl_conf(cell.config, "right", topology))
    left_transit = getattr(addresses, "left_transit", LEFT_TRANSIT)
    right_transit = getattr(addresses, "right_transit", RIGHT_TRANSIT)
    left_protected = getattr(addresses, "left_protected", LEFT_PROTECTED)
    left_host_ip = getattr(addresses, "left_host", LEFT_HOST_IP)
    right_host_ip = getattr(addresses, "right_host", RIGHT_HOST_IP)

    env = {
        "SENTINEL_PSK": secrets.token_hex(24),
        "LEFT_CONF": str(conf_dir / "left.conf"),
        "RIGHT_CONF": str(conf_dir / "right.conf"),
        **(slot_env or {}),
        **built.env,
    }

    endpoints: list[tuple[str, str]] = []
    try:
        _compose(project, "up", "-d", "--wait", env=env, profiles=built.profiles)
        left = _compose(project, "ps", "-q", "left", env=env, profiles=built.profiles).strip()
        right = _compose(project, "ps", "-q", "right", env=env, profiles=built.profiles).strip()
        left_host = _compose(
            project, "ps", "-q", "left_host", env=env, profiles=built.profiles
        ).strip()
        right_host = _compose(
            project, "ps", "-q", "right_host", env=env, profiles=built.profiles
        ).strip()
        if not all((left, right, left_host, right_host)):
            return failure("compose did not report all container ids")

        from testbed.orchestrate.capture import interface_holding

        endpoints = [
            (left, interface_holding(left, left_transit)),
            (right, interface_holding(right, right_transit)),
        ]
        apply_profile(endpoints, impairment)

        ctx = RunContext(
            project=project,
            left_gateway=left,
            right_gateway=right,
            left_host=left_host,
            right_host=right_host,
            left_host_ip=left_host_ip,
            right_host_ip=right_host_ip,
            out_dir=out_dir,
            video_origin_ip=getattr(addresses, "video_origin", "10.2.0.20"),
            web_origin_ip=getattr(addresses, "web_origin", "10.2.0.21"),
            mail_origin_ip=getattr(addresses, "mail_origin", "10.2.0.22"),
            xmpp_origin_ip=getattr(addresses, "xmpp_origin", "10.2.0.23"),
        )
        try:
            built.generator.setup(ctx)
        except Exception as exc:
            return failure(f"generator setup failed: {type(exc).__name__}: {exc}")

        capture = dual_capture_for_pair(left, left_transit, left_protected, out_dir)
        with capture:
            # Capture is already running, so the handshake lands in the outer PCAP.
            initiate = _exec(left, "swanctl", "--initiate", "--child", "net-net", timeout=180)
            if initiate.returncode != 0:
                return failure(
                    f"tunnel did not establish: {initiate.stdout.strip()[:300]}"
                    f"{initiate.stderr.strip()[:300]}"
                )
            generation = built.generator.run(duration_s)
            time.sleep(1)

        if not generation.success:
            return failure(f"generation failed: {generation.error}")

        outer_packets = verify_pcap(capture.outer_pcap)
        inner_packets = verify_pcap(capture.inner_pcap)

        manifest = build_manifest(
            cell.config,
            harvest_swanctl(left),
            harvest_xfrm_state(left),
            capture_meta={
                "cell_id": cell.cell_id,
                "generator": cell.generator,
                "variant": generation.variant,
                "impairment": cell.impairment,
                "repeat": cell.repeat,
                "duration_s": duration_s,
                "outer_pcap": capture.outer_pcap.name,
                "inner_pcap": capture.inner_pcap.name,
                "outer_packets": outer_packets,
                "inner_packets": inner_packets,
                "packets_generated": generation.packets_sent,
                "bytes_generated": generation.bytes_sent,
                "netem": {
                    "delay_ms": impairment.delay_ms,
                    "jitter_ms": impairment.jitter_ms,
                    "loss_pct": impairment.loss_pct,
                    "rate_mbit": impairment.rate_mbit,
                },
            },
            capture_id=cell.cell_id,
        )
        manifest_path = out_dir / "manifest.json"
        manifest_path.write_text(manifest.model_dump_json(indent=2))

        return RunOutcome(
            cell_id=cell.cell_id,
            config_id=cell.config.config_id(),
            generator=cell.generator,
            variant=generation.variant,
            impairment=cell.impairment,
            success=True,
            outer_pcap=str(capture.outer_pcap),
            inner_pcap=str(capture.inner_pcap),
            manifest_path=str(manifest_path),
            negotiation_matched_intent=manifest.negotiation_matched_intent,
            outer_packets=outer_packets,
            inner_packets=inner_packets,
            started_at=started,
            ended_at=datetime.now(UTC),
            details={"mismatches": manifest.mismatches},
        )
    except Exception as exc:
        return failure(f"{type(exc).__name__}: {exc}")
    finally:
        # Unconditional. A leaked qdisc or container does not fail the cell that leaked
        # it; it corrupts every cell that follows.
        # Each step is suppressed on its own so one failure cannot stop the rest of
        # teardown, and so a teardown error never masks the cell's actual result.
        for container, interface in endpoints:
            with contextlib.suppress(Exception):
                clear(container, interface)
        with contextlib.suppress(Exception):
            built.generator.teardown()
        with contextlib.suppress(Exception):
            _compose(
                project,
                "down",
                "-v",
                "--remove-orphans",
                env=env,
                profiles=built.profiles,
                timeout=240,
            )
        _purge(project)
        for leftover in conf_dir.glob("*"):
            leftover.unlink(missing_ok=True)
        conf_dir.rmdir()
