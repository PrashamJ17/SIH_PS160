"""Run one complete testbed cycle end to end.

This is the M1 acceptance entry point and the seed of the Step 3.1 cell runner: render
configuration for a labelled anchor, stand the pair up, establish the tunnel, capture
both taps while traffic flows, harvest ground truth from the daemon and the kernel,
write the manifest, and tear everything down.

Teardown is unconditional. A leaked container or network poisons every later run, and
in a sweep of thousands of cells that failure compounds silently.
"""

from __future__ import annotations

import argparse
import json
import secrets
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Sequence
from pathlib import Path
from typing import Final

from testbed.orchestrate.capture import dual_capture_for_pair, verify_pcap
from testbed.orchestrate.config_gen import TunnelConfig, render_swanctl_conf
from testbed.orchestrate.groundtruth import (
    Manifest,
    build_manifest,
    harvest_swanctl,
    harvest_xfrm_state,
)
from testbed.orchestrate.matrix import expand_matrix

REPO_ROOT: Final = Path(__file__).resolve().parents[2]
PAIR_COMPOSE: Final = REPO_ROOT / "testbed" / "compose" / "pair.yml"

LEFT_TRANSIT: Final = "10.100.0.2"
LEFT_PROTECTED: Final = "10.1.0.2"
LEFT_HOST: Final = "10.1.0.10"
RIGHT_HOST: Final = "10.2.0.10"


class RunError(RuntimeError):
    """The cycle could not be completed."""


def _compose(project: str, *args: str, env: dict[str, str], timeout: int = 300) -> str:
    import os

    result = subprocess.run(
        ["docker", "compose", "-f", str(PAIR_COMPOSE), "-p", project, *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        env={**os.environ, **env},
    )
    if result.returncode != 0:
        raise RunError(
            f"docker compose {' '.join(args)} exited {result.returncode}: "
            f"{result.stderr.strip()[:400]}"
        )
    return result.stdout


def _exec(container: str, *cmd: str, timeout: int = 90) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "exec", container, *cmd],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def config_for_label(label: str) -> TunnelConfig:
    """Look up one of the matrix's labelled anchor configurations."""
    for entry in expand_matrix():
        if entry.label == label:
            return entry.config
    available = sorted({e.label for e in expand_matrix() if e.label})
    raise RunError(f"unknown config label {label!r}; available: {available}")


def run_once(
    cfg: TunnelConfig,
    out_dir: Path,
    *,
    label: str | None = None,
    duration_s: int = 8,
    ping_count: int = 6,
) -> Manifest:
    """Execute one full cycle and return the manifest describing it."""
    out_dir.mkdir(parents=True, exist_ok=True)
    project = f"sentinel-run-{uuid.uuid4().hex[:10]}"
    conf_dir = Path(tempfile.mkdtemp(prefix="sentinel-conf-"))
    (conf_dir / "left.conf").write_text(render_swanctl_conf(cfg, "left"))
    (conf_dir / "right.conf").write_text(render_swanctl_conf(cfg, "right"))

    env = {
        "SENTINEL_PSK": secrets.token_hex(24),
        "LEFT_CONF": str(conf_dir / "left.conf"),
        "RIGHT_CONF": str(conf_dir / "right.conf"),
    }

    try:
        _compose(project, "up", "-d", "--wait", env=env, timeout=420)
        left = _compose(project, "ps", "-q", "left", env=env).strip()
        left_host = _compose(project, "ps", "-q", "left_host", env=env).strip()
        if not left or not left_host:
            raise RunError("compose did not report container ids")

        # Capture MUST start before the tunnel is initiated. The IKE handshake is the
        # single most valuable thing on the wire — it is the entire input to the
        # deterministic parser lane — and it happens exactly once, during initiation.
        # Starting the capture afterwards yields a corpus of ESP with no negotiation to
        # parse: it looks fine until Phase 4 discovers there is nothing to read.
        capture = dual_capture_for_pair(left, LEFT_TRANSIT, LEFT_PROTECTED, out_dir)
        with capture:
            initiate = _exec(left, "swanctl", "--initiate", "--child", "net-net")
            if initiate.returncode != 0:
                raise RunError(f"tunnel did not establish:\n{initiate.stdout}\n{initiate.stderr}")
            ping = _exec(
                left_host,
                "ping",
                "-c",
                str(ping_count),
                "-W",
                "5",
                RIGHT_HOST,
                timeout=duration_s + 60,
            )
            if ping.returncode != 0:
                raise RunError(f"traffic did not cross the tunnel:\n{ping.stdout}")
            time.sleep(1)

        outer_packets = verify_pcap(capture.outer_pcap)
        inner_packets = verify_pcap(capture.inner_pcap)

        manifest = build_manifest(
            cfg,
            harvest_swanctl(left),
            harvest_xfrm_state(left),
            capture_meta={
                "label": label,
                "outer_pcap": capture.outer_pcap.name,
                "inner_pcap": capture.inner_pcap.name,
                "outer_packets": outer_packets,
                "inner_packets": inner_packets,
                "ping_count": ping_count,
                "project": project,
            },
        )
        (out_dir / "manifest.json").write_text(manifest.model_dump_json(indent=2))
        return manifest
    finally:
        # Unconditional: a leaked container or network poisons every later run.
        try:
            _compose(project, "down", "-v", "--remove-orphans", env=env, timeout=180)
        except RunError:
            subprocess.run(
                [
                    "docker",
                    "compose",
                    "-f",
                    str(PAIR_COMPOSE),
                    "-p",
                    project,
                    "down",
                    "-v",
                    "--remove-orphans",
                ],
                capture_output=True,
                check=False,
                timeout=180,
            )
        for leftover in conf_dir.glob("*"):
            leftover.unlink()
        conf_dir.rmdir()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run one full testbed cycle.")
    parser.add_argument(
        "--config-label",
        required=True,
        help="anchor configuration to run (worst, weak, medium, good, best)",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("data/raw/single_run"),
        help="where to write the captures and manifest",
    )
    parser.add_argument("--ping-count", type=int, default=6)
    args = parser.parse_args(argv)

    try:
        cfg = config_for_label(args.config_label)
        manifest = run_once(cfg, args.out_dir, label=args.config_label, ping_count=args.ping_count)
    except RunError as exc:
        print(f"run failed: {exc}", file=sys.stderr)
        return 1

    print(
        json.dumps(
            {
                "capture_id": manifest.capture_id,
                "config_id": manifest.config_id,
                "label": args.config_label,
                "negotiation_matched_intent": manifest.negotiation_matched_intent,
                "mismatches": manifest.mismatches,
                "negotiated": {
                    "ike_version": manifest.negotiated_ike.ike_version
                    if manifest.negotiated_ike
                    else None,
                    "encryption": manifest.negotiated_ike.encryption
                    if manifest.negotiated_ike
                    else None,
                    "keylen": manifest.negotiated_ike.encryption_keylen
                    if manifest.negotiated_ike
                    else None,
                    "dh_group": manifest.negotiated_ike.dh_group
                    if manifest.negotiated_ike
                    else None,
                    "mode": manifest.negotiated_child.mode if manifest.negotiated_child else None,
                },
                "capture": manifest.capture_meta,
            },
            indent=2,
        )
    )
    return 0 if manifest.negotiation_matched_intent else 2


if __name__ == "__main__":
    raise SystemExit(main())
