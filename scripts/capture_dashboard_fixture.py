"""Record every API response the dashboard makes for one capture.

The dashboard is a renderer over five endpoints. Recording their real responses lets the
**unmodified** dashboard code run as a static page — the backend is replaced by a
recording, and nothing else is.

This exists so the dashboard can be shown to somebody who does not have the codebase.
What they get is the real UI rendering real output from a real capture; what they lose is
the ability to analyse a *different* capture, because that needs the parser.

    python -m scripts.capture_dashboard_fixture --out demo/dashboard-fixture.json

Every demo capture is recorded by default, so the static page can offer the same
choice the real one does.
"""

from __future__ import annotations

import argparse
import json
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Final

import httpx

REPO_ROOT: Final = Path(__file__).resolve().parents[1]
DEFAULT_CAPTURE: Final = REPO_ROOT / "demo" / "pcaps" / "04-estate.pcap"
DEFAULT_OUTPUT: Final = REPO_ROOT / "demo" / "dashboard-fixture.json"
API: Final = "/api/v1"


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
        return port


@contextmanager
def running_api(port: int) -> Iterator[str]:
    process = subprocess.Popen(
        [
            str(REPO_ROOT / ".venv" / "bin" / "uvicorn"),
            "ipsec_sentinel.api.app:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        cwd=REPO_ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                    break
            except OSError:
                time.sleep(0.2)
        else:
            raise RuntimeError("the API did not start")
        yield f"http://127.0.0.1:{port}"
    finally:
        process.terminate()
        process.wait(timeout=15)


def record_one(client: httpx.Client, capture: Path) -> dict[str, Any]:
    """Every response the dashboard would receive for one capture."""
    payload = capture.read_bytes()
    analysed = client.post(
        f"{API}/analyse?baseline=default",
        files={"file": (capture.name, payload, "application/vnd.tcpdump.pcap")},
    ).json()
    report_id = analysed["report_id"]
    report = client.get(f"{API}/reports/{report_id}").json()

    tunnels: dict[str, Any] = {}
    for entry in report["inventory"]["entries"]:
        tunnel_id = entry["tunnel_id"]
        response = client.get(f"{API}/tunnels/{tunnel_id}?report_id={report_id}")
        if response.status_code == 200:
            tunnels[tunnel_id] = response.json()

    packages: dict[str, Any] = {}
    for tunnel_id in tunnels:
        response = client.post(
            f"{API}/remediate/{tunnel_id}?baseline=default",
            files={"file": (capture.name, payload, "application/vnd.tcpdump.pcap")},
        )
        packages[tunnel_id] = {"ok": response.status_code == 200, "body": response.json()}

    return {
        "capture": capture.name,
        "bytes": len(payload),
        "analysed": analysed,
        "report": report,
        "tunnels": tunnels,
        "packages": packages,
    }


def record(captures: list[Path]) -> dict[str, Any]:
    port = free_port()
    with running_api(port) as base, httpx.Client(base_url=base, timeout=900) as client:
        health = client.get("/health").json()
        recorded = {}
        for capture in captures:
            print(f"  recording {capture.name}")
            recorded[capture.name] = record_one(client, capture)
    return {"health": health, "captures": recorded}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--captures", type=Path, nargs="*", default=None)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUTPUT)
    arguments = parser.parse_args(argv)

    captures = arguments.captures or sorted(DEFAULT_CAPTURE.parent.glob("*.pcap"))
    missing = [str(path) for path in captures if not path.is_file()]
    if missing:
        print(f"no capture at: {missing}", file=sys.stderr)
        return 1

    fixture = record(list(captures))
    arguments.out.parent.mkdir(parents=True, exist_ok=True)
    arguments.out.write_text(json.dumps(fixture, separators=(",", ":")))

    tunnels = sum(len(entry["tunnels"]) for entry in fixture["captures"].values())
    print(
        f"wrote {arguments.out} ({arguments.out.stat().st_size // 1024} KB): "
        f"{len(fixture['captures'])} captures, {tunnels} tunnels"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
