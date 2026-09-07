"""Capture the dashboard's real screens for the demo video.

Playwright drives the actual dashboard against a real uvicorn and a real capture — the
same path `tests/integration/test_dashboard.py` takes. Every screen in the video is the
product running, not a mock-up.

    python -m scripts.video.shots
"""

from __future__ import annotations

import socket
import subprocess
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Final

REPO: Final = Path(__file__).resolve().parents[2]
OUT: Final = REPO / "demo" / "video" / "shots"
CAPTURE: Final = REPO / "demo" / "pcaps" / "04-estate.pcap"
VIEWPORT: Final[dict[str, int]] = {"width": 1680, "height": 1050}


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
        return port


@contextmanager
def running_api(port: int) -> Iterator[str]:
    process = subprocess.Popen(
        [
            str(REPO / ".venv" / "bin" / "uvicorn"),
            "ipsec_sentinel.api.app:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        cwd=REPO,
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


def main() -> int:
    from playwright.sync_api import sync_playwright

    OUT.mkdir(parents=True, exist_ok=True)
    port = free_port()
    written: list[str] = []

    with running_api(port) as base, sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page(
            viewport={"width": VIEWPORT["width"], "height": VIEWPORT["height"]},
            device_scale_factor=2,
        )
        try:
            page.goto(base, wait_until="networkidle")
            page.screenshot(path=str(OUT / "01_empty.png"))
            written.append("01_empty")

            page.set_input_files("#file", str(CAPTURE))
            page.wait_for_selector("#tabs:not([hidden])", timeout=180_000)
            page.wait_for_timeout(700)
            page.screenshot(path=str(OUT / "02_overview.png"))
            written.append("02_overview")

            for view, name in (
                ("inventory", "03_inventory"),
                ("findings", "04_findings"),
                ("exposure", "05_exposure"),
                ("threats", "06_threats"),
                ("pqc", "07_pqc"),
                ("remediation", "08_remediation"),
            ):
                page.click(f"#tabs button[data-view={view}]")
                page.wait_for_timeout(450)
                page.screenshot(path=str(OUT / f"{name}.png"))
                written.append(name)

            # The tunnel detail, where the SHAP explanation lives.
            page.click("#tabs button[data-view=inventory]")
            page.wait_for_timeout(300)
            row = page.query_selector("tr[data-tunnel]")
            if row is not None:
                row.click()
                page.wait_for_selector("#detail:not([hidden])", timeout=30_000)
                page.wait_for_timeout(600)
                page.screenshot(path=str(OUT / "09_detail.png"), full_page=True)
                written.append("09_detail")
        finally:
            browser.close()

    print(f"wrote {len(written)} shots to {OUT.relative_to(REPO)}")
    for name in written:
        size = (OUT / f"{name}.png").stat().st_size // 1024
        print(f"  {name}.png  {size} KB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
