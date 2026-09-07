"""Capture a screenshot of the dashboard with a real capture loaded.

The README and the deck both need a picture of the product working. A mock-up would be
faster and would also be a claim the repository cannot back, so this drives the real
dashboard against the real API with a real demo capture — the same thing
``tests/integration/test_dashboard.py`` does, minus the assertions.

Run it with::

    python -m scripts.capture_dashboard
"""

from __future__ import annotations

import argparse
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from playwright.sync_api import ViewportSize

REPO_ROOT: Final = Path(__file__).resolve().parents[1]
DEFAULT_CAPTURE: Final = REPO_ROOT / "demo" / "pcaps" / "01-worst-ikev1-aggressive-3des-voip.pcap"
DEFAULT_OUTPUT: Final = REPO_ROOT / "docs" / "images" / "dashboard.png"
VIEWPORT: Final[ViewportSize] = {"width": 1440, "height": 1100}


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
        return port


@contextmanager
def running_api(port: int) -> Iterator[str]:
    """A real uvicorn: the CSP and the static-file serving are part of the picture."""
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
    base = f"http://127.0.0.1:{port}"
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
        yield base
    finally:
        process.terminate()
        process.wait(timeout=15)


def capture(capture_path: Path, output: Path) -> Path:
    from playwright.sync_api import sync_playwright

    output.parent.mkdir(parents=True, exist_ok=True)
    port = free_port()

    with running_api(port) as base, sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page(viewport=VIEWPORT, device_scale_factor=2)
        try:
            page.goto(base, wait_until="networkidle")
            # Selecting the file starts the analysis; there is no submit button.
            page.set_input_files("#file", str(capture_path))
            # The tab strip is hidden until a report comes back.
            page.wait_for_selector("#tabs:not([hidden])", timeout=180_000)
            page.wait_for_selector("#overview:not([hidden])", timeout=30_000)
            page.wait_for_timeout(700)
            page.screenshot(path=str(output), full_page=True)
        finally:
            browser.close()
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, default=DEFAULT_CAPTURE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    arguments = parser.parse_args(argv)

    if not arguments.capture.is_file():
        print(f"no capture at {arguments.capture}", file=sys.stderr)
        return 1

    written = capture(arguments.capture, arguments.output)
    print(f"wrote {written} ({written.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
