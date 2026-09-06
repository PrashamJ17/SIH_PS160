"""Dashboard tests with a real browser (build plan Step 10.3).

The plan's six criteria, driven through Chromium against a live server. A dashboard is
the one part of this project whose failures are invisible to every other kind of test: a
Content Security Policy that blocks the page's own script, a CSS rule that out-specifies
the ``hidden`` attribute, a JSON field renamed on the server — none of those fail a unit
test, and all of them produce a page that loads and does nothing.

Both of the first two actually happened here, and were found by loading the page.

The offline check is the one worth reading. It does not grep the markup for ``http://``;
it aborts every request whose URL is not this server's own origin, and then asserts the
dashboard still works. That is the question the criterion asks.
"""

from __future__ import annotations

import socket
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

pytest.importorskip("playwright", reason="playwright is not installed")

from playwright.sync_api import Browser, Page, Route, expect, sync_playwright

REPO_ROOT = Path(__file__).resolve().parents[2]
SWEEP = REPO_ROOT / "data" / "raw" / "sweep"
STARTUP_TIMEOUT_S = 45

pytestmark = [pytest.mark.integration, pytest.mark.slow]


def a_capture() -> Path:
    found = sorted(SWEEP.glob("*/capture_outer.pcap"))
    if not found:
        pytest.skip("the sweep corpus is not present")
    return found[0]


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@pytest.fixture(scope="module")
def server() -> Iterator[str]:
    """A real uvicorn, because the CSP and static-file behaviour are the point.

    Starlette's TestClient would exercise the handlers and none of the things that
    actually broke.
    """
    port = free_port()
    process = subprocess.Popen(
        [
            str(REPO_ROOT / ".venv" / "bin" / "uvicorn"),
            "ipsec_sentinel.api.app:app",
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    base = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + STARTUP_TIMEOUT_S
    import urllib.error
    import urllib.request

    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"{base}/health", timeout=2):
                break
        except (urllib.error.URLError, OSError, TimeoutError):
            time.sleep(0.3)
    else:
        process.kill()
        pytest.fail("the API did not start")
    try:
        yield base
    finally:
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()


@pytest.fixture(scope="module")
def browser() -> Iterator[Browser]:
    with sync_playwright() as playwright:
        launched = playwright.chromium.launch()
        try:
            yield launched
        finally:
            launched.close()


# A non-2xx response the page asked for and handles is not a page fault: the
# "not a capture" test provokes a 400 on purpose and then renders the message. Chromium
# logs those to the console anyway, so they are filtered out by shape. CSP violations,
# TypeErrors and anything else stay fatal.
HANDLED_RESPONSE = "Failed to load resource: the server responded with a status of"


@pytest.fixture
def page(browser: Browser) -> Iterator[Page]:
    context = browser.new_context()
    opened = context.new_page()
    problems: list[str] = []

    def record(text: str) -> None:
        if HANDLED_RESPONSE not in text:
            problems.append(text)

    opened.on("console", lambda m: record(m.text) if m.type == "error" else None)
    opened.on("pageerror", lambda error: record(str(error)))
    try:
        yield opened
        # A page that renders while logging a CSP violation or a TypeError is a page
        # that is one field rename away from rendering nothing.
        assert not problems, f"the page logged errors: {problems}"
    finally:
        context.close()


def upload(page: Page, base: str) -> None:
    page.goto(base, wait_until="networkidle")
    page.set_input_files("#file", str(a_capture()))
    page.wait_for_selector("#tabs:not([hidden])", timeout=60_000)


class TestThePlansCriteria:
    def test_the_dashboard_loads(self, page: Page, server: str) -> None:
        page.goto(server, wait_until="networkidle")
        assert page.title() == "IPsec Sentinel"
        # The build string only appears once the script has run and reached /health.
        assert "ipsec-sentinel" in page.text_content("#build")

    def test_uploading_a_capture_produces_results(self, page: Page, server: str) -> None:
        upload(page, server)
        assert page.is_visible("#overview")
        assert page.text_content("#overview")
        assert "tunnels" in page.text_content("#overview").lower()

    def test_the_findings_table_populates(self, page: Page, server: str) -> None:
        upload(page, server)
        page.click("nav button[data-view='findings']")
        text = page.text_content("#findings")
        assert "Section A" in text
        assert "Section B" in text

    def test_clicking_a_tunnel_opens_the_detail_view(self, page: Page, server: str) -> None:
        upload(page, server)
        page.click("nav button[data-view='inventory']")
        page.click("#inventory tr[data-tunnel]")
        page.wait_for_selector("#detail:not([hidden])")
        assert page.is_visible("#detail")
        assert "Endpoints" in page.text_content("#detail")

    def test_the_shap_explanation_renders(self, page: Page, server: str) -> None:
        """Only if a model is installed; otherwise the absence must be stated, not blank."""
        upload(page, server)
        page.click("nav button[data-view='inventory']")
        page.click("#inventory tr[data-tunnel]")
        page.wait_for_selector("#detail:not([hidden])")

        if page.query_selector("#shap-sentence"):
            sentence = page.text_content("#shap-sentence")
            assert "Classified as" in sentence
            assert page.query_selector("#shap-table")
            rows = page.query_selector_all("#shap-table tbody tr")
            assert rows, "the explanation table has no contributions"
        else:
            assert page.query_selector("#shap-absent"), (
                "no explanation and no statement that there is none"
            )

    def test_it_works_with_the_browser_offline_after_loading(
        self, browser: Browser, server: str
    ) -> None:
        """Every request outside this origin is aborted, then the dashboard must still work.

        Checked by blocking the network rather than by grepping the markup, because the
        criterion asks whether it works offline and not whether it looks as though it
        would.
        """
        context = browser.new_context()
        page = context.new_page()
        blocked: list[str] = []

        def only_this_origin(route: Route) -> None:
            if route.request.url.startswith(server):
                route.continue_()
            else:
                blocked.append(route.request.url)
                route.abort()

        page.route("**/*", only_this_origin)
        try:
            page.goto(server, wait_until="networkidle")
            page.set_input_files("#file", str(a_capture()))
            page.wait_for_selector("#tabs:not([hidden])", timeout=60_000)
            assert page.is_visible("#overview")
            page.click("nav button[data-view='exposure']")
            assert page.text_content("#exposure")
        finally:
            context.close()
        assert not blocked, f"the dashboard tried to reach {blocked}"


class TestTheThingsThatOnlyABrowserFinds:
    def test_no_content_security_policy_violation(self, page: Page, server: str) -> None:
        """This failed on the first run: the CSP blocked the dashboard's own script.

        The assets were split out of the single HTML file so the policy could forbid
        inline execution entirely rather than permit it.
        """
        page.goto(server, wait_until="networkidle")
        # The `page` fixture asserts no console errors on teardown, which is where a CSP
        # violation surfaces. This makes the intent explicit rather than incidental.
        # A CSP violation surfaces as a console error, which the `page` fixture
        # asserts against on teardown. This makes the intent explicit.
        expect(page.locator("#build")).not_to_have_text("checking service…")
        assert "ipsec-sentinel" in page.text_content("#build")

    def test_the_tabs_are_hidden_before_anything_is_analysed(self, page: Page, server: str) -> None:
        """`nav{display:flex}` out-specified the browser's own [hidden]{display:none}."""
        page.goto(server, wait_until="networkidle")
        assert not page.is_visible("#tabs")
        assert not page.is_visible("#overview")

    def test_a_non_capture_upload_shows_a_message_rather_than_hanging(
        self, page: Page, server: str, tmp_path: Path
    ) -> None:
        rubbish = tmp_path / "notes.txt"
        rubbish.write_text("this is not a capture")
        page.goto(server, wait_until="networkidle")
        page.set_input_files("#file", str(rubbish))
        # Waited for with a locator rather than wait_for_function: that evaluates a
        # string as JavaScript, which the dashboard's own CSP forbids — correctly.
        expect(page.locator("#status")).to_contain_text("not a packet capture", timeout=30_000)
        assert not page.is_visible("#tabs")

    def test_every_view_renders_without_error(self, page: Page, server: str) -> None:
        """A field renamed on the server breaks one view and no unit test."""
        upload(page, server)
        for view in (
            "overview",
            "inventory",
            "findings",
            "exposure",
            "threats",
            "pqc",
            "remediation",
        ):
            page.click(f"nav button[data-view='{view}']")
            page.wait_for_selector(f"#{view}:not([hidden])")
            assert page.text_content(f"#{view}").strip(), f"{view} rendered nothing"

    def test_the_sections_are_labelled_not_only_coloured(self, page: Page, server: str) -> None:
        """A greyscale print, or a reader who cannot tell the two colours apart."""
        upload(page, server)
        page.click("nav button[data-view='overview']")
        text = page.text_content("#overview")
        assert "Section A — verified" in text
        assert "Section B — inferred" in text


class TestRemediationInTheBrowser:
    def test_a_change_package_can_be_generated_and_copied(self, page: Page, server: str) -> None:
        upload(page, server)
        page.click("nav button[data-view='remediation']")
        page.click("#remediate-go")
        expect(page.locator("#remediate-output")).not_to_be_empty(timeout=60_000)
        output = page.text_content("#remediate-output")
        # Either a package, or a plain statement that there is nothing to correct.
        assert "Sequence" in output or "nothing" in output.lower(), output

    def test_a_generated_package_shows_both_ends(self, page: Page, server: str) -> None:
        upload(page, server)
        page.click("nav button[data-view='remediation']")
        page.click("#remediate-go")
        expect(page.locator("#remediate-output")).not_to_be_empty(timeout=60_000)
        if page.query_selector("#config-local"):
            assert page.query_selector("#config-peer"), "one end only is not a both-ends change"
            assert page.text_content("#config-local") != page.text_content("#config-peer")
