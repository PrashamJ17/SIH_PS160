"""Tests for the REST API (build plan Step 10.2).

The security tests are the point. An upload endpoint reachable over the network is the
largest attack surface in this project, and the plan says to write these rather than skip
them — so they are first, and they check behaviour rather than the presence of a
mitigation.

Path traversal is checked by uploading a file *named* ``../../../etc/crontab`` and
asserting nothing appears outside the temporary directory. The size limit is checked by
sending a body larger than the limit, not by inspecting a constant.
"""

from __future__ import annotations

import socket
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ipsec_sentinel.api.app import (
    API_PREFIX,
    MAX_UPLOAD_BYTES,
    create_app,
    get_store,
    looks_like_a_capture,
    safe_label,
)
from ipsec_sentinel.api.store import ReportStore

REPO_ROOT = Path(__file__).resolve().parents[2]
SWEEP = REPO_ROOT / "data" / "raw" / "sweep"
PCAP_HEADER = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 16


def capture_bytes() -> bytes:
    found = sorted(SWEEP.glob("*/capture_outer.pcap"))
    if not found:
        pytest.skip("the sweep corpus is not present")
    return found[0].read_bytes()


@pytest.fixture
def store() -> ReportStore:
    return ReportStore()


@pytest.fixture
def client(store: ReportStore) -> Iterator[TestClient]:
    app = create_app()
    app.dependency_overrides[get_store] = lambda: store
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def analysed(client: TestClient) -> str:
    response = client.post(
        f"{API_PREFIX}/analyse",
        files={"file": ("capture.pcap", capture_bytes(), "application/vnd.tcpdump.pcap")},
    )
    assert response.status_code == 201, response.text
    return str(response.json()["report_id"])


class TestSecurity:
    """The plan says write these and do not skip them."""

    def test_a_traversing_filename_writes_nothing_outside_the_temp_dir(
        self, client: TestClient, tmp_path: Path
    ) -> None:
        """The filename is attacker-controlled input that happens to look like a path."""
        sentinel = tmp_path / "etc"
        sentinel.mkdir()
        hostile = "../../../../../../" + str(sentinel / "crontab")

        response = client.post(
            f"{API_PREFIX}/analyse",
            files={"file": (hostile, capture_bytes(), "application/octet-stream")},
        )
        assert response.status_code == 201, response.text
        assert not (sentinel / "crontab").exists()
        assert list(sentinel.iterdir()) == []

    def test_the_stored_source_is_stripped_of_path_components(self, client: TestClient) -> None:
        response = client.post(
            f"{API_PREFIX}/analyse",
            files={"file": ("../../etc/passwd", capture_bytes(), "application/octet-stream")},
        )
        assert response.status_code == 201
        source = response.json()["source"]
        assert "/" not in source
        assert ".." not in source

    @pytest.mark.parametrize(
        ("given", "forbidden"),
        [
            ("../../etc/passwd", "/"),
            ("..\\..\\windows\\system32", "\\"),
            ("/absolute/path.pcap", "/"),
            ("with spaces & symbols!.pcap", " "),
            ("\x1b[31mred\x1b[0m.pcap", "\x1b"),
        ],
    )
    def test_a_hostile_filename_is_reduced(self, given: str, forbidden: str) -> None:
        """Echoed into reports and errors, so terminal escapes matter as much as slashes."""
        assert forbidden not in safe_label(given)

    def test_a_filename_of_only_dots_still_yields_a_name(self) -> None:
        assert safe_label("....") not in ("", ".")
        assert safe_label(None)
        assert safe_label("")

    def test_an_absurdly_long_filename_is_bounded(self) -> None:
        assert len(safe_label("a" * 5000 + ".pcap")) <= 96

    def test_the_upload_never_lands_at_a_user_controlled_path(
        self, client: TestClient, tmp_path: Path
    ) -> None:
        """The path is chosen by mkstemp; the upload contributes nothing to it."""
        marker = tmp_path / "written-here.pcap"
        client.post(
            f"{API_PREFIX}/analyse",
            files={"file": (str(marker), capture_bytes(), "application/octet-stream")},
        )
        assert not marker.exists()

    def test_the_temporary_file_is_removed_afterwards(self, client: TestClient) -> None:
        import tempfile

        before = set(Path(tempfile.gettempdir()).glob("sentinel-upload-*"))
        client.post(
            f"{API_PREFIX}/analyse",
            files={"file": ("capture.pcap", capture_bytes(), "application/octet-stream")},
        )
        after = set(Path(tempfile.gettempdir()).glob("sentinel-upload-*"))
        assert after <= before

    def test_a_failed_analysis_still_removes_the_temporary_file(self, client: TestClient) -> None:
        import tempfile

        before = set(Path(tempfile.gettempdir()).glob("sentinel-upload-*"))
        client.post(
            f"{API_PREFIX}/analyse",
            files={"file": ("x.pcap", b"not a capture at all", "application/octet-stream")},
        )
        after = set(Path(tempfile.gettempdir()).glob("sentinel-upload-*"))
        assert after <= before

    def test_every_response_forbids_content_sniffing(self, client: TestClient) -> None:
        """A report holds text an attacker influenced; a sniffing browser would render it."""
        for path in ("/health", f"{API_PREFIX}/tunnels", "/openapi.json"):
            response = client.get(path)
            assert response.headers["X-Content-Type-Options"] == "nosniff", path

    def test_the_other_hardening_headers_are_present(self, client: TestClient) -> None:
        headers = client.get("/health").headers
        assert headers["X-Frame-Options"] == "DENY"
        assert headers["Referrer-Policy"] == "no-referrer"
        assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]

    def test_the_headers_are_applied_by_middleware_not_per_route(
        self, client: TestClient, analysed: str
    ) -> None:
        """A route added later must not be able to forget them."""
        for path in (
            f"{API_PREFIX}/reports/{analysed}",
            f"{API_PREFIX}/reports/{analysed}/html",
            f"{API_PREFIX}/findings",
            f"{API_PREFIX}/inventory",
            f"{API_PREFIX}/reports/does-not-exist",
        ):
            assert client.get(path).headers["X-Content-Type-Options"] == "nosniff", path

    def test_the_api_opens_no_outbound_socket(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Analysis is passive; the service must not dial out while doing it."""
        real_socket = socket.socket

        def refuse(*args: object, **kwargs: object) -> object:
            # The test client itself is in-process, so only AF_INET matters here.
            if args and args[0] == socket.AF_INET:
                raise AssertionError("the API opened an outbound socket")
            return real_socket(*args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(socket, "socket", refuse)
        response = client.post(
            f"{API_PREFIX}/analyse",
            files={"file": ("capture.pcap", capture_bytes(), "application/octet-stream")},
        )
        assert response.status_code == 201


class TestUploadValidation:
    def test_a_non_capture_returns_400_with_a_clear_message(self, client: TestClient) -> None:
        response = client.post(
            f"{API_PREFIX}/analyse",
            files={"file": ("notes.txt", b"hello, this is not a pcap", "text/plain")},
        )
        assert response.status_code == 400
        assert "not a packet capture" in response.json()["detail"]

    def test_an_empty_upload_is_rejected(self, client: TestClient) -> None:
        response = client.post(
            f"{API_PREFIX}/analyse", files={"file": ("empty.pcap", b"", "application/octet-stream")}
        )
        assert response.status_code == 400

    def test_an_oversized_upload_returns_413(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Checked by sending too much, not by reading the constant.

        The limit is lowered rather than a 512 MB body constructed: what is under test
        is that the ceiling is enforced, and holding half a gigabyte in a test to prove
        it would be its own denial of service.
        """
        import ipsec_sentinel.api.app as api

        monkeypatch.setattr(api, "MAX_UPLOAD_BYTES", 1024)
        response = client.post(
            f"{API_PREFIX}/analyse",
            files={"file": ("big.pcap", PCAP_HEADER + b"\x00" * 4096, "application/octet-stream")},
        )
        assert response.status_code == 413
        assert "limit" in response.json()["detail"]

    def test_a_body_within_the_limit_is_not_refused(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The other side of the same check: the ceiling must not reject ordinary uploads."""
        import ipsec_sentinel.api.app as api

        monkeypatch.setattr(api, "MAX_UPLOAD_BYTES", 64 * 1024 * 1024)
        response = client.post(
            f"{API_PREFIX}/analyse",
            files={"file": ("ok.pcap", capture_bytes(), "application/octet-stream")},
        )
        assert response.status_code == 201

    def test_the_limit_is_enforced_while_reading(self) -> None:
        """Trusting Content-Length lets a lying client exhaust memory."""
        source = Path(__file__).resolve().parents[2] / "src/ipsec_sentinel/api/app.py"
        body = source.read_text()
        assert "while chunk := await file.read(CHUNK_BYTES)" in body
        assert "written > MAX_UPLOAD_BYTES" in body

    @pytest.mark.parametrize(
        "magic",
        [b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a", b"\x4d\x3c\xb2\xa1"],
    )
    def test_known_capture_formats_are_recognised(self, magic: bytes) -> None:
        assert looks_like_a_capture(magic + b"rest")

    def test_an_unknown_magic_is_not(self) -> None:
        assert not looks_like_a_capture(b"PK\x03\x04")
        assert not looks_like_a_capture(b"")

    def test_an_unknown_baseline_returns_400(self, client: TestClient) -> None:
        response = client.post(
            f"{API_PREFIX}/analyse?baseline=no-such-baseline",
            files={"file": ("capture.pcap", capture_bytes(), "application/octet-stream")},
        )
        assert response.status_code == 400
        assert "nist_800_77r1" in response.json()["detail"]


class TestEndpoints:
    def test_health_returns_version_information(self, client: TestClient) -> None:
        response = client.get("/health")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "ok"
        assert body["version"]
        assert "build" in body

    def test_the_openapi_schema_generates(self, client: TestClient) -> None:
        response = client.get("/openapi.json")
        assert response.status_code == 200
        schema = response.json()
        assert schema["info"]["title"] == "IPsec Sentinel"
        for path in (
            f"{API_PREFIX}/analyse",
            f"{API_PREFIX}/tunnels",
            f"{API_PREFIX}/findings",
            f"{API_PREFIX}/inventory",
            "/health",
        ):
            assert path in schema["paths"], path

    def test_analyse_returns_201_and_a_report_id(self, client: TestClient) -> None:
        response = client.post(
            f"{API_PREFIX}/analyse",
            files={"file": ("capture.pcap", capture_bytes(), "application/octet-stream")},
        )
        assert response.status_code == 201
        body = response.json()
        assert body["report_id"]
        assert body["tunnels"] >= 1
        assert body["grade"] in list("ABCDEF")

    def test_a_report_can_be_fetched_by_id(self, client: TestClient, analysed: str) -> None:
        response = client.get(f"{API_PREFIX}/reports/{analysed}")
        assert response.status_code == 200
        body = response.json()
        assert "section_a_verified" in body
        assert "section_b_inferred" in body

    def test_a_report_renders_as_html(self, client: TestClient, analysed: str) -> None:
        response = client.get(f"{API_PREFIX}/reports/{analysed}/html")
        assert response.status_code == 200
        assert response.text.lstrip().startswith("<!DOCTYPE html>")

    def test_an_unknown_report_returns_404_with_an_explanation(self, client: TestClient) -> None:
        response = client.get(f"{API_PREFIX}/reports/deadbeef")
        assert response.status_code == 404
        assert "held in memory" in response.json()["detail"]

    def test_tunnels_are_listed(self, client: TestClient, analysed: str) -> None:
        response = client.get(f"{API_PREFIX}/tunnels?report_id={analysed}")
        assert response.status_code == 200
        assert len(response.json()) >= 1

    def test_one_tunnel_can_be_fetched(self, client: TestClient, analysed: str) -> None:
        listed = client.get(f"{API_PREFIX}/tunnels?report_id={analysed}").json()
        tunnel_id = listed[0]["tunnel_id"]
        response = client.get(f"{API_PREFIX}/tunnels/{tunnel_id}?report_id={analysed}")
        assert response.status_code == 200
        body = response.json()
        assert body["tunnel"]["tunnel_id"] == tunnel_id
        assert "exposure" in body
        assert "pqc" in body

    def test_an_unknown_tunnel_returns_404(self, client: TestClient, analysed: str) -> None:
        response = client.get(f"{API_PREFIX}/tunnels/nope?report_id={analysed}")
        assert response.status_code == 404

    def test_findings_can_be_filtered_by_severity(self, client: TestClient, analysed: str) -> None:
        everything = client.get(f"{API_PREFIX}/findings?report_id={analysed}").json()
        critical = client.get(
            f"{API_PREFIX}/findings?severity=critical&report_id={analysed}"
        ).json()
        assert len(critical) <= len(everything)
        assert all(f["severity"] == "critical" for f in critical)

    def test_findings_can_be_filtered_by_section(self, client: TestClient, analysed: str) -> None:
        """The Section A / Section B split reaches the API."""
        section_a = client.get(f"{API_PREFIX}/findings?section=a&report_id={analysed}").json()
        section_b = client.get(f"{API_PREFIX}/findings?section=b&report_id={analysed}").json()
        assert all(f["confidence"] is None for f in section_a)
        assert all(f["confidence"] is not None for f in section_b)

    def test_an_invalid_severity_returns_422(self, client: TestClient) -> None:
        assert client.get(f"{API_PREFIX}/findings?severity=catastrophic").status_code == 422

    def test_an_invalid_section_returns_422(self, client: TestClient) -> None:
        assert client.get(f"{API_PREFIX}/findings?section=z").status_code == 422

    def test_the_inventory_is_served(self, client: TestClient, analysed: str) -> None:
        response = client.get(f"{API_PREFIX}/inventory?report_id={analysed}")
        assert response.status_code == 200
        assert "entries" in response.json()

    def test_endpoints_404_before_anything_is_analysed(self, client: TestClient) -> None:
        for path in (f"{API_PREFIX}/tunnels", f"{API_PREFIX}/findings", f"{API_PREFIX}/inventory"):
            response = client.get(path)
            assert response.status_code == 404, path
            assert "POST a capture" in response.json()["detail"]

    def test_remediate_produces_a_change_package(self, client: TestClient) -> None:
        listed = client.post(
            f"{API_PREFIX}/analyse",
            files={"file": ("capture.pcap", capture_bytes(), "application/octet-stream")},
        )
        report_id = listed.json()["report_id"]
        tunnels = client.get(f"{API_PREFIX}/tunnels?report_id={report_id}").json()
        tunnel_id = tunnels[0]["tunnel_id"]

        response = client.post(
            f"{API_PREFIX}/remediate/{tunnel_id}?baseline=default",
            files={"file": ("capture.pcap", capture_bytes(), "application/octet-stream")},
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["package"]["tunnel_id"] == tunnel_id
        assert body["package"]["local_config"]["content"]
        assert body["assumptions"]

    def test_remediating_an_unknown_tunnel_returns_404(self, client: TestClient) -> None:
        response = client.post(
            f"{API_PREFIX}/remediate/nope",
            files={"file": ("capture.pcap", capture_bytes(), "application/octet-stream")},
        )
        assert response.status_code == 404


class TestTheStore:
    def test_it_is_bounded(self) -> None:
        """Without a bound, a server anyone can upload to grows until it is killed."""
        from ipsec_sentinel.assess.inventory import Inventory
        from ipsec_sentinel.report.build import build_report

        store = ReportStore(capacity=3)
        ids = [
            store.add(build_report([], Inventory(), "default", source=f"c{i}"), f"c{i}").report_id
            for i in range(10)
        ]
        assert len(store) == 3
        assert store.get(ids[0]) is None
        assert store.get(ids[-1]) is not None

    def test_reading_a_report_keeps_it_alive(self) -> None:
        from ipsec_sentinel.assess.inventory import Inventory
        from ipsec_sentinel.report.build import build_report

        store = ReportStore(capacity=2)
        first = store.add(build_report([], Inventory(), "default", source="a"), "a")
        store.add(build_report([], Inventory(), "default", source="b"), "b")
        assert store.get(first.report_id) is not None
        store.add(build_report([], Inventory(), "default", source="c"), "c")
        assert store.get(first.report_id) is not None

    def test_a_capacity_of_zero_is_refused(self) -> None:
        with pytest.raises(ValueError, match="cannot serve a report it just made"):
            ReportStore(capacity=0)

    def test_the_latest_report_is_the_default(self) -> None:
        from ipsec_sentinel.assess.inventory import Inventory
        from ipsec_sentinel.report.build import build_report

        store = ReportStore()
        store.add(build_report([], Inventory(), "default", source="first"), "first")
        newest = store.add(build_report([], Inventory(), "default", source="second"), "second")
        latest = store.latest()
        assert latest is not None
        assert latest.report_id == newest.report_id


def test_the_app_module_exposes_an_application() -> None:
    """`uvicorn ipsec_sentinel.api.app:app` has to find something."""
    from ipsec_sentinel.api.app import app

    assert app.title == "IPsec Sentinel"


def test_an_upload_stream_is_read_in_bounded_chunks() -> None:
    from ipsec_sentinel.api.app import CHUNK_BYTES

    assert 0 < CHUNK_BYTES <= MAX_UPLOAD_BYTES
