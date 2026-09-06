"""The REST API.

An upload endpoint that accepts a file from the network is the largest attack surface in
this project, and everything unusual here follows from that.

**The uploaded filename is never used as a path.** It is recorded as a label, after being
stripped to something harmless, and the bytes go to a temporary file whose name this
service chooses. A filename is attacker-controlled input that happens to look like a
path, which is why ``../../etc/crontab`` is the oldest trick there is.

**The size limit is enforced while reading, not after.** Trusting ``Content-Length``
means a client that lies about it can still exhaust memory, so the body is read in
chunks and the request is refused the moment the limit is passed.

**Every response says not to sniff its type.** A report contains text an attacker
influenced — vendor IDs, peer identities — and a browser that decides for itself that a
JSON response is HTML will render that text. The header is applied by middleware so a
route added later cannot forget it.

The service is read-only with respect to the world: it analyses what it is given and
returns documents. Nothing here transmits to a network device or opens an outbound
connection, and a test asserts it.
"""

from __future__ import annotations

import re
import tempfile
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any, Final

from fastapi import Depends, FastAPI, File, HTTPException, Query, Request, UploadFile, status
from fastapi.responses import HTMLResponse, JSONResponse, Response

from ipsec_sentinel.analyse import analyse_capture, assess_tunnel, read_tunnels
from ipsec_sentinel.api.store import ReportStore, StoredReport
from ipsec_sentinel.assess.framework import DEFAULT_BASELINE, UnknownBaselineError
from ipsec_sentinel.models import Severity
from ipsec_sentinel.remediate.generators.strongswan import GenerationError, generate_change_package
from ipsec_sentinel.remediate.observed import config_from_exchange
from ipsec_sentinel.report.render_html import render_html
from ipsec_sentinel.version import describe, git_sha, tool_version

API_PREFIX: Final = "/api/v1"
MAX_UPLOAD_BYTES: Final = 512 * 1024 * 1024
CHUNK_BYTES: Final = 1024 * 1024
PCAP_MAGIC: Final[tuple[bytes, ...]] = (
    b"\xd4\xc3\xb2\xa1",  # libpcap, little-endian
    b"\xa1\xb2\xc3\xd4",  # libpcap, big-endian
    b"\x4d\x3c\xb2\xa1",  # libpcap, nanosecond, little-endian
    b"\xa1\xb2\x3c\x4d",  # libpcap, nanosecond, big-endian
    b"\x0a\x0d\x0d\x0a",  # pcapng section header block
)

_SAFE_LABEL = re.compile(r"[^A-Za-z0-9._-]")
MAX_LABEL_LENGTH: Final = 96

store = ReportStore()


def safe_label(filename: str | None) -> str:
    """Reduce an uploaded filename to something safe to print and store.

    Never used to build a path. Reduced anyway, because it is echoed back in the report
    metadata and in error messages, and an unfiltered filename is a route to both
    terminal escape sequences and HTML injection in whatever renders it next.
    """
    if not filename:
        return "upload.pcap"
    stripped = Path(filename).name  # discards any directory component, "../" included
    cleaned = _SAFE_LABEL.sub("_", stripped).lstrip(".")
    return (cleaned or "upload.pcap")[:MAX_LABEL_LENGTH]


def looks_like_a_capture(head: bytes) -> bool:
    return any(head.startswith(magic) for magic in PCAP_MAGIC)


def get_store() -> ReportStore:
    """Dependency seam, so tests get an isolated store rather than the module's."""
    return store


def create_app() -> FastAPI:
    app = FastAPI(
        title="IPsec Sentinel",
        version=tool_version(),
        description=(
            "Passive IPsec analysis. Upload a capture, receive an assessment. This "
            "service never writes to a network device and stores no credential."
        ),
    )

    @app.middleware("http")
    async def security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """Applied to every route, including ones added after this was written."""
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        # The report renderer emits inline styles and nothing else; this says so.
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; style-src 'unsafe-inline'; img-src data:; frame-ancestors 'none'"
        )
        return response

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "version": tool_version(),
            "revision": git_sha(),
            "build": describe(),
        }

    @app.post(f"{API_PREFIX}/analyse", status_code=status.HTTP_201_CREATED)
    async def analyse(
        file: UploadFile = File(...),  # noqa: B008 - FastAPI's dependency declaration
        baseline: str = Query(default=DEFAULT_BASELINE),
        reports: ReportStore = Depends(get_store),  # noqa: B008 - same
    ) -> dict[str, Any]:
        """Analyse an uploaded capture and return the report."""
        label = safe_label(file.filename)
        # mkstemp, so the path is chosen here and never derived from the upload.
        handle, temporary = tempfile.mkstemp(prefix="sentinel-upload-", suffix=".pcap")
        path = Path(temporary)
        written = 0
        try:
            with Path(temporary).open("wb") as sink:
                while chunk := await file.read(CHUNK_BYTES):
                    written += len(chunk)
                    if written > MAX_UPLOAD_BYTES:
                        raise HTTPException(
                            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                            detail=(
                                f"the capture exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB "
                                f"limit. Split it, or analyse it with the command line, which "
                                f"has no limit."
                            ),
                        )
                    sink.write(chunk)
            import os

            os.close(handle)

            if not looks_like_a_capture(path.read_bytes()[:4]):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=(
                        f"{label} is not a packet capture. Expected a libpcap or pcapng "
                        f"file; the first bytes match neither."
                    ),
                )
            try:
                report = analyse_capture(path, baseline=baseline, source=label)
            except UnknownBaselineError as exc:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
                ) from exc
            except ValueError as exc:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"{label} could not be analysed: {exc}",
                ) from exc
        finally:
            path.unlink(missing_ok=True)

        stored = reports.add(report, label)
        return {
            "report_id": stored.report_id,
            "source": stored.source,
            "tunnels": report.executive.tunnels_assessed,
            "grade": report.executive.estate_grade,
            "score": report.executive.estate_score,
            "headline": report.executive.headline,
        }

    def _stored(report_id: str, reports: ReportStore) -> StoredReport:
        found = reports.get(report_id)
        if found is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=(
                    f"no report {report_id}. Reports are held in memory and the most "
                    f"recent {reports.capacity} are kept; analyse the capture again."
                ),
            )
        return found

    def _current(report_id: str | None, reports: ReportStore) -> StoredReport:
        if report_id:
            return _stored(report_id, reports)
        latest = reports.latest()
        if latest is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="nothing has been analysed yet; POST a capture to /api/v1/analyse",
            )
        return latest

    @app.get(f"{API_PREFIX}/reports/{{report_id}}")
    def get_report(
        report_id: str,
        reports: ReportStore = Depends(get_store),  # noqa: B008
    ) -> dict[str, Any]:
        return _stored(report_id, reports).report.model_dump(mode="json")

    @app.get(f"{API_PREFIX}/reports/{{report_id}}/html", response_class=HTMLResponse)
    def get_report_html(
        report_id: str,
        reports: ReportStore = Depends(get_store),  # noqa: B008
    ) -> HTMLResponse:
        return HTMLResponse(render_html(_stored(report_id, reports).report))

    @app.get(f"{API_PREFIX}/tunnels")
    def list_tunnels(
        report_id: str | None = None,
        reports: ReportStore = Depends(get_store),  # noqa: B008
    ) -> list[dict[str, Any]]:
        report = _current(report_id, reports).report
        return [entry.model_dump(mode="json") for entry in report.inventory.entries]

    @app.get(f"{API_PREFIX}/tunnels/{{tunnel_id}}")
    def get_tunnel(
        tunnel_id: str,
        report_id: str | None = None,
        reports: ReportStore = Depends(get_store),  # noqa: B008
    ) -> dict[str, Any]:
        report = _current(report_id, reports).report
        entry = next((e for e in report.inventory.entries if e.tunnel_id == tunnel_id), None)
        if entry is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"no tunnel {tunnel_id} in this report",
            )
        exposure = next(
            (e for e in report.metadata_exposure.entries if e.tunnel_id == tunnel_id), None
        )
        return {
            "tunnel": entry.model_dump(mode="json"),
            "exposure": exposure.model_dump(mode="json") if exposure else None,
            "findings": [
                finding.model_dump(mode="json")
                for finding in report.all_findings
                if finding.tunnel_id == tunnel_id
            ],
            "pqc": next(
                (e.model_dump(mode="json") for e in report.pqc.entries if e.tunnel_id == tunnel_id),
                None,
            ),
        }

    @app.get(f"{API_PREFIX}/findings")
    def list_findings(
        severity: Severity | None = None,
        section: str | None = Query(default=None, pattern="^[ab]$"),
        report_id: str | None = None,
        reports: ReportStore = Depends(get_store),  # noqa: B008
    ) -> list[dict[str, Any]]:
        report = _current(report_id, reports).report
        if section == "a":
            findings = report.section_a_verified
        elif section == "b":
            findings = report.section_b_inferred
        else:
            findings = report.all_findings
        if severity is not None:
            findings = [f for f in findings if f.severity is severity]
        return [finding.model_dump(mode="json") for finding in findings]

    @app.get(f"{API_PREFIX}/inventory")
    def get_inventory(
        report_id: str | None = None,
        reports: ReportStore = Depends(get_store),  # noqa: B008
    ) -> dict[str, Any]:
        return _current(report_id, reports).report.inventory.model_dump(mode="json")

    @app.post(f"{API_PREFIX}/remediate/{{tunnel_id}}")
    async def remediate(
        tunnel_id: str,
        baseline: str = Query(default=DEFAULT_BASELINE),
        file: UploadFile = File(...),  # noqa: B008
    ) -> dict[str, Any]:
        """Generate a change package for one tunnel in an uploaded capture.

        The capture is required rather than read from a stored report: a change package
        is built from the negotiation itself, and a report holds findings rather than
        the wire.
        """
        label = safe_label(file.filename)
        handle, temporary = tempfile.mkstemp(prefix="sentinel-remediate-", suffix=".pcap")
        path = Path(temporary)
        try:
            with path.open("wb") as sink:
                written = 0
                while chunk := await file.read(CHUNK_BYTES):
                    written += len(chunk)
                    if written > MAX_UPLOAD_BYTES:
                        raise HTTPException(
                            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                            detail="the capture exceeds the upload limit",
                        )
                    sink.write(chunk)
            import os

            os.close(handle)
            if not looks_like_a_capture(path.read_bytes()[:4]):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail=f"{label} is not a capture"
                )

            found = next((t for t in read_tunnels(path) if t.tunnel_id == tunnel_id), None)
            if found is None or found.ike is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"no tunnel {tunnel_id} with an observed negotiation in {label}",
                )
            recovered = config_from_exchange(found.ike)
            if not recovered.ok or recovered.config is None:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=recovered.reason or ""
                )
            try:
                assessed = assess_tunnel(found, baseline)
            except UnknownBaselineError as exc:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
                ) from exc
            rule_ids = [finding.rule_id for finding in assessed.findings]
            if not rule_ids:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"nothing found on {tunnel_id} against baseline {baseline}",
                )
            try:
                package = generate_change_package(
                    tunnel_id, recovered.config, rule_ids, observed=assessed
                )
            except GenerationError as exc:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
                ) from exc
        finally:
            path.unlink(missing_ok=True)

        return {
            "package": package.model_dump(mode="json"),
            "assumptions": list(recovered.assumptions),
        }

    @app.exception_handler(UnknownBaselineError)
    async def unknown_baseline(_request: Request, exc: UnknownBaselineError) -> JSONResponse:
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"detail": str(exc)})

    return app


app = create_app()
