"""PDF export, via WeasyPrint over the HTML report.

The PDF is the HTML — same template, same content, same escaping — so the two cannot
disagree about what the assessment found. WeasyPrint applies the ``@media print`` rules
the template already carries.

**The macOS library path.** WeasyPrint reaches Pango, cairo and GLib through cffi, which
asks dyld for names like ``libgobject-2.0-0``. Homebrew installs those under
``/opt/homebrew/lib``, which is not on dyld's default search path, so the import fails
with an error naming a library that is in fact installed. Setting
``DYLD_FALLBACK_LIBRARY_PATH`` before the import fixes it, and doing it here rather than
in a shell profile means the tool works without anyone having to know that. The variable
is only extended, never replaced, and only with directories that exist.

Import is deferred into the functions on purpose. WeasyPrint pulls in a large dependency
tree and is needed by one output format; importing it at module load would make every
other part of the tool pay for it, and would turn a missing system library into an error
that breaks unrelated commands.
"""

from __future__ import annotations

import os
import platform
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from ipsec_sentinel.report.models import Report
from ipsec_sentinel.report.render_html import render_html

if TYPE_CHECKING:  # pragma: no cover - typing only
    from collections.abc import Sequence

# Where Homebrew puts the Pango/cairo/GLib dylibs, on Apple Silicon and Intel.
MACOS_LIBRARY_DIRS: Final[tuple[str, ...]] = ("/opt/homebrew/lib", "/usr/local/lib")
DYLD_VARIABLE: Final = "DYLD_FALLBACK_LIBRARY_PATH"

INSTALL_HINT: Final = (
    "WeasyPrint could not load its native dependencies. Install them with "
    "`brew install pango` on macOS, or `apt-get install libpango-1.0-0 "
    "libpangoft2-1.0-0` on Debian and Ubuntu. Every other output format — HTML, JSON, "
    "SIEM — works without them."
)


class PDFExportError(RuntimeError):
    """PDF export is unavailable, with the reason and the fix."""


def _extend_macos_library_path() -> None:
    """Put Homebrew's lib directory on dyld's fallback search path.

    A no-op off macOS, and a no-op for any directory that does not exist, so this
    cannot introduce a path that shadows a system library.
    """
    if platform.system() != "Darwin":
        return
    existing = [part for part in os.environ.get(DYLD_VARIABLE, "").split(":") if part]
    additions = [d for d in MACOS_LIBRARY_DIRS if Path(d).is_dir() and d not in existing]
    if additions:
        os.environ[DYLD_VARIABLE] = ":".join([*existing, *additions])


def _weasyprint() -> Any:
    """Import WeasyPrint, preparing the library path first."""
    _extend_macos_library_path()
    try:
        import weasyprint
    except (ImportError, OSError) as exc:
        raise PDFExportError(f"{INSTALL_HINT} Underlying error: {exc}") from exc
    return weasyprint


def pdf_available() -> bool:
    """Whether this machine can render a PDF, without raising if it cannot."""
    try:
        _weasyprint()
    except PDFExportError:
        return False
    return True


def _document(report: Report) -> Any:
    weasyprint = _weasyprint()
    # base_url is deliberately absent: the HTML references nothing external, and giving
    # WeasyPrint a base would let a future template resolve a relative URL against the
    # filesystem — turning a self-contained report into one that reads local files.
    return weasyprint.HTML(string=render_html(report)).render()


def page_count(report: Report) -> int:
    """How many pages the report occupies, without writing a file."""
    pages: Sequence[Any] = _document(report).pages
    return len(pages)


def render_pdf(report: Report) -> bytes:
    """Render the report to PDF bytes."""
    result = _document(report).write_pdf()
    if not isinstance(result, bytes):  # pragma: no cover - defensive
        raise PDFExportError(f"WeasyPrint returned {type(result).__name__}, not bytes")
    return result


def write_pdf(report: Report, destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(render_pdf(report))
    return destination
