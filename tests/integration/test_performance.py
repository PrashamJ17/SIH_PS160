"""Performance benchmarks (build plan Step 11.2).

The plan's five targets, each measured rather than assumed. "A demo that hangs is worse
than a missing feature" is the reason they exist, and every one is checked against real
work: captures built from corpus traffic, a thousand genuinely distinct tunnels, and the
model this project actually ships.

Two things about how these are written.

**The thresholds are generous and the measurements are printed.** A benchmark that fails
at 61 seconds and passes at 59 tells nobody anything on a different machine. These assert
the plan's targets — which are about a demo not hanging — and print what was actually
measured, so a regression shows up as a number moving rather than as a test flipping.

**The memory target is measured in a child process.** ``tracemalloc`` counts Python
allocations and would miss everything scapy does underneath; peak RSS of a subprocess is
the number that matters, because it is the one that gets a process killed.
"""

from __future__ import annotations

import resource
import subprocess
import sys
import time
import warnings
from pathlib import Path

import pytest

warnings.filterwarnings("ignore")

from ipsec_sentinel.analyse import analyse_capture  # noqa: E402
from ipsec_sentinel.models import Proposal, Transform, TransformType  # noqa: E402
from ipsec_sentinel.parser.correlate import correlate  # noqa: E402
from ipsec_sentinel.parser.esp import assemble_esp_flows, extract_esp_packets  # noqa: E402
from ipsec_sentinel.parser.pcap import extract_ike_exchanges  # noqa: E402
from ipsec_sentinel.report.export_json import export_json  # noqa: E402
from ipsec_sentinel.report.render_html import render_html  # noqa: E402
from tests.fixtures.builders import build_ike_sa_init, build_pcap, build_udp_frame  # noqa: E402

pytestmark = [pytest.mark.integration, pytest.mark.slow]

REPO_ROOT = Path(__file__).resolve().parents[2]
SWEEP = REPO_ROOT / "data" / "raw" / "sweep"
MODEL = REPO_ROOT / "models" / "traffic.joblib"
DATASET = REPO_ROOT / "data" / "processed" / "ml_dataset.parquet"

# The plan's targets.
PARSE_100MB_SECONDS = 60.0
ANALYSE_1000_TUNNELS_SECONDS = 120.0
PREDICT_PER_FLOW_MS = 50.0
REPORT_SECONDS = 10.0
MEMORY_1GB_BYTES = 4 * 1024**3

TUNNEL_COUNT = 1000
IKE_OFFSET = 14 + 20 + 8  # ethernet + IPv4 + UDP


def peak_rss_bytes(children: bool = False) -> int:
    """Peak resident set size. macOS reports bytes, Linux kilobytes."""
    who = resource.RUSAGE_CHILDREN if children else resource.RUSAGE_SELF
    peak = resource.getrusage(who).ru_maxrss
    return peak if sys.platform == "darwin" else peak * 1024


def grow_capture(source: Path, destination: Path, target_bytes: int) -> Path:
    """Repeat a real capture's records until the file reaches ``target_bytes``.

    Built from corpus traffic rather than synthesised, so the parser meets the packet
    shapes it will actually meet — including the IKE handshake, which a capture of pure
    ESP would never exercise.
    """
    raw = source.read_bytes()
    header, records = raw[:24], raw[24:]
    with destination.open("wb") as sink:
        sink.write(header)
        written = len(header)
        while written < target_bytes:
            sink.write(records)
            written += len(records)
    return destination


@pytest.fixture(scope="module")
def big_capture(tmp_path_factory: pytest.TempPathFactory) -> Path:
    source = _largest_corpus_capture()
    target = tmp_path_factory.mktemp("perf") / "100mb.pcap"
    return grow_capture(source, target, 100_000_000)


def _largest_corpus_capture() -> Path:
    captures = sorted(SWEEP.glob("*/capture_outer.pcap"), key=lambda p: p.stat().st_size)
    if not captures:
        pytest.skip("the sweep corpus is not present")
    return captures[-1]


def _proposal(weak: bool) -> Proposal:
    if weak:
        return Proposal(
            number=1,
            protocol="IKE",
            transforms=[
                Transform(type=TransformType.ENCR, id=3, name="ENCR_3DES"),
                Transform(type=TransformType.INTEG, id=1, name="AUTH_HMAC_MD5_96"),
                Transform(type=TransformType.PRF, id=1, name="PRF_HMAC_MD5"),
                Transform(type=TransformType.DH, id=2, name="1024-bit MODP"),
            ],
        )
    return Proposal(
        number=1,
        protocol="IKE",
        transforms=[
            Transform(type=TransformType.ENCR, id=12, name="ENCR_AES_CBC", key_length=256),
            Transform(type=TransformType.INTEG, id=12, name="AUTH_HMAC_SHA2_256_128"),
            Transform(type=TransformType.PRF, id=5, name="PRF_HMAC_SHA2_256"),
            Transform(type=TransformType.DH, id=20, name="384-bit ECP"),
        ],
    )


@pytest.fixture(scope="module")
def thousand_tunnels(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A capture holding a thousand genuinely distinct tunnels.

    Each needs its own initiator SPI as well as its own endpoints: negotiations are
    grouped by initiator SPI, so a shared one collapses the whole estate into a single
    row and the benchmark measures nothing.
    """
    frames = []
    for index in range(TUNNEL_COUNT):
        source = f"10.{index // 256}.{index % 256}.1"
        destination = f"10.{index // 256}.{index % 256}.2"
        frame = bytearray(
            build_udp_frame(
                build_ike_sa_init([_proposal(index % 3 == 0)]),
                src_ip=source,
                dst_ip=destination,
            )
        )
        frame[IKE_OFFSET : IKE_OFFSET + 8] = index.to_bytes(8, "big")
        frames.append(bytes(frame))

    target = tmp_path_factory.mktemp("perf") / "thousand.pcap"
    target.write_bytes(build_pcap(frames))
    return target


class TestTheParser:
    def test_a_hundred_megabyte_capture_parses_in_under_a_minute(self, big_capture: Path) -> None:
        size_mb = big_capture.stat().st_size / 1e6
        start = time.monotonic()
        exchanges = extract_ike_exchanges(big_capture)
        flows = assemble_esp_flows(extract_esp_packets(big_capture))
        tunnels = correlate(exchanges, flows)
        elapsed = time.monotonic() - start

        print(
            f"\nparse {size_mb:.0f} MB: {elapsed:.1f}s "
            f"({len(exchanges)} IKE messages, {len(flows)} flows, {len(tunnels)} tunnels)"
        )
        assert elapsed < PARSE_100MB_SECONDS, (
            f"{elapsed:.1f}s against a {PARSE_100MB_SECONDS}s target"
        )
        assert exchanges, "the fixture carried no IKE, so the negotiation path was not exercised"
        assert flows, "the fixture carried no ESP"

    def test_a_gigabyte_capture_stays_within_the_memory_budget(
        self, tmp_path_factory: pytest.TempPathFactory
    ) -> None:
        """Streaming, not full load. Measured as a child's peak RSS.

        ``tracemalloc`` counts Python allocations and would miss what scapy does
        underneath. Peak RSS is the number that gets a process killed, so it is the
        number the target is about.
        """
        target = tmp_path_factory.mktemp("perf") / "1gb.pcap"
        grow_capture(_largest_corpus_capture(), target, 1_000_000_000)
        assert target.stat().st_size >= 1_000_000_000

        child = (
            "import sys, warnings; warnings.filterwarnings('ignore')\n"
            "from pathlib import Path\n"
            "from ipsec_sentinel.parser.esp import extract_esp_packets, assemble_esp_flows\n"
            "from ipsec_sentinel.parser.pcap import extract_ike_exchanges\n"
            "t = Path(sys.argv[1])\n"
            "flows = assemble_esp_flows(extract_esp_packets(t))\n"
            "print(len(extract_ike_exchanges(t)), len(flows))\n"
        )
        before = peak_rss_bytes(children=True)
        start = time.monotonic()
        result = subprocess.run(
            [sys.executable, "-c", child, str(target)],
            capture_output=True,
            text=True,
            timeout=1800,
            check=False,
            cwd=REPO_ROOT,
        )
        elapsed = time.monotonic() - start
        assert result.returncode == 0, result.stderr[-500:]
        peak = max(peak_rss_bytes(children=True), before)

        print(f"\nparse 1 GB: {elapsed:.1f}s, peak child RSS {peak / 1024**3:.2f} GB")
        assert peak < MEMORY_1GB_BYTES, (
            f"{peak / 1024**3:.2f} GB against a {MEMORY_1GB_BYTES / 1024**3:.0f} GB budget; "
            f"the parser is holding the capture rather than streaming it"
        )
        # A file ten times the size must not cost ten times the memory.
        assert peak < 2 * 1024**3, "memory scaled with file size, which is not streaming"


class TestTheAssessment:
    def test_a_thousand_tunnels_are_analysed_in_under_two_minutes(
        self, thousand_tunnels: Path
    ) -> None:
        start = time.monotonic()
        report = analyse_capture(thousand_tunnels, baseline="default")
        elapsed = time.monotonic() - start

        print(
            f"\nanalyse {report.executive.tunnels_assessed} tunnels: {elapsed:.1f}s "
            f"({len(report.all_findings)} findings)"
        )
        assert report.executive.tunnels_assessed == TUNNEL_COUNT, (
            f"the fixture collapsed to {report.executive.tunnels_assessed} tunnels; "
            f"the benchmark would measure nothing"
        )
        assert elapsed < ANALYSE_1000_TUNNELS_SECONDS
        assert len(report.all_findings) > TUNNEL_COUNT, "an estate this weak should raise more"

    def test_a_large_report_renders_quickly(self, thousand_tunnels: Path) -> None:
        report = analyse_capture(thousand_tunnels, baseline="default")
        start = time.monotonic()
        html = render_html(report)
        payload = export_json(report)
        elapsed = time.monotonic() - start

        print(
            f"\nrender: {elapsed:.1f}s ({len(html) / 1e6:.1f} MB HTML, "
            f"{len(payload) / 1e6:.1f} MB JSON)"
        )
        assert elapsed < REPORT_SECONDS
        assert len(html) > 100_000, "a thousand tunnels should not render to a small page"


@pytest.mark.skipif(not MODEL.exists(), reason="no trained model; run `sentinel model train`")
class TestTheModel:
    def test_a_single_flow_is_classified_in_under_fifty_milliseconds(self) -> None:
        """One row at a time, which is how a live analysis calls it."""
        import pandas as pd

        from ipsec_sentinel.ml.predict import predict_with_abstention
        from ipsec_sentinel.ml.train import load_model

        if not DATASET.exists():
            pytest.skip("the ML dataset has not been built")
        model, metadata = load_model(MODEL)
        frame = pd.read_parquet(DATASET)[metadata.feature_names]

        rounds = 50
        start = time.monotonic()
        for index in range(rounds):
            predict_with_abstention(
                model,
                frame.iloc[[index % len(frame)]],
                metadata.class_names,
                metadata.feature_names,
            )
        per_flow_ms = (time.monotonic() - start) / rounds * 1000

        print(f"\nclassify one flow: {per_flow_ms:.1f} ms")
        assert per_flow_ms < PREDICT_PER_FLOW_MS

    def test_explaining_a_prediction_is_affordable(self) -> None:
        """SHAP is the expensive part, and the dashboard asks for it per tunnel.

        Not a plan target, measured because an explanation nobody can wait for is an
        explanation nobody sees, and the tunnel detail view requests one on every click.
        """
        import pandas as pd

        from ipsec_sentinel.ml.explain import explain_prediction
        from ipsec_sentinel.ml.train import load_model

        if not DATASET.exists():
            pytest.skip("the ML dataset has not been built")
        model, metadata = load_model(MODEL)
        frame = pd.read_parquet(DATASET)[metadata.feature_names]

        rounds = 10
        start = time.monotonic()
        for index in range(rounds):
            explain_prediction(
                model, frame.iloc[[index]], metadata.class_names, metadata.feature_names
            )
        per_explanation_ms = (time.monotonic() - start) / rounds * 1000

        print(f"\nexplain one prediction: {per_explanation_ms:.1f} ms")
        assert per_explanation_ms < 500, "a click on a tunnel should not feel slow"
