"""The demo, checked the way the plan asks: by running it (build plan Step 11.7).

A demo that has never been executed end to end on a clean checkout is a demo that fails
in front of judges. So `run_demo.sh` is run here, its exit status is checked, its runtime
is bounded, and the findings the narration promises are asserted against the artefacts it
produced.

The findings assertions are the part that matters. A demo script can exit zero while
producing an empty report, and "the estate scores F because of 3DES on an undocumented
tunnel" is a sentence a presenter will say out loud — so it is checked against the JSON
the script wrote, not against a memory of what the capture used to contain.
"""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

import pytest

from ipsec_sentinel.analyse import read_tunnels

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[2]
DEMO = REPO_ROOT / "demo"
PCAPS = DEMO / "pcaps"
RUN = DEMO / "run_demo.sh"
SCRIPT = DEMO / "SCRIPT.md"
TUNNELS = DEMO / "tunnels.yaml"

TEN_MINUTES = 600
ESTATE = PCAPS / "04-estate.pcap"

# The narration's claims, in the form the report expresses them.
PROMISED_FINDINGS = {
    "CRY-05",  # 3DES
    "CRY-02",  # 1024-bit MODP
    "CRY-06",  # MD5
    "CRY-11",  # DH group weaker than the baseline
    "IKE-01",  # IKEv1
    "IKE-03",  # aggressive mode with a pre-shared key
    "SA-01",  # IKE SA lifetime over 24 hours
    "PQC-01",  # not resistant to harvest-now-decrypt-later
}


class TestTheAssetsExist:
    def test_the_runner_is_present_and_executable(self) -> None:
        assert RUN.is_file()
        assert RUN.stat().st_mode & 0o111, "run_demo.sh is not executable"

    def test_the_runner_parses(self) -> None:
        assert subprocess.run(["bash", "-n", str(RUN)], check=False).returncode == 0

    def test_the_runner_fails_loudly(self) -> None:
        assert "set -euo pipefail" in RUN.read_text()

    def test_the_narration_exists(self) -> None:
        assert SCRIPT.is_file()

    def test_the_documented_tunnel_list_exists(self) -> None:
        assert TUNNELS.is_file()

    def test_there_are_captures_for_every_beat(self) -> None:
        assert len(sorted(PCAPS.glob("*.pcap"))) >= 4


class TestEveryDemoCaptureParses:
    @pytest.mark.parametrize("capture", sorted(PCAPS.glob("*.pcap")), ids=lambda path: path.name)
    def test_it_yields_at_least_one_tunnel(self, capture: Path) -> None:
        """A demo capture that parses to nothing is a beat that fails on stage."""
        tunnels = read_tunnels(capture)
        assert tunnels, f"{capture.name} produced no tunnels"

    def test_the_estate_capture_holds_three_tunnels(self) -> None:
        assert len(read_tunnels(ESTATE)) == 3


@pytest.fixture(scope="module")
def demo_run(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, float, str]:
    """Run the demo once and hand every test its artefacts, runtime and output."""
    output = tmp_path_factory.mktemp("demo")
    started = time.monotonic()
    result = subprocess.run(
        [str(RUN), "--out", str(output), "--quiet"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=TEN_MINUTES + 120,
        check=False,
    )
    elapsed = time.monotonic() - started
    assert result.returncode == 0, (
        f"run_demo.sh exited {result.returncode}\n"
        f"--- stdout ---\n{result.stdout[-4000:]}\n--- stderr ---\n{result.stderr[-4000:]}"
    )
    return output, elapsed, result.stdout


class TestTheDemoRuns:
    def test_it_completes_within_ten_minutes(self, demo_run: tuple[Path, float, str]) -> None:
        _, elapsed, _ = demo_run
        assert elapsed < TEN_MINUTES, f"the demo took {elapsed:.0f}s"

    def test_it_produces_the_estate_report(self, demo_run: tuple[Path, float, str]) -> None:
        output, _, _ = demo_run
        assert (output / "estate.html").stat().st_size > 0
        assert (output / "estate.json").stat().st_size > 0

    def test_it_produces_a_change_package(self, demo_run: tuple[Path, float, str]) -> None:
        output, _, _ = demo_run
        package = output / "change-package"
        assert package.is_dir()
        assert any(package.iterdir()), "the change package is empty"

    def test_every_beat_is_announced(self, demo_run: tuple[Path, float, str]) -> None:
        """The presenter follows the printed beats; a silent step loses the thread."""
        _, _, stdout = demo_run
        for beat in ("BEAT 1", "BEAT 2", "BEAT 3", "BEAT 4", "BEAT 5", "BEAT 6", "BEAT 7"):
            assert beat in stdout, f"{beat} was never announced"


class TestTheNarrationsClaimsAreTrue:
    @pytest.fixture(scope="class")
    @staticmethod
    def report(demo_run: tuple[Path, float, str]) -> dict:  # type: ignore[type-arg]
        output, _, _ = demo_run
        loaded: dict = json.loads((output / "estate.json").read_text())  # type: ignore[type-arg]
        return loaded

    def test_the_estate_grades_f(self, report: dict) -> None:  # type: ignore[type-arg]
        assert report["executive"]["estate_grade"] == "F"

    def test_it_finds_three_tunnels(self, report: dict) -> None:  # type: ignore[type-arg]
        assert report["executive"]["tunnels_assessed"] == 3

    def test_exactly_one_tunnel_is_undocumented(self, report: dict) -> None:  # type: ignore[type-arg]
        assert report["executive"]["tunnels_undocumented"] == 1

    def test_every_promised_finding_appears(self, report: dict) -> None:  # type: ignore[type-arg]
        found = {finding["rule_id"] for finding in report["section_a_verified"]}
        missing = PROMISED_FINDINGS - found
        assert not missing, f"the narration promises findings the demo does not produce: {missing}"

    def test_every_verified_finding_cites_a_standard(self, report: dict) -> None:  # type: ignore[type-arg]
        for finding in report["section_a_verified"]:
            assert finding["standard_ref"].strip(), finding["rule_id"]

    def test_nothing_in_section_a_carries_a_confidence(self, report: dict) -> None:  # type: ignore[type-arg]
        """The separation claim is the centre of the pitch, so the demo proves it."""
        assert all(finding["confidence"] is None for finding in report["section_a_verified"])

    def test_the_undocumented_tunnel_is_the_one_carrying_voip(self, report: dict) -> None:  # type: ignore[type-arg]
        """The story is a shadow VPN carrying voice over 3DES. Check it, do not assume it."""
        undocumented = [
            entry["tunnel_id"]
            for entry in report["inventory"]["entries"]
            if entry["status"] == "undocumented"
        ]
        assert len(undocumented) == 1

        exposure = {entry["tunnel_id"]: entry for entry in report["metadata_exposure"]["entries"]}
        entry = exposure[undocumented[0]]
        assert entry["inferred_traffic"] == "voip"
        assert entry["inferred_traffic_confidence"]["value"] >= 0.9

    def test_the_inference_is_in_section_b_only(self, report: dict) -> None:  # type: ignore[type-arg]
        for entry in report["metadata_exposure"]["entries"]:
            confidence = entry.get("inferred_traffic_confidence")
            if entry.get("inferred_traffic"):
                assert confidence is not None, entry["tunnel_id"]

    def test_post_quantum_readiness_is_reported(self, report: dict) -> None:  # type: ignore[type-arg]
        assert report["pqc"]["entries"], "the PQC beat has nothing to show"
        assert all(entry["grade"] for entry in report["pqc"]["entries"])


class TestTheAlternativeBaselineBeat:
    def test_itsar_produces_a_report_too(self, demo_run: tuple[Path, float, str]) -> None:
        """Beat 7 switches baselines live; an unknown baseline name would end the demo."""
        output, _, _ = demo_run
        payload = json.loads((output / "estate-itsar.json").read_text())
        assert payload["metadata"]["baseline"] == "itsar"
        assert payload["section_a_verified"], "ITSAR selected no rules"


class TestTheFallbackVideo:
    def test_it_exists_or_the_script_says_where_it_is(self) -> None:
        """The plan asks for a recording for when everything fails."""
        video = DEMO / "fallback.mp4"
        assert video.is_file(), "demo/fallback.mp4 is missing"
        assert video.stat().st_size > 100_000, "the fallback video is suspiciously small"

    def test_the_narration_tells_the_presenter_it_exists(self) -> None:
        assert "fallback.mp4" in SCRIPT.read_text()
