"""Tests for the command line (build plan Step 10.1).

The plan's five criteria, and two properties that matter more than any of them.

**`scan` refuses without authorisation.** It is the only command that transmits, and the
refusal is checked both here and in the library, so neither is the sole guard.

**A bad input produces a sentence, not a traceback.** A stack trace tells the reader the
tool broke; a message tells them what to do. Every path an operator can reach with a
wrong path, a malformed file or a typo in a baseline name is checked for a clean exit
code and a readable line.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from ipsec_sentinel.cli import EXIT_REFUSED, EXIT_USAGE, main

REPO_ROOT = Path(__file__).resolve().parents[2]
SWEEP = REPO_ROOT / "data" / "raw" / "sweep"

COMMANDS = [
    [],
    ["analyse"],
    ["inventory"],
    ["remediate"],
    ["scan"],
    ["watch"],
    ["dataset"],
    ["dataset", "build"],
    ["dataset", "audit"],
    ["model"],
    ["model", "train"],
    ["model", "evaluate"],
    ["version"],
]


def capture() -> Path:
    found = sorted(SWEEP.glob("*/capture_outer.pcap"))
    if not found:
        pytest.skip("the sweep corpus is not present")
    return found[0]


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


class TestThePlansCriteria:
    @pytest.mark.parametrize("command", COMMANDS, ids=lambda c: " ".join(c) or "root")
    def test_help_exits_zero(self, runner: CliRunner, command: list[str]) -> None:
        result = runner.invoke(main, [*command, "--help"])
        assert result.exit_code == 0, result.output
        assert "Usage:" in result.output

    def test_analyse_produces_a_report_file(self, runner: CliRunner, tmp_path: Path) -> None:
        destination = tmp_path / "report.html"
        result = runner.invoke(main, ["analyse", str(capture()), "--out", str(destination)])
        assert result.exit_code == 0, result.output
        assert destination.exists()
        assert destination.read_text().lstrip().startswith("<!DOCTYPE html>")

    def test_scan_without_authorisation_exits_non_zero(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["scan", "192.0.2.1"])
        assert result.exit_code == EXIT_REFUSED
        assert "refusing to probe without authorisation" in result.output

    def test_the_refusal_explains_itself(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["scan", "192.0.2.1"])
        assert "--i-have-authorisation" in result.output
        assert "OT networks" in result.output

    def test_an_invalid_pcap_path_is_a_message_not_a_traceback(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["analyse", "/nonexistent/nope.pcap"])
        assert result.exit_code == EXIT_USAGE
        assert "no such capture" in result.output
        assert "Traceback" not in result.output
        assert result.exception is None or isinstance(result.exception, SystemExit)

    def test_version_prints_the_version_and_revision(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output
        assert "revision unknown" in result.output or len(result.output.split("(")[-1]) > 4

    def test_the_version_subcommand_agrees(self, runner: CliRunner) -> None:
        from ipsec_sentinel.version import tool_version

        result = runner.invoke(main, ["version"])
        assert result.exit_code == 0
        assert tool_version() in result.output


class TestFriendlyErrors:
    """Every wrong input an operator can actually supply."""

    def test_a_directory_instead_of_a_capture(self, runner: CliRunner, tmp_path: Path) -> None:
        result = runner.invoke(main, ["analyse", str(tmp_path)])
        assert result.exit_code == EXIT_USAGE
        assert "is a directory" in result.output

    def test_a_file_that_is_not_a_capture(self, runner: CliRunner, tmp_path: Path) -> None:
        rubbish = tmp_path / "notes.txt"
        rubbish.write_text("this is not a pcap")
        result = runner.invoke(main, ["analyse", str(rubbish)])
        assert result.exit_code != 0
        assert "Traceback" not in result.output
        assert "could not be analysed" in result.output

    def test_an_unknown_baseline_names_the_alternatives(self, runner: CliRunner) -> None:
        """The bug this replaced silently reported a clean bill of health."""
        result = runner.invoke(main, ["analyse", str(capture()), "--baseline", "no-such-baseline"])
        assert result.exit_code != 0
        assert "Traceback" not in result.output
        assert "nist_800_77r1" in result.output

    def test_a_missing_documented_list(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["inventory", str(capture()), "--known", "/nope/known.yaml"])
        assert result.exit_code != 0
        assert "Traceback" not in result.output

    def test_a_malformed_documented_list(self, runner: CliRunner, tmp_path: Path) -> None:
        known = tmp_path / "known.yaml"
        known.write_text("tunnels:\n  - name: no endpoints here\n")
        result = runner.invoke(main, ["inventory", str(capture()), "--known", str(known)])
        assert result.exit_code != 0
        assert "endpoints" in result.output
        assert "Traceback" not in result.output

    def test_a_documented_list_with_one_endpoint(self, runner: CliRunner, tmp_path: Path) -> None:
        known = tmp_path / "known.yaml"
        known.write_text("tunnels:\n  - endpoints: [10.0.0.1]\n")
        result = runner.invoke(main, ["inventory", str(capture()), "--known", str(known)])
        assert result.exit_code != 0
        assert "exactly two endpoints" in result.output

    def test_a_missing_dataset_says_how_to_build_one(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["dataset", "audit", "--dataset", "/nope/none.parquet"])
        assert result.exit_code == EXIT_USAGE
        assert "sentinel dataset build" in result.output

    def test_a_missing_corpus_for_dataset_build(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["dataset", "build", "--root", "/nope/corpus"])
        assert result.exit_code == EXIT_USAGE
        assert "no such corpus directory" in result.output

    def test_a_vendor_that_cannot_be_reconstructed_says_why(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["remediate", str(capture()), "--vendor", "cisco"])
        assert result.exit_code == EXIT_USAGE
        assert "strongswan" in result.output

    def test_an_unknown_tunnel_id(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["remediate", str(capture()), "--tunnel", "no-such-tunnel"])
        assert result.exit_code != 0
        assert "no tunnel" in result.output


class TestAnalyse:
    def test_it_reports_the_findings_it_actually_found(self, runner: CliRunner) -> None:
        """The baseline bug made this print a clean bill of health for every capture."""
        result = runner.invoke(main, ["analyse", str(capture())])
        assert result.exit_code == 0, result.output
        assert "tunnels assessed" in result.output
        assert "verified (section A)" in result.output

    def test_every_output_format_can_be_written_at_once(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        html, js = tmp_path / "r.html", tmp_path / "r.json"
        result = runner.invoke(
            main, ["analyse", str(capture()), "--out", str(html), "--json", str(js)]
        )
        assert result.exit_code == 0, result.output
        assert html.exists()
        payload = json.loads(js.read_text())
        assert "section_a_verified" in payload
        assert "executive" in payload

    def test_quiet_prints_nothing(self, runner: CliRunner, tmp_path: Path) -> None:
        result = runner.invoke(
            main, ["analyse", str(capture()), "--quiet", "--out", str(tmp_path / "r.html")]
        )
        assert result.exit_code == 0
        assert result.output.strip() == ""

    def test_the_provenance_is_printed(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["analyse", str(capture())])
        assert "0.1.0" in result.output

    def test_a_documented_list_is_honoured(self, runner: CliRunner, tmp_path: Path) -> None:
        from ipsec_sentinel.analyse import read_tunnels

        tunnels = read_tunnels(capture())
        known = tmp_path / "known.yaml"
        known.write_text(
            "tunnels:\n"
            f"  - endpoints: ['{tunnels[0].endpoints[0]}', '{tunnels[0].endpoints[1]}']\n"
            "    name: documented\n"
        )
        result = runner.invoke(main, ["analyse", str(capture()), "--known", str(known)])
        assert result.exit_code == 0, result.output


class TestInventory:
    def test_it_lists_the_tunnels(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["inventory", str(capture())])
        assert result.exit_code == 0, result.output
        assert "<->" in result.output

    def test_undocumented_tunnels_are_marked(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["inventory", str(capture())])
        assert "undocumented" in result.output


class TestRemediate:
    def test_it_names_the_findings_it_addresses(self, runner: CliRunner) -> None:
        """Not a fixed rule id: an operator checks the package against the report."""
        result = runner.invoke(main, ["remediate", str(capture()), "--baseline", "default"])
        assert result.exit_code == 0, result.output
        assert "finding(s)" in result.output

    def test_it_declares_what_it_had_to_assume(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["remediate", str(capture()), "--baseline", "default"])
        assert "assumption:" in result.output
        assert "perfect forward secrecy" in result.output

    def test_it_writes_both_ends(self, runner: CliRunner, tmp_path: Path) -> None:
        result = runner.invoke(
            main,
            ["remediate", str(capture()), "--baseline", "default", "--out", str(tmp_path)],
        )
        assert result.exit_code == 0, result.output
        written = sorted(p.name for p in tmp_path.glob("*"))
        assert any(".local." in name for name in written), written
        assert any(".peer." in name for name in written), written


class TestScanIsTheOnlyThingThatTransmits:
    def test_no_other_command_opens_a_socket(
        self, runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The product's central claim, asserted at the command line."""
        import socket

        def refuse(*_args: object, **_kwargs: object) -> None:
            raise AssertionError("a passive command opened a socket")

        monkeypatch.setattr(socket, "socket", refuse)
        monkeypatch.setattr(socket, "create_connection", refuse)

        for command in (
            ["analyse", str(capture()), "--out", str(tmp_path / "r.html")],
            ["inventory", str(capture())],
            ["remediate", str(capture()), "--baseline", "default"],
            ["version"],
        ):
            result = runner.invoke(main, command)
            assert result.exit_code == 0, f"{command}: {result.output}"

    def test_scan_warns_before_it_probes(self, runner: CliRunner) -> None:
        """Authorised, but against a port nothing answers on, so nothing is really probed."""
        result = runner.invoke(
            main,
            ["scan", "127.0.0.1", "--port", "9", "--timeout", "0.1", "--i-have-authorisation"],
        )
        assert result.exit_code == 0, result.output
        assert "This transmits to the target" in result.output

    def test_a_silent_target_draws_no_conclusion(self, runner: CliRunner) -> None:
        """Silence is not evidence of a good acceptance policy."""
        result = runner.invoke(
            main,
            ["scan", "127.0.0.1", "--port", "9", "--timeout", "0.1", "--i-have-authorisation"],
        )
        assert "No conclusion can be drawn" in result.output


class TestWatch:
    """The command registers as `watch`; Click strips the `_command` suffix."""

    def test_it_is_reachable_under_the_name_the_plan_uses(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["watch", "--help"])
        assert result.exit_code == 0
        assert "alert when a tunnel gets weaker" in result.output

    def test_the_help_states_the_ike_sa_init_limitation(self, runner: CliRunner) -> None:
        """A limitation nobody should have to rediscover from an empty alert log."""
        result = runner.invoke(main, ["watch", "--help"])
        assert "IKE_SA_INIT" in result.output
        assert "rekey" in result.output

    def test_a_missing_capture_is_a_message(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["watch", "eth0", "--from-capture", "/nope/x.pcap"])
        assert result.exit_code == EXIT_USAGE
        assert "no such capture" in result.output
        assert "Traceback" not in result.output

    def test_an_unknown_baseline_is_refused_before_watching(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        """A watcher that starts, prints "watching", then raises twenty minutes later
        when something finally shows up is worse than one that refuses now."""
        empty = tmp_path / "empty.pcap"
        empty.write_bytes(b"")
        result = runner.invoke(
            main,
            ["watch", "eth0", "--from-capture", str(empty), "--baseline", "no-such-baseline"],
        )
        assert result.exit_code == EXIT_USAGE
        assert "nist_800_77r1" in result.output

    def test_watching_a_quiet_capture_reports_nothing(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        empty = tmp_path / "empty.pcap"
        empty.write_bytes(b"")
        result = runner.invoke(
            main, ["watch", "eth0", "--from-capture", str(empty), "--for", "0.2"]
        )
        assert result.exit_code == 0, result.output
        assert "0 drift alert(s)" in result.output

    def test_it_says_a_first_sighting_is_not_drift(self, runner: CliRunner, tmp_path: Path) -> None:
        empty = tmp_path / "empty.pcap"
        empty.write_bytes(b"")
        result = runner.invoke(
            main, ["watch", "eth0", "--from-capture", str(empty), "--for", "0.2"]
        )
        assert "seen for the first time sets its own baseline" in result.output

    def test_a_malformed_syslog_target_is_refused(self, runner: CliRunner, tmp_path: Path) -> None:
        empty = tmp_path / "empty.pcap"
        empty.write_bytes(b"")
        result = runner.invoke(
            main,
            ["watch", "eth0", "--from-capture", str(empty), "--for", "0.2", "--syslog", ":514"],
        )
        assert result.exit_code == EXIT_USAGE
        assert "host:port" in result.output


class TestWatchRemembers:
    """The mitigations for the IKE_SA_INIT limitation, at the command line."""

    @staticmethod
    def _empty(tmp_path: Path) -> Path:
        target = tmp_path / "empty.pcap"
        target.write_bytes(b"")
        return target

    def test_state_is_written_and_read_back(self, runner: CliRunner, tmp_path: Path) -> None:
        state = tmp_path / "watch.json"
        first = runner.invoke(
            main,
            [
                "watch",
                "eth0",
                "--from-capture",
                str(capture()),
                "--for",
                "0.3",
                "--state",
                str(state),
                "--baseline",
                "default",
            ],
        )
        assert first.exit_code == 0, first.output
        assert state.exists()

        second = runner.invoke(
            main,
            [
                "watch",
                "eth0",
                "--from-capture",
                str(self._empty(tmp_path)),
                "--for",
                "0.2",
                "--state",
                str(state),
                "--baseline",
                "default",
            ],
        )
        assert second.exit_code == 0, second.output
        assert "remembered from earlier" in second.output

    def test_it_says_when_there_is_no_earlier_state(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        result = runner.invoke(
            main,
            [
                "watch",
                "eth0",
                "--from-capture",
                str(self._empty(tmp_path)),
                "--for",
                "0.2",
                "--state",
                str(tmp_path / "absent.json"),
            ],
        )
        assert result.exit_code == 0, result.output
        assert "No earlier state was found" in result.output

    def test_a_previous_capture_can_seed_the_baseline(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        result = runner.invoke(
            main,
            [
                "watch",
                "eth0",
                "--from-capture",
                str(self._empty(tmp_path)),
                "--for",
                "0.2",
                "--since",
                str(capture()),
                "--baseline",
                "default",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "remembered from earlier" in result.output

    def test_a_missing_seed_capture_is_a_message(self, runner: CliRunner, tmp_path: Path) -> None:
        result = runner.invoke(
            main,
            [
                "watch",
                "eth0",
                "--from-capture",
                str(self._empty(tmp_path)),
                "--for",
                "0.2",
                "--since",
                "/nope/audit.pcap",
            ],
        )
        assert result.exit_code == EXIT_USAGE
        assert "no such capture" in result.output
        assert "Traceback" not in result.output

    def test_silent_tunnels_are_reported_rather_than_implied_healthy(
        self, runner: CliRunner
    ) -> None:
        """An empty alert log and a quiet network must not look the same."""
        result = runner.invoke(
            main,
            [
                "watch",
                "eth0",
                "--from-capture",
                str(capture()),
                "--for",
                "0.3",
                "--baseline",
                "default",
                "--stale-after",
                "0",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "not been seen negotiating recently" in result.output
        assert "unverified, not confirmed unchanged" in result.output
