"""The tool's own security posture, asserted rather than claimed (build plan Step 11.3).

The pitch says this tool needs no credentials, never writes to a device, and works on an
air-gapped network. Those are the three claims a buyer would check first, and each is
checked here against the source rather than against the README.

Written with the AST wherever possible. Grepping for the word "password" finds every
comment that mentions one; parsing for an *assignment* of a credential-like name to a
string literal finds the thing that would actually be a problem. A test that cannot
distinguish the two produces noise, and a noisy security test is one people learn to
ignore.
"""

from __future__ import annotations

import ast
import json
import socket
import subprocess
from pathlib import Path

import pytest

from ipsec_sentinel.remediate.models import FORBIDDEN_TRANSPORTS

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC = REPO_ROOT / "src" / "ipsec_sentinel"
SWEEP = REPO_ROOT / "data" / "raw" / "sweep"

# Names that, assigned a literal string, would be a credential in the source.
CREDENTIAL_NAMES = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "api_key",
        "apikey",
        "token",
        "auth_token",
        "private_key",
        "privkey",
        "psk",
        "pre_shared_key",
        "credential",
        "credentials",
        "passphrase",
    }
)

# Markers of key material pasted into source.
KEY_MARKERS = (
    "-----BEGIN RSA PRIVATE KEY",
    "-----BEGIN PRIVATE KEY",
    "-----BEGIN OPENSSH PRIVATE KEY",
    "-----BEGIN EC PRIVATE KEY",
    "-----BEGIN PGP PRIVATE KEY",
)


def product_sources() -> list[Path]:
    return sorted(SRC.rglob("*.py"))


def parsed_sources() -> list[tuple[Path, ast.Module]]:
    return [(path, ast.parse(path.read_text(), filename=str(path))) for path in product_sources()]


class TestNoCredentialIsStoredOrTransmitted:
    """The claim the whole pitch rests on."""

    def test_no_credential_like_name_is_assigned_a_literal(self) -> None:
        offences: list[str] = []
        for path, tree in parsed_sources():
            for node in ast.walk(tree):
                if not isinstance(node, ast.Assign | ast.AnnAssign):
                    continue
                if not isinstance(getattr(node, "value", None), ast.Constant):
                    continue
                if not isinstance(node.value.value, str) or not node.value.value:
                    continue
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    name = getattr(target, "id", None) or getattr(target, "attr", None)
                    if name and name.lower().strip("_") in CREDENTIAL_NAMES:
                        offences.append(f"{path.name}:{node.lineno} {name}")
        assert not offences, f"credential assigned a literal: {offences}"

    def test_no_key_material_is_pasted_into_the_source(self) -> None:
        offences = [
            f"{path.name}: {marker}"
            for path in product_sources()
            for marker in KEY_MARKERS
            if marker in path.read_text()
        ]
        assert not offences, offences

    def test_no_module_reads_a_credential_from_the_environment(self) -> None:
        """A credential the tool never sees is one it cannot leak or store."""
        offences: list[str] = []
        for path, tree in parsed_sources():
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                target = getattr(func, "attr", None) or getattr(func, "id", None)
                if target not in ("getenv", "environ"):
                    continue
                for argument in node.args:
                    named = (
                        isinstance(argument, ast.Constant)
                        and isinstance(argument.value, str)
                        and argument.value.lower().strip("_") in CREDENTIAL_NAMES
                    )
                    if named:
                        offences.append(f"{path.name}:{node.lineno} {argument.value}")
        assert not offences, f"a credential is read from the environment: {offences}"

    def test_the_generated_configurations_carry_no_secret(self) -> None:
        """The documents an operator pastes into a change ticket."""
        from ipsec_sentinel.remediate.generators.strongswan import generate_change_package
        from testbed.orchestrate.matrix import expand_matrix

        config = next(lc.config for lc in expand_matrix() if lc.label == "worst")
        package = generate_change_package("t1", config, ["CRY-05"])
        for document in (package.local_config, package.peer_config):
            lowered = document.content.lower()
            assert "secret =" not in lowered
            assert "psk =" not in lowered
            assert not any(marker.lower() in lowered for marker in KEY_MARKERS)

    def test_no_session_key_survives_state_parsing(self) -> None:
        """``ip xfrm state`` prints keys inline; none may reach a parsed object."""
        import re

        from ipsec_sentinel.collect import parse_xfrm_state

        sample = (
            "src 10.0.0.1 dst 10.0.0.2\n"
            "\tproto esp spi 0xc3337439 reqid 1 mode tunnel\n"
            "\tauth-trunc hmac(sha256) 0x" + "ab" * 32 + " 128\n"
            "\tenc cbc(aes) 0x" + "cd" * 32 + "\n"
        )
        parsed = parse_xfrm_state(sample)
        serialised = " ".join(sa.model_dump_json() for sa in parsed)
        for blob in re.findall(r"0x[0-9a-f]{20,}", sample):
            assert blob not in serialised
            assert blob[2:] not in serialised


class TestNoCodePathWritesToADevice:
    def test_no_remote_access_client_is_imported_anywhere(self) -> None:
        """Not just the remediation lane: the whole product."""
        offences: list[str] = []
        for path, tree in parsed_sources():
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    offences += [
                        f"{path.name}: {a.name}"
                        for a in node.names
                        if a.name.split(".")[0] in FORBIDDEN_TRANSPORTS
                    ]
                elif isinstance(node, ast.ImportFrom):
                    root = (node.module or "").split(".")[0]
                    if root in FORBIDDEN_TRANSPORTS:
                        offences.append(f"{path.name}: from {node.module}")
        assert not offences, f"a device-access client is imported: {offences}"

    def test_the_forbidden_list_covers_what_it_should(self) -> None:
        """A list that omits netmiko is a list that proves nothing."""
        assert {"paramiko", "netmiko", "napalm", "scrapli", "asyncssh"} <= FORBIDDEN_TRANSPORTS

    def test_no_device_write_method_is_called(self) -> None:
        writes = {"send_config_set", "load_merge_candidate", "commit_config", "sendline"}
        offences: list[str] = []
        for path, tree in parsed_sources():
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and getattr(node.func, "attr", None) in writes:
                    offences.append(f"{path.name}:{node.lineno} .{node.func.attr}()")
        assert not offences, offences

    def test_the_cli_offers_no_way_to_reach_a_device(self) -> None:
        from click.testing import CliRunner

        from ipsec_sentinel.cli import main

        runner = CliRunner()
        for command in ("analyse", "inventory", "remediate", "watch"):
            text = runner.invoke(main, [command, "--help"]).output
            for forbidden in ("--host", "--ssh", "--username", "--password", "--api-key"):
                assert forbidden not in text, f"{command} offers {forbidden}"


class TestPassiveModeOpensNoSocket:
    @pytest.fixture
    def a_capture(self) -> Path:
        found = sorted(SWEEP.glob("*/capture_outer.pcap"))
        if not found:
            pytest.skip("the sweep corpus is not present")
        return found[0]

    def test_analysis_opens_nothing(self, a_capture: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from ipsec_sentinel.analyse import analyse_capture

        def refuse(*_args: object, **_kwargs: object) -> None:
            raise AssertionError("passive analysis opened a socket")

        monkeypatch.setattr(socket, "socket", refuse)
        monkeypatch.setattr(socket, "create_connection", refuse)
        monkeypatch.setattr(socket, "getaddrinfo", refuse)
        analyse_capture(a_capture, baseline="default")

    def test_reporting_opens_nothing(
        self, a_capture: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from ipsec_sentinel.analyse import analyse_capture
        from ipsec_sentinel.report.export_json import export_json
        from ipsec_sentinel.report.render_html import render_html
        from ipsec_sentinel.report.siem import report_to_cef, report_to_syslog

        report = analyse_capture(a_capture, baseline="default")

        def refuse(*_args: object, **_kwargs: object) -> None:
            raise AssertionError("reporting opened a socket")

        monkeypatch.setattr(socket, "socket", refuse)
        monkeypatch.setattr(socket, "create_connection", refuse)
        render_html(report)
        export_json(report)
        report_to_cef(report)
        report_to_syslog(report)

    def test_only_two_modules_transmit_at_all(self) -> None:
        """Both are opt-in and neither is reachable from the analysis path."""
        transmitting: set[str] = set()
        for path, tree in parsed_sources():
            for node in ast.walk(tree):
                is_socket_call = isinstance(node, ast.Call) and getattr(
                    node.func, "attr", None
                ) in ("socket", "create_connection")
                if is_socket_call:
                    transmitting.add(path.name)
        assert transmitting <= {"probe.py", "siem.py"}, (
            f"unexpected modules open sockets: {sorted(transmitting - {'probe.py', 'siem.py'})}"
        )

    def test_the_prober_refuses_without_authorisation(self) -> None:
        from ipsec_sentinel.probe import AuthorisationError, enumerate_transforms

        with pytest.raises(AuthorisationError):
            enumerate_transforms("192.0.2.1")


class TestUploadsAreBoundedAndConfined:
    def test_the_size_limit_is_enforced_while_reading(self) -> None:
        body = (SRC / "api" / "app.py").read_text()
        assert "while chunk := await file.read(CHUNK_BYTES)" in body
        assert "written > MAX_UPLOAD_BYTES" in body

    def test_the_upload_path_is_chosen_by_mkstemp(self) -> None:
        """Never derived from the uploaded filename."""
        body = (SRC / "api" / "app.py").read_text()
        assert "tempfile.mkstemp" in body
        assert "Path(file.filename)" not in body

    def test_a_traversing_filename_is_reduced(self) -> None:
        from ipsec_sentinel.api.app import safe_label

        for hostile in ("../../etc/passwd", "/absolute", "..\\..\\windows"):
            reduced = safe_label(hostile)
            assert "/" not in reduced
            assert "\\" not in reduced
            assert ".." not in reduced


class TestExternalDataIsParsedDefensively:
    def test_yaml_is_never_loaded_unsafely(self) -> None:
        """`yaml.load` without a safe loader executes arbitrary Python."""
        offences: list[str] = []
        for path, tree in parsed_sources():
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and getattr(node.func, "attr", None) == "load":
                    value = getattr(node.func, "value", None)
                    if getattr(value, "id", None) == "yaml":
                        offences.append(f"{path.name}:{node.lineno}")
        assert not offences, f"yaml.load without a safe loader: {offences}"

    def test_there_is_no_eval_or_exec(self) -> None:
        offences: list[str] = []
        for path, tree in parsed_sources():
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and getattr(node.func, "id", None) in (
                    "eval",
                    "exec",
                ):
                    offences.append(f"{path.name}:{node.lineno}")
        assert not offences, offences

    def test_a_malformed_capture_raises_rather_than_crashing(self, tmp_path: Path) -> None:
        """The fuzzing in Step 4.9 covers this in depth; this is the surface check."""
        from ipsec_sentinel.parser.pcap import CaptureError, extract_ike_exchanges

        rubbish = tmp_path / "rubbish.pcap"
        rubbish.write_bytes(b"\x00\x01\x02\x03" * 100)
        with pytest.raises((CaptureError, ValueError)):
            extract_ike_exchanges(rubbish)

    def test_a_malformed_baseline_is_refused(self, tmp_path: Path) -> None:
        from ipsec_sentinel.assess.baselines.schema import BaselineError, load_baseline_file

        broken = tmp_path / "broken.yaml"
        broken.write_text("id: x\nrules: not-a-list\n")
        with pytest.raises((BaselineError, ValueError)):
            load_baseline_file(broken)


class TestDeserialisation:
    """The one place this project unpickles, and what is done about it."""

    def test_the_only_pickle_based_load_is_the_model(self) -> None:
        offences: list[str] = []
        for path, tree in parsed_sources():
            body = path.read_text()
            if "pickle.load" in body or "pickle.loads" in body:
                offences.append(f"{path.name}: pickle")
            for node in ast.walk(tree):
                is_joblib = (
                    isinstance(node, ast.Call)
                    and getattr(node.func, "attr", None) == "load"
                    and getattr(getattr(node.func, "value", None), "id", None) == "joblib"
                )
                if is_joblib and path.name != "train.py":
                    offences.append(f"{path.name}:{node.lineno} joblib.load")
        assert not offences, (
            f"unpickling outside the model loader: {offences}. joblib is pickle-based, so "
            f"every such call is arbitrary code execution on a hostile file."
        )

    def test_the_model_loader_says_what_loading_costs(self) -> None:
        """A caveat nobody wrote down is a caveat nobody knows."""
        from ipsec_sentinel.ml.train import load_model

        doc = load_model.__doc__ or ""
        assert "pickle" in doc.lower()
        assert "arbitrary code" in doc.lower() or "code execution" in doc.lower()

    def test_a_capture_is_never_unpickled(self) -> None:
        """Untrusted input meets the parser, never the deserialiser."""
        parser_dir = SRC / "parser"
        for path in parser_dir.rglob("*.py"):
            body = path.read_text()
            assert "pickle" not in body
            assert "joblib" not in body


class TestDependencies:
    @pytest.mark.slow
    def test_pip_audit_reports_no_vulnerability(self) -> None:
        """Run against the environment the tool actually uses."""
        audit = REPO_ROOT / ".venv" / "bin" / "pip-audit"
        if not audit.exists():
            pytest.skip("pip-audit is not installed")
        result = subprocess.run(
            [str(audit), "--format", "json", "--progress-spinner", "off"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=1800,
            check=False,
        )
        # An audit that could not run is not an audit that found nothing, and it is not
        # an audit that found something either. Two network blips turned this red during
        # the M11 re-run — once Docker Hub, once the advisory service — and a release
        # gate that fails because a name did not resolve teaches people to ignore it.
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            pytest.skip(
                f"pip-audit could not complete, so nothing was checked: "
                f"{(result.stderr or result.stdout)[-300:]}"
            )
        dependencies = payload.get("dependencies", [])
        vulnerable = [
            f"{d['name']} {d['version']}: {v['id']}"
            for d in dependencies
            for v in d.get("vulns", [])
        ]
        print(f"\npip-audit: {len(dependencies)} packages, {len(vulnerable)} advisories")
        assert not vulnerable, vulnerable


def test_the_security_document_exists_and_makes_the_claims_checkable() -> None:
    """Every claim in SECURITY.md should name the test that proves it."""
    document = REPO_ROOT / "docs" / "SECURITY.md"
    assert document.is_file(), "docs/SECURITY.md is missing"
    text = document.read_text()
    for claim in (
        "no credential",
        "never writes",
        "outbound socket",
        "pickle",
        "pip-audit",
    ):
        assert claim.lower() in text.lower(), f"SECURITY.md does not address: {claim}"
    assert "tests/unit/test_security.py" in text, (
        "the document should point at the tests that check it"
    )
