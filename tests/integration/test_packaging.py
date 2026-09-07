"""Packaging: the container, the compose stack, and the offline bundle (Step 11.5).

Three claims are made here and each is checked by running the thing rather than reading
it:

* **the container does not run as root** — asserted by asking the running container for
  its own uid, not by grepping the Dockerfile for a ``USER`` line, because a later
  ``USER root`` would satisfy the grep;
* **the image is under 1 GB** — measured with ``docker image inspect``;
* **the bundle installs on a machine with no package index** — a fresh virtualenv is
  built from the tarball with ``--no-index`` and a deliberately unreachable index URL, so
  a dependency that quietly resolved over the network would fail rather than pass.

The static checks that open no daemon run everywhere; the rest skip cleanly when Docker
is absent, which is what lets this file live in the normal integration run.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from tests.fixtures.dockerctl import docker, docker_available

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = REPO_ROOT / "Dockerfile"
COMPOSE = REPO_ROOT / "docker-compose.yml"
INSTALL = REPO_ROOT / "scripts" / "install.sh"
BUNDLE = REPO_ROOT / "scripts" / "build_offline_bundle.sh"
DEMO = REPO_ROOT / "demo" / "pcaps"

IMAGE = "ipsec-sentinel:test"
ONE_GIGABYTE = 1024**3


class TestTheArtefactsExist:
    @pytest.mark.parametrize("path", [DOCKERFILE, COMPOSE, INSTALL, BUNDLE], ids=lambda p: p.name)
    def test_it_is_present(self, path: Path) -> None:
        assert path.is_file(), f"{path.relative_to(REPO_ROOT)} is missing"

    @pytest.mark.parametrize("script", [INSTALL, BUNDLE], ids=lambda p: p.name)
    def test_the_script_is_executable(self, script: Path) -> None:
        assert os.access(script, os.X_OK), f"{script.name} is not executable"

    @pytest.mark.parametrize("script", [INSTALL, BUNDLE], ids=lambda p: p.name)
    def test_the_script_parses(self, script: Path) -> None:
        assert subprocess.run(["bash", "-n", str(script)], check=False).returncode == 0

    @pytest.mark.parametrize("script", [INSTALL, BUNDLE], ids=lambda p: p.name)
    def test_the_script_fails_loudly(self, script: Path) -> None:
        """Without -euo pipefail a failed step is a silent partial install."""
        assert "set -euo pipefail" in script.read_text()


class TestTheDockerfileIsShaped:
    """Static properties. The behavioural ones are asserted against a running image."""

    def test_it_is_multi_stage(self) -> None:
        stages = [line for line in DOCKERFILE.read_text().splitlines() if line.startswith("FROM ")]
        assert len(stages) >= 2, "a single-stage image ships the build toolchain"

    def test_the_base_image_is_pinned(self) -> None:
        """`latest` makes the image unreproducible and the build non-deterministic."""
        for line in DOCKERFILE.read_text().splitlines():
            if line.startswith("FROM "):
                reference = line.split()[1]
                assert ":" in reference, f"unpinned base image: {reference}"
                assert not reference.endswith(":latest"), f"floating base image: {reference}"

    def test_the_last_user_directive_is_not_root(self) -> None:
        users = [
            line.split()[1]
            for line in DOCKERFILE.read_text().splitlines()
            if line.startswith("USER ")
        ]
        assert users, "the Dockerfile never drops privilege"
        assert users[-1] not in ("root", "0"), "the image ends as root"

    def test_it_declares_an_entrypoint(self) -> None:
        assert "ENTRYPOINT" in DOCKERFILE.read_text()


class TestTheComposeStack:
    def test_it_defines_the_engine_and_the_dashboard(self) -> None:
        text = COMPOSE.read_text()
        assert "engine:" in text
        assert "dashboard:" in text

    def test_the_sensor_is_optional(self) -> None:
        """It needs NET_ADMIN, so it must not start by default."""
        text = COMPOSE.read_text()
        assert "sensor:" in text
        assert "profiles:" in text

    def test_no_default_service_is_privileged(self) -> None:
        import yaml

        stack = yaml.safe_load(COMPOSE.read_text())
        for name, service in stack["services"].items():
            if service.get("profiles"):
                continue
            assert not service.get("privileged"), f"{name} runs privileged by default"


@pytest.fixture(scope="module")
def image() -> str:
    available, detail = docker_available()
    if not available:
        pytest.skip(f"Docker unavailable: {detail}")
    docker("build", "-f", str(DOCKERFILE), "-t", IMAGE, str(REPO_ROOT), timeout=3600)
    return IMAGE


class TestTheImageBehaves:
    def test_it_runs_as_a_non_root_user(self, image: str) -> None:
        result = docker("run", "--rm", "--entrypoint", "id", image, "-u", timeout=120)
        assert result.stdout.strip() != "0", "the container runs as root"

    def test_the_user_has_a_name_not_just_a_number(self, image: str) -> None:
        result = docker("run", "--rm", "--entrypoint", "id", image, "-un", timeout=120)
        assert result.stdout.strip() not in ("", "root")

    def test_it_is_under_a_gigabyte(self, image: str) -> None:
        result = docker("image", "inspect", image, "--format", "{{.Size}}", timeout=60)
        size = int(result.stdout.strip())
        assert size < ONE_GIGABYTE, f"image is {size / 1024**3:.2f} GB"

    def test_the_cli_answers(self, image: str) -> None:
        result = docker("run", "--rm", image, "version", timeout=120)
        assert result.stdout.strip()

    def test_it_analyses_a_capture_with_no_network(self, image: str, tmp_path: Path) -> None:
        """--network none is the strongest form of the air-gap claim."""
        captures = sorted(DEMO.glob("*.pcap"))
        if not captures:
            pytest.skip("no demo capture is present")
        outputs = tmp_path / "out"
        outputs.mkdir()
        outputs.chmod(0o777)

        docker(
            "run",
            "--rm",
            "--network",
            "none",
            "-v",
            f"{captures[0]}:/data/capture.pcap:ro",
            "-v",
            f"{outputs}:/out",
            image,
            "analyse",
            "/data/capture.pcap",
            "--json",
            "/out/report.json",
            timeout=600,
        )

        payload = json.loads((outputs / "report.json").read_text())
        assert payload["metadata"]["source"]

    def test_every_subcommand_runs_in_the_image(self, image: str) -> None:
        """`sentinel remediate` was broken in every installed copy and nothing noticed.

        It imported TunnelConfig from `testbed`, which is excluded from the image, so it
        raised ModuleNotFoundError in the container while the whole unit suite passed
        from a checkout. Click resolves subcommands lazily, so `--help` did not touch the
        broken import either. Running each one is the check that catches this.
        """
        for command in ("analyse", "inventory", "remediate", "scan", "watch", "dataset", "model"):
            result = docker("run", "--rm", image, command, "--help", check=False, timeout=120)
            assert result.returncode == 0, (
                f"`sentinel {command} --help` exited {result.returncode} in the image:\n"
                f"{result.stdout[-800:]}{result.stderr[-800:]}"
            )

    def test_it_generates_a_change_package_with_no_network(
        self, image: str, tmp_path: Path
    ) -> None:
        """The behavioural half: --help imports the module, this one runs it."""
        captures = sorted(DEMO.glob("*.pcap"))
        if not captures:
            pytest.skip("no demo capture is present")
        estate = DEMO / "04-estate.pcap"
        source = estate if estate.is_file() else captures[0]

        outputs = tmp_path / "package"
        outputs.mkdir()
        outputs.chmod(0o777)

        docker(
            "run",
            "--rm",
            "--network",
            "none",
            "-v",
            f"{source}:/data/capture.pcap:ro",
            "-v",
            f"{outputs}:/out",
            image,
            "remediate",
            "/data/capture.pcap",
            "--vendor",
            "strongswan",
            "--out",
            "/out",
            timeout=600,
        )

        generated = sorted(outputs.iterdir())
        assert generated, "the container produced no configuration"

        # A substring check for "secret" matches the comment saying there is none, so
        # look for an assignment carrying a value.
        assignment = re.compile(r"^\s*(secret|psk|pre-?shared[_ ]?key)\s*[=:]\s*\S", re.I | re.M)
        for configuration in generated:
            text = configuration.read_text()
            assert not assignment.search(text), f"{configuration.name} carries a secret"
            assert "swanctl" in configuration.name or text.strip()

    def test_the_container_cannot_write_to_its_own_filesystem_root(self, image: str) -> None:
        result = docker(
            "run",
            "--rm",
            "--entrypoint",
            "sh",
            image,
            "-c",
            "touch /probe 2>&1 || echo REFUSED",
            check=False,
            timeout=120,
        )
        assert "REFUSED" in result.stdout or "Permission denied" in result.stdout


@pytest.fixture(scope="module")
def bundle(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Build the offline bundle once. Needs the network; the *install* must not."""
    destination = tmp_path_factory.mktemp("bundle")
    result = subprocess.run(
        [str(BUNDLE), "--output", str(destination), "--no-image"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=2400,
        check=False,
    )
    if result.returncode != 0:
        pytest.skip(f"the bundle could not be built here: {result.stderr[-800:]}")
    tarballs = sorted(destination.glob("*.tar.gz"))
    assert tarballs, f"the script produced no tarball: {result.stdout[-800:]}"
    return tarballs[0]


class TestTheOfflineBundle:
    def test_it_contains_wheels_an_installer_and_a_manifest(self, bundle: Path) -> None:
        with tarfile.open(bundle) as archive:
            names = archive.getnames()
        assert any(name.endswith(".whl") for name in names), "no wheels in the bundle"
        assert any(name.endswith("install.sh") for name in names)
        assert any(name.endswith("MANIFEST.txt") for name in names)

    def test_the_project_wheel_is_in_it(self, bundle: Path) -> None:
        with tarfile.open(bundle) as archive:
            assert any(
                "ipsec_sentinel-" in name and name.endswith(".whl") for name in archive.getnames()
            )

    def test_the_manifest_checksums_match_the_files(self, bundle: Path, tmp_path: Path) -> None:
        """A bundle whose manifest does not describe it cannot be verified on arrival."""
        with tarfile.open(bundle) as archive:
            archive.extractall(tmp_path, filter="data")
        root = next(path for path in tmp_path.iterdir() if path.is_dir())

        manifest = (root / "MANIFEST.txt").read_text().splitlines()
        entries = [line.split(maxsplit=1) for line in manifest if line and not line.startswith("#")]
        assert entries, "the manifest lists nothing"

        for digest, relative in entries:
            target = root / relative
            assert target.is_file(), f"the manifest names a missing file: {relative}"
            assert hashlib.sha256(target.read_bytes()).hexdigest() == digest, relative

    @pytest.mark.slow
    def test_it_installs_with_no_package_index(self, bundle: Path, tmp_path: Path) -> None:
        """The whole point of the bundle, checked the only way that means anything."""
        with tarfile.open(bundle) as archive:
            archive.extractall(tmp_path, filter="data")
        root = next(path for path in tmp_path.iterdir() if path.is_dir())
        prefix = tmp_path / "install"

        environment = {
            **os.environ,
            # Any resolution that escaped --no-index would try this and fail loudly.
            "PIP_INDEX_URL": "http://127.0.0.1:9/simple",
            "PIP_RETRIES": "0",
            "PIP_TIMEOUT": "1",
        }
        result = subprocess.run(
            [
                "bash",
                str(root / "install.sh"),
                "--offline",
                "--prefix",
                str(prefix),
                # The bundle's wheels are compiled for this interpreter. The host's bare
                # `python3` is a different version here, which is exactly the situation
                # the refusal below exists for.
                "--python",
                sys.executable,
            ],
            cwd=root,
            capture_output=True,
            text=True,
            env=environment,
            timeout=1800,
            check=False,
        )
        assert result.returncode == 0, result.stdout[-2000:] + result.stderr[-2000:]

        sentinel = prefix / "bin" / "sentinel"
        assert sentinel.is_file(), f"no entry point at {sentinel}"
        version = subprocess.run(
            [str(sentinel), "version"], capture_output=True, text=True, timeout=120, check=False
        )
        assert version.returncode == 0, version.stderr
        assert version.stdout.strip()

    def test_it_records_the_interpreter_it_was_built_for(
        self, bundle: Path, tmp_path: Path
    ) -> None:
        with tarfile.open(bundle) as archive:
            archive.extractall(tmp_path, filter="data")
        root = next(path for path in tmp_path.iterdir() if path.is_dir())

        declared = json.loads((root / "BUNDLE.json").read_text())

        assert declared["python_version"] == f"{sys.version_info.major}.{sys.version_info.minor}"
        assert declared["wheels"] > 0
        assert declared["platform"]

    def test_the_name_carries_the_interpreter_and_the_platform(self, bundle: Path) -> None:
        """A directory of bundles is unusable if they are all named the same thing."""
        assert f"py{sys.version_info.major}.{sys.version_info.minor}" in bundle.name

    def test_it_refuses_an_interpreter_it_was_not_built_for(
        self, bundle: Path, tmp_path: Path
    ) -> None:
        """The failure this replaces was a mid-resolve "no matching distribution", which
        reads as a corrupt bundle rather than as the wrong Python."""
        with tarfile.open(bundle) as archive:
            archive.extractall(tmp_path, filter="data")
        root = next(path for path in tmp_path.iterdir() if path.is_dir())

        declared = json.loads((root / "BUNDLE.json").read_text())
        declared["python_version"] = "3.99"
        (root / "BUNDLE.json").write_text(json.dumps(declared))

        result = subprocess.run(
            [
                "bash",
                str(root / "install.sh"),
                "--offline",
                "--prefix",
                str(tmp_path / "refused"),
                "--python",
                sys.executable,
            ],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )

        assert result.returncode != 0
        combined = result.stdout + result.stderr
        assert "3.99" in combined, "the refusal must name the version the bundle wants"
        assert not (tmp_path / "refused").exists(), "it built a virtualenv before refusing"

    def test_the_installer_refuses_a_python_that_is_too_old(self, tmp_path: Path) -> None:
        """A partial install on 3.10 is worse than a refusal."""
        fake = tmp_path / "python3"
        fake.write_text("#!/bin/sh\necho 'Python 3.9.7'\n")
        fake.chmod(0o755)

        result = subprocess.run(
            ["bash", str(INSTALL), "--python", str(fake), "--prefix", str(tmp_path / "p")],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        assert result.returncode != 0
        assert "3.11" in (result.stdout + result.stderr)


class TestTheBundleIsHonestAboutItsPlatform:
    def test_the_script_records_the_platform_it_was_built_for(self) -> None:
        """A macOS bundle does not install on Linux, and must not pretend otherwise."""
        text = BUNDLE.read_text()
        assert "--platform" in text, "the script offers no way to build for another platform"

    def test_the_documentation_says_so(self) -> None:
        deployment = REPO_ROOT / "docs" / "DEPLOYMENT.md"
        if not deployment.is_file():
            pytest.skip("DEPLOYMENT.md arrives with Step 11.6")
        assert "platform" in deployment.read_text().lower()


def test_the_helpers_this_module_needs_are_here() -> None:
    """Guards the skip paths above: a missing tool must skip, never silently pass."""
    assert shutil.which("bash")
    assert sys.version_info >= (3, 11)
