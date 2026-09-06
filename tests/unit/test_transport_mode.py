"""Tests for transport-mode support (closing the M7 mode-inference gap).

Transport mode protects the IPsec peers themselves rather than hosts behind them. The
first attempt to capture it drove traffic host-to-host, which transport mode routes
around unprotected — producing cells with a healthy SA and zero ESP. These tests pin
the endpoint resolution that fixes it, and the constraints that keep the two matrices
from drifting into each other.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from testbed.orchestrate.matrix import expand_matrix
from testbed.traffic.base import RunContext

MAIN_MATRIX = Path("testbed/configs/matrix.yaml")
TRANSPORT_MATRIX = Path("testbed/configs/matrix_transport.yaml")


def context(mode: str = "tunnel") -> RunContext:
    return RunContext(
        project="p",
        left_gateway="left-gw",
        right_gateway="right-gw",
        left_host="left-host",
        right_host="right-host",
        left_host_ip="10.110.0.10",
        right_host_ip="10.120.0.10",
        out_dir=Path(),
        mode=mode,
        left_transit_ip="10.100.0.2",
        right_transit_ip="10.100.0.3",
    )


class TestEndpointResolution:
    def test_tunnel_mode_drives_the_hosts(self) -> None:
        """Traffic a gateway originates never crosses its own protected interface."""
        ctx = context("tunnel")
        assert ctx.source_container == "left-host"
        assert ctx.target_ip == "10.120.0.10"
        assert ctx.is_transport is False

    def test_transport_mode_drives_the_gateways(self) -> None:
        """Transport protects the peers themselves; host traffic routes around it."""
        ctx = context("transport")
        assert ctx.source_container == "left-gw"
        assert ctx.target_container == "right-gw"
        assert ctx.target_ip == "10.100.0.3"
        assert ctx.source_ip == "10.100.0.2"
        assert ctx.is_transport is True

    def test_the_default_mode_is_tunnel(self) -> None:
        """Every existing caller must keep the behaviour it had."""
        ctx = RunContext(
            project="p",
            left_gateway="lg",
            right_gateway="rg",
            left_host="lh",
            right_host="rh",
            left_host_ip="10.110.0.10",
            right_host_ip="10.120.0.10",
            out_dir=Path(),
        )
        assert ctx.mode == "tunnel"
        assert ctx.source_container == "lh"

    def test_the_endpoints_differ_between_modes(self) -> None:
        assert context("tunnel").source_container != context("transport").source_container
        assert context("tunnel").target_ip != context("transport").target_ip


class TestGeneratorsUseTheModeAwareEndpoints:
    """A generator addressing left_host directly would silently work only in tunnel mode."""

    @pytest.mark.parametrize("module", ["icmp", "voip", "replay"])
    def test_the_peer_capable_generators_do_not_hardcode_hosts(self, module: str) -> None:
        source = Path(f"testbed/traffic/{module}.py").read_text()
        assert "ctx.left_host" not in source and "_ctx.left_host" not in source
        assert "right_host_ip" not in source

    @pytest.mark.parametrize("module", ["icmp", "voip", "replay"])
    def test_they_use_the_resolved_endpoints(self, module: str) -> None:
        source = Path(f"testbed/traffic/{module}.py").read_text()
        assert "source_container" in source or "target_container" in source
        assert "target_ip" in source or "source_ip" in source


class TestMatrixSeparation:
    def test_the_main_matrix_stays_tunnel_only(self) -> None:
        """Sampling transport into it would orphan configurations the corpus was built on."""
        configs = [lc.config for lc in expand_matrix(MAIN_MATRIX)]
        assert {c.mode for c in configs} == {"tunnel"}

    def test_the_transport_matrix_is_transport_only(self) -> None:
        configs = [lc.config for lc in expand_matrix(TRANSPORT_MATRIX)]
        assert {c.mode for c in configs} == {"transport"}

    def test_the_anchors_are_pinned_to_transport(self) -> None:
        """Without an explicit mode they inherit tunnel and leak into the wrong matrix."""
        loaded = yaml.safe_load(TRANSPORT_MATRIX.read_text())
        anchors = loaded["sampling"]["must_include"]
        assert anchors
        assert all(a.get("mode") == "transport" for a in anchors)

    def test_the_configuration_ids_do_not_collide(self) -> None:
        """Mode is part of the configuration, so the two sets are disjoint by construction."""
        main = {lc.config.config_id() for lc in expand_matrix(MAIN_MATRIX)}
        transport = {lc.config.config_id() for lc in expand_matrix(TRANSPORT_MATRIX)}
        assert not (main & transport)

    def test_the_existing_corpus_configurations_are_preserved(self) -> None:
        """The M3-verified corpus must survive the addition unchanged."""
        import json

        sweep = Path("data/raw/sweep")
        if not sweep.exists():
            pytest.skip("no sweep captures present")
        existing = {json.loads(m.read_text())["config_id"] for m in sweep.glob("*/manifest.json")}
        tunnel_configs = {lc.config.config_id() for lc in expand_matrix(MAIN_MATRIX)}
        transport_configs = {lc.config.config_id() for lc in expand_matrix(TRANSPORT_MATRIX)}
        orphaned = existing - tunnel_configs - transport_configs
        assert not orphaned, f"{len(orphaned)} corpus configurations are in no matrix"


class TestTransportGeneratorSet:
    def test_replay_is_excluded_with_the_reason_recorded(self) -> None:
        """tcpreplay injects at layer 2, bypassing the kernel's XFRM output path."""
        from scripts.run_transport_sweep import TRANSPORT_GENERATORS

        assert "replay" not in TRANSPORT_GENERATORS
        source = Path("scripts/run_transport_sweep.py").read_text()
        assert "XFRM output" in source, "the exclusion must record why"
        assert "layer 2" in source

    def test_only_peer_capable_generators_are_swept(self) -> None:
        from scripts.run_transport_sweep import TRANSPORT_GENERATORS

        assert set(TRANSPORT_GENERATORS) == {"icmp", "voip"}

    def test_the_gateway_image_carries_the_traffic_tools(self) -> None:
        """A transport cell makes the gateway a traffic source as well as an endpoint."""
        dockerfile = Path("testbed/compose/Dockerfile.strongswan").read_text()
        assert "python3-minimal" in dockerfile
        assert "/opt/sentinel/" in dockerfile
