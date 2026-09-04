"""Ground truth harvested from a live tunnel (build plan Step 1.6).

The unit tests parse recorded fixtures; this proves the same parsers work against a
daemon and kernel that are actually running, which is the only way to know the
fixtures have not drifted from reality.
"""

from __future__ import annotations

import secrets

import pytest

from testbed.orchestrate.config_gen import TunnelConfig
from testbed.orchestrate.groundtruth import build_manifest, harvest_swanctl, harvest_xfrm_state
from tests.fixtures.dockerctl import compose, compose_project, exec_in

from .conftest import PAIR_COMPOSE

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("strongswan_image")]

# The configuration the checked-in swanctl.conf actually implements.
DEPLOYED = TunnelConfig(
    ike_version="ikev2",
    encryption="aes256gcm16",
    integrity=None,
    prf="prfsha384",
    dh_group="ecp384",
    pfs=True,
    child_dh_group="ecp384",
    mode="tunnel",
    ip_version=4,
    ike_lifetime_s=14400,
    child_lifetime_s=3600,
)


def container_id(project: str, service: str) -> str:
    cid = compose(PAIR_COMPOSE, project, "ps", "-q", service).stdout.strip()
    assert cid, f"no container for {service}"
    return cid


def test_harvested_encryption_matches_what_was_configured() -> None:
    with compose_project(PAIR_COMPOSE, env={"SENTINEL_PSK": secrets.token_hex(24)}) as project:
        left = container_id(project, "left")
        exec_in(left, "swanctl", "--initiate", "--child", "net-net", timeout=90)
        ike, child = harvest_swanctl(left)
        assert ike.established is True
        assert ike.encryption == "AES_GCM_16"
        assert ike.encryption_keylen == 256
        assert ike.dh_group == "ECP_384"
        assert child is not None
        assert child.mode == "tunnel"


def test_kernel_and_daemon_agree() -> None:
    """Two independent observations of the same reality must not disagree."""
    with compose_project(PAIR_COMPOSE, env={"SENTINEL_PSK": secrets.token_hex(24)}) as project:
        left = container_id(project, "left")
        exec_in(left, "swanctl", "--initiate", "--child", "net-net", timeout=90)
        _, child = harvest_swanctl(left)
        kernel = harvest_xfrm_state(left)

        assert child is not None
        assert len(kernel) == 2, "one kernel SA per direction"
        assert all(sa.mode == "tunnel" for sa in kernel)
        kernel_spis = {sa.spi for sa in kernel}
        assert f"0x{child.spi_in}" in kernel_spis
        assert f"0x{child.spi_out}" in kernel_spis


def test_manifest_from_a_live_run_matches_intent() -> None:
    with compose_project(PAIR_COMPOSE, env={"SENTINEL_PSK": secrets.token_hex(24)}) as project:
        left = container_id(project, "left")
        exec_in(left, "swanctl", "--initiate", "--child", "net-net", timeout=90)
        manifest = build_manifest(DEPLOYED, harvest_swanctl(left), harvest_xfrm_state(left))
        assert manifest.negotiation_matched_intent is True, manifest.mismatches


def test_manifest_detects_a_deliberate_intent_mismatch() -> None:
    """Control: the flag must be able to go False against a real run."""
    with compose_project(PAIR_COMPOSE, env={"SENTINEL_PSK": secrets.token_hex(24)}) as project:
        left = container_id(project, "left")
        exec_in(left, "swanctl", "--initiate", "--child", "net-net", timeout=90)
        wrong = DEPLOYED.with_(encryption="3des", integrity="md5")
        manifest = build_manifest(wrong, harvest_swanctl(left), harvest_xfrm_state(left))
        assert manifest.negotiation_matched_intent is False
        assert any("encryption" in m for m in manifest.mismatches)


def test_live_manifest_contains_no_key_material() -> None:
    import re

    with compose_project(PAIR_COMPOSE, env={"SENTINEL_PSK": secrets.token_hex(24)}) as project:
        left = container_id(project, "left")
        exec_in(left, "swanctl", "--initiate", "--child", "net-net", timeout=90)
        manifest = build_manifest(DEPLOYED, harvest_swanctl(left), harvest_xfrm_state(left))
        payload = manifest.model_dump_json()
        assert not re.search(r"0x[0-9a-f]{16,}", payload), "key material leaked into manifest"
