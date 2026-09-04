"""Tests for tunnel configuration templating (build plan Step 1.4)."""

from __future__ import annotations

import re

import pytest

from testbed.orchestrate.config_gen import (
    AEAD_ENCRYPTIONS,
    TunnelConfig,
    is_aead,
    render_swanctl_conf,
)


def cfg(**kw: object) -> TunnelConfig:
    base: dict[str, object] = {
        "ike_version": "ikev2",
        "encryption": "aes256gcm16",
        "integrity": None,
        "prf": "prfsha384",
        "dh_group": "ecp384",
        "pfs": True,
        "child_dh_group": "ecp384",
        "mode": "tunnel",
        "ip_version": 4,
        "ike_lifetime_s": 14400,
        "child_lifetime_s": 3600,
    }
    base.update(kw)
    return TunnelConfig(**base)  # type: ignore[arg-type]


class TestAEAD:
    @pytest.mark.parametrize("enc", sorted(AEAD_ENCRYPTIONS))
    def test_known_aead_ciphers_are_recognised(self, enc: str) -> None:
        assert is_aead(enc) is True

    @pytest.mark.parametrize("enc", ["aes256", "aes128", "3des", "des"])
    def test_non_aead_ciphers_are_recognised(self, enc: str) -> None:
        assert is_aead(enc) is False

    def test_aead_proposal_has_no_separate_integrity_algorithm(self) -> None:
        proposal = cfg(encryption="aes256gcm16", integrity=None).proposal_string()
        assert proposal == "aes256gcm16-prfsha384-ecp384"
        for integ in ("sha256", "sha384", "sha1", "md5"):
            assert f"-{integ}-" not in proposal

    def test_aead_esp_proposal_has_no_integrity_either(self) -> None:
        assert cfg().esp_proposal_string() == "aes256gcm16-ecp384"

    def test_aead_paired_with_an_integrity_algorithm_is_rejected(self) -> None:
        """AEAD carries its own integrity; pairing one is a configuration error."""
        with pytest.raises(ValueError, match="AEAD"):
            cfg(encryption="aes256gcm16", integrity="sha256")


class TestNonAEAD:
    def test_non_aead_requires_an_integrity_algorithm(self) -> None:
        with pytest.raises(ValueError, match="integrity"):
            cfg(encryption="aes128", integrity=None)

    def test_non_aead_proposal_includes_integrity(self) -> None:
        proposal = cfg(
            encryption="aes128", integrity="sha256", prf="prfsha256", dh_group="modp2048"
        ).proposal_string()
        assert proposal == "aes128-sha256-prfsha256-modp2048"

    def test_non_aead_esp_proposal_includes_integrity(self) -> None:
        c = cfg(
            encryption="aes128",
            integrity="sha256",
            prf="prfsha256",
            dh_group="modp2048",
            child_dh_group="modp2048",
        )
        assert c.esp_proposal_string() == "aes128-sha256-modp2048"


class TestPFS:
    def test_pfs_false_omits_the_child_dh_group_from_the_esp_proposal(self) -> None:
        c = cfg(pfs=False, child_dh_group=None)
        assert c.esp_proposal_string() == "aes256gcm16"
        assert "ecp384" not in c.esp_proposal_string()

    def test_pfs_false_omits_the_group_even_if_one_was_supplied(self) -> None:
        assert cfg(pfs=False, child_dh_group="ecp384").esp_proposal_string() == "aes256gcm16"

    def test_pfs_true_defaults_the_child_group_to_the_ike_group(self) -> None:
        assert cfg(pfs=True, child_dh_group=None).esp_proposal_string() == "aes256gcm16-ecp384"

    def test_pfs_true_honours_a_distinct_child_group(self) -> None:
        c = cfg(pfs=True, dh_group="ecp384", child_dh_group="modp2048")
        assert c.esp_proposal_string() == "aes256gcm16-modp2048"


class TestAggressiveMode:
    def test_aggressive_with_ikev2_is_rejected(self) -> None:
        """IKEv2 has no aggressive mode; asking for one is meaningless."""
        with pytest.raises(ValueError, match=r"[Aa]ggressive"):
            cfg(ike_version="ikev2", aggressive=True)

    def test_aggressive_with_ikev1_is_allowed(self) -> None:
        assert cfg(ike_version="ikev1", aggressive=True).aggressive is True

    def test_ikev1_without_aggressive_is_allowed(self) -> None:
        assert cfg(ike_version="ikev1").aggressive is False


class TestConfigId:
    def test_is_stable_across_calls(self) -> None:
        assert cfg().config_id() == cfg().config_id()

    def test_is_stable_across_separate_equal_instances(self) -> None:
        assert cfg(dh_group="modp2048").config_id() == cfg(dh_group="modp2048").config_id()

    def test_differs_for_different_configurations(self) -> None:
        ids = {
            cfg().config_id(),
            cfg(dh_group="modp2048").config_id(),
            cfg(pfs=False, child_dh_group=None).config_id(),
            cfg(mode="transport").config_id(),
            cfg(ip_version=6).config_id(),
            cfg(ike_lifetime_s=28800).config_id(),
        }
        assert len(ids) == 6, "config_id collides across materially different configs"

    def test_is_filename_safe(self) -> None:
        assert re.fullmatch(r"[0-9a-f]{12}", cfg().config_id())

    def test_does_not_depend_on_process_hash_randomisation(self) -> None:
        """A PYTHONHASHSEED-dependent id would break sweep resumability."""
        import subprocess
        import sys

        code = (
            "from testbed.orchestrate.config_gen import TunnelConfig;"
            "print(TunnelConfig(ike_version='ikev2', encryption='aes256gcm16',"
            "integrity=None, prf='prfsha384', dh_group='ecp384', pfs=True,"
            "child_dh_group='ecp384', mode='tunnel', ip_version=4,"
            "ike_lifetime_s=14400, child_lifetime_s=3600).config_id())"
        )
        outs = {
            subprocess.run(
                [sys.executable, "-c", code],
                capture_output=True,
                text=True,
                check=True,
                env={"PYTHONHASHSEED": seed, "PATH": "/usr/bin:/bin"},
            ).stdout.strip()
            for seed in ("0", "1", "12345")
        }
        assert len(outs) == 1, f"config_id varies with PYTHONHASHSEED: {outs}"
        assert outs.pop() == cfg().config_id()


class TestRendering:
    def test_renders_both_roles_with_mirrored_addresses(self) -> None:
        left = render_swanctl_conf(cfg(), "left")
        right = render_swanctl_conf(cfg(), "right")
        assert "local_addrs  = 10.100.0.2" in left
        assert "remote_addrs = 10.100.0.3" in left
        assert "local_addrs  = 10.100.0.3" in right
        assert "remote_addrs = 10.100.0.2" in right

    def test_traffic_selectors_are_mirrored(self) -> None:
        left = render_swanctl_conf(cfg(), "left")
        right = render_swanctl_conf(cfg(), "right")
        assert "local_ts  = 10.1.0.0/24" in left
        assert "remote_ts = 10.2.0.0/24" in left
        assert "local_ts  = 10.2.0.0/24" in right
        assert "remote_ts = 10.1.0.0/24" in right

    def test_identities_are_mirrored(self) -> None:
        left = render_swanctl_conf(cfg(), "left")
        assert re.search(r"local \{\s+auth = psk\s+id = left", left)
        assert re.search(r"remote \{\s+auth = psk\s+id = right", left)

    def test_contains_no_secret(self) -> None:
        """The PSK is injected at runtime; it must never be rendered into a config."""
        rendered = render_swanctl_conf(cfg(), "left")
        assert "secret" not in rendered.lower() or "include" in rendered
        assert "secrets {" not in rendered

    def test_braces_balance(self) -> None:
        rendered = render_swanctl_conf(cfg(), "left")
        assert rendered.count("{") == rendered.count("}")

    def test_syntax_is_shaped_like_swanctl_conf(self) -> None:
        rendered = render_swanctl_conf(cfg(), "left")
        assert re.search(r"^connections \{$", rendered, re.M)
        assert re.search(r"^\s+children \{$", rendered, re.M)
        assert re.search(r"^\s+proposals = \S+$", rendered, re.M)
        assert re.search(r"^\s+esp_proposals = \S+$", rendered, re.M)
        for line in rendered.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                legal = (
                    stripped.endswith(("{", "}"))
                    or "=" in stripped
                    or stripped.startswith("include ")
                )
                assert legal, f"odd line: {line!r}"

    def test_ikev2_renders_version_2(self) -> None:
        assert "version = 2" in render_swanctl_conf(cfg(), "left")

    def test_ikev1_renders_version_1(self) -> None:
        assert "version = 1" in render_swanctl_conf(cfg(ike_version="ikev1"), "left")

    def test_aggressive_mode_is_rendered_only_for_ikev1(self) -> None:
        aggressive = render_swanctl_conf(cfg(ike_version="ikev1", aggressive=True), "left")
        plain = render_swanctl_conf(cfg(ike_version="ikev1"), "left")
        assert "aggressive = yes" in aggressive
        assert "aggressive = yes" not in plain

    def test_mode_is_rendered(self) -> None:
        assert "mode = transport" in render_swanctl_conf(cfg(mode="transport"), "left")
        assert "mode = tunnel" in render_swanctl_conf(cfg(mode="tunnel"), "left")

    def test_lifetimes_are_rendered(self) -> None:
        rendered = render_swanctl_conf(cfg(ike_lifetime_s=28800, child_lifetime_s=1800), "left")
        assert "over_time" in rendered or "rekey_time" in rendered
        assert "28800" in rendered
        assert "1800" in rendered

    def test_ipv6_topology_renders_v6_addresses(self) -> None:
        rendered = render_swanctl_conf(cfg(ip_version=6), "left")
        assert "fd00:" in rendered

    def test_unknown_role_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="role"):
            render_swanctl_conf(cfg(), "middle")  # type: ignore[arg-type]
