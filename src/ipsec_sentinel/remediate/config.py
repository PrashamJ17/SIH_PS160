"""The tunnel configuration model, and strongSwan rendering for it.

``TunnelConfig`` is one point in the IPsec parameter space, validated on construction:
AEAD ciphers carry their own integrity and must not be paired with a separate algorithm,
non-AEAD ciphers cannot go without one, and IKEv2 has no aggressive mode. Every vendor
generator in this package translates from it, and the testbed sweeps over it.

**This module lived in ``testbed/`` until Step 11.7, and that was a real defect.** The
testbed is the Docker environment that builds the dataset; it is excluded from the wheel,
the container image and the offline bundle. With the model there, ``sentinel remediate``
and ``sentinel watch`` imported a package that is not shipped, so both worked from a
checkout and raised ``ModuleNotFoundError`` in every installed copy. The dependency
pointed from the product to the test harness, which is backwards: a tunnel configuration
is a product concept that the testbed happens to also consume.

``testbed.orchestrate.config_gen`` re-exports these names, so the harness is unchanged.

Rendered configurations contain **no secret**. The pre-shared key is supplied at run time
through the environment and written to ``conf.d/psk.conf`` by the container entrypoint, so
no credential is ever written to disk in this repository.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from typing import Final, Literal

Role = Literal["left", "right"]
IKEVersion = Literal["ikev1", "ikev2"]
Mode = Literal["tunnel", "transport"]
IPVersion = Literal[4, 6]

# Ciphers that authenticate as well as encrypt. RFC 8221 prefers these precisely
# because a separate integrity algorithm is one more thing to get wrong.
AEAD_ENCRYPTIONS: Final[frozenset[str]] = frozenset(
    {
        "aes128gcm8",
        "aes128gcm12",
        "aes128gcm16",
        "aes192gcm8",
        "aes192gcm12",
        "aes192gcm16",
        "aes256gcm8",
        "aes256gcm12",
        "aes256gcm16",
        "aes128ccm8",
        "aes128ccm12",
        "aes128ccm16",
        "aes256ccm8",
        "aes256ccm12",
        "aes256ccm16",
        "chacha20poly1305",
    }
)


def is_aead(encryption: str) -> bool:
    """Whether a strongSwan cipher name denotes an AEAD construction."""
    return encryption in AEAD_ENCRYPTIONS


@dataclass(frozen=True)
class Topology:
    """Addresses the rendered configuration refers to.

    Carried separately from the crypto parameters so the Step 3.2 sweep can place
    concurrent pairs on distinct subnets without perturbing any config identity.
    """

    left_transit: str
    right_transit: str
    left_subnet: str
    right_subnet: str


DEFAULT_TOPOLOGY_V4: Final = Topology(
    left_transit="10.100.0.2",
    right_transit="10.100.0.3",
    left_subnet="10.1.0.0/24",
    right_subnet="10.2.0.0/24",
)

DEFAULT_TOPOLOGY_V6: Final = Topology(
    left_transit="fd00:100::2",
    right_transit="fd00:100::3",
    left_subnet="fd00:1::/64",
    right_subnet="fd00:2::/64",
)


@dataclass(frozen=True)
class TunnelConfig:
    """One point in the configuration matrix.

    Validated on construction, so an impossible combination cannot reach the sweep and
    waste a container pair discovering it.
    """

    ike_version: IKEVersion
    encryption: str
    integrity: str | None
    prf: str
    dh_group: str
    pfs: bool
    child_dh_group: str | None
    mode: Mode
    ip_version: IPVersion
    ike_lifetime_s: int
    child_lifetime_s: int
    aggressive: bool = False

    def __post_init__(self) -> None:
        if is_aead(self.encryption):
            if self.integrity is not None:
                raise ValueError(
                    f"{self.encryption} is an AEAD cipher and carries its own integrity; "
                    f"pairing it with {self.integrity!r} is a configuration error"
                )
        elif self.integrity is None:
            raise ValueError(
                f"{self.encryption} is not AEAD and requires a separate integrity "
                f"algorithm, but integrity is None"
            )
        if self.aggressive and self.ike_version != "ikev1":
            raise ValueError(
                "aggressive mode exists only in IKEv1; "
                f"got aggressive=True with ike_version={self.ike_version!r}"
            )
        if self.ike_lifetime_s <= 0 or self.child_lifetime_s <= 0:
            raise ValueError("SA lifetimes must be positive")

    @property
    def effective_child_dh_group(self) -> str | None:
        """The DH group the ESP proposal will actually carry.

        ``None`` when PFS is off — that absence is exactly what makes PFS-01 fire.
        """
        if not self.pfs:
            return None
        return self.child_dh_group or self.dh_group

    def proposal_string(self) -> str:
        """strongSwan IKE proposal: encryption[-integrity]-prf-dhgroup."""
        parts = [self.encryption]
        if not is_aead(self.encryption) and self.integrity is not None:
            parts.append(self.integrity)
        parts.append(self.prf)
        parts.append(self.dh_group)
        return "-".join(parts)

    def esp_proposal_string(self) -> str:
        """strongSwan ESP proposal: encryption[-integrity][-dhgroup]. No PRF."""
        parts = [self.encryption]
        if not is_aead(self.encryption) and self.integrity is not None:
            parts.append(self.integrity)
        child_group = self.effective_child_dh_group
        if child_group is not None:
            parts.append(child_group)
        return "-".join(parts)

    def config_id(self) -> str:
        """A stable, filename-safe identity for this configuration.

        Derived from a SHA-256 of the canonical field ordering rather than ``hash()``,
        which is randomised per process and would break sweep resumability across
        restarts.
        """
        canonical = "|".join(
            str(x)
            for x in (
                self.ike_version,
                self.encryption,
                self.integrity,
                self.prf,
                self.dh_group,
                self.pfs,
                self.child_dh_group,
                self.mode,
                self.ip_version,
                self.ike_lifetime_s,
                self.child_lifetime_s,
                self.aggressive,
            )
        )
        return hashlib.sha256(canonical.encode()).hexdigest()[:12]

    def with_(self, **changes: object) -> TunnelConfig:
        """Return a copy with fields replaced, re-running validation."""
        return replace(self, **changes)  # type: ignore[arg-type]


def default_topology(ip_version: IPVersion) -> Topology:
    return DEFAULT_TOPOLOGY_V4 if ip_version == 4 else DEFAULT_TOPOLOGY_V6


def render_swanctl_conf(
    cfg: TunnelConfig,
    role: Role,
    topology: Topology | None = None,
) -> str:
    """Render a complete ``swanctl.conf`` for one end of the tunnel.

    Deliberately emits no ``secrets`` section: the PSK arrives at run time via
    ``conf.d/psk.conf``, which the trailing ``include`` picks up.
    """
    if role not in ("left", "right"):
        raise ValueError(f"role must be 'left' or 'right', got {role!r}")

    topo = topology or default_topology(cfg.ip_version)
    if role == "left":
        local_addr, remote_addr = topo.left_transit, topo.right_transit
        local_ts, remote_ts = topo.left_subnet, topo.right_subnet
        local_id, remote_id = "left", "right"
    else:
        local_addr, remote_addr = topo.right_transit, topo.left_transit
        local_ts, remote_ts = topo.right_subnet, topo.left_subnet
        local_id, remote_id = "right", "left"

    # Transport mode protects traffic between the two hosts themselves, so its traffic
    # selectors are the peer addresses. Pointing them at the protected subnets, as
    # tunnel mode does, yields a configuration that cannot establish.
    if cfg.mode == "transport":
        host = "/128" if cfg.ip_version == 6 else "/32"
        local_ts, remote_ts = f"{local_addr}{host}", f"{remote_addr}{host}"

    version = "1" if cfg.ike_version == "ikev1" else "2"
    lines = [
        f"# Generated by config_gen for config_id={cfg.config_id()}",
        "# No secret appears here: the PSK is written to conf.d/psk.conf at run time.",
        "",
        "connections {",
        "    net-net {",
        f"        local_addrs  = {local_addr}",
        f"        remote_addrs = {remote_addr}",
        f"        version = {version}",
        f"        proposals = {cfg.proposal_string()}",
        f"        rekey_time = {cfg.ike_lifetime_s}s",
    ]
    if cfg.aggressive:
        lines.append("        aggressive = yes")
    lines += [
        "",
        "        local {",
        "            auth = psk",
        f"            id = {local_id}",
        "        }",
        "        remote {",
        "            auth = psk",
        f"            id = {remote_id}",
        "        }",
        "",
        "        children {",
        "            net-net {",
        f"                local_ts  = {local_ts}",
        f"                remote_ts = {remote_ts}",
        f"                esp_proposals = {cfg.esp_proposal_string()}",
        f"                mode = {cfg.mode}",
        f"                rekey_time = {cfg.child_lifetime_s}s",
        "                start_action = none",
        "            }",
        "        }",
        "    }",
        "}",
        "",
        "include conf.d/*.conf",
        "",
    ]
    return "\n".join(lines)
