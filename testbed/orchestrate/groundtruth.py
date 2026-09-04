"""Read back what was actually negotiated, not what was proposed.

This is the most important correctness step in the dataset pipeline. A label taken
from the config file records an *intent*; peers negotiate, and what they settle on is
not always what was asked for. Training on intent rather than reality produces a
corpus whose labels are quietly wrong, and no amount of downstream care recovers from
that.

So every label comes from two independent observations of reality — the daemon's view
via ``swanctl --list-sas`` and the kernel's via ``ip xfrm state`` — and the manifest
records explicitly whether they matched the intent.

**No key material is ever extracted.** ``ip xfrm state`` prints session keys inline;
the parsers here read the algorithm name and ICV length and discard the key bytes
without ever placing them in a returned object.
"""

from __future__ import annotations

import re
from typing import Any, Final

from pydantic import BaseModel, Field

from testbed.orchestrate.config_gen import TunnelConfig
from testbed.orchestrate.dockerutil import exec_in_container

# swanctl renders the IKE suite as ENCR[-keylen]/[INTEG/]PRF/DH.
_SA_HEADER = re.compile(
    r"^(?P<name>\S+):\s+#(?P<unique>\d+),\s+(?P<state>\w+),\s+(?P<version>IKEv\d),"
    r"\s+(?P<ispi>[0-9a-f]+)_i\*?\s+(?P<rspi>[0-9a-f]+)_r"
)
_ENDPOINT = re.compile(
    r"^\s+(?P<side>local|remote)\s+'(?P<id>[^']*)'\s+@\s+(?P<host>\S+?)\[(?P<port>\d+)\]"
)
_SUITE = re.compile(r"^\s+([A-Z0-9_]+(?:-\d+)?(?:/[A-Z0-9_]+(?:-\d+)?)+)\s*$")
_CHILD = re.compile(
    r"^\s+(?P<name>\S+):\s+#\d+,\s+reqid\s+(?P<reqid>\d+),\s+(?P<state>\w+),"
    r"\s+(?P<mode>\w+),\s+ESP:(?P<esp>\S+)"
)
_CHILD_SPI = re.compile(r"^\s+(?P<dir>in|out)\s+(?P<spi>[0-9a-f]+),")
_CHILD_TS = re.compile(r"^\s+(?P<side>local|remote)\s+(?P<ts>[0-9a-fA-F:./]+)\s*$")

_XFRM_SRC_DST = re.compile(r"^src\s+(?P<src>\S+)\s+dst\s+(?P<dst>\S+)")
# Fields on the proto line are matched individually: a single regex with an optional
# reqid group between lazy wildcards silently skips it.
_XFRM_PROTO = re.compile(r"^\s+proto\s+(?P<proto>\w+)\s+spi\s+(?P<spi>0x[0-9a-f]+)")
_XFRM_REQID = re.compile(r"\breqid\s+(?P<reqid>\d+)")
_XFRM_MODE = re.compile(r"\bmode\s+(?P<mode>\w+)")
_XFRM_REPLAY = re.compile(r"^\s+replay-window\s+(?P<window>\d+)")
# Deliberately non-capturing on the key: it is matched only so it can be skipped.
_XFRM_ALG = re.compile(
    r"^\s+(?P<kind>aead|enc|auth-trunc|auth)\s+(?P<alg>\S+)\s+0x\S+(?:\s+(?P<bits>\d+))?"
)

NAT_T_PORT: Final = 4500


class NegotiatedIKE(BaseModel):
    """The IKE SA as the daemon reports it."""

    established: bool = False
    ike_version: str | None = None
    encryption: str | None = None
    encryption_keylen: int | None = None
    integrity: str | None = None
    prf: str | None = None
    dh_group: str | None = None
    initiator_spi: str | None = None
    responder_spi: str | None = None
    local_host: str | None = None
    remote_host: str | None = None
    local_port: int | None = None
    remote_port: int | None = None
    nat_t: bool = False


class NegotiatedChild(BaseModel):
    """The child (ESP) SA as the daemon reports it."""

    installed: bool = False
    mode: str | None = None
    esp_encryption: str | None = None
    esp_keylen: int | None = None
    esp_integrity: str | None = None
    spi_in: str | None = None
    spi_out: str | None = None
    local_ts: str | None = None
    remote_ts: str | None = None
    reqid: int | None = None


class KernelSA(BaseModel):
    """One SA as the kernel sees it. Carries no key material by construction."""

    src: str | None = None
    dst: str | None = None
    proto: str | None = None
    spi: str | None = None
    reqid: int | None = None
    mode: str | None = None
    replay_window: int | None = None
    algorithm: str | None = None
    algorithm_kind: str | None = None
    icv_bits: int | None = None


class Manifest(BaseModel):
    """Intent and reality side by side, with an explicit verdict on whether they agree."""

    capture_id: str
    config_id: str
    intent: dict[str, Any]
    negotiated_ike: NegotiatedIKE | None = None
    negotiated_child: NegotiatedChild | None = None
    kernel_sas: list[KernelSA] = Field(default_factory=list)
    negotiation_matched_intent: bool = False
    mismatches: list[str] = Field(default_factory=list)
    capture_meta: dict[str, Any] = Field(default_factory=dict)


def _split_alg_keylen(token: str) -> tuple[str, int | None]:
    """``AES_GCM_16-256`` -> ``("AES_GCM_16", 256)``."""
    if "-" in token:
        head, _, tail = token.rpartition("-")
        if tail.isdigit():
            return head, int(tail)
    return token, None


def parse_list_sas(text: str) -> tuple[NegotiatedIKE, NegotiatedChild | None]:
    """Parse ``swanctl --list-sas`` output.

    Tolerant by design: any field the output does not carry stays ``None`` rather than
    raising, because a half-negotiated SA is exactly the case worth recording.
    """
    ike = NegotiatedIKE()
    child: NegotiatedChild | None = None

    for line in text.splitlines():
        if (m := _SA_HEADER.match(line)) is not None:
            ike.established = m.group("state") == "ESTABLISHED"
            ike.ike_version = m.group("version")
            ike.initiator_spi = m.group("ispi")
            ike.responder_spi = m.group("rspi")
            continue
        if (m := _CHILD.match(line)) is not None:
            esp, keylen = _split_alg_keylen(m.group("esp"))
            child = NegotiatedChild(
                installed=m.group("state") == "INSTALLED",
                mode=m.group("mode").lower(),
                esp_encryption=esp,
                esp_keylen=keylen,
                reqid=int(m.group("reqid")),
            )
            continue
        if (m := _ENDPOINT.match(line)) is not None and child is None:
            port = int(m.group("port"))
            if m.group("side") == "local":
                ike.local_host, ike.local_port = m.group("host"), port
            else:
                ike.remote_host, ike.remote_port = m.group("host"), port
            continue
        if (m := _CHILD_SPI.match(line)) is not None and child is not None:
            if m.group("dir") == "in":
                child.spi_in = m.group("spi")
            else:
                child.spi_out = m.group("spi")
            continue
        if (m := _CHILD_TS.match(line)) is not None and child is not None:
            if m.group("side") == "local":
                child.local_ts = m.group("ts")
            else:
                child.remote_ts = m.group("ts")
            continue
        if (m := _SUITE.match(line)) is not None and ike.encryption is None:
            parts = m.group(1).split("/")
            prf_index = next((i for i, p in enumerate(parts) if p.startswith("PRF_")), None)
            if prf_index is None:
                continue
            ike.encryption, ike.encryption_keylen = _split_alg_keylen(parts[0])
            if prf_index == 2:
                ike.integrity = parts[1]
            ike.prf = parts[prf_index]
            if prf_index + 1 < len(parts):
                ike.dh_group = parts[prf_index + 1]

    # NAT traversal moves IKE to UDP 4500; both endpoints report the shifted port.
    ike.nat_t = NAT_T_PORT in {ike.local_port, ike.remote_port}
    if child is not None and child.esp_encryption is not None and child.esp_keylen is None:
        child.esp_encryption, child.esp_keylen = _split_alg_keylen(child.esp_encryption)
    return ike, child


def parse_xfrm_state(text: str) -> list[KernelSA]:
    """Parse ``ip xfrm state``, discarding every byte of key material."""
    sas: list[KernelSA] = []
    current: KernelSA | None = None
    for line in text.splitlines():
        if (m := _XFRM_SRC_DST.match(line)) is not None:
            current = KernelSA(src=m.group("src"), dst=m.group("dst"))
            sas.append(current)
            continue
        if current is None:
            continue
        if (m := _XFRM_PROTO.match(line)) is not None:
            current.proto = m.group("proto")
            current.spi = m.group("spi")
            reqid = _XFRM_REQID.search(line)
            current.reqid = int(reqid.group("reqid")) if reqid else None
            mode = _XFRM_MODE.search(line)
            current.mode = mode.group("mode") if mode else None
            continue
        if (m := _XFRM_REPLAY.match(line)) is not None:
            current.replay_window = int(m.group("window"))
            continue
        if (m := _XFRM_ALG.match(line)) is not None:
            # The key itself is matched but never captured or stored.
            current.algorithm_kind = m.group("kind")
            current.algorithm = m.group("alg")
            if m.group("bits"):
                current.icv_bits = int(m.group("bits"))
    return sas


def harvest_swanctl(container: str) -> tuple[NegotiatedIKE, NegotiatedChild | None]:
    """Ask the daemon what it actually negotiated."""
    return parse_list_sas(exec_in_container(container, "swanctl", "--list-sas"))


def harvest_xfrm_state(container: str) -> list[KernelSA]:
    """Ask the kernel which SAs are actually installed."""
    return parse_xfrm_state(exec_in_container(container, "ip", "xfrm", "state"))


# Map strongSwan config tokens to the names the daemon reports back.
_ENCRYPTION_ALIASES: Final[dict[str, tuple[str, int | None]]] = {
    "aes128gcm16": ("AES_GCM_16", 128),
    "aes192gcm16": ("AES_GCM_16", 192),
    "aes256gcm16": ("AES_GCM_16", 256),
    "aes128": ("AES_CBC", 128),
    "aes192": ("AES_CBC", 192),
    "aes256": ("AES_CBC", 256),
    "3des": ("3DES_CBC", None),
    "des": ("DES_CBC", None),
}
_DH_ALIASES: Final[dict[str, str]] = {
    "modp1024": "MODP_1024",
    "modp1536": "MODP_1536",
    "modp2048": "MODP_2048",
    "modp3072": "MODP_3072",
    "modp4096": "MODP_4096",
    "ecp256": "ECP_256",
    "ecp384": "ECP_384",
    "ecp521": "ECP_521",
    "curve25519": "CURVE_25519",
}


def compare_intent(
    cfg: TunnelConfig, ike: NegotiatedIKE, child: NegotiatedChild | None
) -> list[str]:
    """List the ways reality departed from intent. Empty means they agree."""
    mismatches: list[str] = []
    if not ike.established:
        mismatches.append("IKE SA was not established")
    expected_version = "IKEv1" if cfg.ike_version == "ikev1" else "IKEv2"
    if ike.ike_version is not None and ike.ike_version != expected_version:
        mismatches.append(f"ike_version: intended {expected_version}, negotiated {ike.ike_version}")

    expected_enc, expected_len = _ENCRYPTION_ALIASES.get(cfg.encryption, (None, None))
    if expected_enc is not None and ike.encryption is not None and ike.encryption != expected_enc:
        mismatches.append(f"encryption: intended {expected_enc}, negotiated {ike.encryption}")
    if (
        expected_len is not None
        and ike.encryption_keylen is not None
        and ike.encryption_keylen != expected_len
    ):
        mismatches.append(
            f"key length: intended {expected_len}, negotiated {ike.encryption_keylen}"
        )

    expected_dh = _DH_ALIASES.get(cfg.dh_group)
    if expected_dh is not None and ike.dh_group is not None and ike.dh_group != expected_dh:
        mismatches.append(f"dh_group: intended {expected_dh}, negotiated {ike.dh_group}")

    if child is None:
        mismatches.append("no child SA was installed")
    else:
        if not child.installed:
            mismatches.append("child SA was not installed")
        if child.mode is not None and child.mode != cfg.mode:
            mismatches.append(f"mode: intended {cfg.mode}, negotiated {child.mode}")
    return mismatches


def build_manifest(
    cfg: TunnelConfig,
    swanctl: tuple[NegotiatedIKE, NegotiatedChild | None],
    xfrm: list[KernelSA],
    capture_meta: dict[str, Any] | None = None,
    capture_id: str | None = None,
) -> Manifest:
    """Merge intent and reality into the label manifest.

    ``negotiation_matched_intent`` is the field every downstream consumer must respect:
    a cell where it is False has labels that describe something other than what was
    captured, and training on it would poison the corpus.
    """
    ike, child = swanctl
    mismatches = compare_intent(cfg, ike, child)
    return Manifest(
        capture_id=capture_id or f"run_{cfg.config_id()}",
        config_id=cfg.config_id(),
        intent={
            "ike_version": cfg.ike_version,
            "encryption": cfg.encryption,
            "integrity": cfg.integrity,
            "prf": cfg.prf,
            "dh_group": cfg.dh_group,
            "pfs": cfg.pfs,
            "child_dh_group": cfg.effective_child_dh_group,
            "mode": cfg.mode,
            "ip_version": cfg.ip_version,
            "ike_lifetime_s": cfg.ike_lifetime_s,
            "child_lifetime_s": cfg.child_lifetime_s,
            "aggressive": cfg.aggressive,
        },
        negotiated_ike=ike,
        negotiated_child=child,
        kernel_sas=xfrm,
        negotiation_matched_intent=not mismatches,
        mismatches=mismatches,
        capture_meta=capture_meta or {},
    )
