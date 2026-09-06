"""Read what a device says about its own IPsec state.

The passive lane reads the wire, and the wire has a blind spot: an IKE rekey is carried
in ``CREATE_CHILD_SA``, whose SA payload is encrypted, so a passive observer sees that a
rekey happened and not what it agreed. Where a device's own state is available, that
blind spot closes completely — the kernel knows exactly which algorithms are installed
right now, whether or not anyone was listening when they were negotiated.

**This module parses; it does not fetch.** Nothing here opens a connection to a remote
device or handles a credential, because the tool's central claim is that it needs
neither. It reads text a device produced — ``ip xfrm state``, ``swanctl --list-sas`` —
that arrives by whatever means the operator already has: a file, a configuration
management run, a sensor on the gateway itself. :func:`local_state` is the one exception
and is not really one: it runs those commands on **the machine the tool is running on**,
which needs no credential and opens no socket.

**Provenance is recorded, not blurred.** A finding from device state is a parsed fact, so
it belongs in Section A alongside the wire-derived ones — but the two are not
interchangeable and the report says which is which. Wire evidence is independently
checkable from a capture anyone can re-read; device state is what the device says about
itself, and a compromised or simply confused device is the case where the two disagree.
That disagreement is worth surfacing rather than averaging away.

**No key material is ever extracted.** ``ip xfrm state`` prints session keys inline. The
parsers read the algorithm name and ICV length and discard the key bytes without ever
placing them in a returned object — the same guarantee the testbed's ground-truth
harvesting has carried since Phase 1, which is where these parsers come from.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from pydantic import BaseModel

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


# --------------------------------------------------------------------------- reading


class StateError(RuntimeError):
    """Device state could not be read."""


@dataclass(frozen=True)
class DeviceState:
    """What one device says about its own IPsec state, at one moment.

    ``source`` names where it came from — a filename, a hostname, "local" — because a
    report that mixes state from several devices must let a reader tell them apart, and
    because "which box said this?" is the first question anyone asks about a surprising
    row.
    """

    source: str
    collected_at: datetime
    ike: NegotiatedIKE | None = None
    child: NegotiatedChild | None = None
    kernel_sas: tuple[KernelSA, ...] = ()

    @property
    def endpoints(self) -> tuple[str, str] | None:
        """The peer pair this state describes, canonicalised, or ``None``."""
        from ipsec_sentinel.parser.correlate import endpoint_pair

        if self.ike and self.ike.local_host and self.ike.remote_host:
            return endpoint_pair(self.ike.local_host, self.ike.remote_host)
        for sa in self.kernel_sas:
            if sa.src and sa.dst:
                return endpoint_pair(sa.src, sa.dst)
        return None

    @property
    def is_empty(self) -> bool:
        return self.ike is None and not self.kernel_sas

    def describe(self) -> str:
        if self.ike is None or not self.ike.established:
            return f"{self.source}: no established IKE SA"
        suite = "/".join(
            part
            for part in (
                f"{self.ike.encryption}-{self.ike.encryption_keylen}"
                if self.ike.encryption_keylen
                else self.ike.encryption,
                self.ike.integrity,
                self.ike.prf,
                self.ike.dh_group,
            )
            if part
        )
        return f"{self.source}: {self.ike.ike_version} {suite}"


def read_state(
    swanctl: Path | None = None, xfrm: Path | None = None, source: str | None = None
) -> DeviceState:
    """Parse state a device produced, from files.

    Either file may be absent: a gateway that is not strongSwan has no
    ``swanctl --list-sas`` and still has kernel SAs, and the reverse holds for a device
    whose kernel is not visible. What is present is read; what is not stays ``None``
    rather than being filled in.
    """
    ike = child = None
    kernel: tuple[KernelSA, ...] = ()
    names: list[str] = []

    if swanctl is not None:
        if not swanctl.is_file():
            raise StateError(f"no such file: {swanctl}")
        ike, child = parse_list_sas(swanctl.read_text(errors="replace"))
        names.append(swanctl.name)
    if xfrm is not None:
        if not xfrm.is_file():
            raise StateError(f"no such file: {xfrm}")
        kernel = tuple(parse_xfrm_state(xfrm.read_text(errors="replace")))
        names.append(xfrm.name)
    if not names:
        raise StateError("give at least one of a swanctl or an xfrm state file")

    return DeviceState(
        source=source or ", ".join(names),
        collected_at=datetime.now(UTC),
        ike=ike,
        child=child,
        kernel_sas=kernel,
    )


LOCAL_COMMANDS: Final[dict[str, tuple[str, ...]]] = {
    "swanctl": ("swanctl", "--list-sas"),
    "xfrm": ("ip", "xfrm", "state"),
}
LOCAL_TIMEOUT_S: Final = 20


def local_state(source: str = "local") -> DeviceState:
    """Read the state of the machine this is running on.

    For a sensor deployed on the gateway itself. No credential, no outbound socket, no
    write of any kind — two read-only commands against the local kernel and daemon.
    Whichever is unavailable is skipped rather than failing the whole read: a host with
    kernel SAs and no strongSwan is a perfectly ordinary case.
    """
    outputs: dict[str, str] = {}
    for key, argv in LOCAL_COMMANDS.items():
        if shutil.which(argv[0]) is None:
            continue
        try:
            result = subprocess.run(
                argv, capture_output=True, text=True, timeout=LOCAL_TIMEOUT_S, check=False
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if result.returncode == 0 and result.stdout.strip():
            outputs[key] = result.stdout

    if not outputs:
        raise StateError(
            "neither `swanctl --list-sas` nor `ip xfrm state` produced anything here. "
            "Reading local state needs one of them, and reading it on a *remote* device "
            "is deliberately not something this tool does: collect the output there by "
            "whatever means you already have, and pass the file in."
        )

    ike, child = parse_list_sas(outputs["swanctl"]) if "swanctl" in outputs else (None, None)
    kernel = tuple(parse_xfrm_state(outputs["xfrm"])) if "xfrm" in outputs else ()
    return DeviceState(
        source=source,
        collected_at=datetime.now(UTC),
        ike=ike,
        child=child,
        kernel_sas=kernel,
    )


def read_state_directory(directory: Path) -> list[DeviceState]:
    """Read every state snapshot a collector has dropped into a directory.

    The shape a real deployment takes: something the operator already runs — Ansible, a
    cron job, a sensor — writes ``<host>.swanctl.txt`` and ``<host>.xfrm.txt``, and this
    reads whatever is there. The collector is theirs; the parsing is ours. That division
    is what keeps this tool free of device credentials.
    """
    if not directory.is_dir():
        raise StateError(f"not a directory: {directory}")

    hosts: dict[str, dict[str, Path]] = {}
    for path in sorted(directory.iterdir()):
        if path.suffix != ".txt":
            continue
        stem = path.stem
        for marker, key in ((".swanctl", "swanctl"), (".xfrm", "xfrm")):
            if stem.endswith(marker):
                hosts.setdefault(stem[: -len(marker)], {})[key] = path

    states = []
    for host, files in sorted(hosts.items()):
        states.append(read_state(swanctl=files.get("swanctl"), xfrm=files.get("xfrm"), source=host))
    return states


def config_from_state(state: DeviceState) -> object | None:
    """Turn a device's reported IKE SA into a comparable configuration.

    Returns ``None`` when the state does not describe an established SA, or names an
    algorithm with no configuration equivalent. Refused rather than approximated, for
    the same reason the wire-side reconstruction refuses: a configuration built from a
    half-understood report is one an operator would be asked to act on.
    """
    from ipsec_sentinel.models import Proposal, Transform, TransformType
    from ipsec_sentinel.remediate.observed import Reconstruction, config_from_proposal

    ike = state.ike
    if ike is None or not ike.established:
        return None

    transforms: list[Transform] = []
    encryption = _DAEMON_TO_IKEV2_ENCR.get(ike.encryption or "")
    if encryption is None:
        return None
    transforms.append(
        Transform(
            type=TransformType.ENCR,
            id=encryption,
            name=ike.encryption or "",
            key_length=ike.encryption_keylen,
        )
    )
    if ike.integrity:
        integrity = _DAEMON_TO_IKEV2_INTEG.get(ike.integrity)
        if integrity is None:
            return None
        transforms.append(Transform(type=TransformType.INTEG, id=integrity, name=ike.integrity))
    if ike.prf:
        prf = _DAEMON_TO_IKEV2_PRF.get(ike.prf)
        if prf is None:
            return None
        transforms.append(Transform(type=TransformType.PRF, id=prf, name=ike.prf))
    group = _DAEMON_TO_DH_GROUP.get(ike.dh_group or "")
    if group is None:
        return None
    transforms.append(Transform(type=TransformType.DH, id=group, name=ike.dh_group or ""))

    recovered: Reconstruction = config_from_proposal(
        Proposal(number=1, protocol="IKE", transforms=transforms),
        ike_version=ike.ike_version or "IKEv2",
    )
    return recovered.config if recovered.ok else None


# The daemon prints its own names for the algorithms. Mapped to IANA IKEv2 transform IDs
# so the reconstruction that already exists for the wire can be reused unchanged, rather
# than growing a second, subtly different mapping that drifts from the first.
_DAEMON_TO_IKEV2_ENCR: Final[dict[str, int]] = {
    "3DES_CBC": 3,
    "AES_CBC": 12,
    "AES_GCM_16": 20,
    "AES_GCM_8": 18,
    "AES_GCM_12": 19,
}
_DAEMON_TO_IKEV2_INTEG: Final[dict[str, int]] = {
    "HMAC_MD5_96": 1,
    "HMAC_SHA1_96": 2,
    "HMAC_SHA2_256_128": 12,
    "HMAC_SHA2_384_192": 13,
    "HMAC_SHA2_512_256": 14,
}
_DAEMON_TO_IKEV2_PRF: Final[dict[str, int]] = {
    "PRF_HMAC_MD5": 1,
    "PRF_HMAC_SHA1": 2,
    "PRF_HMAC_SHA2_256": 5,
    "PRF_HMAC_SHA2_384": 6,
    "PRF_HMAC_SHA2_512": 7,
}
_DAEMON_TO_DH_GROUP: Final[dict[str, int]] = {
    "MODP_1024": 2,
    "MODP_1536": 5,
    "MODP_2048": 14,
    "MODP_3072": 15,
    "MODP_4096": 16,
    "ECP_256": 19,
    "ECP_384": 20,
    "ECP_521": 21,
    "CURVE_25519": 31,
}
