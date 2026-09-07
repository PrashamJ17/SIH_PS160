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
from collections.abc import Sequence
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
# The key is captured only so its *length* can be measured and the bytes dropped on the
# next line. Length is the difference between AES-128 and AES-256, and there is no other
# way to know it: the kernel prints the algorithm family, not the key size.
_XFRM_ALG = re.compile(
    r"^\s+(?P<kind>aead|enc|auth-trunc|auth)\s+(?P<alg>\S+)\s+0x(?P<key>\S+)"
    r"(?:\s+(?P<bits>\d+))?"
)
# RFC 4106 appends a four-byte salt to the GCM key, so the material on the wire is four
# bytes longer than the key itself.
GCM_SALT_BYTES: Final = 4

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
    """One SA as the kernel sees it. Carries no key material by construction.

    Encryption and integrity are separate fields because a non-AEAD SA prints both an
    ``enc`` and an ``auth`` line: holding one ``algorithm`` meant the second overwrote
    the first, and for a 3DES-with-MD5 SA the 3DES was the half that disappeared.
    """

    src: str | None = None
    dst: str | None = None
    proto: str | None = None
    spi: str | None = None
    reqid: int | None = None
    mode: str | None = None
    replay_window: int | None = None

    encryption: str | None = None
    """The kernel's own name, e.g. ``cbc(aes)`` or ``rfc4106(gcm(aes))``."""

    encryption_keylen: int | None = None
    """Bits, measured from the key's length. The key itself is never stored."""

    integrity: str | None = None
    """``None`` for an AEAD cipher, which carries its own integrity."""

    aead: bool = False
    icv_bits: int | None = None

    algorithm: str | None = None
    """Retained for compatibility: whichever algorithm line came last."""

    algorithm_kind: str | None = None


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
            # `AES_CBC-256/HMAC_SHA2_384_192` is a cipher, a key size and an integrity
            # algorithm. Split the suite before the key size, or the trailing split runs
            # on a string whose tail is not a number and silently yields none of them.
            cipher_field, _, integrity_field = m.group("esp").partition("/")
            esp, keylen = _split_alg_keylen(cipher_field)
            child = NegotiatedChild(
                installed=m.group("state") == "INSTALLED",
                mode=m.group("mode").lower(),
                esp_encryption=esp,
                esp_keylen=keylen,
                esp_integrity=integrity_field or None,
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


def _key_bits(key: str) -> int | None:
    """The key's size in bits, or ``None`` when what was printed is not a key.

    Only the length is taken; the characters are never stored. A sanitised file carrying
    a placeholder rather than hex yields ``None``, because a guess here is worse than an
    absence: it would put a key size in a report that no device ever used.
    """
    if len(key) % 2 or not all(c in "0123456789abcdefABCDEF" for c in key):
        return None
    return len(key) // 2 * 8


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
            kind, algorithm = m.group("kind"), m.group("alg")
            # Measured, then dropped: `bits` is this value's whole life, and the key it
            # was measured from is never assigned anywhere.
            #
            # A redacted key yields no length rather than a wrong one. Operators are
            # told to sanitise these files before handing them over, and `0xREDACTED`
            # is eight characters long, which would otherwise be reported as a 32-bit
            # key and read as a catastrophic finding.
            bits = _key_bits(m.group("key"))
            current.algorithm_kind = kind
            current.algorithm = algorithm
            if m.group("bits"):
                current.icv_bits = int(m.group("bits"))
            if kind == "aead":
                current.aead = True
                current.encryption = algorithm
                current.encryption_keylen = bits - GCM_SALT_BYTES * 8 if bits is not None else None
            elif kind == "enc":
                current.encryption = algorithm
                current.encryption_keylen = bits
            else:
                current.integrity = algorithm
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


# The kernel prints Linux crypto API names. Mapped to the canonical names the rest of
# this project uses, and *only* where the mapping is exact: an algorithm or key size with
# no canonical equivalent returns None rather than the nearest thing, because the caller
# would otherwise be told a gateway runs something it does not.
_KERNEL_ENCR: Final[dict[tuple[str, int | None], str]] = {
    ("cbc(aes)", 128): "aes128",
    ("cbc(aes)", 256): "aes256",
    ("rfc4106(gcm(aes))", 128): "aes128gcm16",
    ("rfc4106(gcm(aes))", 256): "aes256gcm16",
    ("cbc(des3_ede)", 192): "3des",
    ("cbc(des)", 64): "des",
}
_KERNEL_ENCR_ANY_LENGTH: Final[dict[str, str]] = {
    "ecb(cipher_null)": "null",
    "cipher_null": "null",
}
_KERNEL_INTEG: Final[dict[str, str]] = {
    "hmac(md5)": "md5",
    "hmac(sha1)": "sha1",
    "hmac(sha256)": "sha256",
    "hmac(sha384)": "sha384",
    "hmac(sha512)": "sha512",
    "xcbc(aes)": "aesxcbc",
    "digest_null": "none",
}

# What an ESP SA cannot tell anyone, however it was collected. Named rather than
# silently omitted: a reader has to be able to see which half of the picture is missing.
IKE_FIELDS_NOT_IN_AN_ESP_SA: Final[frozenset[str]] = frozenset(
    {"ike_version", "encryption", "integrity", "prf", "dh_group", "child_dh_group", "pfs"}
)


def kernel_encryption(name: str, keylen_bits: int | None) -> str | None:
    """A kernel cipher name and key size as this project's canonical name, or ``None``."""
    if name in _KERNEL_ENCR_ANY_LENGTH:
        return _KERNEL_ENCR_ANY_LENGTH[name]
    return _KERNEL_ENCR.get((name, keylen_bits))


def kernel_integrity(name: str) -> str | None:
    """A kernel integrity name as this project's canonical name, or ``None``."""
    return _KERNEL_INTEG.get(name)


@dataclass(frozen=True)
class ESPParameters:
    """What is protecting the traffic, as some source reports it.

    This is the child SA, not the IKE SA. It is the half a kernel can answer for.
    """

    encryption: str
    encryption_keylen: int | None = None
    integrity: str | None = None
    aead: bool = False
    mode: str | None = None
    replay_window: int | None = None
    spi: str | None = None

    def suite(self) -> str:
        parts = [self.encryption]
        if self.integrity:
            parts.append(self.integrity)
        return "/".join(parts)


@dataclass(frozen=True)
class ReportedConfig:
    """What a device's own report supports concluding, and what it does not.

    Two sources answer different questions and neither answers both. The daemon knows
    what was *negotiated* — IKE version, PRF, Diffie-Hellman group — because it did the
    negotiating. The kernel knows what is *installed* — the ESP cipher, its key size, the
    mode and the replay window — because it is enforcing it.

    So this carries both halves and names the fields no available source could supply,
    rather than returning a ``TunnelConfig`` with three invented values. A kernel-only
    read is a real and useful answer to "what is protecting this traffic right now"; it
    is not an answer to "what did the peers agree", and the difference is the point.
    """

    config: object | None = None
    """The comparable IKE-level configuration. Requires daemon output."""

    esp: ESPParameters | None = None
    """What is installed for ESP. Preferred from the kernel, else the daemon."""

    esp_source: str | None = None
    """``"kernel"`` or ``"daemon"``, so a reader knows which box said so."""

    unknown: frozenset[str] = frozenset()
    """Fields no source in this state could supply."""

    @property
    def is_empty(self) -> bool:
        return self.config is None and self.esp is None

    def describe(self) -> str:
        if self.config is not None:
            suite = str(self.config.proposal_string())  # type: ignore[attr-defined]
            if self.esp is None:
                return suite
            return f"{suite} (ESP {self.esp.suite()}, from the {self.esp_source})"
        if self.esp is None:
            return "nothing comparable"
        return (
            f"ESP {self.esp.suite()} from the {self.esp_source}; "
            f"IKE parameters unknown ({', '.join(sorted(self.unknown))})"
        )


def _same_tunnel(sa: KernelSA, other: KernelSA) -> bool:
    """Whether two kernel SAs are the two directions of one tunnel.

    ``reqid`` is the kernel's own grouping and is authoritative when both carry one.
    Falling back to the endpoint pair covers SAs installed without a reqid, and reversing
    it is the point: the inbound SA's src/dst are the outbound SA's dst/src.
    """
    if sa.reqid is not None and other.reqid is not None:
        return sa.reqid == other.reqid
    return {sa.src, sa.dst} == {other.src, other.dst}


def _replay_window_for(chosen: KernelSA, sas: Sequence[KernelSA]) -> int | None:
    """The tunnel's replay window, read from the direction where it means something.

    **Anti-replay is enforced on receive.** There is nothing to replay-check on transmit,
    so a kernel reports ``replay-window 0`` on the outbound SA of every correctly
    configured tunnel. Taking the window from whichever SA happened to be parsed first
    therefore declared anti-replay disabled on a healthy gateway — a false SA-03 that
    would have fired almost everywhere, caught by grading a live pair whose strongest
    configuration scored 92 instead of 100.

    So the window is the largest any direction of *this* tunnel reports. All directions
    reporting zero still means zero, which is the finding SA-03 exists for.
    """
    windows = [
        sa.replay_window for sa in sas if sa.replay_window is not None and _same_tunnel(chosen, sa)
    ]
    return max(windows) if windows else None


def _esp_from_kernel(sas: Sequence[KernelSA]) -> ESPParameters | None:
    """The ESP parameters the kernel installed, from the first SA that maps cleanly.

    The cipher is the same in both directions of a tunnel, so the first mappable SA
    answers for it. The replay window is not — see :func:`_replay_window_for`.
    """
    for sa in sas:
        if sa.proto not in (None, "esp") or sa.encryption is None:
            continue
        encryption = kernel_encryption(sa.encryption, sa.encryption_keylen)
        if encryption is None:
            continue
        integrity = None
        if sa.integrity is not None:
            integrity = kernel_integrity(sa.integrity)
            if integrity is None:
                continue
        return ESPParameters(
            encryption=encryption,
            encryption_keylen=sa.encryption_keylen,
            integrity=integrity,
            aead=sa.aead,
            mode=sa.mode,
            replay_window=_replay_window_for(sa, sas),
            spi=sa.spi,
        )
    return None


def _esp_from_daemon(child: NegotiatedChild | None) -> ESPParameters | None:
    """The ESP parameters the daemon reports, when the kernel was not collected."""
    if child is None or child.esp_encryption is None:
        return None
    encryption = _DAEMON_TO_CANONICAL_ESP.get(child.esp_encryption)
    if encryption is None:
        return None
    if encryption in ("aes128", "aes256") and child.esp_keylen:
        encryption = f"aes{child.esp_keylen}"
    integrity = _DAEMON_TO_CANONICAL_INTEG.get(child.esp_integrity) if child.esp_integrity else None
    return ESPParameters(
        encryption=encryption,
        encryption_keylen=child.esp_keylen,
        integrity=integrity,
        aead=encryption.endswith(("gcm8", "gcm12", "gcm16")),
        mode=child.mode,
        spi=child.spi_out or child.spi_in,
    )


def config_from_state(state: DeviceState) -> ReportedConfig | None:
    """Turn a device's own report into what it supports concluding.

    Both halves are used. The daemon's IKE SA becomes a comparable configuration exactly
    as before; the kernel's ESP SA becomes the installed-cipher half, which until now was
    parsed and then thrown away.

    Returns ``None`` only when neither source yields anything. An algorithm with no
    configuration equivalent is refused rather than approximated, for the same reason the
    wire-side reconstruction refuses: a configuration built from a half-understood report
    is one an operator would be asked to act on.
    """
    from ipsec_sentinel.models import Proposal, Transform, TransformType
    from ipsec_sentinel.remediate.observed import Reconstruction, config_from_proposal

    esp = _esp_from_kernel(state.kernel_sas)
    esp_source = "kernel" if esp is not None else None
    if esp is None:
        esp = _esp_from_daemon(state.child)
        esp_source = "daemon" if esp is not None else None

    ike = state.ike
    if ike is None or not ike.established:
        if esp is None:
            return None
        return ReportedConfig(
            config=None,
            esp=esp,
            esp_source=esp_source,
            unknown=IKE_FIELDS_NOT_IN_AN_ESP_SA,
        )

    def refused() -> ReportedConfig | None:
        """The daemon half could not be mapped; the ESP half may still stand."""
        if esp is None:
            return None
        return ReportedConfig(
            config=None, esp=esp, esp_source=esp_source, unknown=IKE_FIELDS_NOT_IN_AN_ESP_SA
        )

    transforms: list[Transform] = []
    encryption = _DAEMON_TO_IKEV2_ENCR.get(ike.encryption or "")
    if encryption is None:
        return refused()
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
            return refused()
        transforms.append(Transform(type=TransformType.INTEG, id=integrity, name=ike.integrity))
    if ike.prf:
        prf = _DAEMON_TO_IKEV2_PRF.get(ike.prf)
        if prf is None:
            return refused()
        transforms.append(Transform(type=TransformType.PRF, id=prf, name=ike.prf))
    group = _DAEMON_TO_DH_GROUP.get(ike.dh_group or "")
    if group is None:
        return refused()
    transforms.append(Transform(type=TransformType.DH, id=group, name=ike.dh_group or ""))

    recovered: Reconstruction = config_from_proposal(
        Proposal(number=1, protocol="IKE", transforms=transforms),
        ike_version=ike.ike_version or "IKEv2",
    )
    if not recovered.ok or recovered.config is None:
        return refused()
    return ReportedConfig(
        config=recovered.config,
        esp=esp,
        esp_source=esp_source,
        unknown=frozenset() if esp is not None else frozenset({"esp"}),
    )


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


# The daemon's own ESP names, used only when the kernel was not collected.
_DAEMON_TO_CANONICAL_ESP: Final[dict[str, str]] = {
    "AES_CBC": "aes128",
    "AES_GCM_16": "aes128gcm16",
    "AES_GCM_12": "aes128gcm12",
    "AES_GCM_8": "aes128gcm8",
    "3DES_CBC": "3des",
    "DES_CBC": "des",
    "NULL": "null",
}
_DAEMON_TO_CANONICAL_INTEG: Final[dict[str, str]] = {
    "HMAC_MD5_96": "md5",
    "HMAC_SHA1_96": "sha1",
    "HMAC_SHA2_256_128": "sha256",
    "HMAC_SHA2_384_192": "sha384",
    "HMAC_SHA2_512_256": "sha512",
}
