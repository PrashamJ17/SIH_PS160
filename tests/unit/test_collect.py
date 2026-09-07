"""Tests for reading a device's own IPsec state.

Three things are being checked, in order of how badly they would matter.

**No key material escapes.** ``ip xfrm state`` prints session keys inline. A security
tool that lifted them into a report — or into a log line, or a JSON export served over
HTTP — would be a worse problem than any finding it makes. The sample below carries
obviously fake keys; ``tests/integration/test_collect_live.py`` runs the same assertion
against a real kernel's output, with real keys.

**Nothing is fetched.** The module parses text a device produced and reads the local
machine. It opens no connection to a remote device and handles no credential, and a test
asserts that by making every socket constructor raise.

**An algorithm it does not recognise is refused, not approximated.** A configuration
reconstructed from a half-understood report is one an operator would be asked to act on.
"""

from __future__ import annotations

import re
import socket
from datetime import UTC, datetime
from pathlib import Path

import pytest

from ipsec_sentinel.collect import (
    DeviceState,
    StateError,
    config_from_state,
    kernel_encryption,
    kernel_integrity,
    local_state,
    parse_list_sas,
    parse_xfrm_state,
    read_state,
    read_state_directory,
)

# A real `ip xfrm state`, with the key bytes replaced by obviously fake ones. Real keys
# are not committed to this repository even from a throwaway container: a security tool's
# git history is the last place they belong.
XFRM_SAMPLE = """src 10.100.0.2 dst 10.100.0.3
\tproto esp spi 0xc3337439 reqid 1 mode tunnel
\treplay-window 0 flag af-unspec
\tauth-trunc hmac(sha384) 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef 192
\tenc cbc(aes) 0xcafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe
\tanti-replay context: seq 0x0, oseq 0x0, bitmap 0x00000000
src 10.100.0.3 dst 10.100.0.2
\tproto esp spi 0xc17fcfe9 reqid 1 mode tunnel
\treplay-window 32 flag af-unspec
\tauth-trunc hmac(sha384) 0xfeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface 192
\tenc cbc(aes) 0xbaadf00dbaadf00dbaadf00dbaadf00dbaadf00dbaadf00dbaadf00dbaadf00d
\tanti-replay context: seq 0x0, oseq 0x0, bitmap 0x00000000
"""

SWANCTL_SAMPLE = """net-net: #1, ESTABLISHED, IKEv2, f341691f052442d6_i* 467f6af2b5f38b52_r
  local  'left' @ 10.100.0.2[4500]
  remote 'right' @ 10.100.0.3[4500]
  AES_CBC-256/HMAC_SHA2_384_192/PRF_HMAC_SHA2_384/ECP_384
  established 12s ago, rekeying in 13201s
  net-net: #1, reqid 1, INSTALLED, TUNNEL, ESP:AES_CBC-256/HMAC_SHA2_384_192
    installed 12s ago, rekeying in 27514s, expires in 31680s
    in  ceb8e50b,   3780 bytes,    45 packets
    out ca864e35,   3780 bytes,    45 packets
    local  10.1.0.0/24
    remote 10.2.0.0/24
"""


@pytest.fixture
def state_files(tmp_path: Path) -> tuple[Path, Path]:
    swanctl = tmp_path / "gw01.swanctl.txt"
    xfrm = tmp_path / "gw01.xfrm.txt"
    swanctl.write_text(SWANCTL_SAMPLE)
    xfrm.write_text(XFRM_SAMPLE)
    return swanctl, xfrm


class TestNoKeyMaterialEscapes:
    """The guarantee that matters most, checked against what the kernel actually prints."""

    @staticmethod
    def _key_blobs(text: str) -> set[str]:
        """Long hex runs. SPIs are eight digits; keys are far longer."""
        return set(re.findall(r"0x[0-9a-f]{20,}", text))

    def test_the_sample_really_does_contain_keys(self) -> None:
        """Otherwise the test below passes by testing nothing."""
        assert len(self._key_blobs(XFRM_SAMPLE)) == 4

    def test_no_key_reaches_a_parsed_object(self) -> None:
        parsed = parse_xfrm_state(XFRM_SAMPLE)
        serialised = " ".join(sa.model_dump_json() for sa in parsed)
        for blob in self._key_blobs(XFRM_SAMPLE):
            assert blob not in serialised
            assert blob[2:] not in serialised

    def test_the_algorithm_and_icv_length_are_kept(self) -> None:
        """What is dropped is the key, not the useful part."""
        parsed = parse_xfrm_state(XFRM_SAMPLE)
        assert parsed[0].algorithm == "cbc(aes)"
        assert parsed[0].icv_bits == 192

    def test_no_key_reaches_the_device_state(self, state_files: tuple[Path, Path]) -> None:
        state = read_state(*state_files)
        serialised = repr(state) + state.describe()
        for blob in self._key_blobs(XFRM_SAMPLE):
            assert blob not in serialised

    def test_the_spi_is_kept_because_it_is_not_secret(self) -> None:
        """Every ESP packet carries the SPI in the clear; dropping it would lose the join."""
        parsed = parse_xfrm_state(XFRM_SAMPLE)
        assert parsed[0].spi == "0xc3337439"


class TestNothingIsFetched:
    def test_reading_state_opens_no_socket(
        self, state_files: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The tool's claim is that it needs no device access and no credential."""

        def refuse(*_args: object, **_kwargs: object) -> None:
            raise AssertionError("reading device state opened a socket")

        monkeypatch.setattr(socket, "socket", refuse)
        monkeypatch.setattr(socket, "create_connection", refuse)
        assert read_state(*state_files).ike is not None

    def test_the_module_has_no_remote_access_machinery(self) -> None:
        from ipsec_sentinel.remediate.models import FORBIDDEN_TRANSPORTS

        source = Path(__file__).resolve().parents[2] / "src/ipsec_sentinel/collect.py"
        body = source.read_text()
        for transport in FORBIDDEN_TRANSPORTS:
            assert f"import {transport}" not in body

    def test_local_state_says_where_to_get_remote_state(self) -> None:
        """The refusal has to point somewhere, or it is just an obstacle.

        On a machine with no IPsec — every CI runner, and this one — ``local_state``
        raises, and the message is what an operator reads next. It has to say that
        reading a *remote* device is a deliberate non-feature and what to do instead.
        """
        try:
            state = local_state()
        except StateError as exc:
            message = str(exc)
            assert "deliberately not something this tool does" in message
            assert "pass the file in" in message
        else:
            # This machine really does have IPsec state. Then the other guarantee is the
            # one worth checking: it was read without reaching for the network.
            assert state.source == "local"


class TestParsingRealShapes:
    def test_the_ike_suite_is_read(self) -> None:
        ike, child = parse_list_sas(SWANCTL_SAMPLE)
        assert ike.established is True
        assert ike.ike_version == "IKEv2"
        assert (ike.encryption, ike.encryption_keylen) == ("AES_CBC", 256)
        assert ike.integrity == "HMAC_SHA2_384_192"
        assert ike.prf == "PRF_HMAC_SHA2_384"
        assert ike.dh_group == "ECP_384"
        assert child is not None
        assert child.installed is True

    def test_the_endpoints_are_read(self) -> None:
        ike, _ = parse_list_sas(SWANCTL_SAMPLE)
        assert ike.local_host == "10.100.0.2"
        assert ike.remote_host == "10.100.0.3"

    def test_both_directions_of_the_kernel_sa_are_read(self) -> None:
        assert len(parse_xfrm_state(XFRM_SAMPLE)) == 2

    def test_the_replay_window_is_read(self) -> None:
        """One direction has anti-replay off, which is a finding in its own right."""
        windows = [sa.replay_window for sa in parse_xfrm_state(XFRM_SAMPLE)]
        assert windows == [0, 32]

    def test_an_empty_output_parses_to_nothing(self) -> None:
        ike, child = parse_list_sas("")
        assert ike.established is False
        assert child is None
        assert parse_xfrm_state("") == []


class TestReadingState:
    def test_both_files_together(self, state_files: tuple[Path, Path]) -> None:
        state = read_state(*state_files, source="gw01")
        assert state.source == "gw01"
        assert state.ike is not None
        assert len(state.kernel_sas) == 2
        assert state.endpoints == ("10.100.0.2", "10.100.0.3")

    def test_swanctl_alone(self, state_files: tuple[Path, Path]) -> None:
        """A device whose kernel is not visible still reports its daemon's view."""
        state = read_state(swanctl=state_files[0])
        assert state.ike is not None
        assert state.kernel_sas == ()

    def test_xfrm_alone(self, state_files: tuple[Path, Path]) -> None:
        """A gateway that is not strongSwan has no swanctl and still has kernel SAs."""
        state = read_state(xfrm=state_files[1])
        assert state.ike is None
        assert len(state.kernel_sas) == 2
        assert state.endpoints == ("10.100.0.2", "10.100.0.3")

    def test_neither_is_refused(self) -> None:
        with pytest.raises(StateError, match="at least one"):
            read_state()

    def test_a_missing_file_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(StateError, match="no such file"):
            read_state(swanctl=tmp_path / "absent.txt")

    def test_a_directory_of_snapshots(self, tmp_path: Path) -> None:
        for host in ("gw-hq", "gw-branch"):
            (tmp_path / f"{host}.swanctl.txt").write_text(SWANCTL_SAMPLE)
            (tmp_path / f"{host}.xfrm.txt").write_text(XFRM_SAMPLE)
        (tmp_path / "notes.md").write_text("ignored")
        states = read_state_directory(tmp_path)
        assert [s.source for s in states] == ["gw-branch", "gw-hq"]
        assert all(s.ike is not None for s in states)

    def test_a_missing_directory_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(StateError, match="not a directory"):
            read_state_directory(tmp_path / "absent")

    def test_an_empty_state_says_so(self) -> None:
        from datetime import UTC, datetime

        empty = DeviceState(source="x", collected_at=datetime.now(UTC))
        assert empty.is_empty
        assert empty.endpoints is None
        assert "no established IKE SA" in empty.describe()


class TestReconstructingAConfiguration:
    def test_the_reported_suite_becomes_a_configuration(
        self, state_files: tuple[Path, Path]
    ) -> None:
        reported = config_from_state(read_state(*state_files))
        assert reported is not None and reported.config is not None
        assert reported.config.proposal_string() == "aes256-sha384-prfsha384-ecp384"  # type: ignore[attr-defined]

    def test_state_with_no_established_sa_yields_nothing(self) -> None:
        assert config_from_state(DeviceState("x", datetime.now(UTC))) is None

    def test_an_unrecognised_algorithm_is_refused_not_approximated(self, tmp_path: Path) -> None:
        """A configuration built from a half-understood report gets acted on."""
        odd = SWANCTL_SAMPLE.replace("AES_CBC-256", "SOMETHING_NEW-256")
        target = tmp_path / "odd.swanctl.txt"
        target.write_text(odd)
        reported = config_from_state(read_state(swanctl=target))
        assert reported is None or reported.config is None

    def test_the_mapping_matches_the_wire_side_reconstruction(self) -> None:
        """One set of transform IDs, so the two paths cannot drift apart."""
        from ipsec_sentinel.collect import (
            _DAEMON_TO_DH_GROUP,
            _DAEMON_TO_IKEV2_ENCR,
        )
        from ipsec_sentinel.remediate.observed import DH_BY_ID, ENCRYPTION_BY_ID

        assert set(_DAEMON_TO_IKEV2_ENCR.values()) <= set(ENCRYPTION_BY_ID)
        assert set(_DAEMON_TO_DH_GROUP.values()) <= set(DH_BY_ID)


class TestDriftFromStateAlone:
    """The point of the whole module: no wire visibility required."""

    def _state(self, tmp_path: Path, suite: str, name: str) -> DeviceState:
        text = SWANCTL_SAMPLE.replace(
            "AES_CBC-256/HMAC_SHA2_384_192/PRF_HMAC_SHA2_384/ECP_384", suite
        )
        target = tmp_path / f"{name}.swanctl.txt"
        target.write_text(text)
        return read_state(swanctl=target, source=name)

    def test_a_weakening_seen_only_in_state_is_detected(self, tmp_path: Path) -> None:
        from ipsec_sentinel.watch import DriftDetector

        detector = DriftDetector()
        before = self._state(
            tmp_path, "AES_CBC-256/HMAC_SHA2_384_192/PRF_HMAC_SHA2_384/ECP_384", "before"
        )
        after = self._state(tmp_path, "AES_CBC-128/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1024", "after")
        assert detector.observe_state(before) is None
        alert = detector.observe_state(after)
        assert alert is not None
        assert {w.parameter for w in alert.weakenings} >= {"encryption", "integrity", "dh_group"}

    def test_a_state_sighting_is_not_scored(self, tmp_path: Path) -> None:
        """Running the rules against a tunnel with no negotiation returns a perfect score
        precisely because nothing was checked. Reporting that would be the most
        misleading possible output."""
        from ipsec_sentinel.watch import DriftDetector

        detector = DriftDetector()
        detector.observe_state(
            self._state(tmp_path, "AES_CBC-256/HMAC_SHA2_384_192/PRF_HMAC_SHA2_384/ECP_384", "a")
        )
        sighting = next(iter(detector.known().values()))
        assert sighting.score is None
        assert sighting.grade is None

    def test_the_summary_says_why_there_is_no_score(self, tmp_path: Path) -> None:
        from ipsec_sentinel.watch import DriftDetector

        detector = DriftDetector()
        detector.observe_state(
            self._state(tmp_path, "AES_CBC-256/HMAC_SHA2_384_192/PRF_HMAC_SHA2_384/ECP_384", "a")
        )
        alert = detector.observe_state(
            self._state(tmp_path, "3DES_CBC/HMAC_MD5_96/PRF_HMAC_MD5/MODP_1024", "b")
        )
        assert alert is not None
        assert "not scored" in alert.summary()
        assert "device state" in alert.summary()

    def test_a_state_sighting_carries_no_exchange(self, tmp_path: Path) -> None:
        """So nothing downstream mistakes "the device told us" for "we saw it"."""
        from ipsec_sentinel.watch import DriftDetector

        detector = DriftDetector()
        detector.observe_state(
            self._state(tmp_path, "AES_CBC-256/HMAC_SHA2_384_192/PRF_HMAC_SHA2_384/ECP_384", "a")
        )
        assert next(iter(detector.known().values())).exchange is None

    def test_a_cipher_weakening_is_critical_without_a_score(self, tmp_path: Path) -> None:
        from ipsec_sentinel.models import Severity
        from ipsec_sentinel.watch import DriftDetector

        detector = DriftDetector()
        detector.observe_state(
            self._state(tmp_path, "AES_CBC-256/HMAC_SHA2_384_192/PRF_HMAC_SHA2_384/ECP_384", "a")
        )
        alert = detector.observe_state(
            self._state(tmp_path, "3DES_CBC/HMAC_MD5_96/PRF_HMAC_MD5/MODP_1024", "b")
        )
        assert alert is not None
        assert alert.severity is Severity.CRITICAL


# --------------------------------------------------------------- kernel SA support
#
# Until this point the XFRM half of a device's state was parsed and then dead-ended:
# `config_from_state` read `state.ike` only, so `kernel_sas` contributed an endpoint
# pair and nothing else. These tests drive the change that makes it load-bearing.
#
# The boundary matters and is the reason the return type grew rather than the config:
# a kernel ESP SA carries the *child* parameters. It does not carry the IKE version,
# the PRF or the Diffie-Hellman group, and a `TunnelConfig` requires all three. Filling
# those in would be inventing data about somebody's gateway.

# GCM keys carry a four-byte salt, so 256 bits of key is 36 bytes on the wire.
AEAD_SAMPLE = """src 10.0.0.1 dst 10.0.0.2
\tproto esp spi 0x0badc0de reqid 3 mode tunnel
\treplay-window 32 flag af-unspec
\taead rfc4106(gcm(aes)) 0x{key} 128
""".format(key="ab" * 36)

LEGACY_SAMPLE = """src 10.0.0.1 dst 10.0.0.2
\tproto esp spi 0x0badc0de reqid 4 mode transport
\treplay-window 4
\tauth-trunc hmac(md5) 0x{auth} 96
\tenc cbc(des3_ede) 0x{enc}
""".format(auth="cd" * 16, enc="ef" * 24)


class TestTheKernelParserKeepsBothAlgorithms:
    """`enc` and `auth` used to overwrite one another in a single `algorithm` field.

    A non-AEAD SA prints both lines, so whichever came last won and the other was lost.
    For an SA using 3DES with MD5 that meant the 3DES vanished, which is precisely the
    finding an operator most needs.
    """

    def test_encryption_and_integrity_both_survive(self) -> None:
        sa = parse_xfrm_state(LEGACY_SAMPLE)[0]
        assert sa.encryption == "cbc(des3_ede)"
        assert sa.integrity == "hmac(md5)"

    def test_the_key_length_is_derived_from_the_key_it_does_not_keep(self) -> None:
        """3DES is 24 bytes; AES-256 is 32. Without this, AES-128 and AES-256 are one."""
        assert parse_xfrm_state(LEGACY_SAMPLE)[0].encryption_keylen == 192
        assert parse_xfrm_state(XFRM_SAMPLE)[0].encryption_keylen == 256

    def test_an_aead_sa_is_marked_as_such(self) -> None:
        sa = parse_xfrm_state(AEAD_SAMPLE)[0]
        assert sa.aead is True
        assert sa.encryption == "rfc4106(gcm(aes))"
        assert sa.integrity is None, "an AEAD cipher carries its own integrity"
        assert sa.icv_bits == 128

    def test_the_aead_salt_is_not_counted_as_key(self) -> None:
        """36 bytes on the wire is 256 bits of key plus a four-byte salt."""
        assert parse_xfrm_state(AEAD_SAMPLE)[0].encryption_keylen == 256

    def test_no_key_material_survives_the_richer_parse(self) -> None:
        """The reason the length is derived rather than the key stored."""
        for sample in (LEGACY_SAMPLE, AEAD_SAMPLE, XFRM_SAMPLE):
            serialised = " ".join(sa.model_dump_json() for sa in parse_xfrm_state(sample))
            for blob in re.findall(r"0x([0-9a-f]{20,})", sample):
                assert blob not in serialised

    def test_mode_and_replay_window_are_kept(self) -> None:
        sa = parse_xfrm_state(LEGACY_SAMPLE)[0]
        assert sa.mode == "transport"
        assert sa.replay_window == 4


class TestKernelAlgorithmNamesMapToCanonicalOnes:
    """The kernel prints Linux crypto API names; the rest of the tool speaks its own."""

    @pytest.mark.parametrize(
        ("name", "bits", "expected"),
        [
            ("cbc(aes)", 256, "aes256"),
            ("cbc(aes)", 128, "aes128"),
            ("cbc(des3_ede)", 192, "3des"),
            ("cbc(des)", 64, "des"),
            ("ecb(cipher_null)", None, "null"),
            ("rfc4106(gcm(aes))", 256, "aes256gcm16"),
            ("rfc4106(gcm(aes))", 128, "aes128gcm16"),
        ],
    )
    def test_encryption(self, name: str, bits: int | None, expected: str) -> None:
        assert kernel_encryption(name, bits) == expected

    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("hmac(sha256)", "sha256"),
            ("hmac(sha384)", "sha384"),
            ("hmac(sha512)", "sha512"),
            ("hmac(sha1)", "sha1"),
            ("hmac(md5)", "md5"),
        ],
    )
    def test_integrity(self, name: str, expected: str) -> None:
        assert kernel_integrity(name) == expected

    def test_an_unknown_algorithm_is_refused_not_guessed(self) -> None:
        assert kernel_encryption("cbc(camellia)", 256) is None
        assert kernel_integrity("hmac(streebog256)") is None

    def test_an_unknown_key_length_is_refused(self) -> None:
        """AES with a 192-bit key is legal and this tool has no canonical name for it."""
        assert kernel_encryption("cbc(aes)", 192) is None


class TestConfigFromStateUsesTheKernel:
    def _kernel_only(self, sample: str = XFRM_SAMPLE) -> DeviceState:
        return DeviceState(
            source="gw01",
            collected_at=datetime.now(UTC),
            kernel_sas=tuple(parse_xfrm_state(sample)),
        )

    def test_a_kernel_only_state_yields_esp_parameters(self) -> None:
        """The whole point: state with no daemon output is no longer inert."""
        reported = config_from_state(self._kernel_only())

        assert reported is not None
        assert reported.esp is not None
        assert reported.esp.encryption == "aes256"
        assert reported.esp.integrity == "sha384"
        assert reported.esp_source == "kernel"

    def test_a_kernel_only_state_yields_no_ike_config(self) -> None:
        """An ESP SA does not carry the IKE version, the PRF or the DH group."""
        reported = config_from_state(self._kernel_only())

        assert reported is not None
        assert reported.config is None
        assert reported.unknown >= {"ike_version", "prf", "dh_group"}

    def test_the_unknowns_are_named_so_a_reader_can_see_them(self) -> None:
        reported = config_from_state(self._kernel_only())
        assert reported is not None
        assert "child_dh_group" in reported.unknown, "PFS is invisible to the kernel"

    def test_a_daemon_state_still_yields_a_comparable_config(self, state_files: tuple) -> None:
        """The existing contract, unchanged."""
        reported = config_from_state(read_state(*state_files))

        assert reported is not None
        assert reported.config is not None
        assert reported.config.proposal_string()

    def test_the_kernel_supplies_esp_even_when_the_daemon_is_present(
        self, state_files: tuple
    ) -> None:
        """Two sources, and the kernel is the one that says what is *installed*."""
        reported = config_from_state(read_state(*state_files))

        assert reported is not None
        assert reported.esp is not None
        assert reported.esp_source == "kernel"

    def test_a_daemon_only_state_falls_back_to_the_daemon_child_sa(self, tmp_path: Path) -> None:
        target = tmp_path / "swanctl.txt"
        target.write_text(SWANCTL_SAMPLE)
        reported = config_from_state(read_state(swanctl=target))

        assert reported is not None
        assert reported.esp is not None
        assert reported.esp_source == "daemon"

    def test_an_empty_state_yields_nothing(self) -> None:
        assert config_from_state(DeviceState("x", datetime.now(UTC))) is None

    def test_an_unmappable_kernel_algorithm_is_refused_rather_than_approximated(self) -> None:
        exotic = XFRM_SAMPLE.replace("cbc(aes)", "cbc(camellia)")
        reported = config_from_state(self._kernel_only(exotic))

        assert reported is None or reported.esp is None

    def test_the_esp_parameters_carry_the_replay_window(self) -> None:
        """SA-03 and SA-04 judge exactly this, and the kernel is where it is true."""
        reported = config_from_state(self._kernel_only())
        assert reported is not None and reported.esp is not None
        assert reported.esp.replay_window == 0

    def test_the_esp_parameters_name_their_mode(self) -> None:
        reported = config_from_state(self._kernel_only())
        assert reported is not None and reported.esp is not None
        assert reported.esp.mode == "tunnel"

    def test_it_describes_itself_for_a_report(self) -> None:
        reported = config_from_state(self._kernel_only())
        assert reported is not None
        summary = reported.describe()
        assert "aes256" in summary
        assert "sha384" in summary
        assert "kernel" in summary


class TestTheDaemonChildSuiteIsDecomposed:
    """`ESP:AES_CBC-256/HMAC_SHA2_384_192` is three facts, not one string.

    It was being stored whole in ``esp_encryption``, so ``esp_integrity`` was always
    ``None`` and ``esp_keylen`` never set: the trailing key-length split ran on
    ``AES_CBC-256/HMAC_SHA2_384_192``, whose tail is not a number. Nothing noticed
    because nothing read the child SA until the kernel work needed a fallback for it.
    """

    def test_the_cipher_is_separated_from_the_integrity(self) -> None:
        _, child = parse_list_sas(SWANCTL_SAMPLE)
        assert child is not None
        assert child.esp_encryption == "AES_CBC"
        assert child.esp_integrity == "HMAC_SHA2_384_192"

    def test_the_key_length_is_recovered(self) -> None:
        _, child = parse_list_sas(SWANCTL_SAMPLE)
        assert child is not None
        assert child.esp_keylen == 256

    def test_an_aead_child_has_no_separate_integrity(self) -> None:
        text = SWANCTL_SAMPLE.replace("AES_CBC-256/HMAC_SHA2_384_192", "AES_GCM_16-256")
        _, child = parse_list_sas(text)
        assert child is not None
        assert child.esp_encryption == "AES_GCM_16"
        assert child.esp_keylen == 256
        assert child.esp_integrity is None


class TestARedactedKeyYieldsNoLength:
    """Operators are told to sanitise state files before handing them over.

    `0xREDACTED` is eight characters. Measuring it the way a hex key is measured would
    report a 32-bit key, which reads as the most serious finding this tool can make and
    would be entirely an artefact of the redaction.
    """

    def test_a_placeholder_key_gives_no_key_length(self) -> None:
        redacted = (
            "src 10.0.0.1 dst 10.0.0.2\n"
            "\tproto esp spi 0xdeadbeef reqid 2 mode tunnel\n"
            "\tenc cbc(aes) 0xREDACTED\n"
            "\tauth-trunc hmac(sha256) 0xREDACTED 128\n"
        )
        sa = parse_xfrm_state(redacted)[0]

        assert sa.encryption == "cbc(aes)"
        assert sa.integrity == "hmac(sha256)"
        assert sa.encryption_keylen is None, "a redacted key must not be measured"
        assert sa.icv_bits == 128, "the ICV length is printed, not derived"

    def test_an_odd_length_key_is_not_measured(self) -> None:
        odd = (
            "src 10.0.0.1 dst 10.0.0.2\n"
            "\tproto esp spi 0xdeadbeef reqid 2 mode tunnel\n"
            "\tenc cbc(aes) 0xabc\n"
        )
        assert parse_xfrm_state(odd)[0].encryption_keylen is None

    def test_a_redacted_sa_is_refused_rather_than_mapped_to_a_guess(self) -> None:
        """Without a key length there is no way to tell AES-128 from AES-256."""
        redacted = (
            "src 10.0.0.1 dst 10.0.0.2\n"
            "\tproto esp spi 0xdeadbeef reqid 2 mode tunnel\n"
            "\tenc cbc(aes) 0xREDACTED\n"
        )
        state = DeviceState(
            source="gw",
            collected_at=datetime.now(UTC),
            kernel_sas=tuple(parse_xfrm_state(redacted)),
        )
        reported = config_from_state(state)
        assert reported is None or reported.esp is None
