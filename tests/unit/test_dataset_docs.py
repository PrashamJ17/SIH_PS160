"""The dataset documentation must keep its disclosures (build plan Step 3.4).

These are not style checks. Each assertion guards a specific honesty commitment that
would be easy to lose in an edit and expensive to be caught having lost: a corpus
described as containing WhatsApp, or real calls, or trustworthy replay timing, would
discredit every number computed from it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

DOC = Path(__file__).resolve().parents[2] / "docs" / "DATASET.md"
TEXT = DOC.read_text()
LOWER = TEXT.lower()
# Prose is hard-wrapped, so phrase assertions run against a whitespace-flattened copy;
# otherwise a purely cosmetic re-wrap would fail an honesty check.
FLAT = " ".join(TEXT.split())
FLAT_LOWER = FLAT.lower()


def test_the_document_exists_and_is_substantial() -> None:
    assert DOC.exists()
    assert len(TEXT.splitlines()) > 100


class TestRequiredSections:
    @pytest.mark.parametrize(
        "heading",
        [
            "Why we generated our own data",
            "How the named datasets",
            "Known limitations of ISCXVPN2016",
            "Generation methodology",
            "Label provenance",
            "What stands in for something it is not",
            "Known biases and limitations",
        ],
    )
    def test_section_present(self, heading: str) -> None:
        assert heading in TEXT, f"missing section: {heading}"


class TestTheDatasetClaim:
    @pytest.mark.parametrize(
        "dataset",
        ["CIC-IDS2017", "CSE-CIC-IDS2018", "UNSW-NB15", "CTU-13", "CICIoT2023", "LANL", "DARPA"],
    )
    def test_every_named_dataset_is_addressed(self, dataset: str) -> None:
        assert dataset in TEXT

    def test_the_claim_is_stated_plainly(self) -> None:
        assert "no **IKE negotiations**" in FLAT
        assert "ESP" in TEXT

    def test_the_claim_cites_our_own_audit(self) -> None:
        """The plan requires verifying this ourselves rather than citing literature."""
        assert "external_dataset_audit.md" in TEXT
        assert "scripts/audit_external_datasets.py" in TEXT

    def test_the_positive_control_is_explained(self) -> None:
        assert "positive control" in LOWER
        assert "INVALID" in TEXT


class TestProxyDisclosures:
    def test_messaging_is_declared_to_be_xmpp_and_not_whatsapp(self) -> None:
        """The single disclosure most likely to be quietly dropped."""
        assert "XMPP, not WhatsApp" in FLAT
        assert "not** WhatsApp" in FLAT or "not WhatsApp" in FLAT
        assert "shape proxy" in FLAT_LOWER

    def test_voip_is_declared_synthetic(self) -> None:
        assert "no SIP signalling" in FLAT
        assert "no real calls" in FLAT_LOWER

    def test_the_real_protocols_are_distinguished_from_the_proxies(self) -> None:
        assert "Postfix" in TEXT and "Dovecot" in TEXT
        assert "Prosody" in TEXT


class TestLabelProvenance:
    def test_labels_come_from_reality_not_intent(self) -> None:
        assert "swanctl --list-sas" in TEXT
        assert "ip xfrm state" in TEXT
        assert "negotiation_matched_intent" in TEXT

    def test_no_key_material_is_promised(self) -> None:
        assert "No key material is ever extracted" in FLAT

    def test_no_credential_storage_is_promised(self) -> None:
        assert "No credential appears anywhere in this repository" in FLAT


class TestLimitations:
    def test_replay_timing_distortion_is_disclosed(self) -> None:
        assert "distorts inter-arrival" in FLAT_LOWER

    def test_single_implementation_bias_is_disclosed(self) -> None:
        assert "strongSwan on both ends" in FLAT

    def test_lab_generation_is_disclosed(self) -> None:
        assert "Lab-generated" in TEXT

    def test_the_confound_guard_is_described(self) -> None:
        assert "confound" in FLAT_LOWER
        assert "every generator must meet every encryption algorithm" in FLAT_LOWER

    def test_the_aggressive_mode_unlock_is_disclosed(self) -> None:
        """A reader must know the testbed image deliberately enables this."""
        assert "i_dont_care_about_security_and_use_aggressive_mode_psk" in TEXT
        assert "remediation generators emit" in FLAT
