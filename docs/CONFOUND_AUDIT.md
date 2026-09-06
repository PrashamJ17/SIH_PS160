# Confound audit

*Generated 2026-09-06 05:34 UTC by `scripts/confound_audit.py`.*

If application class correlates with cipher in a corpus, a classifier can score
beautifully by learning the cipher and reading the label off it — and every accuracy
figure, confusion matrix and SHAP explanation would look identical to a model that had
genuinely learned traffic shape. This document performs the distinguishing.

**It is written whatever the numbers show.**

## 1. Accuracy conditioned on cipher

Overall traffic-classification accuracy: **96.0%** over
581 windows, grouped 5-fold by capture.

| Cipher | Accuracy | Windows |
|---|---|---|
| 3DES_CBC | 97.2% | 144 |
| AES_CBC | 95.3% | 277 |
| AES_GCM_16 | 96.2% | 160 |

Spread between best and worst: **1.9%**
(tolerance 15%).

## 2. How learnable is the cipher from packet sizes alone?

A deliberate cipher-from-ESP-sizes classifier, given only size features
(20 of 42) — no timing, no volume, nothing that
would let it identify the traffic class and infer the cipher from corpus layout.

| Measure | Value |
|---|---|
| Cipher accuracy from sizes | **80.6%** |
| Majority-class baseline | 47.7% |
| Lift over baseline | **+32.9%** |

## 3. Mutual information with cipher

| Quantity | Nats | Share of traffic-class entropy |
|---|---|---|
| True labels vs cipher | 0.0013 | 0.1% |
| Predicted labels vs cipher | 0.0015 | 0.1% |

Traffic-class entropy: 1.9384 nats.

## Verdict

**Accuracy does not depend on the cipher.** The spread between the best and worst cipher is 1.9%, inside the 15% tolerance. A classifier reading a cipher artifact would score visibly better under the cipher whose artifact it had learned.

**The cipher is identifiable from ESP packet sizes alone at 80.6%, against a 47.7% majority-class baseline.** This is a real finding rather than a defect: AES-CBC pads to a 16-byte block boundary, 3DES to 8 bytes, and AES-GCM not at all, so ESP packet sizes carry the cipher's block structure. **A passive observer can therefore infer the negotiated cipher without ever seeing a handshake** — useful when a capture starts mid-session, and a reminder that padding is a side channel.

The features that carry it: fwd_size_min, size_min, size_p25, size_entropy, fwd_size_mean — the *smallest* packets, which is exactly what padding theory predicts, because a block-boundary rounding is proportionally most visible on a short packet.

**Product implication.** ESP-01 reports tunnels seen with no negotiation in the capture, whose cryptography is currently unassessable. This side channel offers a route to saying something about them — an *inferred* cipher, carrying a calibrated confidence, in Section B. It is not implemented here; it is recorded because the measurement that justifies it now exists.

**The classifier's output carries no more cipher information than the true labels do.** Mutual information with cipher is 0.0015 nats for the predictions against 0.0013 for the ground truth (0.1% and 0.1% of traffic-class entropy). The model is not manufacturing a cipher dependency the corpus does not have.

## Why this audit exists

The master document names this the most fatal trap available in this project. It is
also invisible: a confounded classifier and a sound one produce the same shape of
output, and only a test designed to separate them can tell which you have.

The corpus was built to make the separation possible — every traffic class appears with
every cipher, verified at the M3 gate at 0.0000 nats of cell-level mutual information.
This audit checks that the property survived into the model.
