# Baselines the models must beat

Every baseline here was written and measured **before** the corresponding model was
trained. Establishing the bar afterwards invites choosing a bar the model already
clears, which is how a model that adds nothing comes to look like it adds something.

A machine-learned classifier that cannot outperform twenty lines of arithmetic does not
justify its training cost, its opacity, or the confidence interval it forces a reader to
reason about.

---

## Mode inference — heuristic baseline

`src/ipsec_sentinel/ml/heuristic.py`

### The signal

Tunnel mode encapsulates the entire inner IP packet, so every protected packet carries a
full inner IP header that transport mode does not: **20 bytes for IPv4, 40 for IPv6**.

That offset is present in every packet, which makes the *smallest* packet the most
informative observation. A bare TCP ACK is 40 bytes of inner packet, and whether it
arrives as 40 or 60 bytes of ESP payload is the entire distinction. Large packets are
useless here — they are clamped to the MTU either way.

Expected floors, for a bare ACK plus ESP framing:

| Mode | IPv4 floor |
|---|---|
| Transport | 82 bytes |
| Tunnel | 102 bytes |

### Measured result

The corpus now contains **both modes**: 581 tunnel windows and 56 transport, after
transport-mode cells were added specifically to make this comparison possible.

**Measured on the traffic classes present under both modes only** — `icmp` and `voip`,
224 windows across 96 captures. That restriction is not a convenience. Transport cells
exist only for those two generators, because the sidecar-backed ones cannot produce
protected traffic under transport mode, so across the full corpus **33.6% of the mode
label is predictable from the traffic class alone**. A model evaluated there would score
well by learning "video implies tunnel" and would have learned nothing about mode.
Restricted to the shared classes, that leakage measures **0.0%**.

| Baseline | Accuracy | Coverage |
|---|---|---|
| Majority class (always `tunnel`) | **75.0%** | 100% |
| Size-floor heuristic | **66.7%** | 48.2% |

### The heuristic is worse than guessing, and that is the finding

**66.7% is below the 75.0% majority-class baseline.** The heuristic is not merely weak;
on this data it is worse than always answering `tunnel`.

The cause is measurable. It compares the smallest packet against absolute floors of 82
and 102 bytes, derived from a bare TCP ACK plus assumed ESP framing. Real minimum ESP
packets in this corpus run **136 to 164 bytes**, and vary by *cipher* more than by mode:

| Configuration | Minimum ESP packet |
|---|---|
| 3DES / MD5, tunnel | 136 |
| AES-128 / SHA-256, **transport** | **140** |
| AES-256-GCM, tunnel | 140 |
| AES-256 / MD5, tunnel | 152 |
| AES-128 / SHA-256, **tunnel** | **156** |
| AES-256 / SHA-384, tunnel | 164 |

The mode signal is real — the same cipher and generator gives 156 bytes in tunnel mode
against 140 in transport, a 16-byte gap that is the inner IP header rounded by AES-CBC's
block padding. But it is **only visible relative to the cipher**, and a heuristic using
absolute thresholds cannot see it. Two configurations differing only in mode are 16
bytes apart; two differing only in cipher are up to 28 bytes apart.

**The floors were not adjusted to improve this number.** Tuning them against the corpus
would produce a baseline fitted to the test set, which is precisely what a baseline must
not be.

### Result

| Model | Accuracy | Macro-F1 |
|---|---|---|
| Random forest | **93.3%** | 0.908 |
| Gradient boosting | 88.4% | 0.839 |

Grouped 5-fold by capture. Transport recall 0.82 at precision 0.90, so the model is
identifying the minority class rather than defaulting to `tunnel`.

**The model beats the heuristic by 26.6 points and the majority class by 18.3.** The ML
lane is justified for mode inference: the classifier sees the cipher-relative offset
that a fixed threshold cannot.

---

## Traffic classification — baselines

Measured **before** either classifier was trained, on the corrected 581-row corpus
(7 classes, 252 captures), under the same grouped 5-fold cross-validation the models
use.

| Baseline | Accuracy | Macro-F1 | What it does |
|---|---|---|---|
| Majority class | **16.5%** | 0.041 | always predicts `icmp` |
| Depth-1 decision tree | **24.6%** | 0.129 | one feature, one threshold |

The majority-class figure is the floor beneath every classifier. Quoting an accuracy
without it lets a model that learned nothing look competent on an unbalanced corpus —
this one is balanced, so the floor sits near 1/7.

The depth-1 tree is the bar that matters. If a 300-tree ensemble cannot clearly beat
one number and one threshold, the ensemble is not earning its complexity.

### Result

| Model | Accuracy | Macro-F1 |
|---|---|---|
| Random forest | **96.0%** | 0.963 |
| Gradient boosting (XGBoost) | 95.2% | 0.954 |

Both clear the bar by a wide margin, so the ML lane is justified for traffic
classification. Per-class F1 ranges from 0.89 (`email`) to 1.00 (`messaging`, `voip`).

**Read these as in-distribution numbers.** Folds are grouped by `capture_id`, so no
capture spans train and test and no window is scored against its own siblings — but the
same *configurations* appear on both sides. A deployed analyser meets configurations
nobody trained on, and that is a different and harder question. It is answered in
`docs/GENERALISATION.md` at Step 7.6, where the numbers are expected to fall.

The two models are reported rather than ranked. Choosing the winner on the folds used
to measure them would be selection on the test set; the choice belongs to a held-out
split.
