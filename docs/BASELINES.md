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

Against the full corpus (581 windows, 252 captures):

| Metric | Value |
|---|---|
| Coverage (windows it will answer for) | **70.7%** |
| Accuracy on answered windows | **95.1%** |
| False-`transport` rate | **4.9%** |

Coverage is reported separately from accuracy on purpose. A baseline that abstains on
most rows and is right on the rest is not a highly accurate baseline, and collapsing the
two into one number would flatter it into looking like a bar worth clearing.

### **The number above is not evidence of skill, and must not be quoted as though it were**

**The corpus contains exactly one mode: `tunnel`.** Transport mode was dropped from the
sweep matrix during Phase 2 because those cells produced zero ESP — the tunnel
established and the generated traffic was not protected by it, which the runner's ESP
guard correctly rejected. That deviation is recorded in `PROGRESS.md` and in
`docs/DATASET.md`.

On a single-class corpus, a classifier that always answers `tunnel` scores 100%. The
95.1% figure therefore measures only one thing: **the heuristic's false-positive rate is
4.9%** — one window in twenty is wrongly called `transport`. Accuracy, precision and
recall are all undefined for the absent class.

Concretely, this means:

* **No model may claim to beat this baseline on mode inference using this corpus.** The
  comparison cannot be made. A model trained here would learn to answer `tunnel`
  unconditionally and score 100%, which is not a result.
* Closing the gap needs a corpus containing transport-mode cells with real ESP traffic —
  a testbed change, not a modelling one.
* The heuristic is still shipped, because on a *deployed* estate containing both modes it
  answers 70% of windows from arithmetic alone, and its abstentions are explicit.

### What the abstentions mean

The heuristic returns `unknown` with confidence 0 for 29.3% of windows: their smallest
packet is far from both floors, which happens whenever a flow never carried a bare
acknowledgement. Guessing there would inflate the baseline's apparent coverage and make
every later comparison against it meaningless.

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
