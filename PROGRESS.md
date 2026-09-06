# Build Progress

**Last updated:** 2026-09-05
**Current phase:** 8 — Remediation
**Current step:** 8.4 — zero-downtime sequencing
**Last milestone tag:** `v0.8.0-ml`

Authoritative execution document: `IPsec_Sentinel_BUILD_PLAN.md` (98 steps, 13 phases,
13 milestone gates). Domain reference: `ipsec_ai_platform_master_document.md`.

---

## Completed steps

### Phase 0 — Foundation (8 steps → `v0.1.0-foundation`)
- [x] 0.1 — Initialise repository structure — commit `d4f98f1`
- [x] 0.2 — Python packaging and dependencies — commit `cef9e3d`
- [x] 0.3 — Makefile as the single entry point — commit `8201d12`
- [x] 0.4 — CI pipeline — commit `cd9ec8d`
- [x] 0.5 — Structured logging — commit `7568e7a`
- [x] 0.6 — Core domain models — commit `1edd7a1`
- [x] 0.7 — Protocol constants and lookup tables — commit `6fe9d48`
- [x] 0.8 — Test fixture helpers (synthetic IKE packet builders) — commit `e78766b`
- [x] **▶ MILESTONE M0 PASSED** — tag `v0.1.0-foundation` — commit `f6250a6`

  | M0 acceptance | Result |
  |---|---|
  | All tests pass | **192 passed** |
  | Coverage above 80% | **100.00%** |
  | `mypy --strict` clean | **11 files, no issues** |
  | CI green on GitHub | **success on `f6250a6`** |
  | Domain models round-trip through JSON | **identical; parsed/inferred split preserved** |
  | Builders produce valid byte sequences | **4/4 valid, payload chains terminate exactly** |

### Remaining phases (not started)
### Phase 1 — Testbed (7 steps → `v0.2.0-testbed`)
- [x] 1.1 — Single strongSwan container — commit `fad199f`
- [x] 1.2 — Two-peer network topology — commit `7acc8ea`
- [x] 1.3 — First working tunnel (hardcoded) — commit `4e13351`
- [x] 1.4 — Config templating — commit `2203b97`
- [x] 1.5 — Config validity matrix — commit `5657d84`
- [x] 1.6 — Ground-truth harvester — commit `2f2e3d2`
- [x] 1.7 — Dual-tap capture — commit `dfeab3c`
- [x] **▶ MILESTONE M1 PASSED** — tag `v0.2.0-testbed`

  | M1 acceptance | Result |
  |---|---|
  | Tunnel establishes | **yes** — `weak` anchor, AES_CBC-128 / MODP_1024 / tunnel |
  | Outer PCAP has IKE and ESP, no plaintext | **4 IKE (UDP 500 + NAT-T 4500), 12 ESP, 0 ICMP** |
  | Inner PCAP has plaintext | **6 echo requests + 6 replies** |
  | Manifest written with negotiated (not intended) params | **yes** — intent `aes128`, negotiated `AES_CBC/128` |
  | `negotiation_matched_intent` True for a valid config | **True**, zero mismatches |
  | Containers and networks torn down cleanly | **no leaks** |
  | All previous tests still pass | **304 unit (100% cov), 48 integration** |
### Phase 2 — Traffic generation (9 steps → `v0.3.0-traffic`)
- [x] 2.1 — Traffic generator interface — commit `4cbe556`
- [x] 2.2 — ICMP generator — commit `c1dc5a4`
- [x] 2.3 — VoIP generator — commit `722d07b`
- [x] 2.4 — Video streaming generator — commit `d66a4c5`
- [x] 2.5 — Web browsing generator — commit `ff3f895`
- [x] 2.6 — Email generator — commit `bff1e5c`
- [x] 2.7 — Messaging generator (XMPP proxy) — commit `cdb000f` (+ `5b469ea`, `29a4650`)
- [x] 2.8 — PCAP replay generator — commit `be6a780`
- [x] 2.9 — Network impairment profiles — commit `b36e9f1`
- [x] **▶ MILESTONE M2 PASSED** — tag `v0.3.0-traffic`

  | M2 acceptance | Result |
  |---|---|
  | All 7 generators run without error | **7/7**, measured over 60 s each |
  | Each produces a distinct traffic pattern | **yes** — measured, not eyeballed; see `reports/generator_shapes.json` |
  | Impairment profiles apply and remove cleanly | **yes** — 19 unit + 9 integration tests |
  | All Phase 0 and Phase 1 tests still pass | **341 unit (100% cov), 125 integration** |
### Phase 3 — Dataset and external data (6 steps → `v0.4.0-dataset`)
- [x] 3.1 — Single-run orchestrator — commit `4961d8f`
- [x] 3.2 — Sweep orchestrator with resumability — commit `944a5d1`
- [x] 3.3 — External dataset fetcher — commit `fbf5a0d`
- [x] 3.4 — Dataset documentation — commit `4760d39`
- [x] 3.5 — Prove the external datasets lack IPsec **(UNCUTTABLE)** — commit `890603e`
- [x] 3.6 — Dataset packaging — commit `19ba1e3`
- [x] **▶ MILESTONE M3 PASSED** — tag `v0.4.0-dataset` (9/9, sweep 252/252, 0 failures)
### Phase 4 — Deterministic IKE parser (10 steps → `v0.5.0-parser`)
- [x] 4.1 — Bounds-safe byte reader — commit `aa369a8`
- [x] 4.2 — IKE header parser — commit `26f8c45`
- [x] 4.3 — Payload chain walker with loop guards — commit `319e3fb`
- [x] 4.4 — Transform parser with attribute support — commit `444b875`
- [x] 4.5 — Proposal and SA payload parser — commit `4079e05`
- [x] 4.6 — KE, nonce, notify and vendor ID payloads — commit `13bd785`
- [x] 4.7 — IKEv1 support (aggressive mode + PSK detection) — commit `e920b84`
- [x] 4.8 — PCAP ingestion — commit `809f531`
- [x] 4.9 — Parser fuzzing **(UNCUTTABLE)** — commit `eeca281`
- [x] 4.10 — tshark parity check — commit `6655bcb`
- [x] **▶ MILESTONE M4 PASSED** — tag `v0.5.0-parser` (7/7 acceptance items, `make verify-all` green)
### Phase 5 — ESP analysis (5 steps → `v0.6.0-esp`)
- [x] 5.1 — ESP header parser — commit `2e58048`
- [x] 5.2 — ESP flow assembly — commit `eb2210e`
- [x] 5.3 — Sequence and replay analysis — commit `2206baf`
- [x] 5.4 — IKE-to-ESP tunnel correlation — commit `3e0c26e`
- [x] 5.5 — Tunnel inventory — commit `414ddee`
- [x] **▶ MILESTONE M5 PASSED** — tag `v0.6.0-esp` (4/4 acceptance items)
### Phase 6 — Assessment engine (9 steps → `v0.7.0-assessment`) ← **CURRENT**
- [x] 6.1 — Rule framework — commit `d67658f`
- [x] 6.2 — Cryptographic strength rules (CRY-01..CRY-10) — commit `a547da4`
- [x] 6.3 — IKE configuration rules (IKE-01..IKE-04) — commit `2ed66f2`
- [x] 6.4 — Forward secrecy and SA rules (PFS-01..SA-04) — commit `635355c`
- [x] 6.5 — PQC readiness grading — commit `6093f85`
- [x] 6.6 — Compliance baselines (incl. ITSAR, CERT-In) — commit `7da6b23`
- [x] 6.6b — Four additional rules to reach the M6 count of 26 — commit `7853445`
- [x] 6.7 — Scoring and grading — commit `6a953b1`
- [x] 6.8 — ATT&CK and CVE enrichment — commit `387f0b4`
- [x] 6.9 — Configuration anomaly detection — commit `5f42efd`
- [x] **▶ MILESTONE M6 PASSED** — tag `v0.7.0-assessment` (8/8, at commit `97b5a0f`)
### Phase 7 — Feature extraction and ML (10 steps → `v0.8.0-ml`) ← **CURRENT**
- [x] 7.1 — Flow feature extractor (42 features) — commit `36d8609`
- [x] 7.2 — ML dataset assembly (1,745 rows) — commit `f5a7681`
- [x] 7.3 — Leakage-free splitting — commit `1ee6faa`
- [x] 7.4 — Heuristic baseline for mode inference — commit `4197c81`
- [x] 7.5 — Traffic classifier training — commit `41e3fbe`
- [x] 7.6 — Generalisation report **(UNCUTTABLE)** — commit `9e4f73c`
- [x] 7.7 — Confidence calibration — commit `8d20cd8`
- [x] 7.8 — Prediction abstention — commit `57876e7`
- [x] 7.9 — SHAP explanations — commit `26bb49a`
- [x] 7.10 — Confound audit — commit `ea79e59`
- [x] **▶ MILESTONE M7 PASSED** — tag `v0.8.0-ml` (10/10)
### Phase 8 — Remediation (6 steps → `v0.9.0-remediation`) ← **CURRENT**
- [x] 8.1 — Change package model with both-ends enforcement — commit `cc3e456`
- [x] 8.2 — strongSwan config generator (live-tested) — commit `f28e9ee`
- [x] 8.3a — Libreswan generator (syntax-validated) — commit `8cf629c`
- [x] 8.3b — Cisco, FortiGate, Juniper, Palo Alto generators (syntax-validated) — commit `aa3d1bd`
- [x] 8.4 — zero-downtime change sequencing (live-verified, 0.00s outage) — commit `126ca33`
- [x] 8.5 — blast radius assessment — commit `5c22acf`
- [x] 8.6 — automatic fix verification from traffic — commit `3ad23d3`
- [x] **M8 gate — 7/8 passed, 0 failed, 1 blocked** — tag `v0.9.0-remediation`
- [x] 9.1 — report model with verified/inferred separation — commit `4ca8cde`
- [x] 9.2 — report builder — commit `aa41a84`
- [x] 9.3 — metadata exposure analysis — commit `1a3448d`
- [x] 9.4 — threat matrix — commit `7d66d6d`
- [x] 9.5 — self-contained HTML renderer — commit `8c5d873`
- [x] 9.6 — PDF and JSON export — commit `9a4584e`
- [x] 9.7 — SIEM output formats — commit `43cecb8`
- [x] pipeline — `analyse.py`, capture to report — commit `7b60ca9`
- [x] **M9 gate — 10/10 passed, 0 failed** — tag `v0.10.0-reporting`
- [x] 10.1a — active IKE prober and observed-config reconstruction — commit `40db773`
- [x] 10.1b — **fix: a named baseline selected zero rules** — commit `6ab3861`
- [x] 10.1 — command-line interface — commit `b766978`
- [x] 10.2 — REST API — commit `fe9d6dd`
- [x] 10.3 — dashboard, and the classifier wired in — commit `13ef92f`
- [x] 10.4 — watch mode with drift detection — commit `9c9b490`
- [x] 10.4b — device state collector, closing the rekey blind spot — commit `f572822`
- [x] **M10 gate — 8/8 passed, 0 failed** — tag `v0.11.0-interfaces`
- [x] 11.1a — **fix: 3DES was undetectable over IKEv1** — commit `5aa3e14`
- [ ] Phase 9 — Reporting (7 steps → `v0.10.0-reporting`)
- [ ] Phase 10 — CLI, API and dashboard (4 steps → `v0.11.0-interfaces`)
- [ ] Phase 11 — Hardening, packaging, demo (7 steps → `v1.0.0`)
- [ ] Phase 12 — Presentation and evidence pack (10 steps → `v1.0.0-presentation`)

---

## Blockers

**None.** The one outstanding item (the M3 gate) was closed on 2026-09-06.

### ✅ RESOLVED — the M3 gate (was outstanding through Phase 4 and 5)

Phase 4 is proceeding ahead of the M3 tag. This is deliberate and is **not** a step being
skipped: M3's acceptance depends on a 252-cell sweep that takes roughly four hours of
wall clock and is entirely I/O- and container-bound, so blocking on it would idle the
parser work for no gain. The parser has no dependency on the sweep output — it reads IKE
bytes, and its tests build those bytes synthetically.

**Closed on 2026-09-06.** The sweep finished at 252/252 with 0 failures;
`scripts/package_dataset.py` then `scripts/check_m3.py` were run and all 9 criteria pass.
See the M3 acceptance checklist below. The overlap cost nothing: no gate was weakened and
no step skipped, and the only visible trace is that `v0.4.0-dataset` carries a later
commit date than `v0.5.0-parser`.

### ✅ RESOLVED — Phase 1 testbed viability (was the project's biggest open risk)

This is a macOS arm64 host, so Phase 1's kernel XFRM / netns / `tc netem` requirements can
only be met inside Docker Desktop's LinuxKit VM. **Probed on kernel `6.12.76-linuxkit`
(aarch64) in a `--privileged --cap-add=NET_ADMIN` container. Every requirement passed:**

| Capability | Result |
|---|---|
| `ip xfrm state` / `ip xfrm policy` — read | PASS |
| `ip xfrm policy add` — write | PASS |
| ESP SA, **AES-256-GCM-16** (`rfc4106(gcm(aes))`, 32-byte key + 4-byte salt, ICV 128) | PASS |
| ESP SA, **AES-128-GCM-16** | PASS |
| ESP SA, AES-CBC + HMAC-SHA256 | PASS |
| ESP SA, **3DES-CBC + HMAC-MD5** (the matrix's `worst` anchor) | PASS |
| `tc qdisc add ... netem delay/jitter/loss` | PASS |
| netns / dummy link creation | PASS |

`/proc/crypto` confirms `gcm(aes)`, `cbc(aes)`, `ctr(aes)`, `ccm(aes)`, `des3_ede`,
`cbc(des3_ede)`, `hmac(md5)`, `hmac(sha256)` and the `authenc` composites. This covers
every encryption in `testbed/configs/matrix.yaml`.

**Conclusion: Phases 1–3 and 7 proceed exactly as written. No contingency invoked.**

> Trap for the next session: `rfc4106(gcm(aes))` keys must be 20/28/36 bytes
> (16/24/32-byte key **plus a 4-byte salt**). A wrong length yields the misleading error
> `"Kernel was unable to initialize cryptographic operations"`, which reads like a missing
> kernel module but is not. This cost one false negative during the probe.

> **Transient, expected:** `make test` / `test-unit` / `test-int` / `cov` exit non-zero with
> "no tests ran" at steps 0.3–0.4 because no tests exist yet — the first arrives at Step 0.5.
> Step 0.3's own acceptance criterion is `make lint`, which passes. Full `make verify` becomes
> meaningful from Step 0.5 onward and is the gate for every commit from there.
>
> **Consequence for CI (plan defect, stated not hidden):** Step 0.4's workflow runs
> `make cov`, and Step 0.4's acceptance is "wait for green" — but green is structurally
> impossible before Step 0.5 adds the first test, since `pytest` exits non-zero on an empty
> suite and `--cov-fail-under=80` cannot be met with no coverage data. The workflow was
> pushed verbatim as the plan specifies; it is red for exactly one commit and turns green at
> Step 0.5. The gate was **not** weakened to manufacture a passing badge — disabling CI,
> lint or type checking to make progress is explicitly prohibited.

---

## Step 6.6 — a real bug the tests caught, and a disclosure decision

### CRY-11 compared the wrong scale

`DH_GROUPS` stores **parameter size** — modulus bits for MODP, curve bits for ECP. The
first version of CRY-11 compared those directly, which reports **256-bit ECP (128-bit
strength) as weaker than 2048-bit MODP (112-bit strength)**. Exactly backwards, and the
mistake was warned against in the rule's own docstring before being made in its body.

Caught by an existing Step 6.2 test — the strong fixture uses group 19 and suddenly
failed. Fixed with `DH_SECURITY_BITS`, an explicit NIST SP 800-57 Table 2 strength
table, and the baseline field renamed `dh_group_bits` → **`dh_security_bits`** so the
scale is named at every use site. A regression test pins group 19 as acceptable at a
112-bit floor and group 2 as not.

### Two baselines are unverified, and say so

ITSAR and CERT-In are encoded **from public description, not from a verified copy of the
controlling document**. ITSAR is issued per equipment category by NCCS and is not freely
redistributable; CERT-In issues directions rather than one consolidated cryptographic
standard.

Rather than present either as authoritative, every baseline carries `verified` and a
`provenance` note, the two Indian ones say `NOT FROM A VERIFIED COPY` in capitals, and
the loader **refuses** an unverified baseline whose provenance is too short to explain
what a reader should check. Tests assert all of that. A compliance claim traceable to a
declared interpretation is useful; one that hides being an interpretation is not.

### The baselines are demonstrably not copies of each other

Same 252 tunnels, six authorities, 0 rule errors:

| Baseline | Findings | Severity spread |
|---|---|---|
| `cnsa` | 784 | critical 280, high 224, medium 280 |
| `bsi_tr02102_3` | 714 | critical 91, high 343, medium 280 |
| `itsar` | 686 | critical 91, high 315, medium 280 |
| `nist_800_77r1` | 686 | critical 56, high 259, medium 119, info 252 |
| `certin` | 686 | critical 91, high 224, medium 119, info 252 |
| `rfc_8221_8247` | 406 | critical 91, high 224, low 91 |

CNSA is strictest and RFC 8221/8247 most permissive, which is what those documents
actually are.

---

## Step 6.4 — what a passive observer cannot see

The build plan's PFS and SA rules assess six settings. **Five of them are invisible to a
passive observer**, and saying so was the whole design problem of this step.

| Rule | Observable from a capture? |
|---|---|
| SA-01 IKE lifetime > 24 h | **Yes for IKEv1** — a cleartext phase 1 SA attribute. This corpus carries 31,680 s and 95,040 s, and SA-01 fires 28 times on the second. **No for IKEv2** — RFC 7296 removed lifetimes from the SA payload; each peer keeps its own and never announces it |
| SA-03 anti-replay | **Partly** — duplicate ESP sequence numbers are observable; the *cause* is not |
| PFS-01, PFS-02 | **No** — negotiated in IKEv1 Quick Mode / IKEv2 CREATE_CHILD_SA, both encrypted |
| SA-02 child lifetime | **No** — phase 2, encrypted |
| SA-04 replay window | **No** — a local setting that never appears on the wire |

Three options existed: infer them from side channels and present the guess as fact;
emit them with a confidence and move them to the inferred lane; or take them from the
operator. **The third was chosen.** `ObservedConfig` carries operator-supplied facts,
every field defaults to "not supplied", and a rule whose input is missing returns
`None` — silence, not a default. A report asserting "PFS is disabled" because nobody
said otherwise would be worse than no report, because an operator would act on it.

Every finding stays deterministic: read from the wire, or read from a document the
operator provided. **The evidence always names which**, so a reader can separate the two
without trusting the tool. Fourteen tests assert the silence-without-input behaviour
directly.

SA-03 is the one hybrid, and its wording carries the whole point. On observed
duplicates it says the evidence is "consistent with anti-replay being disabled, but a
passive observer cannot distinguish it from network duplication — confirm against the
device configuration before acting." The observation is certain; the conclusion is not.

---

## MILESTONE M3 — acceptance checklist (executed)

The sweep completed on 2026-09-06: **252/252 cells, 0 failures**, 1,075,251 outer and
1,070,771 inner packets. Run with `scripts/check_m3.py`.

| M3 acceptance | Result |
|---|---|
| At least 24 distinct tunnel configurations | **PASS** — 36 |
| All 7 traffic classes represented | **PASS** — email, icmp, messaging, replay, video, voip, web |
| At least 3 impairment profiles used | **PASS** — clean, wan_good, wan_poor |
| Every encryption appears with ≥2 DH groups | **PASS** — minimum is AES_GCM_16 with 5 |
| Every traffic class appears with ≥3 configurations | **PASS** — minimum is 36 |
| Total labelled flows ≥ 2000 | **PASS** — 21,147 |
| Every packaged cell negotiated what was configured | **PASS** — 252/252 matched intent |
| External dataset audit generated | **PASS** — `docs/external_dataset_audit.md` |
| Corpus is not confounded (class vs cipher) | **PASS** — no confound warnings |

**The confound check is the one that matters.** The master document names it as the most
fatal trap available here: if application class correlates with cipher in the corpus, a
classifier trained on it reads cipher artifacts while appearing to read traffic shape,
and scores beautifully on a corpus that taught it nothing. The sweep was planned to be
balanced and is measured to be.

**Tag ordering.** `v0.4.0-dataset` is tagged after `v0.5.0-parser`, out of numeric order.
That is the visible consequence of the deliberate overlap recorded in Blockers — Phase 4
ran while the sweep occupied the machine for four hours. No milestone was skipped and no
gate was weakened; only the wall-clock order of two tags differs from the plan.

---

## MILESTONE M5 — acceptance checklist (executed)

Run with `scripts/check_m5.py`.

| M5 acceptance | Result |
|---|---|
| All dataset PCAPs produce correlated tunnels | **PASS** — 252 captures, 252 tunnels, exactly one per cell |
| Sequence analysis matches known impairment levels | **PASS** — see below |
| Inventory flags a synthetic undocumented tunnel | **PASS** — 20 real tunnels cleared, only the planted one flagged |
| All earlier tests still pass | **PASS** — 880 unit tests |

Loss measured across the full corpus, against what `tc netem` was configured to inject:

| Profile | Injected | Measured from ESP sequence numbers |
|---|---|---|
| `clean` | 0% | **0.0000%** |
| `wan_good` | 0.1% | **0.1027%** |
| `wan_poor` | 1.0% | **1.0217%** |

"Exactly one tunnel per cell" is the strongest of these. Each cell builds one tunnel
between one pair, and real captures carry four to nine IKE messages — so a correlator
that treated each message as a tunnel would report 252 cells as roughly 1,200 tunnels
and still look like it was working.

---

## Step 5.3 — the impairment cross-check recovered the injected loss

The strongest validation in the project so far, because the expected values were not
computed by this project. `tc netem` was configured with a loss percentage per profile;
the analyser measures loss independently, from ESP sequence numbers, on captures
strongSwan produced.

| Profile | netem was told to drop | Sequence numbers show | Flows with gaps |
|---|---|---|---|
| `clean` | 0% | **0.0000%** | 0 / 70 |
| `wan_good` | 0.1% | **0.0992%** | 38 / 68 |
| `wan_poor` | 1.0% | **0.9088%** | 51 / 68 |

Not just the sign — the number. The analyser measures reality.

One honest observation not asserted on: 15 of the 70 `clean` flows show **reordering**
with zero loss. A path with no impairment should not reorder, so this is most likely a
capture artifact — `tcpdump` writing from a ring buffer — rather than the network. It is
recorded rather than tested against, because the cause has not been established.

### A hang found by the tests, in new code

`test_two_wraps_are_counted` took **82 seconds**. Gap-finding walked every integer
between the lowest and highest sequence number, which is fine when the span is roughly
the packet count and catastrophic otherwise: two counter wraps put four billion values
between lowest and highest, so a **four-packet flow** stalled the analyser.

That is the same defect class Step 4.9's fuzzing exists to prevent, one layer up, and
in code written after it — ESP sequence numbers are attacker-controlled input, and an
analyser stalled by six bytes of them is not a defence. Gaps are now read off the sorted
arrivals, O(n log n) in packets rather than O(span): 82 s → under 5 ms. Four regression
tests pin the timing, and a fifth pins the answer, since fast and wrong would be no
better than slow and right.

**Test-suite performance is a correctness signal, not a convenience.** `make verify` runs
before every commit; had the suite merely been "a bit slow" and left alone, the hang
would have shipped.

---

## MILESTONE M4 — acceptance checklist (executed)

Run with `scripts/check_m4.py`, which is an executable gate rather than a set of
commands typed once: anyone can re-run it, and a later regression fails it instead of
quietly invalidating a claim made in a commit message. Checks that cannot run report
SKIP and never count as passes.

| M4 acceptance | Result |
|---|---|
| Parses 100% of dataset PCAPs without unhandled exceptions | **PASS** — 92 captures, 460 IKE messages, 0 exceptions |
| Agrees with tshark on every field compared, across the dataset | **PASS** — 92/92 captures, 460 messages compared |
| Fuzzing: 10,000 inputs, zero crashes, zero hangs | **PASS** — 35,167 inputs/run, 0 unexpected exceptions, 0 over 1 s |
| IKEv1 Aggressive Mode detected in the `worst` anchor config | **PASS** — 7 captures show it, all 7 with PSK (hash exposed) |
| Key length distinguishes AES-128 from AES-256 | **PASS** — both read back correctly; 128 and 256 both present in the dataset |
| **All** proposals extracted, not just accepted | **PASS** — 2/2 from the fixture including the 3DES fallback |
| Coverage of `parser/` above 90% | **PASS** — 99.0% |

`make verify-all` green in full: ruff clean, `mypy --strict` clean over 53 source files,
**768 unit tests** at 93.33% total coverage, and **158 integration tests** in 14 m 33 s.
Per-module parser coverage: `constants.py` 100%, `ikev1.py` 100%, `ike.py` 99%,
`reader.py` 98%, `message.py` 97%, `pcap.py` 96%.

**Two honest notes on that table.**

*Multi-proposal captures.* The dataset contains **zero** multi-proposal messages: each
sweep cell configures strongSwan with exactly one proposal, so it offers exactly one.
The criterion is therefore met on the synthetic fixture, which offers AES-GCM with a
3DES fallback and proves the fallback survives. That is a real gap in the corpus, not
in the parser, and it is worth closing later with a cell configured to offer several.

*The sweep was paused for this gate.* `make verify-all` includes integration tests that
bring up Docker tunnels, which would have collided with the running sweep. The sweep was
stopped with SIGTERM and resumed afterwards — which incidentally exercised the Step
"killed sweep" fix against the exact failure it was written for: clean exit, **zero**
leftover containers, **zero** leftover networks, lock released, state intact at 93
completed / 0 failed.

---

## Step 4.10 — tshark parity results

**87/87 sweep captures agree with tshark, message for message.** Compared on version,
exchange type, every transform (type and ID) and every key length. Wireshark 4.6.8,
installed via `brew install --formula wireshark` — `tshark` was not present before this
step, and the integration test skips rather than fails where it is absent.

These are strongSwan's own captures, not fixtures this project wrote — which is the
entire point. Every other parser test checks this code against fixtures built from the
same reading of the RFCs, so a misreading would be baked into fixture and test alike.

**The suite contains a negative control**, because a parity check that cannot fail
proves nothing: three tests feed the comparator a deliberately wrong transform, a wrong
version and a dropped message, and assert each is detected. A fourth asserts the dataset
actually contains ISAKMP, since comparing two empty lists passes loudly while testing
nothing.

Two things worth knowing for anyone re-running it:

* The display filter is `isakmp`, not `ike`. Wireshark's dissector predates the IKEv2
  name and never adopted it; `-Y ike` matches nothing and reports no error.
* `tshark -T json` emits **genuinely duplicate object keys**, one per repeated field. A
  plain `json.loads` keeps only the last, so a message with four transforms appears to
  have one — and the parity check would then pass by comparing almost nothing. The
  comparator reads the output as an ordered pair list for that reason.

---

## Step 4.9 — fuzzing results (UNCUTTABLE step, evidence)

**35,167 inputs per run, zero unexpected exceptions, zero inputs over the 1 s limit.**
The whole suite runs in 2.5 s, so it is part of `make verify` rather than a nightly job.

The contract under test: for **any** bytes, `parse_ike_message` returns a result or
raises `TruncatedError` / `MalformedError`. Anything else — `IndexError`, `struct.error`,
`MemoryError`, a hang — fails the test.

| Corpus | Inputs | Purpose |
|---|---|---|
| Pure random | 10,000 | The plan's headline criterion. Seeded, so any finding replays. |
| Header-shaped random | 1,000 | Random bytes rarely survive header validation; these always do |
| Hypothesis `st.binary` | 500 | Shrinking finds minimal counterexamples the seeded loops would not |
| Single-byte flips | 2,000 | 500 per valid fixture |
| Truncation at every offset | 956 | Every prefix of every fixture — what a snaplen cut produces |
| Inflated message length | 28 | The classic overread trigger |
| Every 16-bit word inflated / zeroed | ~1,700 | Payload and transform lengths, without hardcoding their offsets |
| Splices of two valid messages | 1,000 | Version confusion at an arbitrary boundary |
| Every payload type, random body | 12,000 | 60 types × 200 |
| Random SA / proposal-framed / IKEv1 SA bodies | 6,000 | Aimed at the proposal, transform and attribute parsers |

**A measurement that changed the suite.** The first version passed instantly, which was
suspicious. Instrumenting it showed why: of 10,000 pure-random inputs, 5,998 parsed and
4,002 were rejected as truncated — but **zero** ever produced a parsed payload. Random
bytes essentially never name a payload type the parser handles, so the corpus exercised
the chain walker and stopped there, leaving the proposal, transform and attribute
parsers — where the parsing actually happens — untouched. The last four corpora above
were added to aim at them, taking `ike.py` from 90% to 94% and `ikev1.py` to 98% under
fuzzing alone. The lesson is recorded because "the fuzzer found nothing" is only
reassuring once you have checked the fuzzer went anywhere.

---

## Deviations from plan

0. **Step 3.5 was done before Step 3.4.** Step 3.4 instructs: "Verify this claim
   yourself with a script (Step 3.5) and cite your own result." The documentation
   cannot be written honestly before the audit it is supposed to cite has run, so the
   two were swapped. Nothing else in the phase depends on the order.


1. **Repo root is the existing working directory** (`/Users/prasham/Desktop/SIH_Hackathon`)
   rather than a new `ipsec-sentinel/` subdirectory as Step 0.1's shell snippet shows.
   The skeleton beneath it matches the plan exactly.
2. **Added `models/` to the skeleton.** The plan's `.gitignore` references `models/*.pkl`
   and `models/*.joblib` but the directory tree omits the directory.
3. **Added `__init__.py` to each `src/ipsec_sentinel/` subpackage.** The plan shows only
   the top-level one; the subpackages need theirs to be importable packages.
4. **Two host-specific `.gitignore` additions.** The plan's `.gitignore` was written for a
   Linux host: added `.DS_Store` (macOS Finder metadata, which had already staged itself
   into the first commit) and `.claude/` (agent session artifacts, not deliverables).
5. **`mypy` covers `testbed/` as well as `src/`.** The plan sets `files = ["src"]`,
   which would leave the entire testbed and dataset pipeline untyped — the code that
   produces the labelled corpus everything else depends on. Extending it was clean on the
   first try (`Success: no issues found`), so the stricter setting was kept.
6. **`tests/` is a Python package.** Added `__init__.py` to `tests/`, `tests/unit/`,
   `tests/integration/` and `tests/fixtures/` so `tests.fixtures.builders` is importable
   from the unit tests. The plan places the builders at `tests/fixtures/builders.py` and
   imports them, but never makes the directories packages.
7. **`Severity` and `TransformType` use `enum.StrEnum`, not `(str, Enum)`.** The plan's
   Step 0.6 snippet writes `class Severity(str, Enum)`, but the plan's *own* ruff config
   selects the `UP` ruleset, which rejects that on `target-version = "py311"` (UP042) and
   requires `StrEnum`. The plan contradicts itself; the lint config wins, since disabling a
   lint rule to make progress is prohibited. Behaviour is equivalent for every use here
   (`.value`, lookup by value, JSON round-trip) and `str()` is actually cleaner.
8. **Makefile resolves tools from `.venv/bin` when present, else PATH.** The plan's
   recipes call bare `ruff` / `mypy` / `pytest`, which fail locally unless the venv is
   activated first — a footgun across sessions. The shell-detect prefix keeps every target
   name and behaviour identical and works unchanged in CI, where there is no `.venv`.
   Also added `fmt` to `.PHONY` (the plan defines the target but omits it from the list).
9. **Environment created with `uv` rather than `python -m venv` + `pip`.** Step 0.2's
   snippet uses venv+pip; `uv venv` / `uv pip install` produces a byte-compatible standard
   virtualenv that `pip` also operates on, and is far faster on a slow link. `pyproject.toml`
   is verbatim from the plan. No functional difference.

---

## MILESTONE M7 — 10/10 after closing the mode-inference gap

| M7 acceptance | Result |
|---|---|
| Classifier trained with capture-level splitting | **PASS** — 96.4%, macro-F1 0.963, 637 rows in 276 groups |
| Zero `capture_id` overlap | **PASS** — 25 seeds |
| Generalisation report, four splits | **PASS** |
| **Model beats the mode-inference heuristic** | **PASS** — 93.3% vs 66.7%, majority 75.0% |
| ECE below 0.15 | **PASS** — 0.0622, AUROC 0.964 |
| Abstention under 25% | **PASS** — 3.2%, accuracy 97.4% → 99.3% |
| SHAP readable sentences | **PASS** |
| Confound audit published | **PASS** |
| Every ML finding carries a confidence | **PASS** |
| ML test suites | **PASS** — 258 tests |

### The mode-inference result, and the restriction it required

| | Accuracy | Macro-F1 |
|---|---|---|
| Size-floor heuristic | 66.7% (48.2% coverage) | — |
| Majority class (always `tunnel`) | 75.0% | — |
| **Random forest** | **93.3%** | **0.908** |

**The heuristic loses to the majority class**, and that is the finding rather than an
embarrassment. It compares the smallest packet against absolute floors of 82 and 102
bytes; real minimum ESP packets here run **136–164 bytes** and vary by *cipher* more
than by mode. The mode signal is real — 156 bytes tunnel against 140 transport for the
same cipher — but visible only *relative to* the cipher, which a fixed threshold cannot
see and the model can. **The floors were not retuned**, because a baseline fitted to the
corpus is not a baseline.

**Measured on `icmp` and `voip` only**, the classes present under both modes. Transport
cells exist only for those two, so across the full corpus **33.6% of the mode label is
predictable from the traffic class alone** — a model evaluated there would score well by
learning "video implies tunnel". Restricted to the shared classes that leakage is
**0.0%**, and a test asserts it stays there.

### A second artefact the corpus expansion exposed

Six tunnel `replay` captures still reported **48–49 ESP flows** where a tunnel has two.
The Phase 7 structural floor removed the 32-byte protocol-50 frames; 44-byte ones
survived it. The dataset's minimum-packet threshold masked this, so the ML data was
clean while `flows_from_capture` — which ESP-01 and the inventory rely on — was not.

Fixed at the parser with RFC 4303 §3.3.3: a sender's counter starts at 1 for a new SA,
so a capture of tens of seconds cannot observe a *single* packet bearing a sequence
number in the millions. Every capture in the corpus now yields **exactly 2 flows, or 0
for the cells the ESP guard rejected**.

---

## Step 11.1a — 3DES was invisible on every IKEv1 tunnel

Building the end-to-end test found the most serious correctness bug in the project.

```
CRY-05 did not fire on the weak tunnel; got
['CRY-02', 'CRY-06', 'CRY-11', 'IKE-01', 'IKE-03', 'PQC-01', 'SA-01']
```

The tunnel is 3DES. CRY-05 is "3DES encryption offered", severity **critical**. It did
not fire, and it had not been firing on any IKEv1 tunnel since Phase 6.

The rules matched on the raw transform ID. IKEv1 and IKEv2 number their algorithms in
separate registries:

| Value | IKEv2 | IKEv1 | Consequence |
|---|---|---|---|
| 2 | DES | **IDEA** | CRY-04 would report IDEA as DES |
| 3 | 3DES | **Blowfish** | CRY-05 would report Blowfish as 3DES |
| 5 | RC5 | **3DES** | CRY-05 **missed every IKEv1 3DES tunnel** |
| 7 | CAST | **AES** | any rule on 7 misfires |

A critical finding silently absent from compliance-grade Section A, and false positives
standing ready in the other direction.

**Why it hid for four phases.** MD5 and SHA-1 happen to share their value between the two
registries — IKEv1 hash 1 is MD5 and IKEv2 INTEG 1 is HMAC-MD5-96 — so CRY-06 and CRY-07
kept working on IKEv1 captures. Every IKEv1 tunnel in the corpus produced *some* findings
and graded F on the strength of them, so nothing looked wrong. The corpus's own IKEv1
3DES captures were graded F for MD5 and a weak DH group while the 3DES went unreported.

**The fix** is to match the name the parser resolved rather than the number. The parser
already knows which registry applies and has applied it, so the name is the one place the
two versions agree on meaning. This is the third time this registry split has caused a
bug — after `observed.py` in Step 10.1a and the device-state mapping in 10.4b — and the
first time it reached the assessment engine.

Eight regression tests pin it from both directions: 3DES is found under both spellings,
and Blowfish, RC5 and IDEA are each asserted **not** to be reported as something else. A
ninth runs a real IKEv1 3DES capture from the corpus through the whole pipeline.

---

## ▶ MILESTONE M10 — Interfaces complete

`make verify-all`: **2276 unit + 205 integration passed, 0 failed**.
`scripts/check_m10.py`: **8/8**.

| # | Acceptance item | Result |
|---|---|---|
| 1 | CLI covers every workflow | **PASS** — 9 planned commands present; analyse, inventory, remediate and version run end to end on a real capture; `scan` refuses without authorisation (exit 3) |
| 2 | API passes all security tests | **PASS** — 27 passed, and the plan's four named tests confirmed present by name rather than by count |
| 3 | Dashboard loads and functions offline | **PASS** — 13 Chromium tests; the offline one aborts every request outside the origin and then drives an upload to completion |
| 4 | *(added)* Dashboard references nothing external | **PASS** — the static half of the same claim |
| 5 | Watch mode detects a live weakening within 60 seconds | **PASS** — detected in 2.2s, with a control asserting an unchanged tunnel reports nothing |
| 6 | *(added)* Drift is detectable without seeing the negotiation | **PASS** — the rekey blind spot, closed by Step 10.4b |
| 7 | *(added)* No interface dials out except the one that should | **PASS** |
| 8 | Full regression green | **PASS** |

### Item 7 was worth adding

The plan checks each interface separately. Item 7 checks the property they share and the
one the whole product rests on: `analyse`, `inventory` and the API's upload path are run
with `socket.socket` replaced by a recorder, and **no outbound socket is opened by any of
them**. The same check then confirms the prober — the one component that is supposed to
transmit — still refuses without explicit authorisation.

Three interfaces, one claim, checked once rather than trusted three times.

### Item 1 checks that commands work, not that they exist

`--help` exiting zero proves a command is registered. It does not prove it does anything.
The four read-only workflows are run against a real corpus capture, and `scan` is invoked
without its authorisation flag to confirm the refusal is live rather than documented.

---

## Step 10.4b — the rekey blind spot, closed rather than mitigated

Step 10.4 mitigated the CREATE_CHILD_SA limitation three ways and left it a limitation.
Reading a device's own state removes it: the kernel knows exactly which algorithms are
installed **right now**, whether or not anyone was listening when they were negotiated.

Detected from state alone, with no capture anywhere in the test:

```
10.100.0.2 <-> 10.100.0.3 weakened:
  aes256-sha384-prfsha384-ecp384 -> aes128-sha1-prfsha1-modp1024
```

### The tool parses; it does not fetch

`collect.py` reads text a device produced — `ip xfrm state`, `swanctl --list-sas` — that
arrives by whatever means the operator already has: a file, an Ansible run, a sensor on
the gateway. `local_state()` reads **the machine the tool is running on**, which needs no
credential and opens no socket.

There is deliberately no `--host`, no `--ssh`, no `--api-key`, and a test asserts none of
those options exists on any command. The collector is the operator's; the parsing is
ours, and that division is what keeps the no-credentials claim true rather than aspirational.

### Provenance is kept, not blurred

A finding from device state is a parsed fact, so it sits in Section A with the
wire-derived ones — but they are not the same evidence. A capture can be re-read by
anyone; a device's self-report is only as good as the device. So a state-derived sighting
carries **no `exchange`**, and `analyse --device-state` compares the two and prints the
disagreement rather than resolving it:

```
DISAGREES with the capture for eeb4397163c7: the wire negotiated
aes256-sha384-prfsha384-ecp384, the device reports 3des-md5-prfmd5-modp1024.
One of the two is not describing the tunnel that is running.
```

### A lie the first version told

`observe_state` originally scored the sighting by running the rule engine over a tunnel
with no negotiation. The rules found nothing — because there was nothing to find — and
returned **100 out of 100**. The output read `score 100 -> 100` beside a tunnel that had
just dropped from AES-256 to AES-128.

A tunnel appearing to score perfectly *because nothing was checked* is the most
misleading output available. State sightings are now unscored, the summary says why, and
severity falls back to what actually changed: a cipher, IKE version, aggressive mode or
PFS moving the wrong way is critical on its own.

### Two bugs found by making the two mappings agree

A test asserting the device-state transform IDs are a subset of the wire-side ones failed:

* **AES-GCM-8 and GCM-12 were unmapped.** RFC 8221 permits an 8-, 12- or 16-octet ICV and
  all three are deployed; only 16 was reconstructible, so a real device using either of
  the others failed with "no configuration equivalent".
* **AEAD detection was `encryption.endswith("gcm16")`.** With the first bug fixed, GCM-8
  and GCM-12 were then rejected for lacking an integrity transform they are not supposed
  to have. It now asks `config_gen.is_aead`, which owns the answer.

### No key material, verified against real keys

`ip xfrm state` prints session keys inline. The parsers read the algorithm name and ICV
length and never place the key bytes in a returned object — the guarantee the testbed's
ground-truth harvesting has carried since Phase 1, which is where these parsers came from.
They were **promoted** into the product rather than copied, so the corpus's ground truth
and the product's collector cannot drift apart.

The unit test uses a sample with obviously fake keys, because a security tool's git
history is the last place real ones belong. The live test runs the same assertion against
a real kernel's output — four real session keys in, zero out — since a fixture only proves
the regex drops the field it was aimed at.

---

## Step 10.4 — drift detected in 2.2 seconds, and the blind spot behind it

The scenario from the pitch, run for real: a tunnel configured
`aes256-sha384-prfsha384-ecp384` is replaced with `aes128-sha1-prfsha1-modp1024` between
the same endpoints, and the watcher notices **2.2 seconds** after the change — against a
plan deadline of sixty.

```
10.100.0.2 <-> 10.100.0.3 weakened:
  aes256-sha384-prfsha384-ecp384 -> aes128-sha1-prfsha1-modp1024 (score 89 -> 9)
```

Drift is compared against each tunnel's **own past**, not against a baseline. A tunnel
that was always mediocre is a finding `analyse` already made; one that *was* strong is
news, whether or not the new state breaches policy. The direction of travel is the signal.

Two silences are deliberate. A **first sighting is never drift** — with no past there is
nothing to compare, and alerting there would fill an inbox on every restart until nobody
read it. A **strengthening is recorded but never alerted**, because an alert that fires on
good news is one people learn to close.

### The limitation the test design exposed

Building the live test surfaced something that changes what watch mode can promise.

**A rekey is invisible.** `swanctl --rekey` produces `CREATE_CHILD_SA`, whose SA payload
sits inside the encrypted `SK` payload. The first version of the test used a rekey to put
a second handshake on the wire and got four unreadable exchanges. **Only `IKE_SA_INIT`
carries proposals in the clear.**

The narrow version of that limit is benign, for a reason measured back in Step 8.4: an
IKE SA keeps the configuration it was created with, so a rekey renegotiates the *old*
parameters. A configuration change only takes effect when a new IKE SA is built, and
building one is an `IKE_SA_INIT`. The moment the estate actually becomes weaker is the
moment it becomes visible.

The dangerous version is a watcher with **no memory of the strong past**, because then
the weak tunnel is a first sighting and no alert fires. Three mitigations, each tested
live rather than argued:

| Gap | Mitigation |
|---|---|
| A restarted watcher forgets | `--state` persists each tunnel's last-seen configuration, written atomically; a version mismatch is ignored rather than guessed at, because restoring a *wrong* past would invent drift |
| A watcher started after the change has no baseline | `--since <capture>` seeds from the previous audit. Seeded from the capture, not the JSON report: the report holds the suite as a display string, and parsing it back could get one transform wrong and produce a confidently wrong baseline |
| A tunnel not seen negotiating looks the same as one confirmed unchanged | `stale()` names them — *"last seen 38.2h ago as …; its parameters since then are unverified, not confirmed unchanged"* |

`TestTheLimitationIsMitigated` proves the seeded watcher catches the drift **and** that the
same watcher without a seed reports nothing — the control that shows the mitigation is
doing the work.

One residual limit stays a limit: RFC 7296 permits a rekey to renegotiate the SA payload,
so an implementation that re-reads its configuration at rekey could change parameters
where this tool cannot see it. strongSwan does not — measured, not assumed — but not every
stack is strongSwan. It belongs in `LIMITATIONS.md`.

---

## Step 10.3 — three bugs a browser found and nothing else could

The dashboard is plain HTML, CSS and JavaScript served by the API. No framework, no CDN,
no external font. Thirteen Playwright tests drive Chromium against a live uvicorn.

Every one of the following loaded, looked plausible, and was broken. None would have
failed a unit test.

**The Content Security Policy blocked the dashboard's own script.** The middleware header
was written for JSON responses, where `default-src 'none'` is right, and it applied to the
HTML too. The page rendered — the CSS was inline and CSS was permitted — and simply did
nothing. The fix was not to loosen the policy: the stylesheet and script were **split out
of the single file** so the dashboard could be served under `default-src 'self'` with no
`unsafe-inline` at all, which is stricter than what it replaced. API responses keep the
`'none'` policy.

**`nav{display:flex}` out-specified the browser's own `[hidden]{display:none}`.** The tab
bar was visible before any capture had been analysed, with every panel empty behind it.
One line of CSS.

**The SHAP contribution bars used a `style` attribute**, which the new strict policy
blocks. Every bar would have rendered at zero width, silently. Widths now come from
twenty fixed classes.

The offline test is the one worth reading: it aborts every request whose URL is not the
server's own origin and then asserts the dashboard still works — rather than grepping the
markup for `http://`.

### The classifier, wired in without making it a dependency

`ml/classify.py` computes flow features from a live capture, predicts with abstention, and
attaches the SHAP explanation. It is deliberately **not** imported by `analyse.py`'s
default path: `analyse_capture(model_path=...)` is opt-in, so a run with no model produces
a report that says *nothing* about traffic class rather than one that quietly says
"unknown". A missing model file and a tunnel with nothing to infer must not look alike.

The report gained `InferenceExplanation` — the sentence, the signed contributions, and
**how many traffic windows the judgement rests on**, because one window and thirty are
different claims and the confidence alone does not say which. A validator refuses an
explanation without an inference: reasoning for a conclusion the report does not draw.

The schema went to **1.1**. Report models forbid unknown fields, so the published schema
carries `additionalProperties: false` and a consumer validating new output against 1.0
would reject it. Both files are kept; every report declares which it conforms to.

---

## Step 10.2 — the REST API, and its upload endpoint

An upload endpoint reachable over the network is the largest attack surface in this
project, and everything unusual in `api/app.py` follows from that. The plan says to write
the security tests and not skip them, so they come first in the test file and check
*behaviour* rather than the presence of a mitigation.

**The uploaded filename is never used as a path.** It is reduced to a printable label and
the bytes go to a `mkstemp` path this service chooses. The test uploads a file named
`../../../../../../<tmp>/etc/crontab` and asserts that directory stays empty — rather
than asserting that some sanitising function was called.

The label is stripped for more than slashes: it is echoed into report metadata and error
messages, so terminal escape sequences are removed too. A name of only dots still yields
a usable name, and 5000 characters are bounded to 96.

**The size limit is enforced while reading.** Trusting `Content-Length` lets a client
that lies about it exhaust memory anyway, so the body is read in 1 MB chunks and refused
the moment the ceiling is passed. Tested by sending too much with the limit lowered —
constructing a real 512 MB body to prove it would be its own denial of service — and by
the other side of the same check, that an ordinary upload is *not* refused.

**The hardening headers are middleware, not per-route**, so a route added later cannot
forget them, and a test walks five endpoints including a 404 to confirm it. `nosniff`
matters concretely here: a report contains text an attacker influenced, and a browser
that decides for itself that a JSON response is HTML will render it.

The temporary file is removed on the failure path as well as the success path, which is
asserted separately — a service that leaks a capture into `/tmp` for every malformed
upload is a slower version of the same problem.

The report store is **bounded and in memory**. Bounded because a server anyone can upload
to otherwise grows until it is killed, which is a denial of service needing no attacker.
In memory because reports are derived data — persisting them would mean holding an
estate's tunnel inventory, endpoint addresses and traffic volumes on disk in a
network-reachable service, which is a larger promise than this project should make
quietly.

---

## Step 10.1 — the command line

`sentinel analyse | inventory | remediate | scan | dataset | model | version`, with
`watch` arriving in Step 10.4 alongside the module that implements it.

Two properties carry the weight, and both are tested rather than intended.

**A bad input produces a sentence, not a traceback.** A stack trace tells the reader the
tool broke; a message tells them what to do. Ten tests cover the paths an operator can
actually reach — a missing capture, a directory, a file that is not a capture, a typo in
a baseline name, a documented-tunnel list that is missing, malformed, or has one endpoint
instead of two — and each asserts a clean exit code, a readable line, and no `Traceback`
in the output. Exit codes are distinct: `2` for usage, `3` for a refusal.

**`scan` is the only command that transmits.** A test monkeypatches `socket.socket` to
raise and then runs `analyse`, `inventory`, `remediate` and `version` to completion. The
product's central claim, asserted at the surface an operator uses.

### `remediate` names the findings it actually found

The first version passed a fixed `["CRY-05"]` to the generator. The change package then
claimed to address 3DES on a tunnel whose real problem was `PRF_HMAC_MD5` — a document
an operator cannot check against the report beside it. It now runs the assessment, passes
the real finding IDs, and says plainly when a tunnel has nothing wrong with it under the
selected baseline.

The reconstruction's assumptions are printed with the package, so the operator sees which
parts were read off the wire and which were unobservable — SA lifetimes, PFS, the child
group.

---

## Step 10.1b — the clean bill of health that meant nothing had run

Building the CLI surfaced the worst bug in the project so far.

```
$ sentinel analyse capture.pcap --baseline nist_800_77r1
The tunnel examined is fully compliant with the selected baseline,
scoring 100 out of 100 (grade A).
```

That capture negotiates **PRF_HMAC_MD5** and offers no post-quantum protection. The
correct answer is a finding and a score of 92.

`RuleRegistry.select()` accepted `str | Baseline`. Given a `Baseline` object it selected
rules by ID, correctly. Given a **string** it matched against `rule.baselines` — a list of
*tags* written on the rules, containing only `default` and `strict`. So every published
baseline id — `nist_800_77r1`, `cnsa`, `itsar`, `certin`, `bsi_tr02102_3`,
`rfc_8221_8247` — matched no tag, selected **zero rules**, and produced a clean report.

Two namespaces had been quietly conflated: rule tags and baseline ids. Nothing about the
output looked wrong, which is what makes it the most dangerous thing a security tool can
emit.

### It had a test asserting it

```python
def test_an_unknown_baseline_runs_nothing(self) -> None:
    assert registry.evaluate_all(tunnel(), "does-not-exist") == []
```

The behaviour was not merely unnoticed; it was **specified**. That test is now
`test_an_unknown_baseline_is_refused_rather_than_running_nothing`, and it keeps the
original name in its docstring so the reversal is visible rather than tidied away.

### The fix

`resolve()` treats a name as a tag if any registered rule carries it, otherwise loads it
as a published baseline, and otherwise **raises** — listing what would have worked. The
tag mechanism still works for custom registries; only a name matching nothing is now an
error.

`run()` resolves **once** and uses the resolved object for both selection and severity
overrides. Resolving separately was the second half of the same bug: a named baseline
would have selected the right rules and then silently skipped its own severity overrides.

New tests assert that **every shipped baseline selects a non-empty rule set** — the
property whose absence caused this, checked directly rather than implied.

---

## Step 10.1a — the prober, and two registries that must not be confused

Two pieces the CLI needs, each validated against something outside this codebase.

### The prober transmits, so the gate is in the library

`probe.py` is the **only module in the project that transmits**, so
`enumerate_transforms` refuses without `authorised=True` rather than relying on the CLI
to hold the line. A test walks the AST of every module in the passive lane and asserts
none of them imports it: a passive lane that *can* reach the prober is one that
eventually will.

It never completes a handshake. Each probe is one IKE_SA_INIT with a random key exchange
value of the correct length — the responder selects or refuses before that value is used.
A test asserts an established tunnel is untouched after a full enumeration, because the
tool tells operators this is safe and that claim should rest on something.

**Validated against a real strongSwan**, which is the only way to know an encoder is
right: a frame both halves of one codebase agree on can still be one a real daemon drops
without a word, and a dropped frame reads as "no response" — a filtered target rather
than our own bug. Against a responder configured for `aes128-sha256-prfsha256-modp2048`,
that exact proposal is **accepted** and every other candidate **refused**. Three real
replies are checked in as fixtures so the rejection path is testable without Docker.

One behaviour worth recording: strongSwan answers an unacceptable group with
`NO_PROPOSAL_CHOSEN`, not `INVALID_KE_PAYLOAD`. The latter is for a proposal it *would*
accept offered with the wrong group; reading the two as the same would report "the
responder wants a different group" about a device that wants a different everything.

### IKEv1 and IKEv2 number their algorithms differently

`observed.py` turns a negotiation back into a `TunnelConfig`, which is what lets a change
package come from a real capture rather than from a config the operator already had. It
matched the corpus manifests on the first eight captures — and then failed on a quarter
of the next forty with *"encryption transform 7 has no configuration equivalent"*.

**Value 7 is CAST in IKEv2 and AES in IKEv1. Value 5 is DES-IV32 in IKEv2 and 3DES in
IKEv1.** They are separate registries. Reading one through the other's table does not
fail — it yields a different, plausible algorithm, and the change package built from it
would correct a configuration the device does not have. The parser keeps the two apart
and says why in a comment; this module did not, until the corpus said so.

IKEv1 also has no separate PRF: one hash attribute serves as both integrity and PRF
(RFC 2409 §5), so the reconstructed PRF now follows the hash instead of being assumed.

Everything the wire does not carry is **declared, not guessed**: SA lifetimes (IKEv2
removed them from the SA payload) and PFS with the child group (negotiated inside an
encrypted exchange). PFS is assumed *present* rather than absent — assuming absent would
make the generator "enable PFS" on every tunnel including those that already have it,
which is a change an operator would rightly refuse, and one that would discredit every
other recommendation beside it.

---

## ▶ MILESTONE M9 — Reporting complete

`make verify-all`: **1951 unit + 170 integration passed, 0 failed**, coverage 95.18%.
`scripts/check_m9.py` runs every item against a **real capture from the 288-capture sweep
corpus**, not a constructed report.

| # | Acceptance item | Result |
|---|---|---|
| 1 | Full report generated from a real dataset capture | **PASS** — 1 tunnel, grade F (52/100), every section populated |
| 2 | Section A contains only deterministic findings | **PASS** — and the validator is shown refusing the violation |
| 3 | Section B contains only inferred findings with confidence | **PASS** — same, from the other side |
| 4 | HTML opens with no network access | **PASS** — rendered with every socket call disabled |
| 5 | PDF renders | **PASS** — 54 kB, 4 pages, also with networking disabled |
| 6 | JSON validates against schema | **PASS** — validates and round-trips into the model unchanged |
| 7 | Metadata exposure present for a grade-A tunnel | **PASS** — see below |
| 8 | Executive summary understandable by a non-technical reader | **PASS** — rewritten first; see below |
| 9 | *(added)* An empty capture produces a report, not a crash | **PASS** |
| 10 | *(added)* A supplied inference reaches Section B with its confidence | **PASS** |

### Reading the summary changed it

Item 8 is the one criterion the plan phrases as a judgement rather than a test, and doing
it honestly meant finding this in the first sentence of a real report:

> The 1 tunnel examined **are** soundly configured.

Broken agreement in the opening line costs more credibility than the finding beneath it
earns. Subject and verb are now derived together rather than assembled from separate
places, and the multi-tunnel branch leads with a word instead of a digit — `1 of the 4
tunnels examined` opened the document on a numeral, which reads as a statistic rather
than a sentence. Every branch is tested at one tunnel and at several, because the singular
case is the one that reads wrong. What the gate can check automatically it does: no
algorithm names, a complete sentence, no broken agreement.

### Two checks that nearly passed for the wrong reason

**Section A / Section B.** Asserting that the findings in Section A are deterministic is
satisfied by any corpus that happens to contain no inferences — which this one is, since
the pipeline attaches none. The check now also constructs the violation and asserts the
validator refuses it. A guard that is only ever shown valid input proves nothing.

**The grade-A exposure entry.** The first version looked for a capture whose *estate*
grade was A and which contained a finding-free tunnel. No tunnel in the corpus is
finding-free — PQC-01 fires on every classical key exchange — so the check fell through to
a weaker fallback and reported PASS on it. It now searches by each tunnel's *own* grade
and finds a genuine one: **92/100, grade A, and still disclosing its endpoints, 34 kB
across two sessions, and the hour it was active.** That is the demo moment, and it needed
to be shown on a tunnel with nothing wrong with it.

### The offline check disables the network

Item 4 could be satisfied by grepping the HTML for `http://`. It instead replaces
`socket.socket`, `create_connection`, `getaddrinfo` and `gethostbyname` with functions
that raise, for the duration of the render — and the PDF check does the same. The
criterion asks whether the report works with no network, not whether it looks as though
it would.

### The pipeline that M9 required

`src/ipsec_sentinel/analyse.py` is the seam between the parse/assess lanes and the report
lane, and Phase 10's CLI will use it. It is deliberately thin and does two things
deliberately *not*: it loads no model — so an analysis run cannot silently degrade to "no
inferences" while looking complete — and it opens no socket, asserted by monkeypatching
`socket.socket` to raise and then analysing a real capture end to end.

### The lint gap, closed straight after

`ruff` linted `src tests testbed` but **not** `scripts`, while `mypy` checked all four —
so the milestone check scripts accumulated lint that `make verify` never saw. `scripts` is
now in both `lint` and `fmt`, and the 19 accumulated findings are cleared.

One was real: `compare_with_tshark.py` assigned `pending_type` twice and never read it,
left over from a design where the transform type was to be paired with the transform ID.
The type is taken from the field name instead, so tshark's own `isakmp.tf.type` is
genuinely redundant; the dead store is gone and the Step 4.10 parity tests still pass.

The remaining findings were line-length in `confound_audit.py` and
`generalisation_report.py`, whose Markdown tables are literal rows inside triple-quoted
strings — wrapping one to satisfy the limit would break the table in the generated
document, which is the artefact that matters. Both carry a per-file `E501` ignore with
that reason.

---

## Step 9.7 — an unescaped pipe is a wrong-severity alert

CEF, LEEF and RFC 5424 syslog, all built from the same findings, so a site that switches
collectors does not switch what it is told.

**Escaping is the whole risk.** A finding's evidence carries algorithm names, peer
identities and free text read off the wire, and every delimiter these formats use — `|`,
`=`, tab, newline — can appear in it. An unescaped pipe in a CEF header does not corrupt
one field; it shifts every field after it, so the collector reads the **severity out of
the message body** and the alert arrives with the wrong urgency. A payload containing all
of them at once is pushed through all three formats.

One subtlety the tests got wrong before the implementation did: CEF escapes `=` and `\`
in extension values but deliberately **not** `|`, because extension parsing is key/value
rather than positional. The first test split the whole line on pipes and failed on a
spec-correct output. It now splits seven header fields and takes the rest, which is what
a CEF parser does.

**Formatting and sending are separate.** The three formatters are pure functions — no
socket, no clock, no environment — and only `SyslogEmitter` opens a connection. Nothing
in the analysis path constructs one: a passive tool that dials out on its own is no longer
straightforwardly passive, whatever the payload. Tests monkeypatch `socket.socket` to
raise and then build and format a whole report, which is the same property Step 11.3 will
assert from the other direction.

**An unreachable collector never takes the run down.** A SIEM that is down is a normal
operational condition, and losing a completed assessment because the last step could not
deliver it would be the wrong trade every time. Tested against a real closed port rather
than a mock, since what is being asserted is behaviour against a real socket.

Other details worth keeping: severity truncation happens **in the message body only**,
because a collector that cannot parse the header discards the event entirely; truncation
cuts on a UTF-8 boundary so it cannot emit bytes a collector rejects; and the Section A /
Section B distinction travels into every format as an `assurance` field, so an analyst
triaging an alert can still tell a parsed fact from an estimate.

---

## Step 9.6 — the blocked dependency was never missing

`PROGRESS.md` had carried WeasyPrint as a blocked dependency since Phase 1, on the
strength of its error message:

```
OSError: cannot load library 'libgobject-2.0-0'
```

**The library was installed.** So were pango, cairo and glib. WeasyPrint reaches them
through cffi, which asks dyld for `libgobject-2.0-0` — a name Homebrew does not create,
in `/opt/homebrew/lib`, which is not on dyld's default search path. The error names a
library the user has, which is why it read as a missing dependency for eight phases.

Setting `DYLD_FALLBACK_LIBRARY_PATH` before the import fixes it, and doing that inside
`render_pdf.py` means nobody has to know. Preloading the dylibs with `ctypes` was tried
first and does not work — cffi looks the name up itself. The variable is only ever
extended, never replaced, and only with directories that exist. Four tests pin that
behaviour, including that it is a no-op off macOS.

**PDF export now works: 3 pages for a one-tunnel report, valid `%PDF-` header, six tests
running rather than skipping.** The import stays deferred inside the functions, so a
machine genuinely without pango loses only PDF, and the error says exactly which package
to install on which platform rather than naming a library that is already there.

### The schema is a contract, not documentation

`schemas/report-1.0.schema.json` is generated from the model and checked in. A test
regenerates it and compares, so it cannot go stale — a published schema that no longer
matches the model is worse than none, because consumers trust it.

Round-tripping and schema validation are tested separately and neither implies the other:
the first catches losing data, the second catches quietly changing the shape every
downstream consumer reads while staying internally consistent. Keys are deliberately not
sorted, because alphabetising would place `section_b_inferred` before
`section_a_verified` in every export.

---

## Step 9.5 — escaping is a security control here, not a nicety

Most of what this report prints was read off the wire: vendor ID strings, algorithm
names, endpoint addresses, peer identities. **All of it is attacker-controlled.** With
autoescaping off, a crafted IKE vendor ID containing markup would execute in the browser
of whoever opened the report — a security tool turned into a delivery mechanism, which is
about the worst outcome available. Autoescaping is enabled explicitly rather than left to
Jinja's extension-based default (which does not cover `.j2`), and tests feed a
`<script>` payload through the finding evidence, the tunnel identifier and the inventory.

**Nothing loads from anywhere.** No CDN, no external stylesheet, no font, no script. Even
the CVE references render as plain text rather than links: an anchor nobody can follow is
worth less than a URL a reader can copy, and on paper an `href` is invisible. The
self-containment test extracts `src`/`href` through an HTML parser rather than a regex,
so an attribute split across lines cannot slip past.

**Section A and B are distinguishable without colour** — separate headings, a text label
on every finding, and an explanatory note. A test strips every `<style>` block and asserts
the distinction still reads, which is the greyscale-print and colour-blind case.

### The bug the template found

`inventory or Inventory()` silently discarded a real inventory. `Inventory` defines
`__len__`, so **an inventory with no observed entries is falsy** — and the case where that
happens is precisely the interesting one: a documented tunnel list where nothing was seen.
Those tunnels would have vanished from every report, which inverts the finding an operator
most wants ("you documented a tunnel that is not there").

Six models in the codebase define `__len__` and are therefore falsy when empty. Every
default is now chosen with `is not None`, and a test pins the falsiness itself so it is
documented rather than a surprise.

The template is declared in `package-data`. Without that a wheel renders no report at all,
and only once installed — the same failure the baselines comment already warned about.

---

## Step 9.4 — a CVE citation is a claim, so every one was checked

The ATT&CK mapping needed no invention: every rule already declares its technique, so
the matrix groups by that rather than adding a second opinion. The CVEs were the work.

**Every entry was verified against its NVD record before being written down**, because a
CVSS score recalled from memory and printed in a security report is exactly the
confident-wrong output this project spends its effort avoiding.

| CVE | CVSS v3 | Mapped to | Why |
|---|---|---|---|
| CVE-2016-2183 (SWEET32) | 7.5 HIGH | CRY-05, CRY-08 | NVD's own description **names IPsec** alongside TLS and SSH |
| CVE-2018-5389 | 5.9 MEDIUM | IKE-02, IKE-03 | IKEv1 PSK offline dictionary attack |
| ~~CVE-2015-4000 (Logjam)~~ | 3.7 LOW | **excluded** | NVD scopes it to *TLS 1.2 and earlier with DHE_EXPORT* |

Logjam is the interesting one. The underlying research on precomputation against
1024-bit MODP genuinely bears on IKE, and it would have been easy to attach it to CRY-02
(weak Diffie-Hellman group). But the CVE **as registered** is a TLS vulnerability, and
attaching it to an IPsec finding would give a misattribution the authority of a citation.
CRY-02 stands on RFC 8247 instead. The rejection is kept in the source with its reason,
because "why is Logjam not here?" is a fair question and the answer is evidence of the
standard being applied.

Every reference carries a `scope_note` saying what its published record actually covers —
CVE-2018-5389 describes IKEv1 *main* mode, and the note says so and explains why
aggressive mode is the same attack under worse conditions.

### Two structural fixes

**A CVSS score can no longer exist without its CVE.** They were two optional fields on a
row, validated to appear together. They are one `CVEReference` object now, so the invalid
state is unrepresentable rather than rejected.

**Report models refuse unknown fields.** Pydantic ignores them by default, which meant a
test constructing `ThreatMatrixRow(cve_id=...)` after that field had moved kept passing
while testing nothing — found only because `make verify` failed on a *different* test in
the same class. The same default would let a report loaded from a future schema silently
drop what it did not recognise: data loss that validates cleanly.

The matrix also names findings it could not categorise rather than dropping them, and
each row records whether any contributing finding was inferred — the Section A / Section B
split does not stop at the findings list.

---

## Step 9.3 — the section about the tunnels with nothing wrong

The exposure section is produced for **every** tunnel, and the grade-A ones are the
point. A report that lists only problems implies a clean tunnel reveals nothing, and
that is false: encryption protects the contents of a conversation, not the fact that it
happened, who took part, when, or how much was said.

Three details.

**A session is an SA, not a direction.** Each SA appears twice in the flow list, once
each way. Counting flows would double every session figure in the report.

**An abstention is not reported as a class.** If the classifier abstained, the entry
carries no application type at all rather than the class it leaned towards. A reader
shown "voip" has no way to tell a confident classification from a coin flip unless the
number travels with it — and the model refuses one without the other.

**Active hours are a subset of observed hours, never an inference about the rest.** An
hour can be watched and quiet; an hour that was never watched is neither. This is the
same distinction that Step 8.5 needed for maintenance windows.

A tunnel seen negotiating but carrying no observed traffic still gets an entry with zero
volume. That it negotiated at all tells an observer these two peers talk to each other.

### A refactor the second consumer justified

`TrafficProfile` and the hourly profiling moved out of `remediate/blast.py` into
`ipsec_sentinel/traffic.py`. The seam is real: *what was observed* is a neutral fact
about traffic, while *whether that counts as busy* is a remediation policy about
scheduling a change. The thresholds and `is_idle` / `is_busy` / `covers_daily_cycle`
stayed behind as functions in `blast.py`; the measurement moved. The tests split along
the same line.

---

## Step 9.2 — attribution, and a summary that cannot drift

Two decisions worth recording.

**Findings gain a `tunnel_id` when they are flattened.** Rules evaluate one tunnel at a
time and have no need for it, so a rule-produced finding leaves it `None`. But the report
model carries two *flat* lists, and "3DES is in use" without saying where is a fact
nobody can act on. The builder stamps each finding on the way through, and leaves an
existing attribution alone — a caller that already attributed one knows something the
builder does not.

Findings are deliberately **not** deduplicated across tunnels. The same rule firing on
two tunnels is two tunnels to fix, and collapsing them hides the second.

**The executive summary is generated from the findings it summarises**, never passed in.
The model already validates the two against each other; building it this way means the
mismatch cannot arise in the first place. The summary is the part that gets read, so a
summary that disagrees with the body is worse than none.

The headline is written for the M9 criterion — understandable by a non-technical reader —
and a test asserts it contains no algorithm names at all. It also counts *affected
tunnels* rather than findings, because three findings on one tunnel is one tunnel to fix.
A clean estate does not get a blank headline: it points the reader at the exposure
section, since a perfectly configured tunnel still reveals who is talking to whom.

An empty capture produces a valid report graded A, not F. Nothing observed is not the
same as everything broken, and the headline says which of the two it is.

---

## Step 9.1 — the validator that must not be an assertion

The build plan sketches the Section A / Section B guard as:

```python
@model_validator(mode="after")
def enforce_separation(self):
    assert all(f.confidence is None for f in self.section_a_verified)
```

**`python -O` removes assertions.** The guarantee at the centre of the product — that an
estimate is never presented as compliance evidence — would silently disappear in exactly
the deployments most likely to run optimised, and the report would still look correct.
It raises `ValueError` instead, and `test_the_validator_survives_python_dash_o` runs the
check in a subprocess under `-O` to prove it.

Two further guards beyond the plan:

- **The executive summary must agree with the body.** A report claiming three critical
  findings over a section containing one is worse than no summary, because the summary is
  the part that gets read. Counts and per-severity totals are validated against the
  findings actually carried.
- **Provenance records whether the working tree was dirty.** A report naming a commit it
  was not actually produced from is a decoration, not a provenance record. `git_sha()`
  and `git_dirty()` both return `None` rather than a plausible default when the answer is
  unknowable — an installed copy has no repository, and that is not an error.

`ExposureEntry` repeats the `TunnelAssessment` rule that an inference and its confidence
are present together or not at all, because by the time a class reaches a reader without
one it is indistinguishable from a parsed fact.

---

## ▶ MILESTONE M8 — Remediation complete

`make verify-all`: **1632 unit + 170 integration passed, 0 failed**, coverage 94.97%.
`scripts/check_m8.py` executes every acceptance item rather than asserting it.

| # | Acceptance item | Result |
|---|---|---|
| 1 | Both-ends configs generated for every finding type | **PASS** — 18 addressable types, two distinct documents each |
| 2 | strongSwan configs deploy successfully live | **PASS** — `test_gen_strongswan_live.py`, 4 passed in 68s |
| 3 | Libreswan configs deploy successfully live | **BLOCKED** — no Libreswan peer exists in this testbed |
| 4 | Zero-downtime sequence verified with zero packet loss | **PASS** — `test_sequence_live.py`, 5 passed; 0 lost, 0.00s outage |
| 5 | Non-testbed vendors clearly marked as syntax-only | **PASS** — 5 vendors carry the caveat in every emitted document |
| 6 | Auto-verification closes a finding after a live rekey | **PASS** — `test_verify_live.py`, all four verdicts observed in order |
| 7 | The tool never executes a change | **PASS** — 13 modules AST-parsed; no forbidden transport, no device write, no exec/eval |
| 8 | *(added)* Package, sequence and verifier describe the same change | **PASS** |

### The one blocked item

The testbed runs strongSwan only, so there is no Libreswan peer to deploy onto. This
was recorded at Step 8.3 and has not changed. It is reported BLOCKED rather than passed
or failed: the generator is syntax-validated, every document it emits says so in its own
header, and a test pins that status so it cannot quietly be upgraded to a claim nobody
checked. Unblocking needs a Libreswan container image in `testbed/compose`.

### Two gaps the gate found

Working the checklist item by item — rather than asserting it — turned up two things
that would otherwise have shipped.

**`DeploymentStatus.LIVE_TESTED` was defined and used by nobody.** The status mechanism
was built at Step 8.3 for the five vendors that are *not* live-tested; strongSwan, the
one vendor that is, never declared a status at all. So the strongest claim in the set was
the only one its documents did not make. strongSwan now declares `LIVE_TESTED` and its
`swanctl.conf` carries the same provenance banner as the rest.

**Two findings were addressable and not being addressed.** The generator declared 10 of
26 rules out of scope. Three of those were really proposal changes it could make:

- **PFS-02** — child DH group weaker than the IKE group. The existing branch only raised
  a child group weak *in absolute terms*, so `modp2048` under `ecp384` slipped through:
  respectable on its own, and wasting the stronger group above it. Now compared on
  **security bits, not parameter size** — the same distinction that CRY-11 was fixed for,
  since 256-bit ECP is stronger than 2048-bit MODP and the printed numbers say otherwise.
  The strength table is shared with the parser so the two cannot drift.
- **IKE-04** — a weaker proposal was offered but not selected. The generated config emits
  exactly one proposal, so this was already fixed by construction and simply not claimed.
- **CRY-10** — key shorter than 256 bits *where the baseline requires 256*. Left out
  deliberately: `harden` is baseline-agnostic, and raising every AES-128 to AES-256 would
  over-remediate for the baselines that accept 128. "You could use a bigger number" is
  not a finding.

Eight rules remain genuinely outside a config generator's reach — CRY-08, CRY-10, ESP-01,
ESP-02, OPS-01, PQC-01, SA-03, SA-04 — and every package names the ones it does not fix.

---

## Step 8.6 — the field that was always None

`verify_remediation` was written against `IKEExchange.proposal_accepted`. **Nothing in
the codebase ever set that field.** It was declared on the model, defaulted to `None`,
and populated by no parser — so in production the module would have returned `PENDING`
for every tunnel, forever, and reported that as an honest "no evidence yet".

The unit tests passed, because they constructed exchanges with the field set by hand.
That is the whole lesson: a test fixture that builds an object the system never produces
tests the fixture. It surfaced only when the live test parsed a real capture and got
**zero** usable negotiations out of fourteen real IKE messages.

What the wire actually gives:

| | initiator message | responder reply |
|---|---|---|
| carries | the **full offer list** | the **one proposal chosen** |
| responder SPI | zero | non-zero |

Neither message answers "what was agreed" alone, which is why the question belongs to
the negotiation and not to the message. `Negotiation.accepted_proposal` in
`parser/correlate.py` already read it correctly from the responder's reply. The module
now groups messages with `group_negotiations` before deciding anything, and
`proposal_accepted` has been **removed from the model** — a field populated by nobody and
read as fact by somebody is worse than no field.

The test helper was rewritten to emit a message per direction, so it now builds what the
parser builds.

### A fourth verdict the plan does not have

The plan lists verified / failed / pending. There is a fourth, and it is the state the
Step 8.4 sequence deliberately passes through: after step 2 the tunnel is **running on
the target and still offering the old proposal**. Reading the agreed proposal alone,
that is indistinguishable from success — and closing the finding there would sign off a
tunnel a peer can still downgrade by offering only the weak proposal.

`PARTIAL` names that state and keeps the finding open. A model validator enforces the
rule independently of the logic that picks the status: **no status but `VERIFIED` may
close anything.**

The live test walks one real change and observes all four in order — failed, partial,
pending, verified. The pending step matters as much as the rest: removing a proposal from
a config file is not observable until the peers next negotiate, so the fix is *pending*
until the wire confirms it. Anything closing the finding at step 3 would be reporting the
configuration, not the tunnel.

The live pair harness moved to `tests/fixtures/livepair.py` so both integration tests
share one, and gained optional packet capture that starts before the first handshake.

---

## Step 8.5 — blast radius, and the hours nobody watched

The plan asks for traffic volume, inferred application type, peak usage hours and a
suggested maintenance window. Three of those are straightforward. The fourth is a trap,
and most of this step is about not falling into it.

**A short capture cannot locate the quiet time of day.** Almost every capture in the
corpus spans tens of seconds. Bucketing those bytes into a 24-hour histogram leaves 23
hours holding zero — and the quietest window is then, confidently, whichever part of the
day nobody watched. `TrafficProfile` therefore records `observed_hours` separately from
`bytes_by_hour`, `suggest_window` considers only observed hours and only contiguous
stretches of them, and returns `None` with a stated reason when fewer than six hours were
seen. Every window that *is* offered carries a `Confidence` whose method reads
`fraction_of_daily_cycle_observed`, so the number cannot be mistaken for a calibrated
probability from the model lane.

Three related refusals, each with a test:

- **`ChangeRisk.NONE` is never reported.** A tunnel that carried nothing during the
  capture is not a tunnel that carries nothing.
- **An abstaining classifier is not a negative.** `realtime_traffic` returns `None` on
  abstention, and the caller treats that as "unknown", not "not VoIP". Reading an
  abstention as a green light would make every uncertain tunnel look safe.
- **No observation is declared, not assumed benign.** A package generated without a
  traffic observation says so in the operator's own document: *"the timing advice below
  rests on nothing measured. Treat it as a floor, not a verdict."*

Volume is judged as a **sustained rate**, not a total — a megabyte in ten seconds and a
megabyte in an hour are not the same tunnel. VoIP and video force a window regardless of
volume, because one call is not much traffic and is still noticed when it breaks.

### A stale number the wiring exposed

Wiring `blast.py` into the strongSwan generator replaced a hand-written
`estimated_disruption_s=5`. Step 8.4 had just measured **0.00s** on a live pair, so the
package was contradicting its own evidence — and its own step list, every entry of which
declares zero. The figure is now summed from the sequence rather than asserted, and a
test pins it to what was measured.

---

## Step 8.4 — zero downtime, measured rather than asserted

Four steps, verified on a live pair, with a reachability probe running throughout:

| Approach | Probes | Lost | Longest outage |
|---|---|---|---|
| **Sequenced (add → migrate → remove → verify)** | 53 | **0** | **0.00 s** |
| Naive (replace both ends, then re-establish) | 36 | 3 | **3.84 s** |

Both figures come from the same instrument in the same test file, which is the point:
a zero on its own is not evidence unless the same measurement can be shown to read
non-zero when something really does break.

### The plan's step 2 was wrong, and wrong in the dangerous direction

The plan describes step 2 as "rekey and confirm the negotiation now selects the
target". On strongSwan 5.9.8 that does not work, and it fails silently. An established
SA keeps the configuration it was created with, so after `swanctl --load-all` loads a
new proposal list:

- `swanctl --rekey --ike net-net` → renegotiates the **old** proposal
- `swanctl --rekey --child net-net` → renegotiates the **old** proposal
- `swanctl --rekey --ike net-net --reauth`, with `charon.make_before_break = yes` →
  renegotiates the **old** proposal

Every one of those returns "rekey completed successfully", leaves the tunnel up, and
loses no traffic. An operator following the plan's wording would see a healthy tunnel,
conclude the remediation had landed, and proceed to step 3 — which removes the old
proposal from the configuration file while the live SA is still using it. The weak
crypto stays in service, and the config no longer says so.

What actually adopts the new configuration is establishing a *second* SA from it.
strongSwan builds it alongside the existing one, both carry traffic, and the old one is
then deleted. `TestRekeyDoesNotAdoptNewConfiguration` pins the rekey behaviour so that a
future strongSwan release which fixes it fails the test rather than leaving the
workaround in place forever.

One further trap: `swanctl --list-sas` prints the newest SA first. Retiring "the first
one" deletes the SA that just moved to the target and rolls the change back. Step 2's
text now says to identify the old SA by its algorithms.

### The measuring instrument was the second bug

The first version pinged with `ping -i 0.2` and read its summary. It reported *0%
packet loss* for the naive control too — because iputils `ping` **exits** when the route
to its target disappears, which is the exact instant the outage starts. It printed a
clean summary for the seconds before the failure and nothing about the failure.

That is the worst possible failure mode for a measurement: it returns the answer the
test wants precisely when the system under test has broken. It was caught by making the
probe report how long it had been watching and comparing that against the wall-clock
duration of the change — the naive control came back at **52% coverage**, which is what
exposed it. The probe is now a supervising loop that timestamps every sample, survives
the outage, and reports its duration; both runs now show >95% coverage, and the
coverage check is asserted in both tests.

### What the unit tests assert

The safety property is not the four-step ordering, it is that **the two ends always
share at least one proposal** — checked over seven states including the half-applied
ones, where a step has reached one end and not yet the other. `naive_sequence_states`
supplies a sequence that violates it, and a test asserts the check catches that;
`test_a_state_with_no_common_proposal_really_does_fail` puts two real peers into that
state and shows the negotiation returns `NO_PROPOSAL_CHOSEN`.

This superseded the Step 8.2 test asserting the peer is staged before the local end.
Ordering the ends was an attempt to keep the disjoint window *short*; adding the target
alongside the current proposal removes the window altogether, so `add` and `remove` are
now single operations across both ends (`ConfigRole.BOTH`) and there is no ordering left
to assert. The replacement test asserts the stronger property directly.

---

## Step 8.3 — vendor generators, and a mapping that would have been wrong

Five vendors, one live-tested and four not, with the distinction written into every
generated file rather than kept in a README. The file is what gets pasted into a change
ticket, so the caveat has to travel with it.

| Vendor | Status |
|---|---|
| strongSwan | **live-tested** — loaded onto a real pair, tunnel established, findings cleared |
| Libreswan | syntax-validated, not deployment-tested |
| Cisco IOS-XE | syntax-validated, not deployment-tested |
| FortiGate | syntax-validated, not deployment-tested |
| Juniper SRX | syntax-validated, not deployment-tested |
| Palo Alto PAN-OS | syntax-validated, not deployment-tested |

The plan says Libreswan *could* be live-tested. It cannot be here — the testbed runs
strongSwan only — so it is marked with the rest and a test pins that honest until a
Libreswan container exists.

### The mapping that would have been wrong

The first Cisco table mapped `curve25519` to **group 21**. Group 21 is 521-bit ECP, a
different curve; IOS-XE does not implement Curve25519 at all. That configuration would
have loaded cleanly and negotiated something the assessment never asked for — the worst
possible failure mode, because nothing downstream would notice.

Vendors now declare an `UNSUPPORTED` table naming what they genuinely cannot express
*and what to use instead*, and `translate` refuses with that suggestion rather than
approximating. Junos and PAN-OS carry the same Curve25519 gap. Tests assert three
separate things: that every gap is declared rather than silently missing, that a
declared gap names an alternative, and that a gap is not simultaneously mapped.

Ruff caught a second real bug in the Libreswan generator: both role branches produced
identical text, so a "both ends" package described one end twice. The two documents now
mirror each other.

---

## Closing the M7 mode-inference gap: transport mode captured

The blocked M7 item needed transport-mode cells with real ESP. They now exist, and the
route there is worth recording because two of the three obstacles were invisible from
the outside.

### Why the first attempt produced zero ESP

Transport mode protects the IPsec **peers themselves**. The testbed drove traffic
host-to-host, which the peers merely *route* — so the SA established, the traffic went
around it unprotected, and the runner's ESP guard correctly rejected every cell. The fix
is `RunContext.source_container` / `target_ip`, which resolve to the hosts in tunnel mode
and to the gateways in transport mode, so a generator never has to know which mode it is
running under.

### Two obstacles the fix exposed

**The gateway image was not a traffic source.** It carried `ping` but not `python3` or
`tcpreplay`, so voip and replay failed at setup the moment they were asked to run on a
gateway. Transport mode makes the gateway both an IPsec endpoint and a traffic origin,
and the image now carries the tools and the sidecar scripts to match.

**`replay` cannot work in transport mode at all, and this is not a bug.** `tcpreplay`
injects raw frames at layer 2, which bypasses the kernel's XFRM output path — so on a
gateway they leave the interface unencrypted whatever policy is installed. In tunnel
mode it works because the *host* injects and the gateway encapsulates the frames as
forwarded traffic; in transport mode the gateway is both injector and encryptor, and the
injection sidesteps the encryption. The ESP guard catches it every time. `replay` is
therefore excluded from the transport generator set with that reasoning recorded in the
code, not silently dropped.

### The corpus was preserved, deliberately

Sampling transport into the main matrix renumbered the configuration set and **orphaned
15 of the 36 configurations the M3-verified corpus was built from** — measured before it
was committed. Transport coverage is additive instead: `matrix_transport.yaml` holds it,
mode is part of a configuration ID so the two sets are disjoint by construction, and a
test asserts every corpus configuration still belongs to one matrix or the other.

### The signal is real

Same cipher (aes128/sha256), same generator, both modes:

| Mode | Minimum ESP packet |
|---|---|
| Tunnel | **156 bytes** |
| Transport | **140 bytes** |

A 16-byte difference — the inner IP header tunnel mode adds, rounded by AES-CBC's block
padding. Note that it is only visible *relative to the cipher*: across ciphers, sizes
range 136–164 for the same traffic, so cipher overhead swamps the mode offset. That has
a direct consequence for `docs/BASELINES.md`, whose heuristic compares against absolute
floors of 82 and 102 bytes — figures no real ESP packet in this corpus comes near.

---

## MILESTONE M7 — acceptance checklist (executed)

Run with `scripts/check_m7.py`. **9/10 pass, 0 fail, 1 BLOCKED.**

| M7 acceptance | Result |
|---|---|
| Classifier trained with capture-level splitting | **PASS** — 96.0% accuracy, 0.963 macro-F1, 581 rows in 252 groups |
| **Zero `capture_id` overlap between train and test** | **PASS** — 25 seeds, zero overlap in every one |
| Generalisation report with all four splits | **PASS** — 4 splits, 4 confusion matrices |
| Model beats the mode-inference heuristic | **BLOCKED** — see below |
| ECE below 0.15 after calibration | **PASS** — 0.0767, AUROC 0.973 |
| Abstention working, rate under 25% | **PASS** — 2.1%, accuracy 97.2% → 98.6% |
| SHAP explanations render as readable sentences | **PASS** — additive, no raw identifiers |
| Confound audit published | **PASS** — all three measurements with a verdict |
| **Every ML finding carries a non-None confidence** | **PASS** — 143 predictions and every anomaly finding |
| ML test suites pass | **PASS** — 255 tests |

### The blocked item, and why it is not a pass

**The corpus contains exactly one mode: `tunnel`.** No classifier can be compared
against the mode-inference heuristic here, because one answering `tunnel`
unconditionally scores 100%.

The root cause is topological rather than incidental. Transport mode protects traffic
between the two gateways *themselves*; this testbed generates traffic from host
containers *behind* the gateways, which necessarily requires tunnel mode. Those cells
produced ESP=0 in Phase 2 and were dropped when the runner's ESP guard caught them —
correctly, because a cell with no encrypted traffic is not an observation of a tunnel.

Closing it needs transport-mode cells whose traffic originates on the gateways: a
**testbed change plus a partial sweep**, not a modelling change. Recorded in
`docs/BASELINES.md`, which states in terms that **no model may claim to beat this
baseline on this corpus**.

`check_m7.py` reports it as BLOCKED rather than SKIP or PASS, and prints that blocked
items are neither. A gate that quietly converts an impossible check into a green tick is
worse than no gate.

---

## Step 7.10 — the confound audit, and a side channel it found

The audit the master document calls the most fatal trap available here. A confounded
classifier and a sound one produce identical output; only a test built to separate them
can tell which you have.

| Measurement | Result |
|---|---|
| Accuracy conditioned on cipher | 3DES 97.2%, AES-CBC 95.3%, AES-GCM 96.2% — **spread 1.9%** (tolerance 15%) |
| Cipher learnable from packet sizes alone | **80.6%** against a 47.7% baseline — **+32.9%** |
| Mutual information, predictions vs cipher | **0.0015 nats** (0.1% of traffic-class entropy) |

**The classifier is clean.** Accuracy barely moves across ciphers, and its predictions
carry no more cipher information than the ground truth does. The corpus balance verified
at M3 survived into the model.

### The interesting finding is the second row

**The negotiated cipher is 80.6% identifiable from ESP packet sizes alone**, with no
handshake in the capture at all. That is a real property of ESP rather than a defect:
AES-CBC pads to a 16-byte block boundary, 3DES to 8 bytes, and AES-GCM not at all, so
packet sizes carry the cipher's block structure whether anyone wants them to or not.

The features that carry it are `fwd_size_min`, `size_min`, `size_p25` — **the smallest
packets**, which is exactly what padding theory predicts, since a block-boundary
rounding is proportionally most visible on a short packet. That the measurement lands
where theory says it should is the strongest evidence it is real and not an artefact.

**Product implication, recorded but not implemented.** ESP-01 reports tunnels seen with
no negotiation, whose cryptography is currently unassessable and which the rule calls
"not assessed... unexamined". This side channel is a route to saying something about
them — an *inferred* cipher with a calibrated confidence, in Section B, never in the
deterministic lane. The measurement that would justify building it now exists.

---

## Steps 7.7–7.8 — optimising the wrong metric produced a useless confidence

Calibration looked finished. Abstention exercised it and found it inert.

### What went wrong

The calibration method was selected by **Expected Calibration Error** alone, which chose
isotonic regression (ECE 0.0165 against sigmoid's 0.0767). Then abstention was added and
**declined nothing at any threshold up to 0.7.** Inspecting the distribution showed why:

* 95% of isotonic's predictions scored **≥ 0.99**
* the minimum confidence over 143 evaluation rows was **0.875**
* **two of the three rows it got wrong were given a confidence of exactly 1.0**

Low ECE, and a confidence that never signals a mistake. The two properties are
different: **calibration** is whether stated probabilities match observed frequencies in
aggregate; **discrimination** is whether the confidence ranks correct predictions above
incorrect ones. A model right 98% of the time that says "99%" on every row is perfectly
calibrated and completely uninformative.

| Method | ECE | AUROC (confidence ~ correct) | Abstains below 0.7 |
|---|---|---|---|
| isotonic | **0.0165** | 0.639 | 0.0% |
| sigmoid | 0.0767 | **0.973** | 2.8% |

### The fix

Calibration became a **constraint** and discrimination the **objective**: among methods
whose ECE clears the 0.15 trustworthiness gate, take the one with the best AUROC. Only
if none clears the gate does lowest ECE win, since an untrustworthy confidence should at
least be as close to honest as possible. Selection still happens on a validation split,
never on the evaluation set.

Sigmoid is now selected — validation AUROC 0.958 against isotonic's 0.805, both inside
the gate — and confirms on evaluation at ECE 0.0767, AUROC 0.973.

### Abstention now earns its keep

| Threshold | Abstained | Accuracy if forced | Accuracy when it answered |
|---|---|---|---|
| 0.6 | 2.1% | 97.2% | **98.6%** (+1.4) |
| 0.7 | 2.8% | 97.2% | **98.6%** (+1.4) |

Well inside the 25% ceiling, and the gain is measured rather than assumed. `precision_gained`
is reported and can go **negative** — declining on rows the model would have got right —
so a harmful threshold is visible rather than hidden.

**The original prior was that sigmoid would win because isotonic overfits small corpora.
Sigmoid does win, but not for that reason and not on the metric the prior assumed.** That
is recorded rather than quietly claimed as a correct call.

---

### Earlier note (superseded by the section above)

Calibration was expected to be a formality. It was not, and the way it failed is worth
recording.

The documented prior was **Platt scaling (sigmoid)**: it fits two parameters per class,
and isotonic regression is conventionally said to overfit below a few thousand samples.
This corpus has 581 rows, so sigmoid should have been the safe choice.

Measured on a held-out evaluation set:

| Method | ECE before | ECE after |
|---|---|---|
| Sigmoid (the prior) | 0.0610 | **0.0767** — *worse* |
| Isotonic | 0.0610 | **0.0165** |

Sigmoid actively degraded the calibration it was supposed to fix.

**The fix was not to switch the default.** Changing it because isotonic scored better on
the evaluation set would have been selection on the test set — the exact error this
project refuses everywhere else, and it would have been invisible in the result. The
training data is now split three ways: a fit set for the base model, a calibration set
for the calibrator, and a **validation set on which the method is chosen**. The
evaluation set is touched only to report the final number.

On validation, isotonic scores 0.0389 against sigmoid's 0.0978, so isotonic is selected —
and then independently confirms on the evaluation set at **0.0165**, well inside the
0.15 threshold below which a confidence may be shown to a user at all.

The overturned prior is left in the module docstring rather than quietly deleted. A
prior the data contradicts is worth more in the record than one that was never written
down.

---

## Step 7.6 — generalisation results (UNCUTTABLE step, evidence)

All four splits, random forest, on the corrected 581-row corpus. `docs/GENERALISATION.md`
carries the full per-class scores and confusion matrices.

| Split | Accuracy | Macro-F1 | What it tests |
|---|---|---|---|
| Random rows (**leaky**) | 96.6% | 0.969 | Optimistic upper bound |
| Held-out captures | 96.4% | 0.960 | Realistic in-distribution |
| **Held-out configurations** | **94.7%** | 0.951 | **Closest to a deployed analyser** |
| Held-out DH groups | 96.7% | 0.969 | Confound probe |

**The expected drop did not appear, and that needs stating carefully rather than
celebrating.** Accuracy falls only 1.7 points from held-out captures to held-out
configurations, and is unchanged on unseen Diffie-Hellman groups. Two readings, both
true:

* The model genuinely is reading traffic shape rather than a crypto artifact. The DH
  split is the sharpest test available for that, and it passes at 96.7%.
* The seven classes come from **deliberately distinct generators** — ICMP, a VoIP codec,
  video streaming, SMTP. They are far more separable than arbitrary production traffic.
  These numbers are an **upper bound**, and the document says so under Limitations.

### The over-claim I nearly shipped

The report first concluded that the random split scoring only +0.2% above the capture
split showed "the inflation a leaking split buys". Read plainly, that invites the
conclusion that leakage is not a real concern here.

It is not what the number means. This dataset averages **2.31 windows per capture**, so
a random split has almost no sibling windows available to leak — **the test has very
little power.** Before the protocol-50 artefacts were removed, one class averaged 29.4
windows per capture, and a random split over that data would have leaked heavily.

The report now states this explicitly, reports windows-per-capture in its Dataset
section as the quantity that bounds the leak, and a test asserts the words *"not
evidence that leakage is harmless"* are present. The grouped split is cheap insurance
whose value does not happen to show up in this particular number.

---

## Two-thirds of the ML dataset was an artefact

Found in Phase 7 while measuring the mode-inference baseline, in data that had already
passed the M3 gate.

**IP protocol 50 is a claim, not a proof.** The replay generator replays a source
corpus onto the transit link, and that corpus contains protocol-50 packets. They are
not ESP — they carry a distinct random SPI each and sequence numbers near 10⁹, which
no 30-second capture of a fresh SA can reach — but the extractor counted them, and each
became a one-packet pseudo-flow.

One replay capture: **49 flows, of which 2 were real.** The two genuine SAs carried 500
and 406 packets with sequences starting at 1; the other 47 were 32-byte singletons.

| | Rows | Replay share | I(traffic; cipher) |
|---|---|---|---|
| As first built | 1,745 | 61% | **6.3%** of H(traffic) |
| After the RFC structural floor | 982 | 36% | 5.3% |
| After the minimum-packet threshold | **581** | **12%** | **0.1%** |

Two fixes, each justified rather than tuned:

1. **A structural floor in the parser.** RFC 4303 makes Pad Length, Next Header and an
   ICV mandatory, so an ESP body below 4+4+1+1+12 = 22 bytes cannot be authenticated
   ESP whatever its protocol number says.
2. **A minimum packet count per window in the dataset.** Below ten packets a window has
   no inter-arrival distribution, no burst structure and no meaningful percentiles. The
   extractor correctly returns finite zeros, and a row of zeros labelled `voip` teaches
   a model that voip looks like nothing.

**Why M3 did not catch this.** M3 measured the confound at *cell* level, where it is
exactly 0.0000 nats — the sweep is genuinely balanced. The confound appeared only at
*row* level, because the artefacts gave one traffic class 29.4 windows per capture
against 2.4 for the others. The corpus design was sound; the row weighting was not.

The corrected dataset is 581 rows with every class at 2.0–2.7 windows per capture and
essentially zero mutual information between traffic class and cipher. Had this gone
unnoticed, every accuracy figure in Phase 7 would have been measured on data that was
two-thirds fabricated.

---

## Step 6.9 — the anomaly detector flagged 89% of the estate

First run against the real corpus: **224 of 252 tunnels flagged as anomalous.** Not a
crash, not an exception — a confident, well-formed, useless answer.

The cause is that the corpus is a *deliberately diverse* 36-configuration sweep. Its
modal configuration is **5.6%** of the population, so there is no standard to deviate
from and every tunnel is an outlier in the only sense the model can measure.
scikit-learn's `contamination="auto"` assumes a contaminated dataset and duly
contaminated it.

Two fixes, and the second is the one that matters:

1. `contamination` is set explicitly to 0.1. An outlier is a minority by definition.
2. **A no-norm guard.** Before running the model, the modal configuration's share of
   the estate is measured. Below 25%, the module returns nothing and the summary says
   `no_dominant_configuration: true` with the measured share.

That refusal is the honest output. An estate where no configuration is dominant has no
template to deviate from, and "this tunnel is unlike its peers" is true of everything
and therefore means nothing. Reporting it as 224 findings would bury any real signal
and teach an operator to ignore the section.

Verified on real captures both ways: the full corpus now reports
`no_dominant_configuration` with 0 findings, and a realistic 43-tunnel estate built
from one dominant template plus one deviant gateway flags **exactly one** anomaly at
0.90 confidence, with evidence naming the fields that differ and what the other 98% use.

**This is the first component whose findings carry a confidence.** It is an inference —
a statistical statement about a population, not a fact read from a packet — so it lands
in Section B, at INFO severity, capped at 0.95 because an unsupervised outlier score is
never certainty.

---

## Step 6.8 — a stale ATT&CK citation, caught by a test

A test asserting *every technique a rule cites resolves in the catalogue* failed on
IKE-04, which cited **T1562.010**.

The bundle marks T1562 ("Impair Defenses") and T1562.010 ("Downgrade Attack") as
`revoked: true`, modified 2026-04-14. The index deliberately excludes revoked
techniques — a finding citing one renders as a dead link and points an analyst at a
page that says the technique no longer exists. **T1689 "Downgrade Attack"** is the live
replacement, and IKE-04 now cites it.

Worth noting because the error was invisible without the catalogue: T1562.010 was a
correct citation when written, and nothing in the code or a review would have caught
that it had since been revoked. The test does, and it will catch the next one on the
next ATT&CK release.

Of 858 attack-patterns in the bundle, 149 are revoked; the index holds the 709 live
ones.

---

## Plan defects found and corrected

### The plan names 20 rule IDs; M6 requires 26

Steps 6.2–6.4 specify exactly twenty rule IDs (CRY-01..10, IKE-01..04, PFS-01/02,
SA-01..04). The M6 gate's first acceptance item is "**All 26 rules implemented**". The
plan contains no other rule tables — an internal inconsistency of six rules.

Resolved by implementing six additions, each filling a gap the named rules genuinely
leave rather than padding a count:

| Rule | Why it exists |
|---|---|
| `PQC-01` | Step 6.5 specifies `grade_pqc()` but no rule to emit its finding |
| `CRY-11` | DH group below the **baseline's** required strength — the CNSA-vs-NIST differentiator, and the only consumer of `dh_security_bits` |
| `CRY-12` | NULL encryption. No named rule checked for it at all: cleartext inside what looks like a tunnel |
| `ESP-01` | ESP with no negotiation — a tunnel whose cryptography is *unexamined*, listed silently next to assessed ones |
| `ESP-02` | Negotiation with no traffic — failed, or idle and possibly no longer needed |
| `OPS-01` | Implementation and version disclosed in a cleartext vendor ID |

**26 rules, 0 rule errors over 252 tunnels, every finding `confidence is None`.**

`ipsec_sentinel.assess.rules.default_registry()` is now the single answer to "what does
this tool check", and a baseline test asserts every implemented rule is claimed by at
least one baseline — a rule in no baseline never runs, which is coverage that looks
real and is not.

---

## Plan defects found and corrected

**Step 0.7 — `KE_LENGTH_TO_GROUP` was not valid Python and hid a real collision.**
The plan wrote `{96: 1, ..., 96_ECP: 20}`; `96_ECP` is a syntax error. Behind it sits a
genuine protocol fact: a 96-byte KE public value is produced by **both** 768-bit MODP
(group 1, one 96-byte modulus) **and** 384-bit ECP (group 20, an uncompressed point of
2 x 48 bytes). Length therefore cannot determine the group.

Implemented per the plan's own stated resolution — the declared transform wins and length
is only a consistency check — as `dict[int, tuple[int, ...]]` mapping length to *candidate*
groups, plus `check_ke_length()` returning a structured `KELengthCheck` and emitting a
`KELengthWarning` (never an exception) for the ambiguous, mismatched and unrecognised
cases. The 96-byte collision is covered by dedicated tests in both directions.

---

## Environment notes

| Item | State |
|---|---|
| Host | macOS 26.6.2, Darwin 25.6.0, **arm64** (Apple Silicon) — **not Linux** |
| Python | **3.11.15 via `uv`**. Venv at **`~/.venvs/ipsec-sentinel`**, symlinked as `.venv` — see the iCloud note below. Matches the plan's CI pin exactly. |
| Docker | CLI 29.4.3, Compose v5.1.4, daemon **up**. LinuxKit `6.12.76` aarch64. **XFRM verified — see Blockers.** |
| Privileges | uid 501, `admin` group, **not root**. `sudo` is interactive-only and unavailable to the agent. Testbed privilege comes from `--privileged` containers, not host root. |
| `tcpdump` | `/usr/sbin/tcpdump` present (host capture needs sudo; testbed capture is in-container) |
| Network | **Slow.** PyPI took >20 s to first byte; the dependency install ran ~5.5 min at ~0.5 MB/s. Budget generously for anything that downloads. |
| Disk | ~180 GB free |
| Remote | `github.com/PrashamJ17/SIH_PS160` — private. `gh` authenticated as `PrashamJ17`. |

### ⚠️ iCloud Desktop sync — read this before touching the venv or the dataset

`~/Desktop` is **iCloud Drive–synced** (Desktop & Documents sync is on; `bird`,
`fileproviderd` and `cloudd` are all running). This repo therefore lives inside a synced
tree, which caused a genuinely obscure failure worth recording in full:

**Symptom.** `import ipsec_sentinel` worked immediately after install, then began failing
with `ModuleNotFoundError` — including under pytest — despite a correct
`__editable__.ipsec_sentinel-0.1.0.pth` pointing at the right `src` directory.

**Cause.** iCloud's file provider sets the macOS `UF_HIDDEN` flag on `.pth` files
(observed `st_flags=0x8040`), and CPython's `site.addpackage()` **deliberately skips
hidden files**. So *every* `.pth` in the venv was silently ignored and the editable install
never reached `sys.path`. Clearing the flag with `chflags nohidden` worked — for about five
seconds, until the daemon re-applied it. The `.nosync` directory-suffix trick did **not**
help either.

**Fix applied.** The virtualenv now lives **outside** the synced tree at
`~/.venvs/ipsec-sentinel`, with `.venv` in the repo as a symlink to it. Absolute shebangs
inside `.venv/bin/*` still resolve through the symlink, so nothing else changed. Flags now
stay cleared across idle periods and imports are stable. `.gitignore` gained a bare `.venv`
rule, because a `dir/` pattern does not match a symlink.

> **Do not recreate the venv inside the repo.** Use:
> `uv venv --python 3.11 ~/.venvs/ipsec-sentinel && ln -s ~/.venvs/ipsec-sentinel .venv`
> If imports mysteriously break again, check `ls -lO <site-packages>/*.pth` for `hidden`.

**Still outstanding — must be handled before the Phase 3 sweep.** `data/` and `models/` are
git-ignored but *not* iCloud-ignored, so the labelled PCAP corpus (potentially many GB)
would upload to iCloud and be subject to the same flag-mutation behaviour. Relocate
`data/` outside the synced tree with the same symlink pattern, or disable Desktop sync,
**before** running the sweep.

### Image finding — the openssl plugin is not optional

The plan's Step 1.1 Dockerfile installs `strongswan strongswan-swanctl
libcharon-extra-plugins`. Built exactly that way, charon starts and `swanctl --version`
succeeds, so the plan's stated acceptance criteria all pass — but the logs carry
`plugin 'openssl': failed to load`, and `swanctl --list-algs` is then missing **3DES,
AES-GCM, every HMAC, and all ECP groups**. The Step 1.5 matrix requires all of them, so
the first tunnel at Step 1.3 (AES-GCM-256 + DH group 20) would have failed with no
obvious cause.

Fixed by adding **`libstrongswan-standard-plugins`** (which carries the openssl backend)
and `libstrongswan-extra-plugins` (Curve25519, group 31). `test_no_plugin_fails_to_load`
and `test_every_algorithm_the_matrix_needs_is_available` now assert this at Step 1.1 so
the regression cannot reach the sweep silently.

### Capture trap that will matter at Step 1.7 — endpoint decryption artifacts

Capturing on a **peer's** transit interface sees inbound packets **twice**: once as the
ESP packet that actually crossed the wire, and again as the decrypted inner packet the
kernel re-injects after XFRM processing. A naive "capture everything on the transit
interface" would therefore put plaintext into the *outer* PCAP and silently corrupt the
dataset — while still looking correct.

The plan's own outer filter
(`udp port 500 or udp port 4500 or ip proto 50 or ip proto 51`) excludes this by
construction, since the decrypted copies are ICMP/TCP/UDP rather than proto 50/51.
**Use that filter for the outer tap and do not widen it.** A genuinely external view
would need a third vantage point; on a Docker bridge, a peer-side capture with the ESP
filter is the correct equivalent.

Related: **tcpdump buffers.** `pkill` does not exist in the image (no procps), and
killing tcpdump improperly truncates the capture with no error. Captures are started as
`timeout N tcpdump -U -w ...` so SIGTERM arrives from `timeout` and the file is flushed
and closed cleanly. This is the failure the plan warns about at Step 1.7.

### Open item for Phase 3 — the matrix contains IPv6 cells, the topology does not

`matrix.yaml` lists `ip_versions: [4, 6]` as the plan specifies, and expansion emits
IPv6 cells. But `testbed/compose/pair.yml` defines IPv4 networks only, so those cells
cannot establish yet. Before the Step 3.2 sweep, either add dual-stack networks to the
compose topology or restrict `ip_versions` to `[4]`. Left as-is for now because the
plan's matrix is authoritative and the sweep marks failed cells and continues.

### NAT-T is active in this topology — relevant to Step 4.8

Docker's bridge NAT causes IKE to detect NAT and move to **UDP 4500**: harvested SAs
report `10.100.0.2[4500]`. Captures from this testbed therefore exercise the NAT-T
non-ESP marker (four zero bytes before the IKE header) that Step 4.8 must handle, and
`NegotiatedIKE.nat_t` records it. This is realistic rather than a problem, but any test
that assumes IKE on UDP 500 will be wrong here.

### The slim image has no procps — process control must use shell builtins

`debian:bookworm-slim` ships no `ps`, `pkill` or `/bin/kill`. `docker exec <c> kill ...`
therefore **fails silently**, because `docker exec` does not invoke a shell and there is
no `kill` binary to run. This cost real time twice: once on a `ps`-based liveness check,
once when tcpdump was never signalled and every capture came back truncated.

Rules that follow:
* Signals go through `sh -c "kill -TERM <pid>"` (shell builtin).
* Process listings read `/proc/[0-9]*/comm`, never `ps`.
* `test` needs no such care — coreutils provides `/usr/bin/test`.
* tcpdump is launched with its PID recorded to a file, since without procps there is no
  other way to find it again.

### Two images now: gateways and hosts

Gateways run `Dockerfile.strongswan`; the hosts behind them run
`Dockerfile.traffic` (python3, curl, iperf3, tcpreplay, tcpdump, **procps**). Splitting
them keeps traffic tooling out of the daemon image and gives the remaining generators
somewhere to put their dependencies — which is what `TrafficGenerator.requires` is for.

An autouse session fixture in `tests/integration/conftest.py` builds both, so no
pair-based test can forget one and fail with an unexplained "image not found".

**Honesty note carried into `docs/DATASET.md` at Step 3.4:** the VoIP generator drives a
synthetic RTP endpoint, not a softphone. There is no SIP signalling and no real codec.
Packet timing and size distribution are faithful — and through ESP those are the only
observable properties — but the corpus must not be described as containing real calls.

### Sidecars need a return route, or traffic silently bypasses the tunnel

A sidecar placed on a protected network reaches the far side only if it has a route
back through **its own gateway**. `video_origin` initially had none, so its replies to
`10.1.0.0/24` left through Docker's bridge instead of the tunnel: the request was
encrypted, the response was not, and whether the transfer worked at all varied between
runs. The inner capture then showed 44 upstream packets and **zero** downstream.

Every sidecar added on a protected network must set
`ip route replace <far subnet> via <its gateway>` at start, exactly as the host
containers do. `Dockerfile.video_origin` installs `iproute2` for this.

Related: a profiled sidecar can survive `docker compose down` when the profile is not
active on the teardown call, and one surviving container pins its network — whose
subnet then collides with the next run and fails it with an unexplained
"Pool overlaps with other one on this address space". `compose_project` now passes
profiles to `down` **and** sweeps by compose project label afterwards.

### Disclosures owed to `docs/DATASET.md` at Step 3.4

Two generators stand in for something they are not, and both must be named plainly in
the dataset card. This honesty is a scoring asset, not a weakness — a claimed WhatsApp
corpus would be indefensible, and a panel that spots the overclaim discounts everything
else.

* **messaging is XMPP** (Prosody + slixmpp), used as a shape proxy. It is not WhatsApp,
  Signal or any specific consumer messenger; none can be scripted or lawfully captured.
  `MessagingGenerator.PROXY_DISCLOSURE` carries the wording and a test asserts it.
* **voip is a synthetic RTP endpoint**, not a softphone: no SIP signalling, no real
  codec. Packet timing and size distribution are faithful and are the only properties
  visible through ESP, but the corpus contains no real calls.

Everything else is genuine protocol: real Postfix and Dovecot for email, real nginx
origins for web and video, real Prosody for XMPP.

### strongSwan blocks Aggressive Mode + PSK by design

The `worst` anchor — IKEv1 Aggressive Mode with 3DES/MD5/DH-2 — could not establish.
The cause is not a bug: strongSwan **refuses** aggressive mode with a pre-shared key
unless you set

```
charon { i_dont_care_about_security_and_use_aggressive_mode_psk = yes }
```

and it named the option that way deliberately. It is right to. The responder hands a
hash of the PSK to anyone who asks and that hash is crackable offline, which is exactly
why rule IKE-03 is Critical rather than High — and it is a good line for the
presentation: the reference implementation considers this configuration so dangerous
that enabling it requires saying you do not care about security.

The option is baked into **`Dockerfile.strongswan` only**, because the testbed has to be
able to *build* the insecure configuration in order to capture it and prove the analyser
detects it. It must never appear in anything the remediation generators emit — those
exist to move real deployments off precisely this.

Verified on the wire: version `0x10`, exchange type 4, 3DES_CBC / HMAC_MD5_96 /
MODP_1024, with `negotiation_matched_intent` true.

### External corpora present on this machine

`scripts/fetch_external.py` has been run. Fetched automatically:

* **MITRE ATT&CK** — `data/external/mitre_attack/enterprise-attack.json`, 47.9 MB,
  26,085 objects, 858 techniques. Spot-checked: `T1040` resolves to *Network Sniffing*,
  which is what the Appendix A rule table maps the sniffing findings to.

Awaiting a manual download (the script prints exact instructions and exits 0):

* **CIC-IDS2017** and **ISCXVPN2016** — require registration with the University of
  New Brunswick.
* **MAWI** — pick a single samplepoint archive rather than mirroring the set.
* **NVD** — queried per product at enrichment time and cached, not mirrored.

Step 3.5's audit runs over whatever is present and reports exactly that, so the
credibility artifact is produced either way — it simply covers fewer corpora until
those downloads happen.

### Sweep in progress

A 252-cell sweep is running: all 7 traffic classes against all 36 configurations,
three impairment profiles cycled, 30 s of traffic per cell. Roughly 4 hours wall clock.

```bash
nohup .venv/bin/python scripts/run_sweep.py \
  --out data/raw/sweep --duration-s 30 \
  --replay-source data/raw/sweep_source/replay_source.pcap > /tmp/sweep_run.log 2>&1 &
```

It is resumable: state is written after every cell, so re-running the same command
continues rather than restarting and no cell runs twice. Progress is in
`/tmp/sweep_run.log`; the state file is `data/raw/sweep/sweep_state.json`.

### Sweep incident — 199 cells failed in under a minute (resolved, fixed in code)

Recorded in full because the cause was mine and the fix is now part of the product.

**What happened.** Checking whether the sweep was still alive, I used `pgrep` with a
pattern that did not match the actual command line, concluded it had died, and started a
second sweep. Three things then went wrong in sequence:

1. The relaunch used `setsid`, which does not exist on macOS. The command failed — but
   the shell had *already* applied its `> /tmp/sweep_run.log` redirect, truncating the
   running sweep's log. The evidence of what the live sweep was doing was destroyed
   before I looked at it.
2. `pkill -f` then sent SIGTERM to the live sweep. Python's default SIGTERM action
   terminates the interpreter outright, so the runner's `finally` teardown never ran and
   the in-flight cell's containers survived — pinning their networks.
3. The new sweep reused slot 0 for its first cell, collided with the orphaned subnet, and
   failed. Because a sequential sweep never changes slot, **every** subsequent cell
   collided too: 199 failures in well under a minute.

**Why it was expensive.** `remaining_cells()` excludes failed cells as well as completed
ones, so all 199 would have been permanently skipped — a silently 79%-empty dataset that
still looked like a finished sweep.

**Fixed in code, not by cleaning up.** `testbed/orchestrate/sweep.py` now has three
guards, with 14 tests in `tests/unit/test_sweep_recovery.py`:

| Guard | What it prevents |
|---|---|
| `sweep_lock()` — exclusive PID lock, stale locks reclaimed | Two sweeps sharing one state file and one slot allocator |
| `purge_stale_cells()` — preflight removal of `sentinel-cell-*` | Starting a sweep into someone else's leftovers |
| `teardown_on_signal()` — SIGTERM/SIGINT raise instead of terminating | A killed sweep orphaning the resources that break the next one |

`--retry-failed` was added for the recovery itself: an environmental failure is
indistinguishable from a real one in the state file, so re-running those cells is an
explicit human decision rather than a heuristic that guesses at the cause.

**Operational notes.** `setsid` is unavailable on macOS; the sweep is launched via
`subprocess.Popen(start_new_session=True)` instead. Logs are opened in append mode — a
`>` redirect truncates a running process's log even when the command it belongs to
fails.

**The `replay` class uses a synthesised stand-in source**, not real CIC-IDS2017, which
requires registration. The replay *machinery* is real and tested end to end; only the
source corpus is substituted, and `docs/DATASET.md` says so.

### Known environment gaps (not blocking now — install before the step named)

| Missing | Needed by | Fix |
|---|---|---|
| `tshark` | **Step 4.10** (tshark parity) and claim C-02 | `brew install wireshark` |
| ~~libgobject / pango / cairo~~ | ~~Step 9.6 (WeasyPrint PDF export)~~ | **RESOLVED at Step 9.6** — the libraries were installed all along; dyld could not find them. See below. |

Every other dependency imports cleanly: scapy, pydantic 2.13.5, pyyaml, click, rich,
pandas 3.0.5, pyarrow, numpy 2.4.6, scikit-learn 1.9.0, xgboost 3.2.0, shap 0.51.0,
joblib, fastapi, uvicorn, jinja2, pytest 9.1.1, hypothesis, mypy 2.3.1, ruff 0.16.6.

> Note: the plan pins only lower bounds (`>=`), so the resolver picked several **major**
> versions above what the plan was written against — notably **mypy 2.x, pandas 3.x and
> numpy 2.x**. This is faithful to the plan text but means stricter type checking and some
> changed pandas/numpy semantics. Watch for it in Phases 7 and 9.

### For the next session

Read this file first, then `IPsec_Sentinel_BUILD_PLAN.md` for the current step's goal and
acceptance criteria. Activate with `source .venv/bin/activate`. Run `make verify` before
every commit and `make verify-all` at every milestone. Never commit red.
