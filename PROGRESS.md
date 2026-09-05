# Build Progress

**Last updated:** 2026-09-05
**Current phase:** 6 — Assessment engine
**Current step:** 6.3 — IKE configuration rules (IKE-01..IKE-04)
**Last milestone tag:** `v0.6.0-esp`

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
### Phase 5 — ESP analysis (5 steps → `v0.6.0-esp`) ← **CURRENT**
- [x] 5.1 — ESP header parser — commit `2e58048`
- [x] 5.2 — ESP flow assembly — commit `eb2210e`
- [x] 5.3 — Sequence and replay analysis — commit `2206baf`
- [x] 5.4 — IKE-to-ESP tunnel correlation — commit `3e0c26e`
- [x] 5.5 — Tunnel inventory — commit `414ddee`
- [x] **▶ MILESTONE M5 PASSED** — tag `v0.6.0-esp` (4/4 acceptance items)
### Phase 6 — Assessment engine (9 steps → `v0.7.0-assessment`) ← **CURRENT**
- [x] 6.1 — Rule framework — commit `d67658f`
- [x] 6.2 — Cryptographic strength rules (CRY-01..CRY-10) — commit `a547da4`
- [ ] Phase 7 — Feature extraction and ML (10 steps → `v0.8.0-ml`)
- [ ] Phase 8 — Remediation (6 steps → `v0.9.0-remediation`)
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
| libgobject / pango / cairo | **Step 9.6** (WeasyPrint PDF export). `weasyprint` installs but fails to import: `OSError: cannot load library 'libgobject-2.0-0'` | `brew install pango` |

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
