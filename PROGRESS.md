# Build Progress

**Last updated:** 2026-09-05 11:13 UTC
**Current phase:** 2 — Traffic generation
**Current step:** 2.7 — Messaging generator (XMPP proxy)
**Last milestone tag:** `v0.2.0-testbed`

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
### Phase 1 — Testbed (7 steps → `v0.2.0-testbed`) ← **CURRENT**
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
### Phase 2 — Traffic generation (9 steps → `v0.3.0-traffic`) ← **CURRENT**
- [x] 2.1 — Traffic generator interface — commit `4cbe556`
- [x] 2.2 — ICMP generator — commit `c1dc5a4`
- [x] 2.3 — VoIP generator — commit `722d07b`
- [x] 2.4 — Video streaming generator — commit `d66a4c5`
- [x] 2.5 — Web browsing generator — commit `ff3f895`
- [x] 2.6 — Email generator — commit `(this commit)`
- [ ] 2.7 — Messaging generator (XMPP proxy)
- [ ] 2.8 — PCAP replay generator
- [ ] 2.9 — Network impairment profiles
- [ ] **▶ MILESTONE M2** — tag `v0.3.0-traffic`
- [ ] Phase 3 — Dataset and external data (6 steps → `v0.4.0-dataset`)
- [ ] Phase 4 — Deterministic IKE parser (10 steps → `v0.5.0-parser`)
- [ ] Phase 5 — ESP analysis (5 steps → `v0.6.0-esp`)
- [ ] Phase 6 — Assessment engine (9 steps → `v0.7.0-assessment`)
- [ ] Phase 7 — Feature extraction and ML (10 steps → `v0.8.0-ml`)
- [ ] Phase 8 — Remediation (6 steps → `v0.9.0-remediation`)
- [ ] Phase 9 — Reporting (7 steps → `v0.10.0-reporting`)
- [ ] Phase 10 — CLI, API and dashboard (4 steps → `v0.11.0-interfaces`)
- [ ] Phase 11 — Hardening, packaging, demo (7 steps → `v1.0.0`)
- [ ] Phase 12 — Presentation and evidence pack (10 steps → `v1.0.0-presentation`)

---

## Blockers

**None.**

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

## Deviations from plan

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
