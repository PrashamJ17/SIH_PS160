# Build Progress

**Last updated:** 2026-09-04 20:01 UTC
**Current phase:** 0 — Foundation and safety net
**Current step:** 0.3 — Makefile as the single entry point
**Last milestone tag:** none

Authoritative execution document: `IPsec_Sentinel_BUILD_PLAN.md` (98 steps, 13 phases,
13 milestone gates). Domain reference: `ipsec_ai_platform_master_document.md`.

---

## Completed steps

### Phase 0 — Foundation (8 steps → `v0.1.0-foundation`)
- [x] 0.1 — Initialise repository structure — commit `d4f98f1`
- [x] 0.2 — Python packaging and dependencies — commit `(this commit)`
- [ ] 0.3 — Makefile as the single entry point
- [ ] 0.4 — CI pipeline
- [ ] 0.5 — Structured logging
- [ ] 0.6 — Core domain models
- [ ] 0.7 — Protocol constants and lookup tables
- [ ] 0.8 — Test fixture helpers (synthetic IKE packet builders)
- [ ] **▶ MILESTONE M0** — tag `v0.1.0-foundation`

### Remaining phases (not started)
- [ ] Phase 1 — Testbed (7 steps → `v0.2.0-testbed`)
- [ ] Phase 2 — Traffic generation (9 steps → `v0.3.0-traffic`)
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
5. **Environment created with `uv` rather than `python -m venv` + `pip`.** Step 0.2's
   snippet uses venv+pip; `uv venv` / `uv pip install` produces a byte-compatible standard
   virtualenv that `pip` also operates on, and is far faster on a slow link. `pyproject.toml`
   is verbatim from the plan. No functional difference.

---

## Environment notes

| Item | State |
|---|---|
| Host | macOS 26.6.2, Darwin 25.6.0, **arm64** (Apple Silicon) — **not Linux** |
| Python | **3.11.15 via `uv`**, venv at `.venv/`, matching the plan's CI pin exactly |
| Docker | CLI 29.4.3, Compose v5.1.4, daemon **up**. LinuxKit `6.12.76` aarch64. **XFRM verified — see Blockers.** |
| Privileges | uid 501, `admin` group, **not root**. `sudo` is interactive-only and unavailable to the agent. Testbed privilege comes from `--privileged` containers, not host root. |
| `tcpdump` | `/usr/sbin/tcpdump` present (host capture needs sudo; testbed capture is in-container) |
| Network | **Slow.** PyPI took >20 s to first byte; the dependency install ran ~5.5 min at ~0.5 MB/s. Budget generously for anything that downloads. |
| Disk | ~180 GB free |
| Remote | `github.com/PrashamJ17/SIH_PS160` — private. `gh` authenticated as `PrashamJ17`. |

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
