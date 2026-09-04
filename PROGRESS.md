# Build Progress

**Last updated:** 2026-09-04 19:37 UTC
**Current phase:** 0 — Foundation and safety net
**Current step:** 0.1 — Initialise the repository
**Last milestone tag:** none

Authoritative execution document: `IPsec_Sentinel_BUILD_PLAN.md` (98 steps, 13 phases,
13 milestone gates). Domain reference: `ipsec_ai_platform_master_document.md`.

---

## Completed steps

### Phase 0 — Foundation (8 steps → `v0.1.0-foundation`)
- [x] 0.1 — Initialise repository structure — commit `(this commit)`
- [ ] 0.2 — Python packaging and dependencies
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

None currently blocking.

**Pending verification (does not block Phase 0):** Phase 1 requires kernel XFRM, network
namespaces and `tc netem`. This is a macOS arm64 host, so those can only exist inside
Docker Desktop's LinuxKit VM. The probe runs alongside Phase 0; result will be recorded
here before Phase 1 begins. Fallback ladder agreed with the user:
LinuxKit → Colima + Ubuntu → remote Linux host → the build plan's documented
"skip Phases 1–3 and 7" contingency (requires explicit sign-off).

---

## Deviations from plan

1. **Repo root is the existing working directory** (`/Users/prasham/Desktop/SIH_Hackathon`)
   rather than a new `ipsec-sentinel/` subdirectory as Step 0.1's shell snippet shows.
   The skeleton beneath it matches the plan exactly. Rationale: the working directory
   already is the project directory and already holds the two reference documents;
   nesting would put the repo root somewhere every future session has to rediscover.
2. **Added `models/` to the skeleton.** The plan's `.gitignore` references
   `models/*.pkl` and `models/*.joblib` but the directory tree omits the directory.
3. **Added `__init__.py` to each `src/ipsec_sentinel/` subpackage.** The plan shows only
   the top-level one; the subpackages need theirs to be importable packages.
4. **Two host-specific `.gitignore` additions.** The plan's `.gitignore` was written for a
   Linux host: added `.DS_Store` (macOS Finder metadata, which Finder recreates constantly
   and which had already staged itself into the first commit) and `.claude/` (agent session
   artifacts, including the session execution plan — not a project deliverable).

---

## Environment notes

| Item | State |
|---|---|
| Host | macOS 26.6.2, Darwin 25.6.0, **arm64** (Apple Silicon) — **not Linux** |
| Python | **3.11.15 via `uv`** (`~/.local/bin/python3.11`), matching the plan's CI pin. Host also has 3.14.5 / 3.13 / 3.9.6; none is used by this project. |
| `uv` | `~/.local/bin/uv` — used to provision Python |
| Docker | CLI 29.4.3, Compose v5.1.4. Docker Desktop.app installed; daemon launched this session. XFRM support **unverified** — see Blockers. |
| Privileges | uid 501, `admin` group, **not root**. `sudo` is interactive-only, unavailable to the agent non-interactively. Testbed privilege comes from `--privileged` containers, not host root. |
| `tcpdump` | `/usr/sbin/tcpdump` present (host capture needs sudo; testbed capture happens in-container) |
| `tshark` | **NOT INSTALLED.** Needed at Step 4.10 (tshark parity) and for claim C-02. Install with `brew install wireshark` before Phase 4. |
| Disk | ~180 GB free — ample for the sweep corpus |
| Remote | `github.com/PrashamJ17/SIH_PS160` — private, was empty at first push. `gh` authenticated as `PrashamJ17`. |

### For the next session

Read this file first, then `IPsec_Sentinel_BUILD_PLAN.md` for the current step's goal and
acceptance criteria. Activate the venv with `source .venv/bin/activate`. Run
`make verify` before every commit and `make verify-all` at every milestone.
