# IPsec Sentinel — Complete Build Plan
### Software, dataset, and presentation — end to end

**A step-by-step execution plan for Claude Code.**
**Target: Smart India Hackathon 2026.**

Project codename: `ipsec-sentinel`
Target: AI-driven IPsec VPN protocol analysis and security assessment platform

---

## How to use this plan

This document is written **for an AI coding agent**. Each step is small, independently verifiable, and ends with a commit. Do not batch steps. Do not skip verification.

### The loop for every single step

```
1. READ the step's goal and acceptance criteria
2. WRITE the code
3. WRITE the test (or write the test first — preferred)
4. RUN the test — it must pass
5. RUN the full test suite — nothing may regress
6. RUN the linter and type checker — must be clean
7. COMMIT with the specified message
8. PUSH to origin
9. ONLY THEN move to the next step
```

**If a step's verification fails, stop. Fix it. Do not proceed with a failing test.**

### Rules that apply throughout

| Rule | Detail |
|---|---|
| **Never commit broken code** | `pytest` must exit 0 before every commit |
| **Never skip a test** | If a test is hard to write, the design is wrong. Redesign. |
| **Type everything** | `mypy --strict` on `src/`. No `Any` without a comment explaining why. |
| **No bare excepts** | Every `except` names its exception class |
| **Parsers must never crash** | Malformed input returns a structured error, never an unhandled exception |
| **No network calls in unit tests** | Use fixtures. Integration tests are separately marked. |
| **Commit messages** | Conventional commits: `feat:`, `fix:`, `test:`, `chore:`, `docs:`, `refactor:` |
| **One logical change per commit** | If the message needs "and", split it |

### Milestone gates

At each `MILESTONE` marker, run the **full regression suite** (`make verify-all`), confirm every previously built feature still works, tag the release, and push the tag. Do not proceed past a red milestone.

### Environment assumptions

- Python 3.11+
- Docker and Docker Compose v2
- Linux host (or Linux VM) — the testbed needs kernel XFRM and network namespaces
- Root or `CAP_NET_ADMIN` for testbed operations
- Git remote configured as `origin`

---
---

---

## What actually wins SIH

Before any code: understand what the panel is scoring. Judging clusters around innovation (~30%), technical execution (~25%), impact and feasibility (~25%), and presentation (~20%). But underneath those weights, panels are answering one question:

> **Does this team understand the problem well enough that their software would keep getting better?**

They know what is buildable in 36 hours. They are not scoring line count. Five things move that judgment, and this plan is engineered around producing all five as *artifacts*, not assertions:

| # | The differentiator | Where this plan produces it |
|---|---|---|
| 1 | **You found the flaw in the problem statement** — the named datasets contain no IPsec traffic | Step 3.5 generates the audit; Slide 5 presents it |
| 2 | **You know what needs AI and what does not** — 7 of 9 targets are parsing, 2 are inference | Phase 4 vs Phase 7; Slide 6 |
| 3 | **You report where your model fails** — held-out generalisation, not just the flattering number | Step 7.6; Slide 9 |
| 4 | **You produce a finding nothing else could** — undocumented traffic on a SCADA link | Step 7.5 + demo beat 4; Slide 10 |
| 5 | **You built for India** — ITSAR, CERT-In, NCIIPC, PQC readiness | Step 6.6, Step 6.5; Slide 11 |

Every one of those is *counterintuitive*. Teams instinctively hide dataset problems, claim AI everywhere, report only their best number, demo generic features, and target a generic market. Doing the opposite is the entire strategy.

**One rule governs this build:** every claim you will make in the presentation must be produced by a script in the repository before you make it. Phase 12 enforces this with a test that fails if a slide's number drifts from its evidence.

---
---

# PHASE 0 — Foundation and safety net

**Goal:** a repository where every subsequent step is automatically verified. Build this before writing a single line of protocol code.

---

## Step 0.1 — Initialise the repository

**Goal:** empty repo with correct structure and a first commit.

**Do:**
```bash
mkdir ipsec-sentinel && cd ipsec-sentinel
git init
```

Create this directory skeleton (empty `.gitkeep` files where needed):

```
ipsec-sentinel/
├── src/ipsec_sentinel/
│   ├── __init__.py
│   ├── parser/
│   ├── assess/
│   ├── features/
│   ├── ml/
│   ├── remediate/
│   ├── report/
│   └── api/
├── testbed/
│   ├── compose/
│   ├── configs/
│   ├── traffic/
│   └── orchestrate/
├── tests/
│   ├── unit/
│   ├── integration/
│   └── fixtures/
├── dashboard/
├── data/
│   ├── raw/
│   ├── processed/
│   └── external/
├── docs/
└── scripts/
```

**Create `.gitignore`:**
```
__pycache__/
*.py[cod]
.venv/
venv/
.pytest_cache/
.mypy_cache/
.ruff_cache/
*.egg-info/
dist/
build/
.coverage
htmlcov/
data/raw/**/*.pcap
data/raw/**/*.pcapng
data/processed/**/*.parquet
data/external/**
!data/**/.gitkeep
*.log
.env
models/*.pkl
models/*.joblib
```

**Test:** `git status` shows a clean tree after adding.

**Verify:** directory tree matches exactly.

**Commit:** `chore: initialise repository structure`
**Push:** `git push -u origin main`

---

## Step 0.2 — Python packaging and dependencies

**Goal:** installable package with pinned dev tooling.

**Create `pyproject.toml`:**

```toml
[project]
name = "ipsec-sentinel"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = [
    "scapy>=2.5.0",
    "pydantic>=2.5.0",
    "pyyaml>=6.0",
    "click>=8.1",
    "rich>=13.0",
    "pandas>=2.1",
    "pyarrow>=14.0",
    "numpy>=1.26",
]

[project.optional-dependencies]
ml = ["scikit-learn>=1.3", "xgboost>=2.0", "shap>=0.44", "joblib>=1.3"]
api = ["fastapi>=0.109", "uvicorn>=0.27"]
report = ["jinja2>=3.1", "weasyprint>=60.0"]
dev = [
    "pytest>=7.4", "pytest-cov>=4.1", "pytest-xdist>=3.5",
    "hypothesis>=6.92", "mypy>=1.8", "ruff>=0.1.14",
    "types-PyYAML", "pandas-stubs",
]

[project.scripts]
sentinel = "ipsec_sentinel.cli:main"

[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[tool.pytest.ini_options]
testpaths = ["tests"]
markers = [
    "integration: requires Docker/root (deselect with '-m \"not integration\"')",
    "slow: takes more than 5 seconds",
]
addopts = "-q --strict-markers"

[tool.mypy]
python_version = "3.11"
strict = true
warn_unreachable = true
files = ["src"]

[tool.ruff]
line-length = 100
target-version = "py311"

[tool.ruff.lint]
select = ["E", "F", "I", "N", "UP", "B", "A", "C4", "SIM", "ARG", "PTH", "RUF"]
```

**Do:**
```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,ml,api,report]"
```

**Test:** `python -c "import ipsec_sentinel; print(ipsec_sentinel.__file__)"`

**Verify:** import succeeds, no errors.

**Commit:** `chore: add packaging and dependencies`
**Push.**

---

## Step 0.3 — Makefile as the single entry point

**Goal:** every verification runs from one place. Claude Code uses these targets constantly.

**Create `Makefile`:**

```makefile
.PHONY: lint type test test-unit test-int cov verify verify-all clean

lint:
	ruff check src tests testbed
	ruff format --check src tests testbed

fmt:
	ruff format src tests testbed
	ruff check --fix src tests testbed

type:
	mypy

test-unit:
	pytest tests/unit -m "not integration" -n auto

test-int:
	pytest tests/integration -m integration

test:
	pytest -m "not integration" -n auto

cov:
	pytest -m "not integration" --cov=ipsec_sentinel --cov-report=term-missing --cov-fail-under=80

# Run before EVERY commit
verify: lint type test

# Run at EVERY milestone
verify-all: lint type cov test-int

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage
```

**Test:** `make lint` — passes (nothing to lint yet, but must not error).

**Verify:** all targets execute without shell errors.

**Commit:** `chore: add Makefile with verification targets`
**Push.**

---

## Step 0.4 — CI pipeline

**Goal:** GitHub enforces what the Makefile enforces locally.

**Create `.github/workflows/ci.yml`:**

```yaml
name: CI
on:
  push:
    branches: [main]
  pull_request:

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
          cache: pip
      - run: pip install -e ".[dev,ml,api,report]"
      - run: make lint
      - run: make type
      - run: make cov
```

**Test:** push and confirm the workflow goes green on GitHub.

**Verify:** green check appears on the commit.

**Commit:** `ci: add verification workflow`
**Push.** Wait for green before continuing.

---

## Step 0.5 — Structured logging

**Goal:** consistent, greppable logs. Needed for debugging every later phase.

**Create `src/ipsec_sentinel/logging.py`:**

- `get_logger(name: str) -> logging.Logger`
- JSON formatter when `SENTINEL_LOG_FORMAT=json`, human-readable otherwise
- Level from `SENTINEL_LOG_LEVEL`, default INFO

**Test — `tests/unit/test_logging.py`:**
- logger returns the same instance for the same name
- JSON mode emits parseable JSON containing `level`, `name`, `message`
- level respects the env var

**Verify:** `make verify` clean.

**Commit:** `feat: add structured logging`
**Push.**

---

## Step 0.6 — Core domain models

**Goal:** typed data structures every module shares. Getting these right now prevents refactoring later.

**Create `src/ipsec_sentinel/models.py`** with Pydantic models:

```python
class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"

class Confidence(BaseModel):
    """Only attached to INFERRED facts, never to parsed ones."""
    value: float = Field(ge=0.0, le=1.0)
    method: str
    abstained: bool = False

class Transform(BaseModel):
    type: TransformType        # ENCR, PRF, INTEG, DH, ESN
    id: int
    name: str                  # resolved, e.g. "ENCR_AES_GCM_16"
    key_length: int | None = None

class Proposal(BaseModel):
    number: int
    protocol: str              # IKE, ESP, AH
    transforms: list[Transform]

class IKEExchange(BaseModel):
    initiator_spi: str         # hex
    responder_spi: str
    version: str               # "IKEv1" | "IKEv2"
    exchange_type: str
    is_aggressive: bool = False
    proposals_offered: list[Proposal]
    proposal_accepted: Proposal | None = None
    ke_group_from_length: int | None = None
    vendor_ids: list[str] = []
    notifies: list[str] = []
    timestamp: datetime
    src_ip: str
    dst_ip: str

class ESPFlow(BaseModel):
    spi: str
    src_ip: str
    dst_ip: str
    packet_count: int
    byte_count: int
    first_seen: datetime
    last_seen: datetime
    sequence_gaps: int
    replay_suspected: bool

class Finding(BaseModel):
    rule_id: str
    title: str
    severity: Severity
    evidence: str              # what was observed
    standard_ref: str          # e.g. "RFC 8247 §4"
    attack_technique: str | None = None
    remediation_hint: str
    confidence: Confidence | None = None   # None => deterministic fact

class TunnelAssessment(BaseModel):
    tunnel_id: str
    endpoints: tuple[str, str]
    ike: IKEExchange | None
    esp_flows: list[ESPFlow]
    findings: list[Finding]
    score: int = Field(ge=0, le=100)
    grade: str                 # A-F
    inferred_mode: str | None = None
    inferred_mode_confidence: Confidence | None = None
    inferred_traffic: str | None = None
    inferred_traffic_confidence: Confidence | None = None
```

**Critical design rule:** `confidence is None` means the fact was **parsed**. A non-None confidence means it was **inferred**. Enforce this in a validator and test it. This distinction propagates into the report and is the intellectual core of the project.

**Test — `tests/unit/test_models.py`:**
- Severity ordering helper sorts CRITICAL first
- `Confidence` rejects values outside [0,1]
- A `Finding` with `confidence=None` is flagged `is_deterministic == True`
- Round-trip: model → JSON → model is identical

**Verify:** `make verify` clean.

**Commit:** `feat: add core domain models`
**Push.**

---

## Step 0.7 — Protocol constants and lookup tables

**Goal:** every IANA number resolved to a name. Pure data, no logic — but errors here silently corrupt everything downstream, so test exhaustively.

**Create `src/ipsec_sentinel/parser/constants.py`:**

```python
IKE_VERSIONS = {0x10: "IKEv1", 0x20: "IKEv2"}

IKEV2_EXCHANGE_TYPES = {
    34: "IKE_SA_INIT", 35: "IKE_AUTH",
    36: "CREATE_CHILD_SA", 37: "INFORMATIONAL",
}
IKEV1_EXCHANGE_TYPES = {
    0: "NONE", 1: "Base", 2: "Identity Protection (Main Mode)",
    3: "Authentication Only", 4: "Aggressive Mode",
    5: "Informational", 32: "Quick Mode",
}

IKEV2_PAYLOAD_TYPES = {
    33: "SA", 34: "KE", 35: "IDi", 36: "IDr", 37: "CERT",
    38: "CERTREQ", 39: "AUTH", 40: "Ni/Nr", 41: "N",
    42: "D", 43: "V", 44: "TSi", 45: "TSr", 46: "SK", 47: "CP",
}

TRANSFORM_TYPES = {1: "ENCR", 2: "PRF", 3: "INTEG", 4: "DH", 5: "ESN"}

ENCR_ALGORITHMS = {
    1: "ENCR_DES_IV64", 2: "ENCR_DES", 3: "ENCR_3DES",
    5: "ENCR_RC5", 6: "ENCR_IDEA", 7: "ENCR_CAST",
    8: "ENCR_BLOWFISH", 11: "ENCR_NULL", 12: "ENCR_AES_CBC",
    13: "ENCR_AES_CTR", 14: "ENCR_AES_CCM_8", 15: "ENCR_AES_CCM_12",
    16: "ENCR_AES_CCM_16", 18: "ENCR_AES_GCM_8", 19: "ENCR_AES_GCM_12",
    20: "ENCR_AES_GCM_16", 23: "ENCR_CAMELLIA_CBC",
    28: "ENCR_CHACHA20_POLY1305",
}

INTEG_ALGORITHMS = {
    0: "NONE", 1: "AUTH_HMAC_MD5_96", 2: "AUTH_HMAC_SHA1_96",
    5: "AUTH_AES_XCBC_96", 12: "AUTH_HMAC_SHA2_256_128",
    13: "AUTH_HMAC_SHA2_384_192", 14: "AUTH_HMAC_SHA2_512_256",
}

PRF_ALGORITHMS = {
    1: "PRF_HMAC_MD5", 2: "PRF_HMAC_SHA1", 4: "PRF_AES128_XCBC",
    5: "PRF_HMAC_SHA2_256", 6: "PRF_HMAC_SHA2_384", 7: "PRF_HMAC_SHA2_512",
}

DH_GROUPS = {
    1: ("768-bit MODP", 768), 2: ("1024-bit MODP", 1024),
    5: ("1536-bit MODP", 1536), 14: ("2048-bit MODP", 2048),
    15: ("3072-bit MODP", 3072), 16: ("4096-bit MODP", 4096),
    19: ("256-bit ECP", 256), 20: ("384-bit ECP", 384),
    21: ("521-bit ECP", 521), 31: ("Curve25519", 256),
    # PQC hybrids (RFC 9370 additional key exchanges)
}

# KE payload length in bytes -> DH group, for cross-checking
KE_LENGTH_TO_GROUP = {96: 1, 128: 2, 192: 5, 256: 14, 384: 15, 512: 16,
                      64: 19, 96_ECP: 20}  # resolve carefully, ECP vs MODP collide

ATTRIBUTE_KEY_LENGTH = 14

NOTIFY_TYPES = {
    14: "NO_PROPOSAL_CHOSEN", 17: "INVALID_KE_PAYLOAD",
    16390: "NAT_DETECTION_SOURCE_IP", 16391: "NAT_DETECTION_DESTINATION_IP",
    16388: "USE_TRANSPORT_MODE", 16389: "HTTP_CERT_LOOKUP_SUPPORTED",
    16406: "REDIRECT", 16395: "COOKIE",
}
```

**Note on `KE_LENGTH_TO_GROUP`:** MODP and ECP groups can produce colliding lengths. Resolve by preferring the group named in the transform, and use length only as a *consistency check* that raises a warning on mismatch. Write a test for the collision case.

**Test — `tests/unit/test_constants.py`:**
- Every dict has no duplicate values where uniqueness is required
- `resolve_transform_name(type, id)` returns the right name for a table of ~20 known pairs
- Unknown IDs return `"UNKNOWN_<type>_<id>"` and never raise
- DH group 2 maps to 1024 bits
- `KE_LENGTH_TO_GROUP` collision raises the documented warning, not an exception

**Verify:** `make verify` clean.

**Commit:** `feat: add IKE protocol constants and resolvers`
**Push.**

---

## Step 0.8 — Test fixture helpers

**Goal:** build synthetic IKE packets in tests without needing real captures. This makes the parser testable before the testbed exists.

**Create `tests/fixtures/builders.py`:**

```python
def build_ike_header(
    i_spi: bytes = b"\x11" * 8,
    r_spi: bytes = b"\x00" * 8,
    next_payload: int = 33,
    version: int = 0x20,
    exchange_type: int = 34,
    flags: int = 0x08,
    message_id: int = 0,
    length: int | None = None,
) -> bytes: ...

def build_transform(t_type: int, t_id: int, key_length: int | None = None,
                    is_last: bool = False) -> bytes: ...

def build_proposal(number: int, protocol: int,
                   transforms: list[bytes], is_last: bool = False) -> bytes: ...

def build_sa_payload(proposals: list[bytes], next_payload: int = 0) -> bytes: ...

def build_ike_sa_init(proposals: list[Proposal]) -> bytes:
    """Full, valid IKE_SA_INIT message."""

def build_weak_ike_sa_init() -> bytes:
    """3DES + MD5 + DH group 2 — the canonical bad config."""

def build_strong_ike_sa_init() -> bytes:
    """AES-GCM-256 + SHA2-384 PRF + DH group 20."""

def build_ikev1_aggressive() -> bytes:
    """IKEv1 Aggressive Mode with PSK."""
```

**Test — `tests/unit/test_builders.py`:**
- Built header is exactly 28 bytes
- Length field matches actual total length
- Transform substructure length is correct with and without a key-length attribute
- `build_weak_ike_sa_init()` and `build_strong_ike_sa_init()` produce different bytes

**Verify:** `make verify` clean.

**Commit:** `test: add synthetic IKE packet builders`
**Push.**

---

## ▶ MILESTONE M0 — Foundation complete

**Run:**
```bash
make verify-all
```

**Confirm:**
- [ ] All tests pass
- [ ] Coverage above 80%
- [ ] `mypy --strict` clean
- [ ] CI green on GitHub
- [ ] Domain models importable and round-trip through JSON
- [ ] Synthetic packet builders produce valid byte sequences

**Tag:**
```bash
git tag -a v0.1.0-foundation -m "Foundation: models, constants, test harness, CI"
git push origin v0.1.0-foundation
```

---
---

# PHASE 1 — The testbed

**Goal:** reproducible IPsec tunnels in Docker, with ground truth read back from the daemons. This is your data source and it gates everything else.

**Critical scheduling note:** if Phase 1 is not producing labelled PCAPs by the end of your allotted time for it, **abandon the ML lane** and proceed to Phase 5 (parser) with publicly available captures. The deterministic auditor is a complete product on its own.

---

## Step 1.1 — Single strongSwan container

**Goal:** one container that starts charon and stays alive.

**Create `testbed/compose/Dockerfile.strongswan`:**

```dockerfile
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    strongswan strongswan-swanctl libcharon-extra-plugins \
    iproute2 iputils-ping tcpdump iperf3 curl \
    && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
```

`entrypoint.sh` starts charon in the foreground and traps SIGTERM.

**Test — `tests/integration/test_container_boot.py`** (marked `integration`):
- Build the image
- Run the container
- `docker exec <c> swanctl --version` returns 0
- Container is still running after 5 seconds

**Verify:** `make test-int` passes for this test.

**Commit:** `feat(testbed): add strongSwan container image`
**Push.**

---

## Step 1.2 — Two-peer network topology

**Goal:** two containers on an isolated network that can ping each other.

**Create `testbed/compose/pair.yml`:**

- Services `left` and `right`
- `cap_add: [NET_ADMIN]`, `privileged: true` (needed for XFRM)
- Custom bridge network with fixed IPs (e.g. 10.100.0.2 and 10.100.0.3)
- Optional "protected" subnets behind each peer via secondary interfaces

**Test — `tests/integration/test_topology.py`:**
- `docker compose -f pair.yml up -d` succeeds
- `left` can ping `right` on the transit network
- Teardown leaves no orphaned networks

**Verify:** `make test-int` green; `docker network ls` clean afterwards.

**Commit:** `feat(testbed): add two-peer compose topology`
**Push.**

---

## Step 1.3 — First working tunnel (hardcoded)

**Goal:** one IPsec tunnel comes up. Prove the mechanism before generalising.

Write `swanctl.conf` for both peers by hand: IKEv2, AES-GCM-256, DH group 20, PFS on, tunnel mode, PSK auth.

**Test — `tests/integration/test_first_tunnel.py`:**
- Bring up the pair
- `swanctl --initiate --child net-net` succeeds
- `swanctl --list-sas` shows an ESTABLISHED SA
- Traffic between protected subnets is encrypted: `tcpdump` on the transit network shows **ESP (proto 50)**, and shows **no plaintext ICMP**

**This last assertion is the important one.** Assert that the plaintext payload marker does *not* appear on the wire. That is your proof the tunnel is genuinely protecting traffic.

**Verify:** `make test-int` green.

**Commit:** `feat(testbed): establish first working IPsec tunnel`
**Push.**

---

## Step 1.4 — Config templating

**Goal:** generate `swanctl.conf` from a parameter set instead of hand-writing.

**Create `testbed/orchestrate/config_gen.py`:**

```python
@dataclass(frozen=True)
class TunnelConfig:
    ike_version: Literal["ikev1", "ikev2"]
    encryption: str          # "aes256gcm16", "aes128", "3des"
    integrity: str | None    # None for AEAD
    prf: str
    dh_group: str            # "modp1024", "ecp384", ...
    pfs: bool
    child_dh_group: str | None
    mode: Literal["tunnel", "transport"]
    ip_version: Literal[4, 6]
    ike_lifetime_s: int
    child_lifetime_s: int
    aggressive: bool = False   # IKEv1 only

    def proposal_string(self) -> str: ...
    def config_id(self) -> str:       # stable hash for filenames
        ...

def render_swanctl_conf(cfg: TunnelConfig, role: Literal["left","right"]) -> str: ...
```

**Test — `tests/unit/test_config_gen.py`:**
- AEAD ciphers produce a proposal with **no** separate integrity algorithm
- Non-AEAD ciphers **require** an integrity algorithm — raise `ValueError` if None
- `pfs=False` omits the child DH group from the ESP proposal
- `aggressive=True` with `ike_version="ikev2"` raises `ValueError` (IKEv2 has no aggressive mode)
- `config_id()` is stable across runs and different for different configs
- Rendered config is valid TOML-ish syntax strongSwan accepts (regex sanity check)

**Verify:** `make verify` clean.

**Commit:** `feat(testbed): add tunnel config templating`
**Push.**

---

## Step 1.5 — Config validity matrix

**Goal:** define which parameter combinations are legal. Prevents wasted sweep time on impossible configs.

**Create `testbed/configs/matrix.yaml`:**

```yaml
ike_versions: [ikev1, ikev2]
encryptions:
  - {name: aes256gcm16, aead: true,  keylen: 256}
  - {name: aes128gcm16, aead: true,  keylen: 128}
  - {name: aes256,      aead: false, keylen: 256}
  - {name: aes128,      aead: false, keylen: 128}
  - {name: 3des,        aead: false, keylen: 168, deprecated: true}
integrities: [sha256, sha384, sha1, md5]
prfs: [prfsha256, prfsha384, prfsha1, prfmd5]
dh_groups: [modp1024, modp1536, modp2048, ecp256, ecp384, curve25519]
pfs: [true, false]
modes: [tunnel, transport]
ip_versions: [4, 6]

# Sampling strategy — do NOT run full factorial
sampling:
  strategy: stratified
  target_count: 36
  must_include:
    - {label: worst,  encryption: 3des,        integrity: md5,    dh_group: modp1024, pfs: false, ike_version: ikev1, aggressive: true}
    - {label: weak,   encryption: aes128,      integrity: sha1,   dh_group: modp1024, pfs: false}
    - {label: medium, encryption: aes128,      integrity: sha256, dh_group: modp2048, pfs: true}
    - {label: good,   encryption: aes256,      integrity: sha384, dh_group: ecp384,   pfs: true}
    - {label: best,   encryption: aes256gcm16, integrity: null,   dh_group: curve25519, pfs: true}
```

**Create `testbed/orchestrate/matrix.py`** with `expand_matrix() -> list[TunnelConfig]` implementing stratified sampling plus the must-include anchors.

**Test — `tests/unit/test_matrix.py`:**
- Expansion produces exactly `target_count` configs (plus anchors, deduplicated)
- No AEAD cipher paired with a separate integrity algorithm
- No IKEv2 config marked aggressive
- All five anchor labels are present
- Every DH group in the matrix appears at least once
- **Balance check:** every encryption algorithm appears with at least two different DH groups (guards against the confound trap)

**Verify:** `make verify` clean.

**Commit:** `feat(testbed): add configuration matrix with stratified sampling`
**Push.**

---

## Step 1.6 — Ground-truth harvester

**Goal:** read back what was *actually negotiated*, not what was proposed. This is the single most important correctness step in the whole dataset pipeline.

**Create `testbed/orchestrate/groundtruth.py`:**

```python
def harvest_swanctl(container: str) -> dict:
    """Parse `swanctl --list-sas` output."""

def harvest_xfrm_state(container: str) -> dict:
    """Parse `ip xfrm state` — kernel's view of active SAs."""

def build_manifest(cfg: TunnelConfig, swanctl: dict, xfrm: dict,
                   capture_meta: dict) -> Manifest:
    """Merge intent + reality into the label manifest."""
```

The `Manifest` model must include a `negotiation_matched_intent: bool` field.

**Test — `tests/unit/test_groundtruth.py`:**
- Parse a captured `swanctl --list-sas` fixture correctly (store a real one in `tests/fixtures/`)
- Parse an `ip xfrm state` fixture correctly
- When intent and reality disagree, `negotiation_matched_intent` is `False`
- Missing fields produce `None`, never a crash

**Test — `tests/integration/test_groundtruth_live.py`:**
- Bring up a known tunnel
- Harvest
- Assert the harvested encryption algorithm matches what was configured

**Verify:** both suites green.

**Commit:** `feat(testbed): add ground-truth harvester from swanctl and xfrm`
**Push.**

---

## Step 1.7 — Dual-tap capture

**Goal:** capture encrypted (outer) and plaintext (inner) simultaneously. The inner tap gives perfect application labels.

**Create `testbed/orchestrate/capture.py`:**

```python
class DualCapture:
    """Starts two tcpdump processes: outer (transit net) and inner (protected net)."""
    def __enter__(self) -> "DualCapture": ...
    def __exit__(self, *args) -> None: ...   # graceful SIGTERM, wait for flush
    @property
    def outer_pcap(self) -> Path: ...
    @property
    def inner_pcap(self) -> Path: ...
```

Outer filter: `udp port 500 or udp port 4500 or ip proto 50 or ip proto 51 or ip6 proto 50`
Inner filter: none (capture everything on the protected side)

**Critical:** tcpdump buffers. On exit, send SIGTERM and **wait for the process to flush**, then assert the file is non-empty and readable by Scapy. A truncated PCAP silently corrupts your dataset.

**Test — `tests/integration/test_capture.py`:**
- Capture during a ping through an established tunnel
- Outer PCAP contains ESP packets (proto 50)
- Outer PCAP contains **zero** ICMP echo packets
- Inner PCAP contains ICMP echo packets
- Both files open cleanly in Scapy with no truncation warning

**Verify:** `make test-int` green.

**Commit:** `feat(testbed): add dual-tap packet capture`
**Push.**

---

## ▶ MILESTONE M1 — Testbed operational

**Run:** `make verify-all`

**Manual acceptance:** run one full cycle end to end —
```bash
python -m testbed.orchestrate.single_run --config-label weak
```

**Confirm:**
- [ ] Tunnel establishes
- [ ] Outer PCAP contains IKE and ESP, no plaintext
- [ ] Inner PCAP contains plaintext
- [ ] Manifest written with negotiated (not intended) parameters
- [ ] `negotiation_matched_intent` is True for a valid config
- [ ] Containers and networks torn down cleanly
- [ ] All previous tests still pass

**Tag:** `v0.2.0-testbed` and push.

---
---
# PHASE 2 — Traffic generation

**Goal:** realistic application traffic inside the tunnels, with reliable class labels.

---

## Step 2.1 — Traffic generator interface

**Goal:** one contract every generator implements, so the orchestrator treats them uniformly.

**Create `testbed/traffic/base.py`:**

```python
class TrafficGenerator(Protocol):
    name: str                    # the ML class label
    requires: list[str]          # extra containers/services needed

    def setup(self, ctx: RunContext) -> None: ...
    def run(self, duration_s: int) -> GenerationResult: ...
    def teardown(self) -> None: ...

@dataclass
class GenerationResult:
    generator: str
    variant: str          # e.g. "g711_20ms", "dash_1080p"
    packets_sent: int
    bytes_sent: int
    started_at: datetime
    ended_at: datetime
    success: bool
    error: str | None = None
```

**Test — `tests/unit/test_traffic_base.py`:**
- A dummy generator satisfies the Protocol (use `isinstance` with `runtime_checkable`)
- `GenerationResult` requires `success=False` to carry a non-None `error` (validator)

**Verify + Commit:** `feat(traffic): add generator interface` — **Push.**

---

## Step 2.2 — ICMP generator

**Goal:** the simplest generator. Establishes the pattern.

**Create `testbed/traffic/icmp.py`:**
- Variants: `steady_1s` (one 64-byte ping/sec), `flood_small`, `large_payload` (1400 bytes)
- Uses `ping` inside the container

**Test — `tests/integration/test_traffic_icmp.py`:**
- Run for 10 seconds
- Inner PCAP contains approximately 10 echo requests (allow ±2)
- Outer PCAP ESP packet count is at least the inner count
- `GenerationResult.success` is True

**Verify + Commit:** `feat(traffic): add ICMP generator` — **Push.**

---

## Step 2.3 — VoIP generator

**Goal:** the most distinctive traffic shape, and the one that most clearly demonstrates the ML value.

**Create `testbed/traffic/voip.py`:**
- Use SIPp with RTP media, or `rtpgen` if simpler
- **Variants matter here:** `g711_20ms` (constant ~160-byte payload every 20 ms) and `g729_20ms` (~20-byte payload every 20 ms)
- Bidirectional and roughly symmetric

**Test — `tests/integration/test_traffic_voip.py`:**
- Inner PCAP inter-arrival times cluster at 20 ms ± 5 ms for at least 80% of packets
- G.711 payload sizes have standard deviation below 10 bytes
- G.729 mean payload is substantially smaller than G.711
- Forward/backward byte ratio is between 0.7 and 1.4 (symmetric)

**These assertions are the ground truth for your classifier.** If they fail, the generator is not producing VoIP-shaped traffic and any model trained on it is worthless.

**Verify + Commit:** `feat(traffic): add VoIP generator with codec variants` — **Push.**

---

## Step 2.4 — Video streaming generator

**Goal:** bursty, asymmetric, idle-gapped traffic.

**Create `testbed/traffic/video.py`:**
- Self-host DASH or HLS via nginx in a sidecar container (do **not** depend on the public internet — the sweep must be reproducible and air-gappable)
- Pre-generate segments once, reuse across runs
- Player: `ffmpeg` reading the manifest, or a small script fetching segments on a buffer schedule
- Variants: `dash_720p`, `dash_1080p`, `hls_adaptive`

**Test — `tests/integration/test_traffic_video.py`:**
- Downstream bytes exceed upstream by at least 10×
- At least 3 idle gaps longer than 2 seconds in a 60-second run
- Burst packets are predominantly at or near MTU

**Verify + Commit:** `feat(traffic): add video streaming generator` — **Push.**

---

## Step 2.5 — Web browsing generator

**Create `testbed/traffic/web.py`:**
- Local nginx serving a **mirrored corpus** of pages with varied asset counts and sizes
- Playwright or a scripted `curl`-based fetcher with realistic think-time gaps (2–15 s)
- **Rotate the page set** — never fetch the same page in every run, or the model memorises content

**Test — `tests/integration/test_traffic_web.py`:**
- Request/response asymmetry present (small out, large in)
- At least 2 think-time gaps over 2 seconds
- Consecutive runs fetch different page sets (assert set difference is non-empty)

**Verify + Commit:** `feat(traffic): add web browsing generator` — **Push.**

---

## Step 2.6 — Email generator

**Create `testbed/traffic/email.py`:**
- Postfix + Dovecot sidecar
- SMTP send with varied message sizes and attachments; IMAP poll
- Variants: `smtp_small`, `smtp_attachment`, `imap_sync`

**Test — `tests/integration/test_traffic_email.py`:**
- Mostly idle with discrete bursts
- Attachment variant produces a burst above 100 KB

**Verify + Commit:** `feat(traffic): add email generator` — **Push.**

---

## Step 2.7 — Messaging generator

**Create `testbed/traffic/messaging.py`:**
- **Do not claim WhatsApp.** Use XMPP (Prosody sidecar) or Matrix as a shape-proxy
- Small, sporadic, bidirectional messages with human-like gaps
- The generator's `name` must be `"messaging"` and its docstring must state it is a proxy protocol

**Test:** small mean packet size; irregular gaps; roughly symmetric.

**Documentation requirement:** add a note in `docs/DATASET.md` stating explicitly that messaging traffic is XMPP-shaped, not WhatsApp. **This honesty is a scoring asset, not a weakness.**

**Verify + Commit:** `feat(traffic): add messaging generator (XMPP proxy)` — **Push.**

---

## Step 2.8 — PCAP replay generator

**Goal:** the move that legitimately uses the datasets named in the problem statement.

**Create `testbed/traffic/replay.py`:**
- `tcpreplay` an external PCAP through the protected interface so it becomes inner payload
- Rewrite MACs/IPs as needed (`tcprewrite`)
- Variants keyed by source dataset: `cicids2017_benign`, `mawi_sample`

**Test — `tests/integration/test_traffic_replay.py`:**
- Replayed packet count matches source (within tolerance for rewrites)
- Inner PCAP packet size distribution correlates with the source's (Kolmogorov–Smirnov p > 0.05)
- Outer PCAP shows ESP only

**Verify + Commit:** `feat(traffic): add external PCAP replay generator` — **Push.**

---

## Step 2.9 — Network impairment profiles

**Goal:** stop the classifier learning your unnaturally clean lab network.

**Create `testbed/orchestrate/netem.py`:**

```python
@dataclass(frozen=True)
class ImpairmentProfile:
    name: str
    delay_ms: int
    jitter_ms: int
    loss_pct: float
    rate_mbit: int | None

PROFILES = [
    ImpairmentProfile("clean",     0,   0,  0.0,  None),
    ImpairmentProfile("lan",       1,   0,  0.0,  1000),
    ImpairmentProfile("wan_good",  20,  2,  0.1,  100),
    ImpairmentProfile("wan_poor",  80,  15, 1.0,  10),
    ImpairmentProfile("satellite", 300, 30, 2.0,  5),
]
```

**Test — `tests/integration/test_netem.py`:**
- Applying `wan_poor` raises measured RTT above 140 ms
- Removing the qdisc restores baseline RTT
- Teardown is idempotent (applying removal twice does not error)

**Verify + Commit:** `feat(testbed): add network impairment profiles` — **Push.**

---

## ▶ MILESTONE M2 — Traffic generation complete

**Run:** `make verify-all`

**Manual acceptance:** for each of the 7 generators, run one 60-second capture through a known tunnel and eyeball the inner PCAP in Wireshark's IO Graph. **The shapes must be visually distinct.** If VoIP and messaging look identical, fix the generators now — no model will separate them later.

**Confirm:**
- [ ] All 7 generators run without error
- [ ] Each produces a visually distinct traffic pattern
- [ ] Impairment profiles apply and remove cleanly
- [ ] All Phase 0 and Phase 1 tests still pass

**Tag:** `v0.3.0-traffic` and push.

---
---

# PHASE 3 — Dataset sweep and external data

---

## Step 3.1 — Single-run orchestrator

**Goal:** one function that does the complete cycle for one (config × traffic × impairment) cell.

**Create `testbed/orchestrate/runner.py`:**

```python
def run_cell(cfg: TunnelConfig, generator: TrafficGenerator,
             impairment: ImpairmentProfile, duration_s: int,
             out_dir: Path) -> RunOutcome:
    """
    1. Render configs, start containers
    2. Apply impairment
    3. Establish tunnel; abort if it fails
    4. Start dual capture
    5. Run generator
    6. Stop capture, flush
    7. Harvest ground truth
    8. Write manifest
    9. Tear down (ALWAYS, even on failure)
    """
```

**Critical:** teardown must be in a `finally` block. A leaked container or netem qdisc poisons every subsequent run in the sweep.

**Test — `tests/integration/test_runner.py`:**
- Happy path produces outer PCAP, inner PCAP, manifest
- Forced failure (invalid config) still tears down completely
- After a failed run, `docker ps -a` shows no leftover containers
- Manifest `negotiation_matched_intent` correct in both cases

**Verify + Commit:** `feat(orchestrate): add single-cell runner` — **Push.**

---

## Step 3.2 — Sweep orchestrator with resumability

**Goal:** run the full matrix, survive interruption.

**Create `testbed/orchestrate/sweep.py`:**
- Build the cell list: configs × generators × impairments × repeats
- **Write a `sweep_state.json` after every cell** recording completed cell IDs
- On restart, skip completed cells
- Parallelism: N concurrent container pairs (default 4, configurable) on distinct subnets
- Per-cell timeout; on timeout, mark failed and continue

**Test — `tests/unit/test_sweep_planning.py`:**
- Cell list length equals configs × generators × impairments × repeats
- **Balance assertion:** every generator appears with every encryption algorithm at least once — this is the automated guard against the confound trap
- Resuming from a state file with 10 completed cells yields `total - 10` remaining

**Test — `tests/integration/test_sweep_small.py`:**
- Run a 4-cell mini-sweep
- All 4 manifests written
- Kill mid-sweep, restart, confirm no cell runs twice

**Verify + Commit:** `feat(orchestrate): add resumable sweep orchestrator` — **Push.**

---

## Step 3.3 — External dataset fetcher

**Goal:** reproducible acquisition of the public datasets, with integrity checking.

**Create `scripts/fetch_external.py`:**

```python
DATASETS = {
    "cicids2017": {
        "url": "https://www.unb.ca/cic/datasets/ids-2017.html",  # manual/registration
        "kind": "pcap",
        "use": "inner payload replay (benign subset only)",
        "note": "Contains NO IPsec. Used as replay source only.",
        "manual_download": True,
    },
    "iscxvpn2016": {
        "kind": "pcap",
        "use": "comparison baseline for traffic classification",
        "note": "OpenVPN, not IPsec. Known quality issues — see docs/DATASET.md.",
        "manual_download": True,
    },
    "mawi": {
        "url": "http://mawi.wide.ad.jp/mawi/",
        "kind": "pcap",
        "use": "inner payload replay (background traffic)",
    },
    "nvd_cve": {
        "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "kind": "json_api",
        "use": "VID fingerprint -> CVE correlation",
    },
    "mitre_attack": {
        "url": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
        "kind": "json",
        "use": "technique mapping for findings",
    },
}
```

For each: download (or print manual instructions), verify SHA-256 against a recorded checksum, extract to `data/external/<name>/`, write a provenance record.

**Test — `tests/unit/test_fetch_external.py`:**
- Checksum mismatch raises and does **not** leave a partial file
- Already-present dataset is skipped
- Manual-download entries print clear instructions and exit 0
- Provenance JSON records URL, checksum, fetch timestamp

**Verify + Commit:** `feat(data): add external dataset fetcher with integrity checks` — **Push.**

---

## Step 3.4 — Dataset documentation

**Goal:** the honesty artifact. This is a scoring asset — write it properly.

**Create `docs/DATASET.md`** covering:

1. **Why we generated our own data.** State plainly: CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15, CTU-13, CICIoT2023, LANL and DARPA contain **no IKE negotiations and no ESP packets**, and carry no labels for cipher, DH group, mode or PFS. Verify this claim yourself with a script (Step 3.5) and cite your own result.
2. **How the named datasets *are* used** — benign traffic replayed as inner payload.
3. **Known limitations of ISCXVPN2016** — OpenVPN not IPsec; documented broadcast-flow contamination.
4. **Our generation methodology** — matrix, sampling, impairments, dual tap.
5. **Label provenance** — read from `swanctl --list-sas` and `ip xfrm state`, not from intent.
6. **Known biases** — lab-generated, limited implementation diversity (strongSwan/Libreswan only), synthetic think-times.
7. **The messaging proxy disclosure.**

**Verify + Commit:** `docs: add dataset methodology and limitations` — **Push.**

---

## Step 3.5 — Prove the external datasets lack IPsec

**Goal:** turn an assertion into a reproducible result you can show a panel.

**Create `scripts/audit_external_datasets.py`:**
- For each external PCAP, count packets matching `ip proto 50`, `ip proto 51`, `udp port 500`, `udp port 4500`
- Emit a table and write `docs/external_dataset_audit.md`

**Test — `tests/unit/test_dataset_audit.py`:**
- Given a fixture PCAP with known IPsec content, counts are correct
- Given a fixture with none, all counts are zero
- Handles unreadable/truncated files without crashing

**Run it on whatever external data you have and commit the generated report.** This one artifact answers the "why didn't you use our datasets?" question with evidence.

**Verify + Commit:** `feat(data): add external dataset IPsec content audit` — **Push.**

---

## Step 3.6 — Dataset packaging

**Goal:** a distributable corpus.

**Create `scripts/package_dataset.py`:**
- Validate every manifest against the schema
- Verify each referenced PCAP exists and opens
- Compute per-file checksums
- Emit `dataset/INDEX.json` with counts per class, per config, per impairment
- Emit `dataset/DATACARD.md` (following the datasheets-for-datasets pattern)

**Test — `tests/unit/test_packaging.py`:**
- Missing PCAP causes failure with a clear message
- Schema-invalid manifest causes failure
- INDEX counts match the actual file inventory

**Verify + Commit:** `feat(data): add dataset packaging and validation` — **Push.**

---

## ▶ MILESTONE M3 — Dataset complete

**Run:** `make verify-all`, then the full sweep.

**Acceptance criteria:**
- [ ] At least 24 distinct tunnel configurations captured
- [ ] All 7 traffic classes represented
- [ ] At least 3 impairment profiles used
- [ ] Every encryption algorithm appears with at least 2 DH groups (confound guard)
- [ ] Every traffic class appears with at least 3 different cipher configurations (confound guard)
- [ ] Total labelled flows ≥ 2000
- [ ] `package_dataset.py` exits 0
- [ ] `docs/external_dataset_audit.md` generated and committed
- [ ] Sweep is resumable (verified by killing and restarting)

**Run the balance report and paste it into the milestone commit message.**

**Tag:** `v0.4.0-dataset` and push.

---
---

# PHASE 4 — Deterministic IKE parser

**This is the heart of the product. Correctness matters more here than anywhere else.**

---

## Step 4.1 — Safe byte reader

**Goal:** never read past a buffer. Every parser bug in this class of software is a bounds error.

**Create `src/ipsec_sentinel/parser/reader.py`:**

```python
class SafeReader:
    def __init__(self, data: bytes) -> None: ...
    def u8(self) -> int: ...
    def u16(self) -> int: ...
    def u32(self) -> int: ...
    def bytes(self, n: int) -> bytes: ...
    def remaining(self) -> int: ...
    def sub(self, n: int) -> "SafeReader": ...   # bounded child reader

class TruncatedError(Exception): ...
```

Every method raises `TruncatedError` on insufficient data. **Never** returns partial or padded results.

**Test — `tests/unit/test_reader.py`:**
- Reading past the end raises `TruncatedError`
- `sub(n)` cannot read beyond its bound even if the parent has more data
- **Property test (hypothesis):** for arbitrary bytes and arbitrary read sequences, the reader either returns correct values or raises `TruncatedError` — it never raises anything else and never returns wrong-length data

**Verify + Commit:** `feat(parser): add bounds-safe byte reader` — **Push.**

---

## Step 4.2 — IKE header parser

**Goal:** parse the fixed 28-byte header.

**Create `src/ipsec_sentinel/parser/ike.py`:**

```python
def parse_ike_header(data: bytes) -> IKEHeader:
    """
    Initiator SPI  8 bytes
    Responder SPI  8 bytes
    Next Payload   1
    Version        1   (high nibble = major)
    Exchange Type  1
    Flags          1
    Message ID     4
    Length         4
    """
```

**Test — `tests/unit/test_ike_header.py`:**
- Version 0x20 → "IKEv2", 0x10 → "IKEv1"
- Exchange type 34 with IKEv2 → "IKE_SA_INIT"; type 4 with IKEv1 → "Aggressive Mode"
- Flags decode: initiator bit, response bit, version bit
- Length field shorter than 28 → `MalformedError`
- Length field longer than actual data → `TruncatedError`
- Header of 27 bytes → `TruncatedError`
- Unknown version → parsed but flagged `unknown_version=True`, no exception

**Verify + Commit:** `feat(parser): add IKE header parser` — **Push.**

---

## Step 4.3 — Payload chain walker

**Goal:** traverse the linked list of payloads without infinite loops.

**Add to `ike.py`:**

```python
def walk_payloads(reader: SafeReader, first_type: int) -> Iterator[RawPayload]:
    """Generic payload header: next(1), critical+reserved(1), length(2)."""
```

**Guards that must exist:**
- Payload length < 4 → stop, record error
- Payload count > 64 → stop, record error (loop guard)
- Cumulative length exceeding the message length → stop

**Test — `tests/unit/test_payload_walk.py`:**
- Three chained payloads yield 3 items in order
- Zero-length payload does not loop forever
- Self-referencing/oversized chain terminates within the guard limit
- **Property test:** for arbitrary bytes, `walk_payloads` always terminates and never raises an unexpected exception

**This test is non-negotiable.** A parser that hangs on hostile input is a denial-of-service vector.

**Verify + Commit:** `feat(parser): add payload chain walker with loop guards` — **Push.**

---

## Step 4.4 — Transform parser with attributes

**Goal:** parse to the **attribute** level, so AES-128 and AES-256 are distinguishable.

**Add to `ike.py`:**

```python
def parse_transform(r: SafeReader) -> Transform:
    """
    last(1) reserved(1) length(2) type(1) reserved(1) id(2) [attributes...]
    Attribute: AF|type (2), then either value (2) if AF=1, or length(2)+value(n) if AF=0
    Key length attribute type = 14
    """
```

**Test — `tests/unit/test_transform.py`:**
- ENCR/12 with key-length attribute 256 → `ENCR_AES_CBC`, `key_length=256`
- ENCR/12 with no attribute → `key_length=None`
- ENCR/20 (AES-GCM-16) with key length 256
- INTEG/0 → "NONE"
- DH/2 → group 2, and helper reports 1024 bits
- Unknown transform ID → `UNKNOWN_ENCR_99`, no exception
- Both attribute formats (TV and TLV) parse correctly
- Truncated attribute → `TruncatedError`

**Verify + Commit:** `feat(parser): add transform parser with attribute support` — **Push.**

---

## Step 4.5 — Proposal and SA payload parser

**Goal:** extract **every** proposal, not just the accepted one.

**Add to `ike.py`:**

```python
def parse_proposal(r: SafeReader) -> Proposal: ...
def parse_sa_payload(r: SafeReader) -> list[Proposal]: ...
```

**Test — `tests/unit/test_sa_payload.py`:**
- A 3-proposal SA payload yields exactly 3 proposals
- Each proposal's transforms are correctly grouped
- Proposal numbers are preserved
- SPI-size handling: 0 for IKE SA, 4 for ESP child SA
- Last-proposal flag terminates iteration correctly
- **The weak/strong fixtures from Step 0.8 parse to the expected values**

**Verify + Commit:** `feat(parser): add proposal and SA payload parser` — **Push.**

---

## Step 4.6 — KE, Nonce, Notify, Vendor ID payloads

**Add to `ike.py`:**

- `parse_ke_payload` → DH group field + public value; derive length and **cross-check** against the transform's declared group. Mismatch → warning, not exception.
- `parse_nonce_payload` → length only
- `parse_notify_payload` → protocol, SPI size, notify type; resolve to name. **Extract the responder's preferred group from `INVALID_KE_PAYLOAD`** — that is free intelligence.
- `parse_vendor_id_payload` → raw bytes + hex

**Test — `tests/unit/test_other_payloads.py`:**
- KE group matching transform → no warning
- KE group mismatching transform → warning recorded, both values retained
- `NAT_DETECTION_SOURCE_IP` notify resolved by name
- `INVALID_KE_PAYLOAD` yields the responder's preferred group number
- Unknown notify type → `UNKNOWN_NOTIFY_<n>`
- Vendor ID hex is lowercase and stable

**Verify + Commit:** `feat(parser): add KE, nonce, notify and vendor ID parsers` — **Push.**

---

## Step 4.7 — IKEv1 support

**Goal:** IKEv1 differs enough to need its own path — and Aggressive Mode is your highest-value finding.

**Create `src/ipsec_sentinel/parser/ikev1.py`:**
- IKEv1 payload type numbering differs from IKEv2 — use a separate table
- IKEv1 SA payload has DOI and Situation fields before proposals
- IKEv1 transform attributes are all TV/TLV encoded (no fixed transform IDs in the v2 sense)
- **Detect Aggressive Mode** from exchange type 4
- **Detect PSK auth** from the auth-method attribute

**Test — `tests/unit/test_ikev1.py`:**
- Main Mode (type 2) parses
- Aggressive Mode (type 4) parses and sets `is_aggressive=True`
- Aggressive + PSK sets `psk_hash_exposed=True`
- IKEv1 DOI/Situation fields consumed correctly before proposals
- IKEv1 transform attributes (encryption, hash, group, auth method, lifetime) all extracted

**Verify + Commit:** `feat(parser): add IKEv1 parsing with aggressive mode detection` — **Push.**

---

## Step 4.8 — PCAP ingestion

**Goal:** go from a file to a list of `IKEExchange` objects.

**Create `src/ipsec_sentinel/parser/pcap.py`:**

```python
def extract_ike_exchanges(pcap: Path) -> list[IKEExchange]:
    """
    UDP 500  -> IKE directly
    UDP 4500 -> check 4-byte non-ESP marker (0x00000000) before IKE
    """
```

**The NAT-T marker is a common bug source.** On port 4500, four zero bytes precede IKE; if the first four bytes are non-zero it is ESP-over-UDP, not IKE. Test both.

**Test — `tests/unit/test_pcap_ingest.py`:**
- Fixture PCAP on port 500 yields the expected exchange count
- Fixture on port 4500 with the marker parses as IKE
- ESP-over-UDP on 4500 is **not** misparsed as IKE
- Corrupt PCAP raises a clear error, not a Scapy traceback
- Empty PCAP returns an empty list

**Verify + Commit:** `feat(parser): add PCAP ingestion for IKE` — **Push.**

---

## Step 4.9 — Fuzzing the parser

**Goal:** prove the parser cannot be crashed. **Do not skip this step.**

**Create `tests/unit/test_parser_fuzz.py`** using hypothesis:

```python
@given(st.binary(min_size=0, max_size=4096))
def test_parser_never_crashes(data: bytes) -> None:
    try:
        parse_ike_message(data)
    except (TruncatedError, MalformedError):
        pass          # acceptable
    # any other exception fails the test
```

Also fuzz with **structured mutations**: take a valid message and flip random bytes, truncate at random offsets, and inflate length fields.

**Add a timeout assertion:** no input may take more than 1 second to parse.

**Test acceptance:**
- 10,000 random inputs produce zero unexpected exceptions
- Structured mutation of the valid fixtures produces zero unexpected exceptions
- No input exceeds the time limit

**Verify + Commit:** `test(parser): add fuzzing for crash and hang resistance` — **Push.**

---

## Step 4.10 — Validate against Wireshark

**Goal:** independent confirmation that your parser is right.

**Create `scripts/compare_with_tshark.py`:**
- Run `tshark -r <pcap> -Y isakmp -T json` (remember: the filter is `isakmp`, not `ike`)
- Parse the same file with your parser
- Compare: version, exchange type, transform IDs, DH groups, key lengths
- Report any discrepancy

**Test — `tests/integration/test_tshark_parity.py`:**
- For every PCAP in the dataset, your parser and tshark agree on version, exchange type, and every transform
- Any mismatch fails the test with a detailed diff

**This is your strongest correctness evidence and a good demo slide.**

**Verify + Commit:** `test(parser): add tshark parity validation` — **Push.**

---

## ▶ MILESTONE M4 — Parser complete

**Run:** `make verify-all`

**Acceptance:**
- [ ] Parses 100% of dataset PCAPs without unhandled exceptions
- [ ] Agrees with tshark on every field compared, across the whole dataset
- [ ] Fuzzing: 10,000 inputs, zero crashes, zero hangs
- [ ] IKEv1 Aggressive Mode detected in the `worst` anchor config
- [ ] Key length correctly distinguishes AES-128 from AES-256
- [ ] **All proposals extracted, not just accepted** — verify on a multi-proposal capture
- [ ] Coverage of `parser/` above 90%

**Tag:** `v0.5.0-parser` and push.

---
---
# PHASE 5 — ESP analysis

---

## Step 5.1 — ESP header parser

**Create `src/ipsec_sentinel/parser/esp.py`:**

```python
def parse_esp_header(data: bytes) -> ESPHeader:
    """SPI (4 bytes), Sequence Number (4 bytes). Rest is opaque."""
```

**Test — `tests/unit/test_esp_header.py`:**
- SPI extracted as lowercase hex
- Sequence number is big-endian
- 7-byte input raises `TruncatedError`
- **Explicit test that the ESP SPI (4 bytes) is not confused with the IKE SPI (8 bytes)** — different types in the model

**Verify + Commit:** `feat(parser): add ESP header parser` — **Push.**

---

## Step 5.2 — Flow assembly

**Goal:** group ESP packets into per-SA flows.

**Add to `esp.py`:**

```python
def assemble_esp_flows(packets: Iterable[ESPPacket]) -> list[ESPFlow]:
    """Key on (src_ip, dst_ip, spi). Each direction is a separate SA."""
```

Record: packet count, byte count, first/last seen, size list, timestamp list.

**Test — `tests/unit/test_esp_flows.py`:**
- Two SPIs produce two flows
- Bidirectional traffic produces two flows (one per direction), correctly paired
- Flow byte count matches sum of packet sizes
- Empty input returns empty list

**Verify + Commit:** `feat(parser): add ESP flow assembly` — **Push.**

---

## Step 5.3 — Sequence number and replay analysis

**Goal:** detect loss, reordering, and replay — a real security finding.

**Add to `esp.py`:**

```python
def analyse_sequence(flow: ESPFlow) -> SequenceAnalysis:
    """
    gaps:        missing sequence numbers (loss)
    reorders:    out-of-order arrivals within a window
    duplicates:  same sequence seen twice  -> REPLAY SUSPECTED
    wraps:       32-bit counter rollover
    """
```

**Test — `tests/unit/test_sequence.py`:**
- Perfect sequence 1..100 → zero gaps, zero duplicates
- Missing 50 → one gap of size 1
- Duplicate 50 → `replay_suspected=True`
- Sequence 1,3,2,4 → one reorder, zero gaps
- Wrap from 0xFFFFFFFF to 0 handled as a wrap, not a massive gap
- **Impairment cross-check:** flows captured under the `wan_poor` profile show gaps; `clean` profile flows show none. This validates the analyser against known ground truth.

**Verify + Commit:** `feat(parser): add ESP sequence and replay analysis` — **Push.**

---

## Step 5.4 — Tunnel correlation

**Goal:** link an IKE negotiation to the ESP flows it produced.

**Create `src/ipsec_sentinel/parser/correlate.py`:**

```python
def correlate(exchanges: list[IKEExchange],
              flows: list[ESPFlow]) -> list[Tunnel]:
    """
    Match on endpoint pair + temporal ordering
    (ESP flows begin after the IKE exchange that created them).
    Unmatched flows -> orphan tunnels (still assessed, but flagged).
    """
```

**Orphan flows are a feature, not an error.** ESP seen with no preceding IKE means either the negotiation happened before capture started, or the tunnel is long-lived. Both are worth reporting.

**Test — `tests/unit/test_correlate.py`:**
- One IKE + two ESP flows (bidirectional) → one tunnel
- Two IKE exchanges between the same pair → two tunnels, temporally distinct
- ESP with no IKE → orphan tunnel with `ike=None`
- IKE with no ESP → tunnel flagged `negotiation_only` (failed or idle)

**Verify + Commit:** `feat(parser): add IKE-to-ESP tunnel correlation` — **Push.**

---

## Step 5.5 — Tunnel inventory

**Goal:** the feature that delivers value in hour four. Build it early.

**Create `src/ipsec_sentinel/assess/inventory.py`:**

```python
def build_inventory(tunnels: list[Tunnel],
                    known: list[KnownTunnel] | None = None) -> Inventory:
    """
    Every observed tunnel: endpoints, first seen, last seen,
    volume, IKE version, negotiated suite.
    If a known-tunnel list is supplied, flag anything not in it as UNDOCUMENTED.
    """
```

**Test — `tests/unit/test_inventory.py`:**
- Inventory count matches distinct tunnels
- With a known list of 3 and 5 observed → 2 flagged undocumented
- With no known list → nothing flagged, all listed
- Endpoints normalised (IPv6 canonical form, consistent ordering)

**Verify + Commit:** `feat(assess): add tunnel inventory with undocumented detection` — **Push.**

---

## ▶ MILESTONE M5 — ESP analysis complete

**Acceptance:**
- [ ] All dataset PCAPs produce correlated tunnels
- [ ] Sequence analysis matches known impairment levels
- [ ] Inventory correctly flags a synthetic undocumented tunnel
- [ ] All earlier tests still pass

**Tag:** `v0.6.0-esp` and push.

---
---

# PHASE 6 — Assessment engine

---

## Step 6.1 — Rule framework

**Create `src/ipsec_sentinel/assess/framework.py`:**

```python
class Rule(Protocol):
    id: str
    title: str
    severity: Severity
    standard_ref: str
    attack_technique: str | None
    baselines: list[str]      # which baselines include this rule

    def evaluate(self, tunnel: Tunnel) -> Finding | None: ...

class RuleRegistry:
    def register(self, rule: Rule) -> None: ...
    def evaluate_all(self, tunnel: Tunnel,
                     baseline: str) -> list[Finding]: ...
```

**Every rule must produce a `Finding` with `confidence=None`** — these are deterministic.

**Test — `tests/unit/test_rule_framework.py`:**
- Duplicate rule ID raises on registration
- Baseline filtering returns only rules for that baseline
- A rule that raises is caught, logged, and does not abort the run
- All findings from rules have `confidence is None`

**Verify + Commit:** `feat(assess): add rule framework` — **Push.**

---

## Step 6.2 — Cryptographic strength rules (CRY-01 to CRY-10)

**Create `src/ipsec_sentinel/assess/rules/crypto.py`:**

| ID | Check | Severity |
|---|---|---|
| CRY-01 | DH group 1 | Critical |
| CRY-02 | DH group 2 | Critical |
| CRY-03 | DH group 5 | High |
| CRY-04 | DES | Critical |
| CRY-05 | 3DES | Critical |
| CRY-06 | MD5 integrity | High |
| CRY-07 | SHA-1 integrity | High |
| CRY-08 | CBC with integrity NONE | High |
| CRY-09 | Key length < 128 | High |
| CRY-10 | AES-128 where baseline requires 256 | Medium |

**Each rule must check every offered proposal, not just the accepted one**, and say so in the evidence string ("offered in proposal 3 of 3, not selected in this session").

**Test — `tests/unit/test_crypto_rules.py`:**
One test per rule, each with a positive and a negative case. Plus:
- Weak fixture triggers CRY-02, CRY-05, CRY-06
- Strong fixture triggers none of CRY-01..CRY-09
- A tunnel where 3DES is *offered but not accepted* still triggers CRY-05 with the fallback evidence wording

**Verify + Commit:** `feat(assess): add cryptographic strength rules` — **Push.**

---

## Step 6.3 — IKE configuration rules (IKE-01 to IKE-04)

**Create `src/ipsec_sentinel/assess/rules/ike.py`:**

| ID | Check | Severity |
|---|---|---|
| IKE-01 | IKEv1 in use | Medium |
| IKE-02 | Aggressive Mode | High |
| IKE-03 | Aggressive Mode + PSK | **Critical** |
| IKE-04 | Weak proposal offered but not selected | Medium |

IKE-03's evidence must state: *"The pre-shared key hash is exposed to any passive observer and can be cracked offline. Treat this PSK as compromised."*

**Test:** each rule positive/negative; IKE-03 supersedes IKE-02 (only the critical one fires, not both).

**Verify + Commit:** `feat(assess): add IKE configuration rules` — **Push.**

---

## Step 6.4 — Forward secrecy and SA rules (PFS-01 to SA-04)

**Create `src/ipsec_sentinel/assess/rules/sa.py`:**

| ID | Check | Severity |
|---|---|---|
| PFS-01 | PFS disabled | High |
| PFS-02 | Child DH group weaker than IKE DH group | Medium |
| SA-01 | IKE SA lifetime > 24h | Medium |
| SA-02 | Child SA lifetime > 8h | Low |
| SA-03 | Anti-replay disabled | Medium |
| SA-04 | Replay window < 64 | Low |

**Test:** each rule; plus SA-03 fires when `analyse_sequence` reports duplicates with no rejection.

**Verify + Commit:** `feat(assess): add forward secrecy and SA lifetime rules` — **Push.**

---

## Step 6.5 — PQC readiness rules

**Create `src/ipsec_sentinel/assess/rules/pqc.py`:**

```python
def grade_pqc(tunnel: Tunnel) -> PQCGrade:
    """
    EXPOSED      : classical DH only AND PFS off  -> past traffic retroactively at risk
    AT_RISK      : classical DH only, PFS on      -> future traffic at risk
    TRANSITIONAL : RFC 8784 post-quantum PSK in use
    READY        : RFC 9370 additional key exchange with ML-KEM
    """
```

Detect RFC 9370 via additional key-exchange transform types (ADDKE1..ADDKE7) and ML-KEM group IDs.

**Test — `tests/unit/test_pqc_rules.py`:**
- Classical DH + no PFS → EXPOSED
- Classical DH + PFS → AT_RISK
- ML-KEM hybrid transform present → READY
- Grade ordering is total and stable

**Verify + Commit:** `feat(assess): add post-quantum readiness grading` — **Push.**

---

## Step 6.6 — Compliance baselines

**Create `src/ipsec_sentinel/assess/baselines/`** as YAML:

- `nist_800_77r1.yaml`
- `rfc_8221_8247.yaml`
- `cnsa.yaml`
- `bsi_tr02102_3.yaml`
- **`itsar.yaml`** — the Indian differentiator
- **`certin.yaml`**
- `custom.yaml.example`

Each declares: which rule IDs apply, severity overrides, and minimum acceptable values.

**Test — `tests/unit/test_baselines.py`:**
- Every baseline YAML validates against the schema
- Every referenced rule ID exists in the registry
- The same tunnel graded against CNSA and NIST produces **different** results (proves baselines are actually differentiated, not copies)
- ITSAR baseline is loadable and references at least 15 rules

**Verify + Commit:** `feat(assess): add compliance baselines including ITSAR and CERT-In` — **Push.**

---

## Step 6.7 — Scoring and grading

**Create `src/ipsec_sentinel/assess/scoring.py`:**

```python
SEVERITY_WEIGHTS = {CRITICAL: 40, HIGH: 20, MEDIUM: 8, LOW: 3, INFO: 0}

def score_tunnel(findings: list[Finding]) -> tuple[int, str]:
    """Start at 100, subtract weights, floor at 0. Map to A-F."""

def score_estate(tunnels: list[TunnelAssessment]) -> EstateScore:
    """Weighted by tunnel criticality if supplied; else mean."""
```

**Document the weighting choice in a docstring and in `docs/SCORING.md`.** A panel may ask why 40 and not 50 — have an answer.

**Test — `tests/unit/test_scoring.py`:**
- No findings → 100, grade A
- One critical → 60, grade D
- Three criticals → 0 (floored), grade F
- Score is monotonic: adding a finding never increases the score
- Estate score of one tunnel equals that tunnel's score

**Verify + Commit:** `feat(assess): add scoring and grading` — **Push.**

---

## Step 6.8 — MITRE ATT&CK and CVE enrichment

**Create `src/ipsec_sentinel/assess/enrich.py`:**

- Load the ATT&CK JSON fetched in Step 3.3; resolve technique IDs to names and URLs
- **VID → product/version fingerprint** (seed the table from ike-scan's fingerprint list)
- Product/version → NVD CVE query, **cached locally** so the tool works offline

**Test — `tests/unit/test_enrich.py`:**
- Known VID hash resolves to the expected vendor
- Unknown VID returns `None`, no exception
- T1040 resolves to "Network Sniffing"
- CVE lookup uses cache when offline and does not raise
- Cache is written atomically (no partial JSON on interrupt)

**Verify + Commit:** `feat(assess): add ATT&CK and CVE enrichment` — **Push.**

---

## Step 6.9 — Configuration anomaly detection

**Goal:** find the odd one out that violates no rule. This is Tier 2 AI.

**Create `src/ipsec_sentinel/assess/anomaly.py`:**

```python
def detect_config_anomalies(tunnels: list[Tunnel],
                            min_estate_size: int = 10) -> list[Finding]:
    """
    Encode each tunnel's config as a feature vector.
    IsolationForest over the estate.
    Outliers -> Finding(severity=INFO, confidence=<score>).
    Returns [] if the estate is too small to have a meaningful baseline.
    """
```

**These findings carry a confidence** because they are inferred, unlike every rule-based finding.

**Test — `tests/unit/test_anomaly.py`:**
- 40 identical configs + 1 different → exactly 1 anomaly flagged
- 40 identical configs → zero anomalies
- Estate of 5 → returns empty (below `min_estate_size`)
- All returned findings have `confidence is not None`

**Verify + Commit:** `feat(assess): add configuration anomaly detection` — **Push.**

---

## ▶ MILESTONE M6 — Assessment engine complete

**Acceptance:**
- [ ] All 26 rules implemented and individually tested
- [ ] `worst` anchor config scores below 25 with grade F
- [ ] `best` anchor config scores above 90 with grade A
- [ ] Every baseline loads and produces differentiated results
- [ ] PQC grading correct for all four grades
- [ ] Anomaly detection finds the planted outlier
- [ ] **Every rule-based finding has `confidence is None`** — assert this globally in a test
- [ ] Coverage of `assess/` above 90%

**Tag:** `v0.7.0-assessment` and push.

---
---

# PHASE 7 — Feature extraction and ML

---

## Step 7.1 — Flow feature extractor

**Create `src/ipsec_sentinel/features/flow.py`:**

Per flow window, compute:

| Group | Features |
|---|---|
| Volume | packet count, byte count, duration, bytes/sec, packets/sec |
| Size | mean, std, min, max, median, p25, p75, p90 |
| Size (directional) | same stats for forward and backward separately |
| Timing | IAT mean, std, min, max, median, p90 |
| Direction | fwd/bwd packet ratio, fwd/bwd byte ratio |
| Burst | burst count, mean burst size, mean idle duration, max idle |
| Shape | fraction of packets at MTU, fraction below 100 bytes, size entropy |

**Design rule:** the feature vector must be **deterministic and order-independent** given the same packet list. Test this.

**Test — `tests/unit/test_features.py`:**
- Known packet list produces hand-computed expected values
- Empty flow returns zeros, not NaN
- Single-packet flow does not divide by zero
- Feature vector length is constant across all inputs
- **Determinism: same input twice → identical vector (exact float equality)**
- Feature names list matches vector length

**Verify + Commit:** `feat(features): add flow feature extraction` — **Push.**

---

## Step 7.2 — Dataset assembly for ML

**Create `src/ipsec_sentinel/features/dataset.py`:**

```python
def build_ml_dataset(manifests: list[Manifest],
                     window_s: int = 30) -> pd.DataFrame:
    """
    One row per (flow, window).
    Columns: features + labels (inner_traffic, mode, cipher, dh_group, pfs)
             + grouping keys (capture_id, config_id).
    """
```

**The grouping keys are essential** — they drive leakage-free splitting in the next step.

**Test — `tests/unit/test_ml_dataset.py`:**
- Row count matches expected windows
- No NaN in any feature column
- Every row has a `capture_id` and `config_id`
- Label distribution matches the manifest inventory

**Verify + Commit:** `feat(features): add ML dataset assembly` — **Push.**

---

## Step 7.3 — Leakage-free splitting

**Goal:** the step that makes or breaks your credibility.

**Create `src/ipsec_sentinel/ml/split.py`:**

```python
def split_by_capture(df, test_frac=0.2, seed=42) -> tuple[DataFrame, DataFrame]:
    """GroupShuffleSplit on capture_id. No capture spans both sides."""

def split_by_config(df, holdout_configs: list[str]) -> tuple[DataFrame, DataFrame]:
    """Hold out entire configurations — the generalisation test."""

def split_by_dh_group(df, train_groups, test_groups) -> tuple[DataFrame, DataFrame]:
    """Train on some DH groups, test on unseen ones."""
```

**Test — `tests/unit/test_split.py`:**
- **Assert zero `capture_id` overlap between train and test** — this is the critical assertion
- Config split: held-out config IDs appear only in test
- DH group split: test contains only the specified groups
- Splits are reproducible with a fixed seed
- Both splits are non-empty

**Verify + Commit:** `feat(ml): add leakage-free dataset splitting` — **Push.**

---

## Step 7.4 — Baseline heuristic for mode inference

**Goal:** establish the bar the model must beat. Do this *before* training anything.

**Create `src/ipsec_sentinel/ml/heuristic.py`:**

```python
def infer_mode_heuristic(flow_features: dict) -> tuple[str, float]:
    """
    Tunnel mode adds 20 bytes (IPv4) / 40 (IPv6) per packet.
    If median ESP payload ~= MTU - overhead_tunnel -> tunnel.
    Returns (mode, crude_confidence).
    """
```

**Test — `tests/unit/test_heuristic.py`:**
- Synthetic tunnel-mode sizes → "tunnel"
- Synthetic transport-mode sizes → "transport"
- Ambiguous sizes → low confidence
- **Record the heuristic's accuracy on the real dataset and commit it to `docs/BASELINES.md`.** Your model must beat this number or the ML lane is not justified.

**Verify + Commit:** `feat(ml): add heuristic baseline for mode inference` — **Push.**

---

## Step 7.5 — Traffic classifier training

**Create `src/ipsec_sentinel/ml/train.py`:**

- Random forest and XGBoost, compared
- Stratified group cross-validation using `capture_id` as the group
- Report: accuracy, macro-F1, per-class precision/recall, confusion matrix
- Persist model + feature names + training metadata (dataset checksum, git SHA, timestamp)

**Test — `tests/unit/test_train.py`:**
- Training on a small synthetic set converges above 90% (sanity check on the pipeline, not a claim)
- Saved model reloads and predicts identically
- Metadata records the dataset checksum
- Training with a single class raises a clear error

**Verify + Commit:** `feat(ml): add traffic classifier training` — **Push.**

---

## Step 7.6 — The generalisation test

**Goal:** the honest result that wins credibility. **Do not skip or soften this.**

**Create `scripts/generalisation_report.py`:**

Run and record four evaluations:

| Split | What it tests |
|---|---|
| Random flow split | Optimistic upper bound (leaky — report as such) |
| Capture-level split | Realistic in-distribution performance |
| Held-out configuration | Generalisation to unseen crypto settings |
| Held-out DH groups | Generalisation to unseen key exchange |

Write `docs/GENERALISATION.md` with all four numbers and an honest interpretation of the gap.

**Test — `tests/unit/test_generalisation_report.py`:**
- Report generates all four splits
- Report includes the confusion matrix per split
- The document is written even when performance is poor (no silent suppression of bad results)

**Expected outcome:** accuracy will drop on the held-out splits. **That is the finding.** Report it.

**Verify + Commit:** `feat(ml): add generalisation evaluation across split strategies` — **Push.**

---

## Step 7.7 — Confidence calibration

**Create `src/ipsec_sentinel/ml/calibrate.py`:**

- `CalibratedClassifierCV` with isotonic or Platt scaling
- Compute Expected Calibration Error before and after
- Produce a reliability diagram

**Test — `tests/unit/test_calibration.py`:**
- ECE after calibration is lower than before
- Calibrated probabilities sum to 1
- Reliability diagram data has the expected bin count
- **Assert calibrated ECE below 0.15** — if it fails, the model's confidence is not trustworthy and must not be shown to users

**Verify + Commit:** `feat(ml): add confidence calibration` — **Push.**

---

## Step 7.8 — Abstention

**Create `src/ipsec_sentinel/ml/predict.py`:**

```python
def predict_with_abstention(model, features, threshold: float = 0.6) -> Prediction:
    """Below threshold -> class='insufficient_signal', abstained=True."""
```

**Test — `tests/unit/test_abstention.py`:**
- High-confidence input returns a class
- Low-confidence input abstains
- Abstained predictions set `Confidence.abstained=True`
- Abstention rate on the test set is reported and reasonable (under 25%)

**Verify + Commit:** `feat(ml): add prediction abstention` — **Push.**

---

## Step 7.9 — SHAP explanations

**Create `src/ipsec_sentinel/ml/explain.py`:**

```python
def explain_prediction(model, features) -> Explanation:
    """Top-5 contributing features with signed SHAP values,
       rendered as a human-readable sentence."""
```

Target output: *"Classified as VoIP because 91% of packets fall in a 20-byte band (contribution +0.34) at consistent 20 ms intervals (contribution +0.28)."*

**Test — `tests/unit/test_explain.py`:**
- Explanation returns exactly 5 features
- SHAP values sum approximately to (prediction − base value)
- Human-readable sentence contains real feature names, not indices
- Explanation generation does not exceed 2 seconds per prediction

**Verify + Commit:** `feat(ml): add SHAP explanations for predictions` — **Push.**

---

## Step 7.10 — Confound audit

**Goal:** prove the classifier is reading traffic shape, not cipher artifacts.

**Create `scripts/confound_audit.py`:**

1. Report classification accuracy **conditioned on cipher** — if accuracy varies wildly by cipher, the model is cipher-dependent
2. Train a deliberate "cipher-from-ESP-sizes" classifier — measure how learnable cipher is from packet sizes alone (this is a **legitimate finding** about AES-CBC padding)
3. Report mutual information between predicted class and cipher

Write `docs/CONFOUND_AUDIT.md`.

**Test — `tests/unit/test_confound_audit.py`:**
- Audit runs on the dataset and produces all three metrics
- Report is written even when results are unfavourable

**This document is a strong differentiator.** Almost no team will do it.

**Verify + Commit:** `feat(ml): add confound audit for cipher leakage` — **Push.**

---

## ▶ MILESTONE M7 — ML lane complete

**Acceptance:**
- [ ] Traffic classifier trained with capture-level splitting
- [ ] **Zero capture_id overlap between train and test** (assert in CI)
- [ ] Generalisation report published with all four splits
- [ ] Model beats the heuristic baseline for mode inference
- [ ] ECE below 0.15 after calibration
- [ ] Abstention working, rate under 25%
- [ ] SHAP explanations render as readable sentences
- [ ] Confound audit published
- [ ] **Every ML-derived finding carries a non-None confidence** (assert globally)

**Tag:** `v0.8.0-ml` and push.

---
---

# PHASE 8 — Remediation

---

## Step 8.1 — Remediation model

**Create `src/ipsec_sentinel/remediate/models.py`:**

```python
class ChangePackage(BaseModel):
    tunnel_id: str
    findings_addressed: list[str]
    local_config: DeviceConfig      # BOTH ends
    peer_config: DeviceConfig       # are mandatory
    sequence: list[ChangeStep]      # ordered, zero-downtime
    verification: list[str]
    rollback: list[str]
    blast_radius: BlastRadius
    requires_maintenance_window: bool
```

**Validator:** a `ChangePackage` **cannot** be constructed without both `local_config` and `peer_config`. Enforce it in the model, not in a comment.

**Test — `tests/unit/test_remediation_models.py`:**
- Constructing without `peer_config` raises `ValidationError`
- Empty `sequence` raises
- Empty `rollback` raises

**Verify + Commit:** `feat(remediate): add change package model with both-ends enforcement` — **Push.**

---

## Step 8.2 — strongSwan config generator

**Create `src/ipsec_sentinel/remediate/generators/strongswan.py`:**

Emit valid `swanctl.conf` implementing the corrected proposal.

**Test — `tests/unit/test_gen_strongswan.py`:**
- Generated proposal string is syntactically valid
- AEAD ciphers omit the integrity algorithm
- PFS produces an `esp_proposals` DH group
- **Round-trip test:** feed the generated config back into `config_gen.TunnelConfig` parsing and confirm it describes the intended settings

**Test — `tests/integration/test_gen_strongswan_live.py`:**
- **Deploy the generated config to a live testbed pair and confirm the tunnel establishes.** This is the only proof that matters.

**Verify + Commit:** `feat(remediate): add strongSwan config generator` — **Push.**

---

## Step 8.3 — Additional vendor generators

Create generators for: Libreswan (`ipsec.conf`), Cisco IOS/ASA (`crypto ikev2 proposal`), FortiGate (`config vpn ipsec phase1-interface`), Juniper SRX, Palo Alto.

**Test:** syntax validation per vendor against a grammar or regex suite; snapshot tests against known-good reference configs.

**Note:** only strongSwan and Libreswan can be live-tested in your testbed. **Mark the others clearly as "syntax-validated, not deployment-tested"** in the output and in the docs. Do not overclaim.

**Verify + Commit (one per vendor):** `feat(remediate): add <vendor> config generator` — **Push after each.**

---

## Step 8.4 — Zero-downtime sequencing

**Goal:** the operational detail that proves you understand IPsec.

**Create `src/ipsec_sentinel/remediate/sequence.py`:**

```python
def build_sequence(current: Proposal, target: Proposal) -> list[ChangeStep]:
    """
    1. Add target proposal ALONGSIDE current, on BOTH ends
    2. Verify negotiation now selects target
    3. Remove the weak proposal from BOTH ends
    4. Verify tunnel still established
    """
```

**Test — `tests/unit/test_sequence.py`:**
- Sequence has exactly 4 steps
- Step 1 config contains **both** proposals
- Step 3 config contains **only** the target
- Every step names which end it applies to
- Sequence never has a state where the two ends share no common proposal — **assert this explicitly by simulating each intermediate state**

**Test — `tests/integration/test_sequence_live.py`:**
- Execute the full sequence on a live testbed pair
- **Ping continuously throughout and assert zero packet loss**

That last assertion is the demo moment. Make it work.

**Verify + Commit:** `feat(remediate): add zero-downtime change sequencing` — **Push.**

---

## Step 8.5 — Blast radius assessment

**Create `src/ipsec_sentinel/remediate/blast.py`:**

Estimate: traffic volume affected, inferred application types (so "carries VoIP" is a warning), peak usage hours from observed traffic, and a suggested maintenance window.

**Test:** high-volume tunnel → `requires_maintenance_window=True`; idle tunnel → False; window suggestion falls in the observed low-traffic period.

**Verify + Commit:** `feat(remediate): add blast radius assessment` — **Push.**

---

## Step 8.6 — Automatic fix verification

**Goal:** close the loop from observed evidence.

**Create `src/ipsec_sentinel/remediate/verify.py`:**

```python
def verify_remediation(tunnel_id: str, expected: Proposal,
                       new_exchanges: list[IKEExchange]) -> VerificationResult:
    """Watch for the next negotiation. If it matches target -> auto-close."""
```

**Test — `tests/unit/test_verify.py`:**
- New exchange matching target → `verified=True`, finding closed
- New exchange still weak → `verified=False`, finding stays open
- No new exchange within the SA lifetime → `pending`

**Test — `tests/integration/test_verify_live.py`:**
- Apply a fix, force a rekey, confirm the finding auto-closes

**Verify + Commit:** `feat(remediate): add automatic fix verification from traffic` — **Push.**

---

## ▶ MILESTONE M8 — Remediation complete

**Acceptance:**
- [ ] Both-ends configs generated for every finding type
- [ ] strongSwan and Libreswan configs deploy successfully live
- [ ] Zero-downtime sequence verified with **zero packet loss** during the change
- [ ] Non-testbed vendors clearly marked as syntax-only
- [ ] Auto-verification closes a finding after a live rekey
- [ ] **The tool never executes a change** — assert no code path calls a device write API

**Tag:** `v0.9.0-remediation` and push.

---
---
# PHASE 9 — Reporting

---

## Step 9.1 — Report data model

**Create `src/ipsec_sentinel/report/models.py`:**

```python
class Report(BaseModel):
    metadata: ReportMetadata        # source, timestamp, tool version, git SHA
    executive: ExecutiveSummary
    inventory: Inventory
    section_a_verified: list[Finding]    # confidence is None  -> compliance-grade
    section_b_inferred: list[Finding]    # confidence not None -> intelligence
    metadata_exposure: MetadataExposure
    threat_matrix: ThreatMatrix
    remediation: list[ChangePackage]
    pqc: PQCSummary
```

**The Section A / Section B split is the intellectual centre of the product. Enforce it in a validator:**

```python
@model_validator(mode="after")
def enforce_separation(self):
    assert all(f.confidence is None for f in self.section_a_verified)
    assert all(f.confidence is not None for f in self.section_b_inferred)
    return self
```

**Test — `tests/unit/test_report_models.py`:**
- A finding with confidence placed in Section A raises `ValidationError`
- A deterministic finding placed in Section B raises `ValidationError`
- Report round-trips through JSON unchanged

**Verify + Commit:** `feat(report): add report model with verified/inferred separation` — **Push.**

---

## Step 9.2 — Report builder

**Create `src/ipsec_sentinel/report/build.py`:**

```python
def build_report(assessments: list[TunnelAssessment],
                 inventory: Inventory,
                 baseline: str) -> Report:
    """Route each finding to Section A or B based on confidence is None."""
```

**Test:** all findings routed correctly; executive summary counts match the section contents; empty assessment produces a valid empty report.

**Verify + Commit:** `feat(report): add report builder` — **Push.**

---

## Step 9.3 — Metadata exposure report

**Goal:** what an observer learns even from a perfect tunnel. The memorable demo moment.

**Create `src/ipsec_sentinel/report/exposure.py`:**

For every tunnel — including grade-A ones — report: endpoint pair, active hours, total volume, session count, and the inferred application type with its confidence.

**Test — `tests/unit/test_exposure.py`:**
- A perfectly configured tunnel still produces an exposure entry
- Exposure entry includes the inferred traffic class
- Active-hours histogram matches the observed timestamps

**Verify + Commit:** `feat(report): add metadata exposure analysis` — **Push.**

---

## Step 9.4 — Threat matrix

**Create `src/ipsec_sentinel/report/threat_matrix.py`:**

Cross findings with ATT&CK techniques and CVEs. Output a matrix: technique × affected tunnels × severity.

**Test:** matrix rows match distinct techniques; a tunnel with no findings appears in no row; CVE-derived entries include the CVE ID and CVSS score.

**Verify + Commit:** `feat(report): add threat matrix` — **Push.**

---

## Step 9.5 — HTML renderer

**Create `src/ipsec_sentinel/report/render_html.py`** with Jinja2 templates.

Requirements: self-contained single file (inline CSS, no CDN — must work air-gapped), print-friendly, Section A and B **visually distinct** with an explanatory note on the difference.

**Test — `tests/unit/test_render_html.py`:**
- Output is valid HTML (parse with an HTML parser)
- Contains no external resource references (assert no `http://` or `https://` in `src`/`href`)
- Section B entries display their confidence value
- Section A entries display no confidence
- Renders correctly with zero findings

**Verify + Commit:** `feat(report): add self-contained HTML renderer` — **Push.**

---

## Step 9.6 — PDF and JSON export

**Create `render_pdf.py`** (WeasyPrint from the HTML) and **`export_json.py`** (machine-readable, schema-versioned).

**Test:** PDF is non-empty and opens; page count is reasonable; JSON validates against a published schema; JSON round-trips into the `Report` model.

**Verify + Commit:** `feat(report): add PDF and JSON export` — **Push.**

---

## Step 9.7 — SIEM output

**Create `src/ipsec_sentinel/report/siem.py`:**

- CEF and LEEF formatters
- Syslog emitter (RFC 5424)
- Severity mapped to syslog levels

**Test:** CEF output matches the format spec; special characters escaped; syslog message under 1024 bytes; emitter handles an unreachable collector without crashing the run.

**Verify + Commit:** `feat(report): add SIEM output formats` — **Push.**

---

## ▶ MILESTONE M9 — Reporting complete

**Acceptance:**
- [ ] Full report generated from a real dataset capture
- [ ] Section A contains only deterministic findings — verified by validator
- [ ] Section B contains only inferred findings with confidence
- [ ] HTML opens with no network access (test with network disabled)
- [ ] PDF renders
- [ ] JSON validates against schema
- [ ] Metadata exposure present for a grade-A tunnel
- [ ] Manually read the executive summary — is it understandable by a non-technical reader? If not, rewrite.

**Tag:** `v0.10.0-reporting` and push.

---
---

# PHASE 10 — CLI, API and dashboard

---

## Step 10.1 — CLI

**Create `src/ipsec_sentinel/cli.py`** with Click:

```
sentinel analyse <pcap> [--baseline itsar] [--out report.html]
sentinel inventory <pcap> [--known known.yaml]
sentinel watch <interface> [--baseline itsar]
sentinel scan <target>            # active mode, requires --i-have-authorisation
sentinel remediate <tunnel-id> --from-report report.json
sentinel dataset build|package|audit
sentinel model train|evaluate
```

**Safety requirement:** `sentinel scan` must **refuse to run** without an explicit authorisation flag and must print a warning about active probing on production networks.

**Test — `tests/unit/test_cli.py`:**
- Each command's `--help` exits 0
- `analyse` on a fixture PCAP produces a report file
- `scan` without the authorisation flag exits non-zero with a clear message
- Invalid PCAP path gives a friendly error, not a traceback
- `--version` prints the version and git SHA

**Verify + Commit:** `feat(cli): add command-line interface` — **Push.**

---

## Step 10.2 — REST API

**Create `src/ipsec_sentinel/api/app.py`** with FastAPI:

```
POST /api/v1/analyse          (multipart PCAP upload)
GET  /api/v1/tunnels
GET  /api/v1/tunnels/{id}
GET  /api/v1/findings?severity=critical
GET  /api/v1/inventory
GET  /api/v1/reports/{id}
POST /api/v1/remediate/{tunnel_id}
GET  /health
```

**Test — `tests/unit/test_api.py`:**
- All endpoints return correct status codes
- Upload of a non-PCAP returns 400 with a clear message
- Upload above the size limit returns 413
- OpenAPI schema generates
- `/health` returns 200 with version info

**Security tests (write these, do not skip):**
- Path traversal in the filename is rejected
- Uploaded file is written to a temp dir, never a user-controlled path
- Response headers include `X-Content-Type-Options: nosniff`

**Verify + Commit:** `feat(api): add REST API` — **Push.**

---

## Step 10.3 — Dashboard

**Create `dashboard/`** — a single-page app (plain HTML/JS or React, your choice; plain is faster and has fewer failure modes in a demo).

Views:
1. **Estate overview** — grade, tunnel count, findings by severity
2. **Inventory** — table with the undocumented flag prominent
3. **Tunnel detail** — parsed parameters, findings, inferred traffic with SHAP explanation
4. **Threat matrix**
5. **PQC readiness**
6. **Remediation** — the change package, copyable

**Design requirement:** Section A and Section B must be visually distinguishable at a glance. Use a clear label, not just a colour.

**Test — `tests/integration/test_dashboard.py`** with Playwright:
- Dashboard loads
- Uploading a PCAP produces results
- Findings table populates
- Clicking a tunnel opens the detail view
- SHAP explanation renders
- **Works with the browser offline after initial load** (no CDN dependencies)

**Verify + Commit:** `feat(dashboard): add web dashboard` — **Push.**

---

## Step 10.4 — Continuous watch mode

**Create `src/ipsec_sentinel/watch.py`:**

- Live capture on an interface
- Incremental analysis in a rolling window
- **Drift detection:** compare current tunnel config against the last-seen config for that tunnel; any weakening raises an immediate alert
- Emit to SIEM on new findings

**Test — `tests/integration/test_watch.py`:**
- Start watch on the testbed transit interface
- Bring up a strong tunnel — no critical findings
- Tear down, bring up a **weak** tunnel between the same endpoints
- **Assert a drift alert fires within 60 seconds**

This test reproduces the Jhunjhunu scenario from your pitch. Make it pass and you can demo it live.

**Verify + Commit:** `feat(watch): add continuous monitoring with drift detection` — **Push.**

---

## ▶ MILESTONE M10 — Interfaces complete

**Acceptance:**
- [ ] CLI covers every workflow
- [ ] API passes all security tests
- [ ] Dashboard loads and functions offline
- [ ] Watch mode detects a live config weakening within 60 seconds
- [ ] Full regression green

**Tag:** `v0.11.0-interfaces` and push.

---
---

# PHASE 11 — Hardening, packaging, demo

---

## Step 11.1 — End-to-end integration test

**Create `tests/integration/test_e2e.py`** — the single test that proves the whole product:

```
1. Bring up a WEAK tunnel in the testbed
2. Generate VoIP traffic through it
3. Capture
4. Run `sentinel analyse`
5. ASSERT: grade F, CRY-05 (3DES), CRY-02 (DH-2), IKE-03 (aggressive+PSK) present
6. ASSERT: inferred traffic == "voip" with confidence > 0.6
7. ASSERT: inferred mode == "tunnel"
8. Extract the change package
9. Apply it to both ends using the generated sequence
10. ASSERT: zero packet loss during the change
11. Force a rekey
12. Re-run analyse
13. ASSERT: grade A, zero critical findings
14. ASSERT: original findings auto-closed by verification
```

**If this test passes, the product works.** Run it in CI on every push (nightly if too slow for per-commit).

**Verify + Commit:** `test: add full end-to-end integration test` — **Push.**

---

## Step 11.2 — Performance benchmarks

**Create `tests/integration/test_performance.py`:**

| Scenario | Target |
|---|---|
| Parse 100 MB PCAP | under 60 s |
| Analyse 1000 tunnels | under 120 s |
| ML prediction per flow | under 50 ms |
| Report generation | under 10 s |
| Memory on 1 GB PCAP | under 4 GB (streaming, not full load) |

**If any target fails, profile and optimise before proceeding.** A demo that hangs is worse than a missing feature.

**Verify + Commit:** `test: add performance benchmarks` — **Push.**

---

## Step 11.3 — Security review of the tool itself

**Create `docs/SECURITY.md`** and a test suite asserting:

- [ ] **No code path stores or transmits a credential** — grep the codebase for credential-like patterns and assert none
- [ ] **No code path writes to a network device** — assert no SSH/NETCONF/REST-write client is imported
- [ ] Passive mode opens no outbound socket (assert with a socket monkeypatch)
- [ ] Uploaded files are size-limited and written only to temp dirs
- [ ] All external data (PCAP, YAML, JSON) is parsed defensively
- [ ] No `eval`, `exec`, `pickle.load` on untrusted input
- [ ] Dependencies scanned (`pip-audit`) with zero high-severity findings

**These assertions are your "zero-credential" pitch, made verifiable.**

**Verify + Commit:** `docs: add security posture documentation and assertions` — **Push.**

---

## Step 11.4 — Offline and air-gapped operation

**Test — `tests/integration/test_offline.py`:**
- Disable network (or monkeypatch socket to raise)
- Run full analyse → report pipeline
- **Assert it completes successfully**
- CVE lookups use cache and degrade gracefully with a note in the report

**Verify + Commit:** `test: verify air-gapped operation` — **Push.**

---

## Step 11.5 — Packaging

**Create:**
- `Dockerfile` for the analysis engine (multi-stage, non-root user)
- `docker-compose.yml` for engine + dashboard + optional sensor
- `scripts/install.sh` for bare-metal
- `scripts/build_offline_bundle.sh` producing a tarball with all wheels and images for air-gapped install

**Test:** clean-machine install from the bundle with no network; container runs as non-root; image size under 1 GB.

**Verify + Commit:** `chore: add packaging and offline bundle` — **Push.**

---

## Step 11.6 — Documentation

Complete `docs/`:

| File | Contents |
|---|---|
| `README.md` | What it is, what it is not, quickstart, screenshot |
| `ARCHITECTURE.md` | The two-lane design and why |
| `DATASET.md` | Methodology and limitations (Step 3.4) |
| `GENERALISATION.md` | Honest ML results (Step 7.6) |
| `CONFOUND_AUDIT.md` | Cipher leakage analysis (Step 7.10) |
| `SCORING.md` | Weighting rationale |
| `RULES.md` | Every rule with its standard reference |
| `SECURITY.md` | Tool's own security posture |
| `DEPLOYMENT.md` | Mirror port, TAP, sensor sizing |
| `LIMITATIONS.md` | **What the tool cannot do** |

**`LIMITATIONS.md` must state:** passive analysis sees only negotiated sessions not full capability; no accreditation authority; no governance coverage; ML trained on lab data; vendor generators beyond strongSwan/Libreswan are syntax-validated only.

**Writing this document honestly is a scoring asset.** It is also the section a technical judge is most likely to read first.

**Verify + Commit:** `docs: complete documentation set` — **Push.**

---

## Step 11.7 — Demo preparation

**Create `demo/`:**

- `demo/pcaps/` — pre-captured files for every demo beat (never depend on a live capture during a presentation)
- `demo/run_demo.sh` — scripted sequence
- `demo/SCRIPT.md` — the ten-minute narration with timings
- `demo/fallback.mp4` — recorded video if everything fails

**Demo beats:**

| Time | Beat |
|---|---|
| 0:00 | Same PCAP in Wireshark — visible but unjudged |
| 1:30 | In Sentinel — grade F, cited findings |
| 3:00 | Inventory — more tunnels than documented |
| 4:30 | Undocumented traffic finding with SHAP |
| 6:00 | Change package, both ends, sequenced |
| 7:30 | Live fix on testbed, zero packet loss, auto-close |
| 9:00 | PQC readiness and ITSAR view |

**Test — `tests/integration/test_demo.py`:**
- `run_demo.sh` completes without error
- Every demo PCAP parses
- Every asserted finding appears
- **Total runtime under 10 minutes**

**Rehearse three times minimum.**

**Verify + Commit:** `chore: add demo assets and script` — **Push.**

---

## ▶ MILESTONE M11 — Release candidate

**Run the complete verification:**
```bash
make verify-all
pytest tests/integration/test_e2e.py -v
pytest tests/integration/test_performance.py -v
pytest tests/integration/test_offline.py -v
bash demo/run_demo.sh
```

**Final checklist — every item must be ticked:**

**Correctness**
- [ ] Parser agrees with tshark on 100% of dataset captures
- [ ] Fuzzing: 10,000 inputs, zero crashes, zero hangs
- [ ] E2E test passes: weak → detected → remediated → verified
- [ ] Coverage above 85% overall, above 90% for parser and assess

**Honesty**
- [ ] Generalisation report published with degraded held-out numbers
- [ ] Confound audit published
- [ ] Dataset limitations documented
- [ ] External dataset IPsec audit committed
- [ ] `LIMITATIONS.md` complete and honest
- [ ] Section A / B separation enforced by validator

**Security**
- [ ] Zero credential storage, verified by test
- [ ] Zero device-write paths, verified by test
- [ ] Passive mode makes no outbound connections
- [ ] `pip-audit` clean
- [ ] Air-gapped operation verified

**Completeness**
- [ ] All 26 rules implemented
- [ ] All 7 baselines including ITSAR and CERT-In
- [ ] PQC grading
- [ ] VID fingerprinting with CVE correlation
- [ ] Inventory with undocumented detection
- [ ] Anomaly detection
- [ ] Both-ends remediation with zero-downtime sequencing
- [ ] Auto-verification
- [ ] Watch mode with drift detection

**Deliverables**
- [ ] Working prototype
- [ ] Trained classification engine with published metrics
- [ ] Interactive dashboard
- [ ] Sample reports (executive + technical)
- [ ] Demo video
- [ ] Complete technical documentation
- [ ] Packaged dataset with datacard

**Tag:** `v1.0.0` and push.

---
---

# PHASE 12 — Presentation, evidence pack, and pitch

**Goal:** a deck where every claim traces to a generated artifact in the repository. Judges do not score assertions; they score evidence. This phase turns the work into something a panel can verify in fifteen minutes.

**Core discipline for this phase:** *no slide may contain a number, screenshot, or claim that was not produced by a script in this repo.* Mockups, hand-drawn diagrams of unbuilt features, and remembered figures are forbidden. If a slide needs a number, generate it.

---

## Step 12.1 — Evidence pack assembly

**Goal:** one command collects every citable artifact. This is what makes the deck auditable.

**Create `scripts/build_evidence_pack.py`:**

```python
EVIDENCE = {
    "dataset_audit":        "docs/external_dataset_audit.md",
    "dataset_card":         "dataset/DATACARD.md",
    "dataset_index":        "dataset/INDEX.json",
    "generalisation":       "docs/GENERALISATION.md",
    "confound_audit":       "docs/CONFOUND_AUDIT.md",
    "tshark_parity":        "reports/tshark_parity.json",
    "fuzz_results":         "reports/fuzz_summary.json",
    "coverage":             "reports/coverage.json",
    "performance":          "reports/performance.json",
    "e2e_result":           "reports/e2e_run.json",
    "rules_catalogue":      "docs/RULES.md",
    "limitations":          "docs/LIMITATIONS.md",
    "security_assertions":  "reports/security_checks.json",
}

def build() -> EvidencePack:
    """
    Verify every artifact exists and is non-stale (regenerated after the last
    source change). Emit evidence/MANIFEST.json mapping claim-id -> artifact
    + the exact value it supports.
    """
```

Each entry records: the artifact path, its SHA-256, the git SHA at generation time, and the timestamp.

**Test — `tests/unit/test_evidence_pack.py`:**
- Missing artifact fails with a named error listing what to run to produce it
- Stale artifact (generated before the last commit touching its source) raises a warning
- MANIFEST.json validates against schema
- Every claim ID referenced in `docs/CLAIMS.md` resolves to an artifact

**Create `docs/CLAIMS.md`** — the master list of every claim you will make on a slide, each with an ID and its supporting artifact:

```markdown
| Claim ID | Claim | Evidence |
|---|---|---|
| C-01 | Named datasets contain zero IPsec packets | docs/external_dataset_audit.md |
| C-02 | Parser agrees with tshark on 100% of captures | reports/tshark_parity.json |
| C-03 | Parser survives 10,000 fuzz inputs | reports/fuzz_summary.json |
| C-04 | Classifier reaches X% on held-out captures | docs/GENERALISATION.md |
| C-05 | Classifier drops to Y% on held-out configs | docs/GENERALISATION.md |
| C-06 | Zero packet loss during remediation | reports/e2e_run.json |
| C-07 | Tool holds no credentials | reports/security_checks.json |
| C-08 | Drift detected within 60s | reports/e2e_run.json |
```

**Verify + Commit:** `feat(evidence): add evidence pack assembly and claims register` — **Push.**

---

## Step 12.2 — Automated screenshot generation

**Goal:** slide screenshots are always current. Regenerate them whenever the UI changes.

**Create `scripts/capture_screenshots.py`** using Playwright:

```python
SHOTS = [
    ("dashboard_overview",   "/",                    "Estate grade + finding counts"),
    ("inventory_undocumented","/inventory",          "41 found, 34 documented"),
    ("tunnel_detail_weak",   "/tunnel/weak-001",     "Grade F with cited findings"),
    ("shap_explanation",     "/tunnel/weak-001#ml",  "Why it classified as VoIP"),
    ("threat_matrix",        "/threats",             "ATT&CK mapping"),
    ("pqc_readiness",        "/pqc",                 "Four-grade breakdown"),
    ("itsar_compliance",     "/compliance/itsar",    "Indian baseline view"),
    ("change_package",       "/remediate/weak-001",  "Both-ends sequenced fix"),
    ("wireshark_comparison", None,                   "Same PCAP, unjudged"),
]
```

Fixed viewport (1920×1080), deterministic demo data, PNG output to `presentation/assets/screenshots/`.

**Test — `tests/integration/test_screenshots.py`:**
- All screenshots generate
- Each file is non-empty and above 50 KB (catches blank renders)
- Image dimensions are exactly as specified
- **Content assertion:** OCR or DOM check confirms the expected text appears (e.g. "Grade F" present in `tunnel_detail_weak`)

That last check matters. A screenshot that silently captured a loading spinner is worse than no screenshot.

**Verify + Commit:** `feat(presentation): add automated screenshot capture` — **Push.**

---

## Step 12.3 — Results figures from real data

**Goal:** every chart on a slide is generated from the actual dataset, not drawn.

**Create `scripts/generate_figures.py`** producing SVG and PNG into `presentation/assets/figures/`:

| Figure | Content | Source |
|---|---|---|
| `fig_dataset_balance` | Traffic class × cipher heatmap | `dataset/INDEX.json` |
| `fig_generalisation` | Accuracy across the four split strategies | `docs/GENERALISATION.md` |
| `fig_confusion_matrix` | Per-class confusion, held-out captures | model eval |
| `fig_calibration` | Reliability diagram before/after | calibration output |
| `fig_traffic_shapes` | Packet-size vs time, one panel per class | real captures |
| `fig_score_distribution` | Estate scores across all dataset configs | assessment run |
| `fig_pqc_breakdown` | Tunnels per PQC grade | assessment run |
| `fig_architecture` | Two-lane diagram | hand-authored SVG, version controlled |

**`fig_traffic_shapes` is your most persuasive figure.** Six small panels showing VoIP as a metronome, video as bursts-and-gaps, web as a sawtooth, ICMP as perfect regularity. It makes the ML lane self-evidently reasonable before you explain a single feature.

**Test — `tests/unit/test_figures.py`:**
- Every figure generates without error
- SVG files are valid XML
- Figures regenerate identically given the same input (deterministic seeds)
- `fig_generalisation` contains all four split labels

**Verify + Commit:** `feat(presentation): add results figure generation` — **Push.**

---

## Step 12.4 — Slide content in version control

**Goal:** slide text lives in the repo as markdown, reviewed like code, so it stays in sync with reality.

**Create `presentation/DECK.md`** — one section per slide, each with: slide number, title, body content, the figure or screenshot it uses, the claim IDs it asserts, and speaker notes.

**The structure — 14 slides for a 15-minute slot with a 5-minute demo:**

### Slide 1 — Title
Project name, team, problem statement ID, institution. Nothing else. Ten seconds.

### Slide 2 — The problem, in one number
> **46.**
> NCIIPC audits of India's entire Power & Energy sector in FY 2024-25.
> Transport received **three**.
> A single CERT-In audit takes **3 to 6 weeks**.

No architecture, no product. Just the gap. Let it sit for three seconds.

### Slide 3 — What a weak tunnel looks like
Screenshot: `wireshark_comparison`. Point at `3DES`, `DH group 2`, `Aggressive Mode`.

> Everything needed to assess this is on screen, in plain text, right now.
> It takes an expert to know it is critical. There are not enough experts.

### Slide 4 — What we built
One sentence, then the architecture figure. No feature list yet.

> A passive analyser that reads the IPsec handshake off the wire, grades it against national and international standards, and infers what it cannot read — **without holding a single credential.**

### Slide 5 — The dataset problem we found (claims C-01)
**This is your credibility slide. Do not skip it and do not soften it.**

> The problem statement points to CIC-IDS2017, UNSW-NB15, CTU-13, CICIoT2023, LANL and DARPA.
> We audited all of them for IPsec content.

Show the generated audit table: **zero IKE negotiations, zero ESP packets, zero crypto labels** across every dataset.

> No public IPsec corpus with cipher and DH-group labels exists. So we built the generator that produces one — and we replayed the benign traffic from those datasets *through* our tunnels as inner payload, which is the only technically sound way to use them here.

### Slide 6 — Two lanes: what we read, what we infer
The parse-vs-infer table. Seven of nine parsed, two inferred.

> Seven of these are cleartext fields in the handshake. A classifier there would be less accurate than a struct read, so we did not build one. Two are inside the encrypted portion and cannot be read at all. That is where our models operate.

### Slide 7 — Demo (5–6 minutes)
Slide is a single word: **DEMO**. Everything else is live or recorded.

### Slide 8 — What we detect (claim C-02, C-03)
The rules catalogue summary: 26 rules, 7 baselines, each finding carrying a standard citation. Plus the correctness evidence — tshark parity 100%, 10,000 fuzz inputs with zero crashes.

### Slide 9 — The honest ML slide (claims C-04, C-05)
`fig_generalisation` with all four numbers, **including the bad one**.

> Random flow split: 94%. Capture-level split: 87%. Held-out configurations: 71%.
> That gap tells us the model partially learned our lab. So we ship it with calibrated confidence and an abstention threshold, and we report it as intelligence, not evidence.

Every other team will claim a single high number. **You will be the only team that shows where it breaks.**

### Slide 10 — What nothing else does
The capability comparison table. Highlight only the five rows nothing else can do: Indian baselines, tunnel/transport inference, in-tunnel traffic classification, PQC readiness, metadata exposure.

Then the closing question:

> This finding — an undocumented video stream on a SCADA link — came from a model noticing the traffic did not match telemetry. Which existing tool would have produced it?

### Slide 11 — Built for India (differentiator)
ITSAR, CERT-In directions, NCIIPC context. Plus PQC readiness with the four grades, and RFC 8784/9370 support.

> Government CISOs are now being asked for a post-quantum migration plan. Almost none can answer, because nobody has told them which tunnels are exposed. This produces that inventory.

### Slide 12 — Deployment reality (claim C-07)
One cable to a mirror port. No agent, no credential, no configuration change.

> A tool holding admin credentials for two hundred critical devices is itself a high-value target. Compromise the auditor and you own the grid. Ours has nothing to steal and, in passive mode, no path to act — and that is asserted by a test in our CI, not just a claim on a slide.

### Slide 13 — Impact and path to adoption
Coverage multiplication (one auditor covering 50 sites instead of 5), the deployment scenarios, and the realistic adoption routes: CERT-In empanelled firms as channel, NCIIPC RVDP, PSU utilities, GeM listing, STQC certification.

### Slide 14 — Limitations and what comes next
**The maturity slide. Counterintuitive, and it works.**

> Passive analysis sees negotiated sessions, not full device capability — so we added optional active probing.
> We cannot issue an audit certificate; we are an input to an audit, not a substitute.
> We have no visibility into governance — who holds the PSK, whether rotation is documented.
> Vendor generators beyond strongSwan and Libreswan are syntax-validated, not deployment-tested.
> Our classifier is trained on lab data. Field validation is the next step.

**Test — `tests/unit/test_deck_claims.py`:**
- Every claim ID in `DECK.md` exists in `docs/CLAIMS.md`
- Every referenced figure and screenshot file exists
- **Every numeric claim matches the current value in its evidence artifact** — this test fails if results change and the deck was not updated

That last test is the whole point of this step. It makes it impossible to present a stale number.

**Verify + Commit:** `feat(presentation): add slide content with claim traceability` — **Push.**

---

## Step 12.5 — Deck assembly

**Goal:** a `.pptx` that regenerates from the repo.

**Two paths. Choose based on time remaining.**

**Path A — automated (preferred if you have the hours).** `scripts/build_deck.py` using `python-pptx`:
- Read `DECK.md`
- Apply a consistent template (`presentation/template.pptx`)
- Insert generated figures and screenshots at fixed positions
- Write speaker notes into the notes pane
- Output `presentation/build/sentinel_sih2026.pptx`

**Path B — hybrid (pragmatic).** Generate all figures and screenshots automatically, keep slide text in `DECK.md`, assemble manually in PowerPoint or Google Slides for visual polish. Commit the `.pptx` to the repo and re-export when figures change.

**Path B is the honest recommendation under hackathon time pressure.** Automated deck generation is satisfying but design polish matters to the presentation score, and `python-pptx` fights you on layout.

**Design constraints either way:**

| Constraint | Reason |
|---|---|
| Maximum 6 lines of text per slide | Judges read or listen, not both |
| Minimum 24pt body text | Back of the room |
| One idea per slide | If it needs "and", split it |
| No stock photography | It signals padding |
| No clip-art security icons | Same |
| Dark text on light background | Projector-safe |
| Every figure has a caption naming its source artifact | Auditability |
| Slide numbers on every slide | So judges can reference them in Q&A |

**Test — `tests/unit/test_deck_build.py`:**
- Deck builds without error
- Slide count matches `DECK.md` section count
- Every slide has speaker notes
- No slide exceeds the text limit (parse and count)
- All embedded images resolve

**Verify + Commit:** `feat(presentation): add deck assembly` — **Push.**

---

## Step 12.6 — Speaker notes and timing

**Goal:** the deck can be delivered by any team member, on time.

**Create `presentation/SCRIPT.md`** with per-slide: allotted seconds, the exact opening line, key points, the transition sentence into the next slide, and a cut marker for what to drop if running long.

**Timing budget for a 15-minute slot:**

| Segment | Slides | Minutes |
|---|---|---|
| Problem framing | 1–3 | 2:00 |
| What we built | 4 | 0:45 |
| Credibility (dataset + two lanes) | 5–6 | 2:15 |
| **Demo** | 7 | **5:30** |
| Results and differentiation | 8–11 | 3:00 |
| Deployment, impact, limitations | 12–14 | 1:30 |
| **Total** | | **15:00** |

**Cut order if running long:** slide 13 first, then slide 11's PQC half, then slide 8's evidence detail. **Never cut slides 5, 6, 9, or the demo** — those are the four that differentiate you.

**Test — `tests/unit/test_script_timing.py`:**
- Sum of allotted times equals the target
- Every slide has an opening line and a transition
- Cut markers are present and ordered

**Verify + Commit:** `docs(presentation): add speaker script with timing` — **Push.**

---

## Step 12.7 — Demo video

**Goal:** an insurance policy and a deliverable.

**Create `scripts/record_demo.sh`:**
- Runs `demo/run_demo.sh` under screen capture (ffmpeg or OBS CLI)
- 1080p, 30fps, with narration audio
- Produces `presentation/build/demo.mp4` and a 60-second `demo_short.mp4`

**Content:** the seven demo beats from Step 11.7, narrated.

**Test — `tests/integration/test_demo_video.py`:**
- Video file exists and is non-empty
- Duration between 8 and 11 minutes for the full version
- Short version under 70 seconds
- Video opens in a standard player (probe with ffprobe)

**Rule: record this before the finale, not during.** A recorded demo that already works removes the single largest source of presentation risk.

**Verify + Commit:** `chore(presentation): add demo video production` — **Push.**

---

## Step 12.8 — Judge Q&A preparation

**Goal:** rehearse the hard questions until the answers are reflexive.

**Create `presentation/QA.md`** with prepared answers. These are the questions a technically competent panel will actually ask:

**Q1 — "Why not just use Wireshark?"**
> Wireshark shows you the fields. It has no opinion about them. It will display `3DES` and `DH group 2` in the same neutral font as everything else. Our contribution is the judgment layer — grading against seven baselines with citations — plus the two things Wireshark structurally cannot do: infer the mode and classify what is inside the tunnel.

**Q2 — "The DH group is readable. Where is the AI?"**
> Correct, and we say so on slide 6. Seven of the nine identification targets are cleartext parsing and we deliberately did not put a model there — a classifier would be less accurate than reading the field. The AI operates on three things that cannot be read: what the tunnel is carrying, which configurations are anomalous rather than non-compliant, and when an estate starts drifting.

**Q3 — "Your accuracy drops to 71% on held-out configurations. Isn't that a failure?"**
> It is a finding, and reporting it is why you can trust our other numbers. It tells us the model partially learned lab-specific artifacts, which is exactly what you would expect from lab-generated training data. We handle it by shipping calibrated confidence with an abstention threshold, and by classifying these outputs as intelligence rather than compliance evidence. A team reporting only the 94% number has not run this test.

**Q4 — "A gateway might accept weak crypto even if this session used strong. How do you catch that?"**
> Two ways. Passively, we parse *every proposal offered*, not just the accepted one — a device advertising 3DES will accept 3DES from a peer that offers only that, and we flag it as fallback exposure. Actively, we integrate `ike-scan` transform enumeration as an opt-in mode, behind an explicit authorisation flag because active probing is unsafe on production OT networks.

**Q5 — "Why didn't you use the datasets in the problem statement?"**
> We did — as inner payload. We also audited them, and the report is in our repository: zero IKE negotiations, zero ESP packets, zero crypto labels across all six. They were built for intrusion detection, not protocol analysis. We replay their benign traffic through our own tunnels so the inner traffic is real while our configuration supplies the labels.

**Q6 — "Can this run on a live grid network?"**
> That is the deployment we designed for. Passive mode requires one cable to a mirror port or a passive TAP. No agent, no credential, no change to any running device. Our CI asserts that no code path opens an outbound socket in passive mode. That is why it works on equipment nobody is permitted to log into.

**Q7 — "What if your remediation config breaks the tunnel?"**
> It cannot, because we never apply it. We generate a change package containing both ends — IPsec is a negotiation, so changing one end alone kills the tunnel — sequenced to add the strong proposal before removing the weak one, with rollback commands and a blast-radius note. A human approves and applies it through their existing change process. Our end-to-end test executes that sequence on a live tunnel while pinging continuously and asserts zero packet loss.

**Q8 — "How is this different from Nipper or Nessus?"**
> Access model. Nipper reads a configuration file, which needs administrative credentials and device access — white box. We read packets — black box. That changes what is auditable at all: legacy OT equipment, third-party tunnels you do not own, incident-response captures from isolated devices. Plus five capabilities none of them have, on slide 10.

**Q9 — "What is your false positive rate?"**
> For the rule engine, structurally zero — a finding fires only when a deprecated algorithm is genuinely present in the parsed handshake, and every finding cites the byte offset and the standard clause. False positives are possible only in the inferred lane, which is why those findings carry confidence scores and abstain below threshold. We report the two lanes separately for exactly this reason.

**Q10 — "Could an attacker evade your traffic classifier?"**
> Yes. Padding and traffic shaping defeat side-channel classification, and we have not tested adversarial robustness. That is in our limitations document. It matters less than it sounds, because the classifier is not a security control — it is an investigative aid that surfaces undocumented flows. The compliance findings do not depend on it.

**Q11 — "Who buys this, and how does government actually procure it?"**
> Realistically, not direct procurement from a hackathon. The channel is CERT-In empanelled audit firms, who benefit most immediately — turning two weeks of manual configuration review into a day. Beyond that: NCIIPC's responsible disclosure programme, GeM listing with STQC certification, and PSU utilities directly. We have built for on-premises and air-gapped operation because government will not accept SaaS for this data.

**Q12 — "What did you not finish?"**
> Answer honestly and specifically. Naming an unfinished item costs less than being caught claiming it.

**Test — `tests/unit/test_qa_doc.py`:**
- Every answer references at least one artifact or slide number
- No answer exceeds 120 words (they must be deliverable in under 45 seconds)

**Rehearsal requirement:** one team member plays hostile judge and asks all twelve, in random order, twice.

**Verify + Commit:** `docs(presentation): add judge Q&A preparation` — **Push.**

---

## Step 12.9 — One-page leave-behind

**Create `presentation/ONEPAGER.md` → PDF:**

Front: the problem in one number, what it does in one sentence, the five differentiating capabilities, the deployment diagram.
Back: architecture, honest results table including the held-out numbers, limitations, repository link and QR code.

**Judges keep paper. Give them something accurate to keep.**

**Test:** PDF generates, fits on one double-sided page, all numbers match the evidence pack.

**Verify + Commit:** `docs(presentation): add one-page leave-behind` — **Push.**

---

## Step 12.10 — Rehearsal protocol

**Create `presentation/REHEARSAL.md`** — a checklist to run at least three times.

**Rehearsal 1 — content.** Full run, timed. Record it. Watch it back. Cut anything that does not earn its seconds.

**Rehearsal 2 — failure modes.** Deliberately break things mid-run:
- Kill the network before the demo → does the fallback video play?
- Kill a testbed container → does the presenter notice and recover?
- Skip to slide 9 out of order → can the presenter pick up?
- Interrupt with a Q&A question mid-demo → can they answer and return?

**Rehearsal 3 — hostile Q&A.** All twelve questions, random order, with follow-ups.

**Pre-presentation checklist:**
- [ ] Laptop charged, charger present
- [ ] HDMI and USB-C adapters present
- [ ] Deck on the laptop, on a USB stick, and in cloud storage
- [ ] Demo video downloaded locally, not streaming
- [ ] Testbed containers pre-warmed and verified 30 minutes before
- [ ] All demo PCAPs present locally
- [ ] Browser zoom set so text is readable from the back
- [ ] Notifications and screen sleep disabled
- [ ] Terminal font size increased
- [ ] One-pagers printed, one per judge
- [ ] Every team member can answer Q1, Q2, Q3 and Q5 unprompted

**Test — `tests/integration/test_presentation_ready.py`:**
- Deck file exists and opens
- Demo video exists and plays
- One-pager PDF exists
- Every screenshot and figure is present
- **Every numeric claim in the deck matches the current evidence pack** — run this immediately before presenting

**Verify + Commit:** `docs(presentation): add rehearsal protocol and readiness checks` — **Push.**

---

## ▶ MILESTONE M12 — Presentation ready

**Run:**
```bash
python scripts/build_evidence_pack.py
python scripts/capture_screenshots.py
python scripts/generate_figures.py
pytest tests/unit/test_deck_claims.py -v
pytest tests/integration/test_presentation_ready.py -v
```

**Acceptance:**
- [ ] Evidence pack complete, no stale artifacts
- [ ] Every claim in the deck traces to an artifact
- [ ] Every numeric claim matches its current evidence value
- [ ] All screenshots regenerated from the current build
- [ ] All figures regenerated from the current dataset
- [ ] Deck delivers in 15:00 ± 0:30 when rehearsed
- [ ] Demo video recorded and plays offline
- [ ] One-pager printed
- [ ] All twelve Q&A answers rehearsed by at least two team members
- [ ] Three full rehearsals completed, including the failure-mode run

**Tag:** `v1.0.0-presentation` and push.

---
---
# Contingency plans

## If the testbed will not work by its deadline

**Do not persist.** Switch immediately:

1. Source public IPsec captures (Wireshark sample captures, packetlife.net, university lab archives)
2. Hand-label them by reading the IKE in Wireshark
3. **Skip Phase 7 (ML) entirely**
4. Build Phases 4, 5, 6, 8, 9, 10, 12 — parser, ESP, assessment, remediation, reporting, interfaces, presentation
5. Present the deterministic auditor as the product, and the ML lane as designed-but-unvalidated future work

**A working deterministic auditor with a clean demo beats a half-working AI platform.** State this decision openly in your presentation as a scoping choice — it reads as judgment, not failure. Add a slide: *"We scoped the ML lane out at hour 14 when the testbed was not producing labelled data fast enough. Here is what we would have built and why we chose correctness over coverage."* Panels reward that.

## If ML accuracy is poor (below 85% closed-world)

**Do not hide it.** Present it as the research finding it is:

> "In-tunnel classification reached 78% on held-out captures and 61% on held-out configurations. The gap tells us the model partially learned lab-specific artifacts. We therefore ship it with calibrated confidence and abstention, and we report it as intelligence rather than evidence."

That paragraph earns more credibility than a claimed 97%. Slide 9 is built for exactly this.

## If the demo breaks during the presentation

1. **Do not troubleshoot on stage.** Ten seconds maximum.
2. Cut to `demo.mp4`, already open in a background window.
3. Say: *"We will use the recording — the live testbed is on the venue network."* Then continue narrating over the video as though nothing happened.
4. Return to live for the final beat if it recovers.

**The recorded video is not a fallback you hope not to use. It is a planned redundancy.** Rehearse the switch.

## If you run out of build time

**Priority order — build strictly in this sequence:**

1. Parser (Phase 4) — nothing works without it
2. Assessment rules (Phase 6) — this is the product
3. Reporting (Phase 9) — without it there is nothing to show
4. CLI (Step 10.1) — minimal interface
5. Inventory (Step 5.5) — highest value per hour
6. **Presentation (Phase 12)** — reserve the final 4 hours regardless of what is unfinished
7. Remediation (Phase 8) — makes it actionable
8. Dashboard (Step 10.3) — makes it demoable
9. ML (Phase 7) — the differentiator, but not the foundation
10. Everything else

**Reserve the last four hours for Phase 12 no matter what.** A finished product presented badly loses to a partial product presented well. Teams routinely code until the final minute and then present something nobody can follow.

**Ship items 1–6 polished rather than 1–10 broken.**

---

# Git workflow reference

```bash
# Every step
git add -A
git commit -m "feat(scope): description"
git push

# Every milestone
make verify-all
git tag -a vX.Y.Z-name -m "Milestone: description"
git push origin vX.Y.Z-name

# Before presenting — verify the deck matches reality
python scripts/build_evidence_pack.py
pytest tests/unit/test_deck_claims.py

# If a step fails verification — do NOT commit
git stash
# investigate, fix, re-verify
git stash pop

# If a commit broke something
git revert <sha>   # never force-push main
```

**Branch policy:** work directly on `main` for hackathon speed, but **never push a commit where `make verify` fails.** The CI gate is your safety net; do not disable it under time pressure. A red main branch at hour 30 costs more time than it saves.

**Repository presentation matters.** Judges will open your GitHub. Ensure: a README with a screenshot above the fold, a clean commit history showing steady progress rather than three giant dumps, green CI badge, tagged releases at every milestone, and the `docs/` folder visible. A repository that *looks* engineered is itself evidence.

---

# Step and milestone summary

| Phase | Steps | Milestone | Deliverable |
|---|---|---|---|
| 0 — Foundation | 8 | M0 | Models, constants, CI, test harness |
| 1 — Testbed | 7 | M1 | Reproducible IPsec tunnels with ground truth |
| 2 — Traffic generation | 9 | M2 | Seven distinct application traffic classes |
| 3 — Dataset | 6 | M3 | Labelled corpus + external dataset audit |
| 4 — IKE parser | 10 | M4 | Deterministic, fuzz-proof, tshark-verified |
| 5 — ESP analysis | 5 | M5 | Flow assembly, replay detection, inventory |
| 6 — Assessment | 9 | M6 | 26 rules, 7 baselines, PQC grading |
| 7 — ML | 10 | M7 | Classifier + calibration + honest generalisation |
| 8 — Remediation | 6 | M8 | Both-ends, zero-downtime, auto-verified |
| 9 — Reporting | 7 | M9 | Section A/B separation, HTML/PDF/JSON/SIEM |
| 10 — Interfaces | 4 | M10 | CLI, API, dashboard, watch mode |
| 11 — Hardening | 7 | M11 | E2E, performance, security, packaging, demo |
| **12 — Presentation** | **10** | **M12** | **Evidence pack, deck, video, Q&A, rehearsal** |
| **Total** | **98 steps** | **13 gates** | |

Each step: write code → write test → run test → run suite → lint → type-check → commit → push.

**98 commits minimum. No step is complete until it is pushed and green.**

---

# The final instruction to Claude Code

Work through this plan in order. Do not skip verification steps under time pressure — a failing test caught at step 4.7 costs minutes; the same bug found at step 11.1 costs hours, and found during the demo costs the competition.

Four things in this plan will feel like they can be cut. **They cannot:**

1. **Step 3.5** — the external dataset audit. It is your single strongest credibility artifact.
2. **Step 4.9** — parser fuzzing. A parser that hangs on hostile input is not a security tool.
3. **Step 7.6** — the generalisation report, including the unflattering numbers.
4. **Phase 12** — reserve the time. A finished product presented badly loses.

Build honestly, test relentlessly, commit constantly, and let the evidence make the argument.
