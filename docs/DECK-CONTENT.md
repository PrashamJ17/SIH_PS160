# SIH 2026 deck — complete slide-by-slide content

Everything on every slide, as text you can paste. Generated alongside
`docs/SIH2026-Highlanders-IPsec-Sentinel.pptx`; if you edit the deck by hand, edit this
too, or regenerate both with `python -m scripts.deck.build_deck`.

**Canvas:** 960 × 540 pt (13.333in × 7.5in, 16:9) — the official template's exact size.

**Fonts:** Garamond Bold (banner), Times New Roman Bold (slide titles), Arial / Arial
Bold (body and section headings), Calibri (footer and team ellipse).

**Colours:**

| Role | Hex |
|---|---|
| Section heading, accents | `#1F497D` |
| Footer band | `#0070C0` |
| Team ellipse outline | `#8064A2` |
| Body text | `#17202A` |
| Muted / secondary | `#5B6A7A` |
| Critical / risk | `#8C1C13` |
| Good / solution | `#1D6B3F` |
| Panel fill | `#F4F7FA` |

**Furniture repeated on slides 2–6:**

- Team ellipse, no fill, `#8064A2` 1.5pt outline, at (26, 21), 99 × 63 pt — text
  **Highlanders**, Calibri Bold 15pt, centred
- SIH 2026 logo at (770, 2), 177 × 82 pt
- Footer band `#0070C0`, full width, from y = 501, height 39 — centred white Calibri
  12.3pt: **@SIH Idea submission- Template**; slide number right-aligned at (880, 505)
- Slide title: Times New Roman Bold 36pt, black, centred, at y = 34
- Section heading: `❖ ` + Arial Bold 21pt underlined `#1F497D`, at (8, 92), with a 2pt
  `#1F497D` rule from x = 36 to x = 930 at y = 125

---

## Slide 1 — TITLE PAGE

| Element | Content | Position |
|---|---|---|
| Banner | **SMART INDIA HACKATHON 2026** — Garamond Bold 40pt, `#1F497D` | (60, 14) |
| Title | **TITLE PAGE** — Times New Roman Bold 31.7pt, centred | (330, 96) |
| Logo | SIH 2026 | (770, 2) |
| Footer | **IPsec Sentinel — passive IPsec protocol analysis and security assessment** — Calibri Bold 13pt white on `#0070C0` | y = 501 |

Bullets at (33, 186), Arial Bold 19pt. Label in black, value in `#1F497D`:

- **Problem Statement ID –** SIH 26160
- **Problem Statement Title-** AI-Powered IPsec VPN Protocol Analyzer and Security
  Assessment Framework
- **Theme-** Blockchain & Cybersecurity
- **PS Category-** Software
- **Team ID-** SIH 163
- **Team Name (Registered on portal)-** Highlanders

---

## Slide 2 — PROPOSED SOLUTION

**Section heading:** ❖ IPsec Sentinel — passive IPsec assessment with auditable evidence

### Left column — three callout panels

Rounded rectangles, `#F4F7FA` fill, 1.25pt coloured outline, 268pt wide, at x = 8.
Label Arial Bold 12.5pt underlined; body Arial 11pt `#17202A`.

**(8, 142) — outline `#8C1C13`**
> **Real-world issue:**
> Wireshark decodes an IKE exchange but has no opinion about it. Weak IPsec survives for
> years because nothing judges what it sees.

**(8, 236) — outline `#1F497D`**
> **How it addresses the problem:**
> 26 deterministic rules, each citing the clause it applies, across NIST, CNSA, BSI,
> RFC 8221/8247, ITSAR and CERT-In.

**(8, 336) — outline `#1D6B3F`**
> **Innovation and uniqueness:**
> Facts are parsed. Estimates are inferred. A validator refuses to build a report that
> mixes them — the split is enforced, not promised.

### Centre — hero diagram (`two_lane.png`, at 286,140, 394 × 298 pt)

```
                    ONE PACKET CAPTURE
                     ↙              ↘
    SECTION A — VERIFIED        SECTION B — INFERRED
   parsed from cleartext IKE   estimated from encrypted ESP

   26 deterministic rules       traffic class from flow shape
   every finding cites a clause calibrated + SHAP explained
   confidence = None            abstains when signal is thin
   → compliance evidence        → what to fix first
                     ↓              ↓
   ┌──────────────────────────────────────────────┐
   │ Report.enforce_separation() — raises, not asserts │
   └──────────────────────────────────────────────┘
   python -O strips assertions. The guarantee at the centre of the
   product would vanish in exactly the deployment most likely to run optimised.

   An auditor reads Section A. An engineer triaging forty tunnels reads Section B.
```

### Right — GAP vs WHAT WE BUILT chips (`risk_solution.png`, at 690,140, 262 × 251 pt)

Red `#8C1C13` left, green `#1D6B3F` right, arrow between:

| GAP | → | WHAT WE BUILT |
|---|---|---|
| Wireshark shows, never judges | → | 26 cited rules, clause by clause |
| Rekey is encrypted — tunnel goes dark | → | Kernel + daemon state read and graded |
| Payload is encrypted — what does it carry? | → | Flow-shape inference, calibrated, abstains |
| A one-sided fix is an outage | → | Both ends, sequenced, zero packet loss |

### Footer text at (8, 446)

- **Working prototype — v1.0.0 tagged, M11 acceptance 20/20, nothing skipped** —
  Arial Bold 11pt `#1F497D`
- Dashboard, demo video and source: github.com/PrashamJ17/SIH_PS160 — Arial 10pt muted

---

## Slide 3 — TECHNICAL APPROACH

**Section heading:** ❖ Technologies and methodology

### Left — pipeline diagram (`pipeline.png`, at 8,142, 560 × 319 pt)

Top-left badge: **PASSIVE — never transmits, never writes to a device**
Top-right badge: **DEVICE STATE — ip xfrm state · swanctl / parsed, never fetched**

Five stages left to right, navy boxes with a caption under each:

| Stage | Caption |
|---|---|
| **PCAP / live interface** | libpcap-free streaming reader |
| **PARSE — IKEv1 · IKEv2 · ESP** | NAT-T 4500, both registries |
| **CORRELATE into tunnels** | negotiation + protected flows |
| **ASSESS — 26 rules × baseline** | deterministic, cited |
| **REPORT — HTML · PDF · JSON** | CEF / LEEF for a SIEM |

Two panels beneath:
- **ML lane · flow shape only** — sizes · timings · directions — payload never decrypted
- **Remediation · both ends, sequenced** — six vendors — a person applies it

Bottom lines:
- Python 3.11 · scapy · pydantic v2 · scikit-learn · SHAP · FastAPI · Jinja2 · WeasyPrint
- strongSwan testbed under netem · Docker · ruff · mypy --strict · pytest

### Right — dashboard screenshot (`docs/images/dashboard.png`, at 580,142, 372 × 284 pt)

Caption at (580, 316): **Working prototype — the dashboard on a real capture**

### Chips — navy rounded rectangles, 178 × 32 pt, Arial Bold 10pt white

| | |
|---|---|
| (580, 348) **26 rules** | (770, 348) **6 baselines + 2 tags** |
| (580, 388) **6 vendor generators** | (770, 388) **IKEv1 · IKEv2 · ESP** |

### Callout at (8, 366), 560 × 74 pt, outline `#8C1C13`

> **Two boundaries the design will not cross:**
> It never writes to a network device and stores no credential — an AST sweep over every
> module enforces both. Configuration is generated; a person applies it.

At (580, 434): *Reproducible build — git 263bec9*

---

## Slide 4 — FEASIBILITY AND VIABILITY

**Section heading:** ❖ Feasibility, the risks, and the strategies for overcoming them

### Left — four-quadrant map (`feasibility.png`, at 8,142, 470 × 317 pt)

**FEASIBILITY** (`#1C4F82`)
- Working prototype, v1.0.0 tagged
- Runs on a laptop: 0.68 GB container
- No agent, no credential, no outage

**VIABILITY** (`#1D6B3F`)
- Reads captures operators already have
- Air-gapped install, offline bundle
- ITSAR + CERT-In: no rival ships these

**CHALLENGES & RISKS** (`#8C1C13`)
- Model trained on laboratory traffic
- 5 of 6 vendor configs not device-tested
- A capture can miss an encrypted rekey

**STRATEGIES** (`#1F497D`)
- Publish held-out numbers, worst included
- Every generated file states its own status
- Read kernel + daemon state to close it

### Right — performance chart (`performance.png`, at 490,142, 462 × 231 pt)

Horizontal bars on a log scale, red line at the target:

| Target | Measured | Margin |
|---|---|---|
| Parse 100 MB PCAP under 60 s | **0.5 s** | 120× |
| Analyse 1000 tunnels under 120 s | **0.1 s** | 1200× |
| ML prediction per flow under 50 ms | **5.5 ms** | 9× |
| Report generation under 10 s | **0.1 s** (3.8 MB HTML) | 100× |
| Memory on 1 GB PCAP under 4 GB | **0.40 GB** | 10× |

### Stat chips at y = 400 (110 × 30 pt), label under each at y = 432

| (490) | (607) | (724) | (841) |
|---|---|---|---|
| **2,613** unit tests | **306** integration, on live pairs | **93.8%** coverage | **20/20** M11 acceptance |

Colours: navy, green, navy, `#8C1C13`.

### Callout at (490, 458), 462 × 38 pt, outline `#1D6B3F`

> **Deployable today:** 0.68 GB container, non-root, runs under `--network none`.

---

## Slide 5 — IMPACT AND BENEFITS

**Section heading:** ❖ Impact on the target audience, and the benefits

### Left — who gains (`benefits.png`, at 8,142, 300 × 265 pt)

Numbered navy circles, name in `#1F497D` bold, detail beneath:

1. **Auditors** — cited evidence, not an opaque score
2. **Network teams** — both-ends fix, zero packet loss
3. **Regulators** — ITSAR & CERT-In from one capture
4. **Air-gapped sites** — runs offline, no credentials

### Centre — generalisation chart (`generalisation.png`, at 320,142, 330 × 212 pt)

Title: *The middle bar is the one that matters — and it is the lowest*

| Split | Accuracy | Macro-F1 | Test rows |
|---|---|---|---|
| unseen captures | 99.2% | 0.993 | 125 |
| **unseen configurations** | **95.5%** | **0.956** | **132** |
| unseen DH groups | 96.7% | 0.966 | 337 |

The middle bar is orange `#B8500F`; the other two green.

Text under it at (320, 344):
> **Honest about its own limits**
> Trained on 637 rows across 7 classes of laboratory traffic. The unflattering number is
> published, not the best one.

### Right — endpoint visibility (`endpoint_visibility.png`, at 664,142, 288 × 162 pt)

```
  ON THE WIRE                →   IN THE KERNEL
  negotiated AES-256/ECP-384     3DES / MD5 installed

           estate grade, same capture
  ┌─────────────┐            ┌─────────────┐
  │  33 / 100   │     →      │  11 / 100   │
  │ 17 findings │            │ 20 findings │
  └─────────────┘            └─────────────┘

  The replay window never appears on the wire in any form.
  No passive capture of that gateway could ever have found this.
```

Text under it at (664, 344):
> **Endpoint visibility**
> A gateway's own kernel state is parsed and graded against the same rules — never
> fetched, never with a credential.

### Bottom callout at (8, 436), 944 × 58 pt, outline `#1D6B3F`

> **Social and economic benefit:**
> Government, telecom and enterprise VPN estates get audit-grade evidence from a capture
> they already have — no agent, no credential, no outage, and an Indian baseline (ITSAR,
> CERT-In) that no comparable tool ships.

---

## Slide 6 — RESEARCH AND REFERENCES

**Section heading:** ❖ Details / Links of the reference and research work

Two columns (x = 8 and x = 484), rows 46pt apart from y = 142. Name in Arial Bold 11.5pt
`#1F497D`, description Arial 9.5pt black.

| Reference | Why it is here |
|---|---|
| **RFC 7296** | IKEv2 — the protocol the parser implements |
| **RFC 2408 / 2409** | ISAKMP and IKEv1, including aggressive mode |
| **RFC 8221 / 8247** | Algorithm implementation requirements for ESP and IKEv2 |
| **RFC 4303** | ESP, and the anti-replay window SA-03/SA-04 judge |
| **RFC 9370 / 8784** | Post-quantum: additional key exchanges, PPKs |
| **NIST SP 800-77 Rev. 1** | IPsec VPN guidance — the default baseline |
| **NIST SP 800-131A Rev. 2** | 3DES disallowed after 2023; DES, MD5, SHA-1 |
| **CNSA 1.0 · BSI TR-02102-3** | The strict and German baselines |
| **ITSAR (NCCS) · CERT-In** | Indian telecom security assurance requirements |
| **MITRE ATT&CK** | Technique mapping for every finding |

Order on the slide is left-right, then down: RFC 7296 · RFC 2408/2409 / RFC 8221/8247 ·
RFC 4303 / RFC 9370/8784 · NIST SP 800-77 / NIST SP 800-131A · CNSA & BSI / ITSAR &
CERT-In · MITRE ATT&CK.

### Two callouts at y = 378, 466 × 106 pt

**(8, 378) — outline `#1F497D`**
> **Our own published research:**
> GENERALISATION.md — held-out results including the lowest. CONFOUND_AUDIT.md — did the
> model learn traffic or cipher? DATASET.md — methodology and limits. LIMITATIONS.md —
> what it cannot do. external_dataset_audit.md — the named datasets contain no IPsec.

**(486, 378) — outline `#1D6B3F`**
> **Code, evidence and demo:**
> github.com/PrashamJ17/SIH_PS160 — v1.0.0, M11 acceptance 20/20. Testbed: real
> strongSwan pairs under netem. Published JSON report schema 1.3. docs/SECURITY.md names
> the test behind every security claim.

---

## Where every number comes from

Counted live from the code or parsed from a committed document by
`scripts/deck/facts.py`, so nothing here can drift from what the repository proves.

| Number | Source |
|---|---|
| 26 rules | `default_registry().rules` |
| 6 baselines + 2 tags | `load_baselines()` + `BUILTIN_TAGS` |
| 6 vendor generators | files in `remediate/generators/` |
| 2,613 unit / 306 integration | `pytest --collect-only` |
| 637 rows, 7 classes | `models/traffic.metadata.json` |
| 0.68 GB | `docker image inspect` |
| Benchmarks | `PROGRESS.md`, Step 11.2 table |
| 99.2 / 95.5 / 96.7 | `docs/GENERALISATION.md` |
| 33 → 11, 17 → 20 findings | `sentinel analyse … --device-state` on `04-estate.pcap` |
| 93.8% coverage, 20/20 | `make verify-all`, `scripts/check_m11.py` |

## The template's own rules

1. Six slides maximum, including the title slide.
2. Avoid paragraphs — use points, diagrams, infographics, pictures.
3. Do not change the idea-details pointers from the template.
4. **Upload as PDF.** No PPT, DOC or any other format is accepted.
