# Architecture

One design decision explains most of this codebase:

> **Facts are parsed. Estimates are inferred.**

Everything read from cleartext IKE is deterministic and carries no confidence.
Everything derived from encrypted traffic is a model output and carries a calibrated one.
The two never mix in a report, and that separation is enforced by code rather than by
discipline.

Every other structural choice here follows from making that separation survive contact
with a real codebase.

---

## Why the split matters

A report that mixes them is neither compliance evidence nor intelligence.

An auditor asks: *what is provably wrong with this tunnel?* Only parsed facts can answer
that. "The responder selected ENCR_3DES" is a statement about bytes on the wire; it is
reproducible, citable, and survives cross-examination.

An engineer asks: *which of these forty tunnels should I fix first?* That needs judgement
about what the tunnel carries, which is only obtainable by inference — the payload is
encrypted. "This looks like VoIP, 0.94 confidence" is useful for prioritisation and
worthless as evidence.

Put both in one undifferentiated list and the reader cannot tell which is which, so the
document does neither job. Hence:

- **Section A — verified.** `Finding.confidence is None`. Parsed from the wire.
- **Section B — inferred.** `Finding.confidence` is a `Confidence`. Produced by a model.

The routing is one function, `report.build.route()`, so exactly one place in the codebase
decides it.

### The validator, and why it is not an `assert`

`Report.enforce_separation` is a Pydantic `model_validator` that **raises** if a finding
with a confidence appears in Section A, or a finding without one appears in Section B.

The build plan sketched it as an `assert`. `python -O` removes assertions — so the
guarantee at the centre of the product would silently disappear in exactly the deployment
most likely to run optimised. A test runs the validator under `-O` and pins the behaviour.

---

## The lanes

```
                         ┌─────────────────────────────────────┐
   capture.pcap ────────▶│ parser/  pcap → IKE → correlate     │
                         └─────────────────┬───────────────────┘
                                           │  Tunnel objects
                    ┌──────────────────────┴──────────────────────┐
                    │                                             │
        ┌───────────▼───────────┐                    ┌────────────▼────────────┐
        │  DETERMINISTIC LANE   │                    │     INFERENCE LANE      │
        │  assess/rules/        │                    │  features/ → ml/        │
        │  26 rules, baselines  │                    │  flow shape → class     │
        │  confidence = None    │                    │  calibrated + abstains  │
        └───────────┬───────────┘                    └────────────┬────────────┘
                    │  Section A                                  │  Section B
                    └──────────────────────┬──────────────────────┘
                                           │
                         ┌─────────────────▼───────────────────┐
                         │ report/  build → render → export    │
                         │ enforce_separation()                │
                         └─────────────────┬───────────────────┘
                                           │
                    ┌──────────────────────┼──────────────────────┐
                    ▼                      ▼                      ▼
              HTML / PDF              JSON + schema          CEF / LEEF / syslog
```

The lanes meet in exactly one place — `analyse.py`, the pipeline seam — and they meet as
two lists of findings that are immediately routed apart again.

An analysis run with **no model** produces a complete Section A and an empty Section B.
That is a supported mode, not a degraded one: the deterministic findings are the
compliance product, and they do not depend on the classifier existing.

---

## Module map

| Package | Responsibility |
|---|---|
| `parser/` | pcap → IKE/ESP structures → correlated `Tunnel` objects. Handles IKEv1 and IKEv2, NAT-T on 4500 with the non-ESP marker, and malformed input without crashing. |
| `assess/` | The 26 deterministic rules, the baselines that select them, scoring, inventory, anomaly detection and offline enrichment. |
| `features/` | Flow-shape features from ESP: sizes, timings, directions. The only thing extracted from encrypted traffic. |
| `ml/` | Training, calibration, abstention, prediction and SHAP explanation. Isolated so the rest of the product runs without it. |
| `report/` | The report model, the separation validator, and every output format. |
| `remediate/` | Six vendor generators, both-ends change packages, zero-downtime sequencing, blast-radius assessment and auto-verification. |
| `api/` + `dashboard/` | A read-mostly HTTP surface and the static dashboard it serves. |
| `analyse.py` | The seam. Capture in, `Report` out. |
| `cli.py` | `analyse`, `inventory`, `remediate`, `scan`, `watch`, `dataset`, `model`, `version`. |
| `collect.py`, `watch.py`, `probe.py` | Device state, drift detection, and the one active mode. |

`testbed/` is the Docker environment that generates the dataset: strongSwan pairs under
`netem`, carrying seven classes of real traffic. It is how every number in
[DATASET.md](DATASET.md) was produced.

---

## Two boundaries the design will not cross

**Nothing writes to a network device.** The remediation lane produces text. There is no
SSH, NETCONF or vendor-API client anywhere in the product, and
`tests/unit/test_security.py` walks the AST of every module to keep it that way. A wrong
finding therefore costs a wasted review and nothing else.

**Nothing stores a credential.** The tool never authenticates to anything, so there is no
field, flag, environment variable or prompt for a secret. Where device state is useful,
the operator collects it with the access they already have and passes a file. `ip xfrm
state` prints session keys inline; the parser reads the algorithm and drops the key bytes,
checked against a real kernel's output.

Both are load-bearing claims rather than aspirations. [SECURITY.md](SECURITY.md) names the
test behind each one.

---

## Where the honesty machinery lives

The separation validator is the largest piece, but not the only one:

- **Abstention.** The classifier returns "insufficient signal" rather than a low-confidence
  guess when the observation is thin, and an abstention is reported as one. It is never
  silently converted to a class.
- **Coverage findings.** `ESP-01` and `ESP-02` exist so that "this tunnel could not be
  assessed" is a finding rather than an absence — a tunnel that never renegotiated during
  the capture must not score as a pass.
- **Enrichment status.** A report built without the ATT&CK or CVE corpora says so. Missing
  reference data and "nothing matched" produce the same empty tables, and on an air-gapped
  host the first is the normal case.
- **Provenance.** Every report carries the tool version, the git SHA, and whether the
  working tree was dirty. `None` for the dirty flag means the question could not be
  answered, which is different from "clean".
- **A published JSON schema**, versioned, generated from the model, with a test that
  regenerates and compares. Schema `1.2`; `1.0` and `1.1` are retained because the models
  forbid unknown fields.

---

## Performance

Measured, not estimated — see the benchmarks in `tests/integration/test_performance.py`.

| Target | Measured |
|---|---|
| Parse a 100 MB pcap under 60 s | **0.5 s** |
| Assess 1000 tunnels under 120 s | **0.1 s** |
| Predict per flow under 50 ms | **5.5 ms** |
| Generate a report under 10 s | **0.1 s** |
| Memory on a 1 GB pcap under 4 GB | **0.40 GB** |

The parser streams rather than loading a capture into memory, which is the only one of
these that required design rather than care.

---

## Further reading

| Question | Document |
|---|---|
| What does each rule check? | [RULES.md](RULES.md) |
| What does each baseline require? | [BASELINES.md](BASELINES.md) |
| How is the score computed? | [SCORING.md](SCORING.md) |
| How well does the model generalise? | [GENERALISATION.md](GENERALISATION.md) |
| Did the model learn the cipher instead of the traffic? | [CONFOUND_AUDIT.md](CONFOUND_AUDIT.md) |
| What is in the dataset? | [DATASET.md](DATASET.md) |
| How secure is the tool itself? | [SECURITY.md](SECURITY.md) |
| Where do I put the sensor? | [DEPLOYMENT.md](DEPLOYMENT.md) |
| What can it not do? | [LIMITATIONS.md](LIMITATIONS.md) |
