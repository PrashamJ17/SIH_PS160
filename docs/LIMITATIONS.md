# What this tool cannot do

Every section below is a real boundary, not a roadmap item phrased as one. Where a
limitation is fundamental it is named as fundamental; where it is merely unbuilt it says
so. A tool that only advertises its strengths is asking you to find the gaps during an
audit instead of before one.

---

## It sees what was negotiated, not what a device supports

This is the deepest limitation in the product and it follows from the method.

Passive analysis reads the IKE exchange on the wire. That exchange contains the proposals
one peer *offered* and the transform the other *selected*, for the sessions that happened
to establish while the capture was running. It does not contain the device's configured
capability.

Concretely:

- A gateway configured to accept both AES-256 and 3DES, whose peers all happen to choose
  AES-256, is reported as an AES-256 tunnel. **The 3DES acceptance is invisible.** The
  weakness is real, exploitable by a peer that downgrades, and this tool will not see it.
- A tunnel that did not renegotiate during the capture window is not assessed at all. It
  appears in the inventory with `ESP-01` — ESP traffic with no observed negotiation —
  which is a statement that the tool *could not* judge it, deliberately not a pass.
- `IKE-04` reports a weaker proposal that was offered and rejected, which is the one case
  where offered capability is visible. It is visible because the offer was on the wire,
  not because the tool asked the device anything.

There is one deliberate exception, and it is opt-in: `sentinel scan` actively enumerates
which transforms a responder will accept. It transmits, it appears in the target's logs as
a series of failed negotiations, and it refuses to run without `--i-have-authorisation`.
It answers the capability question the passive path cannot. It is not part of an
assessment run and never runs by accident.

**Reading device state does not close this gap either.** `sentinel watch --device-state`
parses `ip xfrm state` and `swanctl --list-sas` output that an operator collected, which
says what is *installed* right now — closing the rekey blind spot, since a
CREATE_CHILD_SA is encrypted and its proposals are unreadable on the wire. Installed is
still not configured-capability.

---

## It is not an accreditation authority

The tool checks tunnels against published baselines — NIST SP 800-77 Rev. 1, CNSA 1.0,
BSI TR-02102-3, RFC 8221/8247, ITSAR, and CERT-In. A grade from this tool is **evidence
you can bring to an assessment. It is not a certification, an attestation, or a
compliance sign-off**, and no output of this project should be presented as one.

Nobody has accredited this tool, and no certification body has reviewed its rule set. The
baselines it encodes are its authors' reading of public documents; where a requirement is
ambiguous, `docs/BASELINES.md` records the reading taken and why. A conformity assessment
body will have its own reading, and theirs is the one that counts.

The same applies to the security of the tool itself: `SECURITY.md` makes checkable claims
backed by tests, and states plainly that **there has been no third-party penetration
test.**

---

## It does not cover governance, process, or people

The scope is one protocol on the wire. It says nothing about:

- **Key management** — how pre-shared keys or certificates are generated, distributed,
  rotated, escrowed or revoked. A tunnel using AES-256-GCM with a PSK of `vpn123`
  scores an A. The tool cannot see the PSK and would not store it if it could.
- **Certificate lifecycle** — issuance, validity, revocation checking, CA trust chains.
- **Change control** — whether a configuration was reviewed, approved, or applied by an
  authorised person.
- **Policy, training, incident response, physical security, supplier assurance**, or
  anything else an ISMS covers.
- **Endpoint security** — a perfectly configured tunnel to a compromised host is a
  perfectly configured tunnel to a compromised host.

An assessment framework such as ISO 27001, SOC 2 or a national telecom security assurance
scheme covers those. This tool produces one input to one control among many.

---

## The traffic classifier was trained on laboratory data

The inference lane — everything in Section B of a report — comes from a model trained on
traffic **generated in a Docker testbed**, not captured from a production network. This
matters more than the accuracy number suggests.

- Real enterprise VoIP shares links with everything else, traverses NAT and SD-WAN
  overlays, and is shaped by devices this dataset does not contain. Lab VoIP is clean.
- The dataset is **637 rows across 7 classes**, which is small, and its per-class balance
  is documented in [DATASET.md](DATASET.md) rather than smoothed over.
- Held-out performance degrades against the in-distribution number, and by how much is
  published in [GENERALISATION.md](GENERALISATION.md) — including the unflattering
  figures. [CONFOUND_AUDIT.md](CONFOUND_AUDIT.md) covers the cipher-leakage analysis, i.e.
  whether the model learned traffic shape or learned which cipher the cell was configured
  with.
- The model **abstains** rather than guessing when signal is thin, and an abstention is
  reported as an abstention. A short capture legitimately produces "insufficient signal".

Every inferred finding carries a calibrated confidence and lives in Section B. Section A —
the deterministic findings — is produced without the model and is unaffected by any of
this. A report generated with no model at all says *nothing* about traffic class rather
than quietly saying "unknown", and the two sections are kept apart by a validator, not by
convention.

**Do not use Section B as the sole basis for a business decision about a specific
tunnel.** It is a prioritisation aid: it tells you which of forty tunnels to look at
first.

---

## Only one vendor generator is validated against a running implementation

The remediation lane generates configuration for six targets. They are not equally
trustworthy, and the table says which is which.

| Target | Validation |
|---|---|
| **strongSwan** | Loaded, negotiated and re-analysed on a live daemon in integration tests |
| Libreswan | **Syntax-validated only** |
| Cisco IOS | **Syntax-validated only** |
| Juniper Junos | **Syntax-validated only** |
| Fortinet FortiOS | **Syntax-validated only** |
| Palo Alto PAN-OS | **Syntax-validated only** |

The build plan anticipated Libreswan being live-testable too. It is not: the testbed runs
strongSwan only, so Libreswan sits with the other four. Adding a Libreswan container is
the obvious next step and would move exactly one row.

"Syntax-validated" means the generated text is checked for structural correctness and for
the parameters it is supposed to carry. It has **not** been loaded onto a device of that
vendor, in any version, by this project. Vendor CLIs differ across releases; a command
accepted by one IOS train is rejected by another.

This caveat is not confined to this document. Every generated configuration carries a
`DeploymentStatus` banner in its own header, so the file an operator pastes into a change
ticket says what it is — a caveat that lives only in a README does not travel with the
artefact.

Treat those five as a well-informed draft for a network engineer to review, which is what
every change package this tool produces is for anyway. **Nothing here is ever applied
automatically:** there is no code path that writes to a network device, and a test asserts
it.

---

## Other boundaries worth stating

**The capture is the ceiling.** A tunnel that never renegotiated during the window is
invisible; a mirror port that drops packets under load produces an incomplete inventory
and the tool cannot tell that from a quiet network. [DEPLOYMENT.md](DEPLOYMENT.md) covers
sensor placement and sizing for exactly this reason.

**Encrypted means encrypted.** ESP payloads are not decrypted, and nothing in this project
attempts to. Everything said about protected traffic is derived from packet sizes, timings
and directions.

**No IPv6 assessment corpus.** The parser handles IPv6, and the dataset's tunnels are
IPv4. IPv6 behaviour is therefore less exercised than IPv4 behaviour.

**No IKEv2 fragmentation, MOBIKE or EAP-specific rules.** They are parsed where they
appear; there are no rules that judge them.

**Anomaly detection is unsupervised and estate-relative.** It flags tunnels unlike the
rest of *this* estate. In an estate where everything is misconfigured the same way,
nothing looks anomalous.

**Enrichment may be unavailable.** ATT&CK technique names and vendor CVEs come from local
corpora that an air-gapped host often does not have. When they are missing the report says
so, in the report, rather than looking complete.

**Timestamps are the capture's.** Traffic-profile hours come from packet timestamps, so a
capture from a host with a wrong clock produces a wrong maintenance-window suggestion.

---

## Where the honest numbers live

| Question | Document |
|---|---|
| How well does the model actually generalise? | [GENERALISATION.md](GENERALISATION.md) |
| Did it learn traffic shape or cipher configuration? | [CONFOUND_AUDIT.md](CONFOUND_AUDIT.md) |
| What is in the dataset, and what is not? | [DATASET.md](DATASET.md) |
| How is the score computed, and why those weights? | [SCORING.md](SCORING.md) |
| What does each rule check, and against what? | [RULES.md](RULES.md) |
| How secure is the tool itself? | [SECURITY.md](SECURITY.md) |
