# Walkthrough

A guided tour of IPsec Sentinel, end to end, using the captures bundled in this
repository. Every command below is runnable as written from the repository root, and
**every block of output was produced by running it** — nothing here is illustrative.

The tour follows the shape of a real engagement: look at one tunnel, then a whole
estate, then discover that the wire was not telling you the whole truth, then fix it.

| Act | What you learn | Time |
|---|---|---|
| [1. First analysis](#act-1--one-tunnel) | What a finding looks like, and what a grade means | 2 min |
| [2. The estate](#act-2--the-estate) | Inventory, and the tunnel nobody documented | 3 min |
| [3. The blind spot](#act-3--what-the-wire-cannot-tell-you) | Why a capture alone can mislead you | 5 min |
| [4. Remediation](#act-4--fixing-it) | A sequenced change package for both ends | 5 min |
| [5. Continuous](#act-5--watching-for-drift) | Drift detection, and honest silence | 3 min |
| [6. Dashboard and SIEM](#act-6--dashboard-api-and-siem) | The other faces of the same engine | 5 min |

---

## Before you start

You need Python 3.11 or newer. Everything in acts 1 to 5 is offline and needs nothing
else — no network, no Docker, no gateway.

```bash
bash scripts/install.sh --prefix /opt/ipsec-sentinel
```

```bash
export PATH="/opt/ipsec-sentinel/bin:$PATH"
```

Confirm the build identity. Every report carries this string, so an assessment can
always be traced back to the code that produced it:

```bash
sentinel version
```

---

## Act 1 — one tunnel

Start with the worst capture in the set: one tunnel, negotiated badly.

```bash
sentinel analyse demo/pcaps/01-worst-ikev1-aggressive-3des-voip.pcap
```

```
0.1.0 (04fdc26)

The tunnel examined is protected by cryptography that is no longer considered safe,
and should be changed. The estate scores 0 out of 100 (grade F).

  tunnels assessed     1
  estate score         0/100 (grade F)
  verified (section A) 8
  inferred (section B) 0
  critical             2
  high                 3
  medium               2
  informational        1
```

Eight findings, all **verified**. That word is load-bearing. Each one was *read* out of
the cleartext IKE exchange — IKEv1 aggressive mode, 3DES, MD5, a 1024-bit MODP group —
and each cites the clause that disallows it. None of them is a guess.

To see them, write the report out:

```bash
sentinel analyse demo/pcaps/01-worst-ikev1-aggressive-3des-voip.pcap --out report.html
```

Open `report.html`. Findings are split into two sections, and the split is the central
design decision of the whole project:

- **Section A — verified.** Parsed from cleartext IKE. No confidence value, because
  there is nothing to be uncertain about. This is what an auditor cites.
- **Section B — inferred.** Derived from encrypted ESP by a model. Always carries a
  calibrated confidence, and abstains when the signal is thin.

A [Pydantic validator](../src/ipsec_sentinel/report/models.py) refuses to build a report
that puts a finding in the wrong section. It raises rather than asserts, because
`python -O` strips assertions and a safety check that vanishes under optimisation is
not a safety check.

### Where the machine learning actually appears

Notice that Section B is empty above. That does **not** mean the classifier did nothing.
Run it with the model:

```bash
sentinel analyse demo/pcaps/01-worst-ikev1-aggressive-3des-voip.pcap --model models/traffic.joblib
```

The summary counts still show `inferred (section B) 0`, because Section B holds inferred
*findings* — anomalies — and this tunnel has none. The traffic classification lands in
the **metadata exposure** section of the report instead, as a property of the tunnel:

```
exposure: a3157cbb2a42  inferred=voip  confidence=1.0  abstained=False
```

The tool identified VoIP from packet sizes and timings alone. It never decrypted
anything — it cannot. That is the point of the exposure section: strong cryptography
protects the *contents* of a tunnel and not the *fact* of it, and a VoIP tunnel is
recognisable from its shape whatever cipher it uses.

> If you are reading the CLI summary and expecting the classifier's verdict there, it is
> not shown. Write the report with `--out` or `--json` to see it.

---

## Act 2 — the estate

One tunnel is a demo. Three is an assessment. `04-estate.pcap` holds three tunnels
between the same hub and three different peers.

A real engagement starts with the customer's documented tunnel list — what they
*believe* exists. One is bundled:

```bash
cat demo/tunnels.yaml
```

Two tunnels are listed. The capture contains three.

```bash
sentinel inventory demo/pcaps/04-estate.pcap --known demo/tunnels.yaml
```

```
  828e1abb53c8  198.51.100.10 <-> 203.0.113.11  documented    3DES_CBC / MD5 / 1024-bit MODP
! 766f2e38dc23  198.51.100.10 <-> 203.0.113.10  undocumented  3DES_CBC / MD5 / 1024-bit MODP
  da10571d54a2  198.51.100.10 <-> 203.0.113.12  documented    ENCR_AES_CBC-256 / AUTH_HMAC_SHA2_384_192 / PRF_HMAC_SHA2_384 / 384-bit ECP

1 tunnel(s) marked ! are not on the documented list.
```

There is a tunnel nobody documented, running 3DES. Finding it required no credential, no
device access, and no scanning — it announced itself by negotiating.

Grade the estate:

```bash
sentinel analyse demo/pcaps/04-estate.pcap --known demo/tunnels.yaml --out estate.html
```

```
Of the 3 tunnels examined, 2 are protected by cryptography that is no longer considered
safe, and should be changed. The estate scores 33 out of 100 (grade F).

  tunnels assessed     3
  estate score         33/100 (grade F)
  verified (section A) 17
```

Two bad, one good. The good one — `da10571d54a2`, `dc-chennai` — negotiated AES-256 with
a 384-bit elliptic curve group. On the wire, it looks healthy.

**Remember that.**

---

## Act 3 — what the wire cannot tell you

Here is the uncomfortable part, and the reason this tool reads more than packets.

A capture shows you what a tunnel **negotiated**, at the moment it negotiated. It cannot
show you what the tunnel is running *now*, because:

- IKE parameters are only in the clear during `IKE_SA_INIT` (or IKEv1 Main Mode).
- **`CREATE_CHILD_SA` is encrypted.** Every rekey after the first is invisible.

So a tunnel that established strong and later rekeyed to something weak looks strong
forever, to anyone reading only the wire. This is not a gap in the implementation. It is
a property of the protocol.

The way to close it is to ask the gateway what it actually has installed. The operator
runs one read-only command and sends you the output:

```bash
ip xfrm state > gw-chennai.xfrm.txt
```

A sample is bundled, standing in for what an operator would send back:

```bash
cat demo/state/gw-chennai.xfrm.txt
```

Now cross-check the capture against it:

```bash
sentinel analyse demo/pcaps/04-estate.pcap --known demo/tunnels.yaml --device-state demo/state/gw-chennai.xfrm.txt
```

```
installed ESP (kernel): 3des/md5
  mode tunnel, replay window 32, spi 0xaaaa0001
  installed SA scores 37/100 (grade F)
    [CRITICAL] CRY-05  3DES encryption installed
               NIST SP 800-131A Rev. 2 (disallowed after 2023)
    [HIGH    ] CRY-06  MD5 integrity installed
               NIST SP 800-131A Rev. 2
    [LOW     ] SA-04  Anti-replay window smaller than 64 packets
               RFC 4303 section 3.4.3
  no IKE parameters in this state, so there is nothing to compare against the capture:
  child_dh_group, dh_group, encryption, ike_version, integrity, pfs, prf

Of the 3 tunnels examined, 3 are protected by cryptography that is no longer considered
safe, and should be changed. The estate scores 12 out of 100 (grade F).

  estate score         12/100 (grade F)
  verified (section A) 20
```

**The estate dropped from 33 to 12.** The tunnel that negotiated AES-256 has 3DES and MD5
installed in the kernel right now. It rekeyed, invisibly, into something disallowed — and
a capture-only assessment would have signed it off as the healthy one.

Three details in that output are worth dwelling on, because each was a bug once:

1. **`3des/md5`, not just one of them.** The kernel prints `enc` and `auth` on separate
   lines, and an earlier version let each overwrite the other, so a 3DES+MD5 SA reported
   only MD5.
2. **`replay window 32`, not 0.** A kernel prints one SA per direction, and the outbound
   one always reports `replay-window 0` because anti-replay is an inbound property. Taking
   the largest window across the tunnel's directions is what stops a false SA-03 on every
   healthy tunnel in an estate. The unit fixture was pinning the bug; only a live pair
   exposed it.
3. **The last line lists what is *absent*.** An ESP SA carries no IKE parameters at all,
   so there is no DH group or IKE version to compare. Saying so explicitly is the
   difference between "we checked and it agrees" and "we could not check". Silence would
   have read as the former.

This is the architectural rule applied to state as well as packets: **absence is reported,
never defaulted.**

Also note what did *not* happen. The tool did not connect to the gateway. It read a text
file someone handed it. There is no SSH client, no NETCONF client and no vendor API client
in this codebase — a test walks the AST of every module to keep it that way.

---

## Act 4 — fixing it

Findings without a fix are just criticism. Generate a change package:

```bash
sentinel remediate demo/pcaps/01-worst-ikev1-aggressive-3des-voip.pcap --vendor strongswan --out change-package/
```

```
=== a3157cbb2a42 ===
a3157cbb2a42: 8 finding(s), 5 step(s), ~0s disruption, risk single_tunnel (maintenance window required)

  assumption: SA lifetimes are local policy and IKEv2 does not carry them on the wire;
  the testbed defaults are used and the lifetime rules should be read from the
  operator's configuration instead

  assumption: perfect forward secrecy and the child key exchange group are negotiated
  inside an encrypted exchange and were not observed; PFS is assumed enabled and the
  child group assumed to match the IKE group

  1. [both] Rotate the pre-shared key before anything else. Aggressive Mode has already
     exposed a crackable hash of the current key, so reusing it carries the compromise
     forward into the corrected tunnel.

  2. [both] Add aes256gcm16-prfsha256-curve25519 alongside the existing
     3des-md5-prfmd5-modp1024 on both ends. Both proposals are offered, so the tunnel
     keeps negotiating 3des-md5-prfmd5-modp1024 until it is told otherwise.

  3. [both] Establish a second SA under the reloaded configuration, confirm it negotiated
     aes256gcm16-prfsha256-curve25519, then retire the SA still running
     3des-md5-prfmd5-modp1024. Do not rekey the existing SA: a running SA keeps the
     configuration it was established with, so a rekey renegotiates
     3des-md5-prfmd5-modp1024 and the change silently does nothing. This is the point of
     no return — if the new SA does not report aes256gcm16-prfsha256-curve25519, stop here
     and investigate rather than continuing.

  4. [both] Remove 3des-md5-prfmd5-modp1024 from both ends, leaving
     aes256gcm16-prfsha256-curve25519 alone. Safe only because step 3 proved the tunnel is
     already running on aes256gcm16-prfsha256-curve25519.

  5. [both] Confirm the tunnel is still established with the weak proposal gone, and that
     traffic is still passing.

  written: change-package/a3157cbb2a42.local.swanctl.conf
  written: change-package/a3157cbb2a42.peer.swanctl.conf
```

Four things in there are worth naming:

- **`~0s disruption.`** The sequence adds the strong proposal *alongside* the weak one,
  proves the tunnel moved, and only then removes the weak one. Nobody is cut off.
- **Step 3 is a warning, not an instruction.** Rekeying an existing SA renegotiates the
  configuration it was established with — the change would silently do nothing. That is a
  real operational trap and the generator says so at the point where it matters.
- **Both ends.** `local` and `peer` configuration are generated together, because a
  proposal change applied to one end is an outage.
- **The assumptions are printed, not buried.** Two parameters could not be observed. The
  tool says which, and says what it assumed instead of quietly assuming it.

Six platforms are supported: `strongswan`, `libreswan`, `cisco`, `fortigate`, `juniper`,
`paloalto`. Only strongSwan and Libreswan are verified against a running daemon; the other
four are syntax-validated only, which [LIMITATIONS.md](LIMITATIONS.md) states plainly.

**Nothing is applied.** The files are for a human to review and push.

---

## Act 5 — watching for drift

A one-off assessment ages. `watch` follows an interface and reports when a tunnel gets
*weaker than it used to be* — measured against its own history, not against the baseline,
so a tunnel that was always mediocre does not alert nightly.

Against a file, so you can try it without an interface:

```bash
sentinel watch eth0 --from-capture demo/pcaps/04-estate.pcap --for 3
```

```
Watching demo/pcaps/04-estate.pcap against baseline nist_800_77r1. A tunnel seen for the
first time sets its own baseline; only a later weakening is reported.
0 drift alert(s).

3 tunnel(s) have not been seen negotiating recently. Their current parameters are
unverified, not confirmed unchanged:
  198.51.100.10 <-> 203.0.113.11: last seen negotiating 50.3h ago as
    3des-md5-prfmd5-modp1024. Its parameters since then are unverified, not confirmed
    unchanged.
  ...
```

Zero alerts — correct, since every tunnel is being seen for the first time and sets its
own baseline.

The paragraph after it is the interesting one. **An empty alert log and a quiet network
look identical unless something says which.** So the tool distinguishes them: these three
tunnels have not renegotiated recently, and their current parameters are therefore
*unverified*, which is not the same as *confirmed unchanged*. This is the rekey blind spot
from Act 3, stated rather than hidden — and `--device-state` is how you close it.

On a real interface, with alerts to a SIEM:

```bash
sudo sentinel watch eth0 --syslog siem.internal:514 --state /var/lib/sentinel/seen.json
```

`--state` makes drift survive a restart. Without it, every restart forgets what each
tunnel used to negotiate, and the first sighting after a reboot silently becomes the new
baseline.

---

## Act 6 — dashboard, API and SIEM

The same engine has three other faces.

### The dashboard

```bash
docker compose up -d
```

The engine listens on `127.0.0.1:8000`, the dashboard on `127.0.0.1:8080`. Drop captures
into `./captures`. Upload a capture, get the estate grade, drill into a tunnel, and read
the SHAP explanation behind an inference.

![The IPsec Sentinel dashboard](images/dashboard.png)

The page is served under a Content Security Policy with **no `unsafe-inline` at all**. The
stylesheet and script were split out of the HTML specifically so the policy could forbid
inline execution rather than permit it.

### The HTTP API

```bash
curl -F file=@demo/pcaps/04-estate.pcap "http://127.0.0.1:8000/api/v1/analyse?baseline=nist_800_77r1"
```

Then `GET /api/v1/reports/{id}`, `/tunnels`, `/findings`, `/inventory`. Uploads are capped
at 512 MB; the command line has no limit.

Reports are held **in memory and never written to disk** by the service. That is
deliberate: persisting them would mean holding an estate's tunnel inventory and endpoint
addresses on disk inside something reachable over the network.

### SIEM export

```bash
sentinel analyse demo/pcaps/04-estate.pcap --json estate.json
```

The JSON is versioned and validated against a published schema in [`schemas/`](../schemas).
CEF, LEEF and RFC 5424 syslog are produced by the same report object, so a SIEM alert and
the PDF on the auditor's desk cannot disagree.

---

## When it does not work

Four failures you are likely to hit first, and what they mean.

**"not a packet capture"** — Wireshark saves **pcapng** by default and this parser reads
classic **pcap**. Re-save as pcap, or convert:

```bash
mergecap -F pcap -w capture.pcap capture.pcapng
```

**Lots of ESP flows, no findings.** You captured a running tunnel but never saw it
establish. IKE parameters are only readable at `IKE_SA_INIT`. Start the capture *before*
the tunnel comes up, or supply `--device-state`.

**"no matching distribution" during an offline install.** The offline bundle is built for
one Python version. `BUNDLE.json` records which; the installer refuses before creating a
virtualenv rather than failing halfway.

**Everything scores zero on a live capture.** Check you are not looking at a capture taken
*inside* the tunnel. `iter_ip_packets` will happily read decrypted inner traffic and find
no IKE at all.

---

## Command reference

| Command | What it does | Transmits? |
|---|---|---|
| `sentinel analyse` | Assess a capture, write HTML / JSON / PDF | No |
| `sentinel inventory` | List tunnels, flag undocumented ones | No |
| `sentinel remediate` | Generate a sequenced change package | No |
| `sentinel watch` | Follow an interface, alert on drift | No |
| `sentinel scan` | Enumerate what a gateway *accepts* | **Yes** |
| `sentinel model` | Train and evaluate the classifier | No |
| `sentinel dataset` | Build, package and audit the dataset | No |
| `sentinel version` | Print the build identity | No |

`scan` is the only command that puts a packet on the wire. It refuses to run without
`--i-have-authorisation`, and the refusal is enforced in the library, not just the CLI, so
importing the function directly does not bypass it.

---

## Where to go next

- [ARCHITECTURE.md](ARCHITECTURE.md) — the two-lane design, and the validator that enforces it
- [RULES.md](RULES.md) — all 26 rules with their standard references
- [LIMITATIONS.md](LIMITATIONS.md) — **read this before quoting a grade to anyone**
- [DEPLOYMENT.md](DEPLOYMENT.md) — mirror ports, TAPs, sensor sizing, air-gapped install
- [GENERALISATION.md](GENERALISATION.md) — how well the classifier holds up off its training distribution
