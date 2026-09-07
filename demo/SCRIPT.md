# Demo script — ten minutes

Seven beats. Every number below is produced by `run_demo.sh` on the captures in
`demo/pcaps/`, and `tests/integration/test_demo.py` runs the script and asserts each
claim — so if a number here is wrong, the build is red.

**Before you start**

```bash
bash demo/run_demo.sh
```

Without `--quiet` it pauses between beats and waits for Enter, so you control the pace.
Nothing needs a network, a device, or a live tunnel. Rehearse it three times.

**If everything fails:** `demo/fallback.mp4` is a recording of this exact script running.
Play it and narrate over the top. Do not debug on stage.

---

## The captures

| File | What it is |
|---|---|
| `01-worst-ikev1-aggressive-3des-voip.pcap` | One tunnel. IKEv1 aggressive mode, PSK, 3DES, 1024-bit MODP, carrying VoIP. |
| `02-weak-ikev1-aggressive-3des-email.pcap` | One tunnel. Same weaknesses, carrying email. |
| `03-strong-ikev2-aes256-ecp384-voip.pcap` | One tunnel. IKEv2, AES-256, ECP-384, carrying VoIP. |
| `04-estate.pcap` | The three merged into one three-site estate. |

All four are real captures from the strongSwan testbed. `04-estate.pcap` is the other
three with their IP addresses rewritten to RFC 5737 documentation ranges so each
represents a different site — `demo/build_estate.py` does it, and changes nothing else.
**Say this out loud if a judge asks.** The packets, the negotiations and the traffic are
untouched; only the addresses differ.

---

## 0:00 — Beat 1 · The same capture, in a protocol analyser

> "This is a packet capture from a VPN gateway. Here it is in tshark — the tool every
> network engineer already has."

*(the frame list appears: exchange type 4)*

> "Everything is here. Source, destination, exchange type 4. Wireshark will happily
> decode every field.
>
> What it will not tell you is that exchange type 4 is IKEv1 Aggressive Mode, that NIST
> SP 800-77 tells you not to use it, that with a pre-shared key it leaks a crackable
> hash to anyone who asks, or what to put in its place.
>
> That gap — between *visible* and *judged* — is what we built."

**Timing: 90 seconds. Do not linger.**

---

## 1:30 — Beat 2 · The same capture, in Sentinel

> "Same file. One command."

*(grade F, 0/100, 8 verified findings)*

> "Grade F. Eight findings, and every one of them cites the clause it comes from —
> 3DES against NIST SP 800-131A, which disallowed it after 2023. A 1024-bit
> Diffie-Hellman group. MD5. Aggressive mode with a pre-shared key.
>
> These are not opinions. Each one was read off the wire, and an auditor can check every
> citation."

If asked *how many rules*: **26**, each carrying its standard reference — `docs/RULES.md`
is generated from the registry itself, so it cannot drift.

**Timing: 90 seconds.**

---

## 3:00 — Beat 3 · The estate, and the tunnel nobody documented

> "One tunnel is a demo. Here is an estate — three sites, and the operator's own
> documented tunnel list."

*(3 tunnels, 1 undocumented, estate grade F, 33/100)*

> "Two tunnels are documented. The wire has three.
>
> That third one is a tunnel nobody wrote down. It is not in the CMDB, it is not in the
> change log, and it is the weakest one here."

This is the beat that lands with an operations audience. **Pause here.**

**Timing: 90 seconds.**

---

## 4:30 — Beat 4 · What the undocumented tunnel is carrying

> "So what is going through it?"

*(inferred traffic: voip, confidence 1.00, with the SHAP contributions)*

> "The payload is encrypted, and we never decrypt it. This is packet size, timing and
> direction — nothing else.
>
> And it tells you *why*: packet size entropy, burst length, size variation. Those are
> the fingerprints of a voice codec.
>
> Now — this is an **estimate**. It sits in Section B of the report, it carries a
> confidence, and a validator refuses to build a report that puts it in Section A next
> to the parsed facts. When the signal is thin the model abstains and says so, rather
> than guessing.
>
> An auditor reads Section A. An engineer deciding what to fix first reads Section B.
> Mixing them produces a document that does neither job."

**This is the intellectual centre of the pitch.** If you have to cut a beat, do not cut
this one.

**Timing: 90 seconds.**

---

## 6:00 — Beat 5 · The change package, both ends, sequenced

> "Knowing is half of it. Here is the fix."

*(four configuration files: local and peer, for each of the two weak tunnels)*

> "Configuration for **both ends**, because a one-sided IPsec change is an outage.
> Reconstructed from what the peer actually negotiated, not from what a document claims
> it runs.
>
> And it is sequenced. A proposal change applied in the right order costs **zero packet
> loss** — we measure that on a live strongSwan pair in the integration suite.
>
> The tool generates this. **A person applies it.** There is no SSH client in this
> codebase, no NETCONF client, no vendor API client — and a test walks the syntax tree of
> every module to keep it that way. A wrong finding costs a wasted review, never an
> outage."

**Timing: 90 seconds.**

---

## 7:30 — Beat 6 · Proving the fix landed

*(before: grade F, 8 findings — after: grade A, 1 finding, PQC-01)*

> "Verification reads a follow-up capture and closes a finding only when the fix is
> actually on the wire. Not when someone ticks a box.
>
> Grade A. One finding left, and it is the post-quantum one — which is the next beat."

With `--with-testbed` this beat runs the real remediation on a live strongSwan pair and
measures the packet loss. **Only do that if you have rehearsed it and have the time.**

**Timing: 90 seconds.**

---

## 9:00 — Beat 7 · Post-quantum readiness, and a different authority

*(three tunnels, all AT_RISK; then the same capture under ITSAR)*

> "Every tunnel here is at risk from harvest-now-decrypt-later. Traffic captured today
> is decryptable in retrospect once the hardware exists — that is about traffic already
> on the wire, not just future sessions.
>
> And the last thing: same capture, same parse, different authority. That was NIST. This
> is ITSAR, India's telecom security standard — 17 findings instead of 8.
>
> One capture. Whichever regulator you have to answer to."

**Timing: 60 seconds. Stop talking.**

---

## Questions you will be asked

**"How is this different from Wireshark?"**
> Wireshark decodes. This judges, cites, and tells you what to do. Beat 1 versus beat 2 is
> the whole answer.

**"How accurate is the traffic classification?"**
> 95.5% on held-out configurations — crypto settings the model has never seen, which is
> the number closest to deployment. 99.2% on held-out captures. Both are in
> `docs/GENERALISATION.md`, along with what degrades and why. It was trained on 637 rows
> of laboratory traffic, and `docs/DATASET.md` says what that costs.

**"Can it fix things automatically?"**
> No, deliberately. It generates configuration; a person applies it. There is no code path
> that writes to a device and a test enforces that.

**"What can it not do?"**
> It sees what tunnels *negotiated*, not what a gateway would *accept* — a device
> configured to accept 3DES whose peers all choose AES looks clean. `sentinel scan`
> answers the capability question actively, and refuses to run without an explicit
> authorisation flag. `docs/LIMITATIONS.md` is four pages of this, and it is the document
> we would want a technical judge to read.

**"Is it production ready?"**
> It runs air-gapped, in a container, as a non-root user, with no credentials anywhere.
> It has not had a third-party penetration test, and `docs/SECURITY.md` says so.

**"Which vendors are supported?"**
> Six generators. **One** — strongSwan — is loaded and negotiated on a live daemon in the
> test suite. The other five are syntax-validated only, every generated file says so in
> its own header, and the limitations document has the table.

---

## Rehearsal checklist

- [ ] Run `bash demo/run_demo.sh` three times end to end.
- [ ] Time yourself. The beats are 90 seconds each; the demo runs in seconds, so the
      clock is entirely your talking.
- [ ] Know the four answers above without reading them.
- [ ] Have `demo/fallback.mp4` open in a second window before you start.
- [ ] Check the terminal font size from the back of the room.
