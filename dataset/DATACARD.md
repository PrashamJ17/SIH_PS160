# Datacard: IPsec Sentinel corpus

*Generated 2026-09-05 20:44 UTC by `scripts/package_dataset.py`.*

## What this is

Packet captures of IPsec tunnels, each labelled with the cryptographic
parameters that were **actually negotiated** and with the application traffic
carried inside. Each cell ships an outer capture (what a passive observer of
the link sees), an inner capture (the cleartext, which supplies the traffic
label) and a manifest recording both intent and reality.

It exists because no public corpus supplies IPsec crypto labels. See
[`docs/external_dataset_audit.md`](../docs/external_dataset_audit.md) for the
measurement behind that claim, and [`docs/DATASET.md`](../docs/DATASET.md) for
methodology and limitations.

## Contents

* **252 cells**, of which **252** negotiated exactly what was configured
* 1,075,251 outer packets, 1,070,771 inner packets
* 1794.8 MiB total

### Cells per traffic class

| Class | Cells |
|---|---:|
| email | 36 |
| icmp | 36 |
| messaging | 36 |
| replay | 36 |
| video | 36 |
| voip | 36 |
| web | 36 |

### Cells per impairment profile

| Profile | Cells |
|---|---:|
| clean | 84 |
| wan_good | 84 |
| wan_poor | 84 |

### Cells per negotiated encryption

| Encryption | Cells |
|---|---:|
| 3DES_CBC | 63 |
| AES_CBC | 119 |
| AES_GCM_16 | 70 |

### Cells per negotiated DH group

| DH group | Cells |
|---|---:|
| CURVE_25519 | 63 |
| ECP_256 | 21 |
| ECP_384 | 35 |
| MODP_1024 | 49 |
| MODP_1536 | 56 |
| MODP_2048 | 28 |

## Labels and how they were obtained

Labels come from **reality, not intent**: every value is read back from
`swanctl --list-sas` (the daemon) and `ip xfrm state` (the kernel) after the
tunnel established. Each manifest carries `negotiation_matched_intent` and a
list of any divergence; a cell where that flag is false describes something
other than what was configured and must be treated accordingly.

**No key material is present.** The kernel prints session keys inline and they
are discarded during parsing, never stored. No credential of any kind appears
in this corpus or the repository that produced it.

## Balance

Every traffic class appears with every negotiated encryption algorithm in
this corpus, so application class is not confounded with cipher. That is the
trap this design most needed to avoid: a classifier trained on a confounded
corpus would read cipher artifacts while appearing to read traffic shape.

## What it is fit for

* Training and evaluating in-tunnel traffic classification
* Evaluating tunnel-versus-transport mode inference
* Testing IKE parsers against real negotiations, including IKEv1 Aggressive Mode
* Benchmarking assessment rules against known-bad configurations

## What it is not fit for

* **Field deployment claims.** Every tunnel is strongSwan on both ends; no
  Cisco, FortiGate, Juniper or Palo Alto behaviour is represented.
* **Consumer messenger identification.** The messaging class is XMPP used as a
  shape proxy; it is not WhatsApp or Signal and has never seen either.
* **Voice quality or codec work.** The VoIP class is synthetic RTP with no SIP
  signalling and no real codec.
* **Timing analysis of replayed cells.** Replay preserves packet sizes but
  distorts inter-arrival timing.

The full limitation list is in [`docs/DATASET.md`](../docs/DATASET.md).

## Integrity

`INDEX.json` records a SHA-256 for every capture and manifest. Packaging
refuses to proceed if any referenced capture is missing or does not read end
to end, so an index never promises data that is not there.
