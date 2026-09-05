# External dataset audit: IPsec content

*Generated 2026-09-05 13:27 UTC by `scripts/audit_external_datasets.py`.*

## The claim under test

The problem statement points at CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15,
CTU-13, CICIoT2023, LANL and DARPA. Every one was built for intrusion
detection. This audit tests whether any of them contains what an IPsec
analyser actually needs:

* **IKE negotiations** — UDP 500, or UDP 4500 preceded by the non-ESP marker
* **ESP** — IP protocol 50
* **AH** — IP protocol 51

Without a negotiation there is also no label for cipher, DH group, mode or
PFS, because those values exist only inside one.

## Method

Each capture is walked record by record. The link layer is stripped
(Ethernet, VLAN-tagged Ethernet, Linux SLL, raw IP or BSD loopback), the IP
protocol number is read, and UDP source and destination ports are compared
against 500 and 4500. On 4500 the four-byte non-ESP marker is checked, so
ESP-over-UDP is counted separately and never inflates the IKE total.

No sampling: every packet in every file present is examined.

## Positive control

A counter that reports zero proves nothing until it is shown to find IPsec
when IPsec is present. Before auditing anything else, the same code is run
over captures produced by this project's own testbed, which are known to
contain IKE and ESP.

| Capture | Packets | IKE | ESP | AH |
|---|---:|---:|---:|---:|
| `email/capture_outer.pcap` | 6210 | 0 | 6210 | 0 |
| `icmp/capture_outer.pcap` | 120 | 0 | 120 | 0 |
| `messaging/capture_outer.pcap` | 114 | 0 | 114 | 0 |
| `replay/capture_outer.pcap` | 726 | 0 | 726 | 0 |
| `video/capture_outer.pcap` | 20693 | 0 | 20693 | 0 |
| `voip/capture_outer.pcap` | 6001 | 0 | 6001 | 0 |
| `web/capture_outer.pcap` | 28909 | 0 | 28909 | 0 |
| `single_run/capture_outer.pcap` | 16 | 4 | 12 | 0 |
| `email/capture_inner.pcap` | 1318 | 0 | 0 | 0 |
| `icmp/capture_inner.pcap` | 139 | 0 | 0 | 0 |

**Control result: PASS.** The scanner finds both IKE negotiations and ESP in captures known to contain them, so a zero elsewhere is a property of that corpus and not of this code.

## Results

### Corpora not present on this machine

These were not scanned because the files are not here. CIC-IDS2017 and
ISCXVPN2016 require registration with the University of New Brunswick;
`scripts/fetch_external.py` prints the exact steps. LANL is authentication
logs rather than packet captures, so there is nothing to scan in any case.

| Dataset | Why it is named |
|---|---|
| cicids2017 | CIC-IDS2017 — benign + attack traffic, HTTP/HTTPS/FTP/SSH/SMTP only |
| csecicids2018 | CSE-CIC-IDS2018 — extension of 2017, same methodology |
| unswnb15 | UNSW-NB15 — IXIA-generated, nine attack families |
| ctu13 | CTU-13 — thirteen botnet capture scenarios |
| ciciot2023 | CICIoT2023 — IoT DDoS/DoS/Mirai/recon/spoofing |
| lanl | LANL — authentication logs, not packet captures |
| darpa | DARPA — legacy 1998-2000 intrusion captures |
| iscxvpn2016 | ISCXVPN2016 — closest public VPN corpus, but OpenVPN not IPsec |
| mawi | MAWI — backbone background traffic |

This audit reports only what it measured. Where a corpus is absent it says
so rather than inferring a zero from the literature.

## What follows from this

1. **No public corpus supplies IPsec crypto labels.** Even a capture that did
   contain ESP would carry no record of the cipher or DH group negotiated, so
   it could not train or evaluate the identification this problem asks for.
2. **Generating the corpus is therefore objective (a), not a workaround.** The
   testbed configures each tunnel and reads back what was actually negotiated,
   which is the only way to obtain ground truth here.
3. **The named datasets are still used, as inner payload.** Their benign
   traffic is real traffic; replayed through our tunnels it supplies authentic
   packet-size and burst structure while our configuration supplies the labels.
   That is the only technically sound use of them for this problem.

*Reproduce with `python scripts/audit_external_datasets.py`.*
