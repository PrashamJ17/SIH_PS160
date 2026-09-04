# AI-Driven IPsec VPN Protocol Analysis Platform
## Complete Project Reference Document

**Smart India Hackathon — Problem Statement Analysis, Technical Foundations, Architecture, Feasibility, and Strategy**

---

**Document status:** Complete working reference, compiled from a full analysis session.
**Scope:** Every question asked and every answer given, reproduced in full detail.
**Intended use:** Team onboarding, technical reference during build, pitch preparation, and documentation source material.

---

## How to use this document

This is not a summary. It is the complete record, reorganised into a usable order.

- **Sections 1–2** establish what the problem actually is and whether it can be built. Read these first, as a team.
- **Sections 3–5** cover the dataset problem, the technical foundations, and the competitive landscape. Read before designing anything.
- **Sections 6–7** are the protocol deep-dive. Whoever writes the parser must read these.
- **Sections 8–10** cover the product, the AI positioning, and the pitch. Read before the finale.
- **Appendices** are lookup material — rule tables, RFC references, glossary, checklists.

---

## Table of contents

1. [The problem statement, decoded](#1-the-problem-statement-decoded)
2. [Feasibility, datasets, and the winning assessment](#2-feasibility-datasets-and-the-winning-assessment)
3. [Building your own dataset](#3-building-your-own-dataset)
4. [The technical foundations in plain language](#4-the-technical-foundations-in-plain-language)
5. [What exists today, and how your project compares](#5-what-exists-today-and-how-your-project-compares)
6. [IPsec from first principles](#6-ipsec-from-first-principles)
7. [IKE, ISAKMP, and the negotiation layer](#7-ike-isakmp-and-the-negotiation-layer)
8. [How the software works, end to end](#8-how-the-software-works-end-to-end)
9. [Where the AI actually lives](#9-where-the-ai-actually-lives)
10. [Additional features and winning the panel](#10-additional-features-and-winning-the-panel)
11. [Appendices](#11-appendices)

---
---

# 1. The problem statement, decoded

> **Original question:** Explain this problem statement.

## 1.1 The core ask

You are being asked to build a tool that looks at network traffic from an IPsec VPN and tells a security analyst, automatically, what that VPN is doing and whether it is configured safely.

Right now, if you want to know whether an organisation's VPN uses AES-256-GCM with a strong Diffie-Hellman group and Perfect Forward Secrecy, you open the capture in Wireshark, find the IKE handshake, read the proposal payloads by hand, and know enough about RFC 7296 and NIST guidance to judge whether what you are seeing is good or bad.

That is expert work and it does not scale. The problem statement wants that expertise encoded into software, with a machine learning layer on top for the parts that cannot be read directly.

## 1.2 Breaking down the five objectives

### (a) VPN Testbed Generation

You have no dataset, so you have to manufacture one. Build a lab — usually Docker containers or VMs running strongSwan or Libreswan — where you can programmatically stand up VPN tunnels across the whole configuration matrix:

- Tunnel mode vs Transport mode
- AES-128 vs AES-256
- AES-GCM vs AES-CBC + HMAC
- Several DH groups
- Perfect Forward Secrecy enabled and disabled
- IPv4 and IPv6

Then push different kinds of traffic through each tunnel: ICMP pings, HTTP browsing, a VoIP call, video streaming, email, messaging. Every combination gives you labelled data, because you configured it and therefore know the ground truth.

This is the least glamorous part and usually the largest time sink. **Automate it.** A config-driven script that spins up a tunnel, runs a traffic generator, captures, tears down, and repeats will save you weeks.

### (b) Traffic Capture

Straightforward tcpdump or Scapy work, but capture at the right point. You need:

- The IKE negotiation on UDP 500 (or 4500 when NAT traversal is in play)
- The ESP packets that follow
- Ideally the plaintext side of the tunnel too, since that is your ground truth for what application traffic was inside

### (c) AI-Based Protocol Identification

This is where the problem statement blurs two very different tasks, and understanding the difference matters enormously for how you build it.

**Some of the listed attributes are readable from the wire.** In IKEv2, the IKE_SA_INIT exchange is unencrypted, and it contains the SA payload listing the proposed encryption algorithm, integrity algorithm, PRF, and DH group, plus the actual key exchange payload. You do not need machine learning for that. You need a parser. The same applies to detecting that a packet is ESP versus AH, or reading the SPI and sequence number from an ESP header.

**Other attributes are genuinely hidden.** Tunnel versus transport mode is negotiated inside IKE_AUTH, which is encrypted. So you infer it — from packet size distributions (tunnel mode adds a full extra IP header of overhead), from whether the endpoints look like gateways or hosts, from the addressing structure. That is a classification problem.

**And "predict the type of traffic inside ESP" is the real machine learning core of this project.** The payload is encrypted; you cannot read it. What you can see is the shape of the flow: packet sizes, inter-arrival times, burstiness, directionality, flow duration. VoIP looks like a steady stream of small equal-sized packets at 20ms intervals. Video streaming looks like large bursts followed by idle gaps. Web browsing looks like a request-response sawtooth. ICMP looks like nothing else.

You extract statistical features from windows of traffic and train a classifier. Random forest and gradient boosting work well here; 1D CNNs or LSTMs if you want sequence modelling. This is a well-established research area called encrypted traffic classification, and it is the part judges will care about most.

**Design principle:** be explicit about which facts are parsed and which are inferred, and attach confidence only to the inferred ones. A system that claims 87% confidence about something it read verbatim from a cleartext header looks unserious.

### (d) Security Assessment

This is a rules engine, not a model. You take the extracted configuration and score it against known-good baselines:

- DH Group 2 (1024-bit MODP) is weak
- 3DES and MD5 are deprecated
- AES-CBC without a separate integrity check is dangerous
- PFS disabled means a compromised long-term key exposes all past sessions
- Long SA lifetimes increase exposure
- Missing anti-replay is a risk
- Aggressive Mode in IKEv1 leaks identity information

Encode these as a rule set with references to NIST SP 800-77, RFC 8221, and the organisation's compliance baseline, so each finding cites why it is a finding. **That citation is what turns output into a report an analyst will trust.**

"Metadata exposure" is a separate idea and a valuable one to include: even a perfectly configured tunnel leaks who is talking to whom, when, how much, and — per objective (c) — roughly what kind of application is running. Your tool demonstrating that leakage is itself a security finding.

### (e) Reporting

Two audiences:

- **Executive report:** a risk score, a red/amber/green summary, and a short list of what to fix.
- **Technical report:** the parsed SA parameters, the packet evidence, the rule that triggered each finding, and remediation config snippets.

The threat matrix maps findings to attack scenarios. Mapping to MITRE ATT&CK techniques is an easy way to make it look professional.

## 1.3 The parts that will actually be hard

**Deciding where AI belongs.** Much of this problem is deterministic parsing dressed up in AI language. Resist the urge to throw a model at everything. Use parsing where parsing works, use ML for encrypted traffic classification and for anomaly detection over configurations, and say clearly which is which.

**Dataset realism.** A classifier trained only on your lab traffic will overfit to your lab. Vary conditions, add latency and loss, use real applications rather than synthetic generators where you can, and hold out entire configurations from training so you can prove generalisation.

**Confidence calibration.** The problem statement asks for an AI confidence score. A model that outputs 0.99 on everything is useless. Look at calibration, and consider abstaining when uncertain.

**Live capture.** Real-time is much harder than offline PCAP analysis. Build offline first, then add a streaming path if time allows.

## 1.4 What the deliverables imply

A working prototype, a trained classification engine, a dashboard, sample reports, a demo video, documentation, and the dataset.

**That last one matters more than teams usually expect.** A cleanly packaged, labelled IPsec dataset with the generation scripts is a contribution in its own right, and it is the artifact that proves your results are reproducible rather than hand-picked.

---
---

# 2. Feasibility, datasets, and the winning assessment

> **Original question:** If I were to use AI to build this complete project end to end — all objectives met and achieved — can it happen? Will I be able to make it from start to end? What additional features must I integrate to impress the SIH judges and panels? How will the government use it? Is it actually buildable? Does it have real-world impact? Will I win the hackathon? What are the chances?

## 2.1 Headline assessment

**Yes, a strong version is buildable in a hackathon timeframe with heavy AI/LLM coding help — but only if you re-scope it honestly.**

The deterministic parts (parsing IKE negotiations, auditing crypto parameters against NIST/BSI/Indian baselines, auto-generating remediation configs) are the winnable core. The "AI identifies encryption algorithm and DH group from captured traffic" framing is largely a myth for ESP and should be reframed as ML for application-inside-tunnel classification plus deterministic parsing of the cleartext IKE handshake.

**The datasets named in the problem statement contain essentially no labelled IPsec traffic and cannot support the stated crypto-identification objective.** No public IPsec PCAP corpus with ground-truth labels for cipher, DH group, mode or PFS exists. A winning team must generate its own testbed captures. This is exactly objective (a) and should be treated as a feature, not a chore.

**Realistic odds are moderate-to-good but not high.** A security/defence problem statement from NCIIPC/NTRO draws fewer but more serious teams. The official SIH selection process nominates roughly 5–7 colleges per problem statement for the grand finale, with one ₹1 lakh winner per statement. Your edge comes from clear-eyed scoping, mapping to Indian standards (ITSAR, CERT-In, NCIIPC), PQC-readiness, and a working demo — not from over-promising an AI that "breaks" IPsec.

## 2.2 The dataset premise is misleading — this is the most important finding

The problem statement points to a list of well-known network-security datasets. Every one of them was built for intrusion or anomaly detection, not IPsec analysis.

| Dataset | What it contains | IPsec content |
|---|---|---|
| **CIC-IDS2017** | ~50 GB PCAP + 80-feature CSVs (CICFlowMeter), 5 days, benign + brute-force/DoS/DDoS/web/infiltration/botnet. Benign profiles use HTTP, HTTPS, FTP, SSH, SMTP only. | None |
| **CSE-CIC-IDS2018** | Extension of 2017, same methodology, adds Heartbleed/botnet/DDoS. | None |
| **UNSW-NB15** | 100 GB PCAP, 2.54M records, 49 features, 9 attack families (Fuzzers, Exploits, Generic, DoS), IXIA-generated. | None |
| **CTU-13** | 13 botnet capture scenarios (IRC, spam, click-fraud, DDoS, port-scan) as PCAP. | None |
| **CICIoT2023** | 46.7M records / 99 GB / 79 PCAPs, IoT DDoS/DoS/Mirai/recon/spoofing. | None |
| **LANL** | Authentication logs. | None |
| **DARPA** | Legacy 1998–2000 intrusion captures. | None |
| **MITRE ATT&CK / CAPEC / CVE-NVD** | Knowledge bases, not traffic. Useful for mapping and enrichment. | N/A |

**None of these contain IKEv1/IKEv2 negotiations (UDP 500/4500), ESP (IP proto 50) or AH (IP proto 51) packets with ground-truth labels for encryption algorithm, DH group, tunnel-vs-transport mode, or PFS.**

Dedicated follow-up research confirmed that **no public IPsec-specific PCAP corpus with crypto-parameter ground-truth labels exists at all.**

### The closest public VPN datasets

**ISCXVPN2016 (UNB)** — the canonical VPN/non-VPN dataset (7 traffic categories: browsing, email, chat, streaming, file transfer, VoIP, P2P). Its "VPN" captures are **OpenVPN**, not IPsec. Researchers have documented serious quality problems: per Aceto et al.'s DISTILLER analysis (2021), roughly 65% of the biflows have only one UDP packet and destination (255.255.255.255, 10505) — network broadcasts sent every two seconds by default by BlueStacks. Later work (FlowCLIP) notes 98.9% of some of its traffic is actually unencrypted. It must be cleaned before use.

**VNAT** — 165 PCAPs / 36.1 GB / ~272 hours. VPN side is OpenVPN, no IPsec, no crypto labels.

**USBVPN2022 (Naas & Fesl, Data in Brief 2023)** — includes an L2TP-IPSEC subset (2.5 GB, 1,955 flows) among 6 VPN protocols, but stored as JSON flow records (not raw PCAP), labelled only by VPN-protocol type. No cipher/DH/mode/PFS ground truth.

A 2022 ML tunnel-classification study explicitly states its authors could not find any data for IPsec, OpenVPN or WireGuard and had to build their own testbed to capture IPsec tunnel traffic.

### Implication

Objective (a) "testbed generation" is not optional busywork — it is the *only* way to obtain labelled IPsec data, and it should be the backbone of your project. Build a reproducible strongSwan/Libreswan testbed (Docker Compose) that spins up tunnels across a matrix of ciphers, DH groups, PFS on/off, tunnel/transport, IKEv1/IKEv2, then captures PCAPs with the configuration as the label.

That single artifact simultaneously solves your data problem and demonstrates rigour to judges.

## 2.3 Most of "AI-based protocol identification" is deterministic parsing

This is a crucial technical truth that will impress security-literate judges if you state it plainly, and will sink you if you pretend otherwise.

### Readable in cleartext — no ML, no keys needed

- **IKEv2 IKE_SA_INIT (RFC 7296)** is sent in the clear. Its SA payload contains the proposed and accepted transforms: encryption algorithm (e.g. ENCR_AES_GCM_16), integrity algorithm, PRF, and DH group. The KE payload (Diffie-Hellman value) and nonces are also visible. RFC 7296 §1.2 states the first pair of messages "negotiate cryptographic algorithms, exchange nonces, and do a Diffie-Hellman exchange."
- **IKEv1** main/aggressive mode SA payloads similarly expose transform sets. Aggressive mode additionally leaks the identity and a PSK hash — the basis for ike-scan/psk-crack attacks.
- **ESP headers:** SPI and sequence number are always in cleartext; everything after is encrypted.

### Encrypted — requires the key, or must be inferred

- IKE_AUTH exchange: identities, certificates, traffic selectors, and crucially the tunnel-vs-transport mode negotiation. RFC 7296: "Parts of these messages are encrypted and integrity protected with keys established through the IKE_SA_INIT exchange, so the identities are hidden from eavesdroppers."
- The actual data inside ESP.

### The honest three-lane architecture

**Lane 1 — Deterministic IKE parser** (the bulk of objective c): read IKE_SA_INIT, extract cipher/integrity/PRF/DH group, IKEv1-vs-v2, aggressive-mode detection. Wireshark's ISAKMP dissector and Zeek's corelight/zeek-spicy-ipsec analyzer already log transforms, ke_dh_groups, proposals and notify_messages, so your value-add is the assessment layer, not the parsing.

**Lane 2 — Active probing** (optional, powerful): integrate ike-scan/iker/IKESS to enumerate all transforms a gateway will accept, not just what one client negotiated. This is how you find that a device still accepts 3DES/DH-2/aggressive mode even if the observed session used AES. ike-scan's default probe sends 8 transforms covering DES/3DES × MD5/SHA-1 × DH groups 1/2.

**Lane 3 — ML** for the genuinely inferential parts: classifying the application inside an ESP tunnel from side-channel features, and inferring tunnel-vs-transport from packet-size overhead and address structure heuristics.

## 2.4 Encrypted traffic classification: state of the art

The academic literature is large and the accuracy numbers look impressive but come with heavy caveats.

- Classic time-related-feature work on ISCXVPN2016 (Draper-Gil et al.) reports ~92% recall over six traffic classes using kNN/C4.5. Many later papers report 96–99%+ (random-forest and CNN/autoencoder approaches, up to 99.2% non-VPN / 98.3% VPN in the Semi-2DCAE work).
- **Directly relevant to IPsec:** Okada et al. (IEEE CQR 2011 and ICMLA 2011) classified applications inside IPsec/PPTP tunnels using statistical features + SVM. Per the MDPI *Applied Sciences* review (13(3):1974), the best Estimated Feature Method using SVM identified IPsec tunnel traffic with **97.2% accuracy** (Okada selected 29 features with correlation >0.7), with a further **28.5% improvement** in protocol identification accuracy when mixed with HTTP, FTP, SMTP and SSH passenger protocols. Kumano et al. (ICNC 2014) achieved 92.5% in a real-time variant.
- A 2022 study found IPsec and WireGuard are actually *easier* to classify inside than SSH/OpenVPN, with random forest and decision tree performing best, using packet-size-with-direction and byte-burst features.
- ET-BERT, 1D-CNN, LSTM and flow-image transformer approaches report the highest headline numbers but are least practical for a 36-hour finale and most prone to dataset overfitting.

### Methodological caveats you must state

Judges from NTRO/NCIIPC will know these:

- Most numbers are **closed-world** (fixed known app set); open-world generalisation collapses.
- Cross-dataset validation is notoriously poor.
- IPsec differs from OpenVPN/TLS in ways that matter — ESP padding, tunnel-mode encapsulation overhead, and block-cipher padding blur packet-size features. Figures from OpenVPN datasets do not transfer directly.

**Recommended stack for a hackathon:** random forest / XGBoost on flow-statistical features (fast, explainable, defensible), with a 1D-CNN as an optional comparison. Add SHAP/LIME for explainability and confidence calibration plus abstention so the tool says "I don't know" rather than guessing.

## 2.5 Existing tools and the real gap

Parts of this already exist:

- `ike-scan` — transform enumeration, backoff/VID fingerprinting, PSK cracking via psk-crack
- `iker`/`IKESS` — wrappers producing risk-rated JSON/HTML reports
- nmap `ike-version`
- Wireshark ISAKMP/ESP dissectors
- **Zeek's corelight/zeek-spicy-ipsec** — logs transforms, DH groups, proposals, notify messages, vendor IDs
- strongSwan diagnostics and `save-keys`
- Nessus/OpenVAS IKE plugins
- Commercial VPN/firewall auditors

**The genuine gap your project can fill:** none of these is a unified, AI-assisted, India-standard-aware assessment platform that:

1. Ingests both passive PCAP and active scan results
2. Grades a configuration against multiple baselines simultaneously (NIST SP 800-77r1, RFC 8221/8247, CNSA, BSI TR-02102-3, ANSSI, **and Indian ITSAR/CERT-In/NCIIPC**)
3. Maps findings to MITRE ATT&CK/CAPEC and pulls relevant strongSwan/Libreswan/racoon CVEs
4. Assesses PQC-readiness
5. Auto-generates fixed configs

That integration plus Indian-context layer is defensibly novel for SIH even though no individual component is.

## 2.6 Security assessment baselines to encode

### International

- **NIST SP 800-77 Rev.1** — Barker, Dang, Frankel, Scarfone & Wouters, "Guide to IPsec VPNs," published 30 June 2020 (DOI 10.6028/NIST.SP.800-77r1). The primary reference.
- **RFC 8221 (ESP/AH)** and **RFC 8247 (IKEv2)** — MUST/SHOULD/SHOULD NOT algorithm tables; deprecate 3DES, DES, MD5, DH-1/2/5.
- **CNSA / CNSSP-15** — US national-security suite: AES-256, SHA-384/512, ECDSA P-384, RSA-3072+. **CNSA 2.0** now mandates ML-KEM-1024 / ML-DSA-87 (FIPS 203/204).
- **BSI TR-02102-3** — German IPsec crypto guideline; recommends PFS, flags SHA-1, states (EC)DH sole use is only recommended until end of 2031 with ml-kem-768/1024 as the quantum-safe path.
- **ANSSI** IPsec recommendations and **CIS Benchmarks** for vendor configs.

### Indian — your differentiator

- **ITSAR** (Indian Telecom Security Assurance Requirements) from **NCCS** under DoT mandate NIST-recommended crypto (IPsec/TLS/SSH, AES/DH/RSA/SHA); ITSAR certification is valid 10 years.
- **CERT-In 2022 Directions** — 6-hour incident reporting, 180-day log retention, 5-year VPN subscriber logs; binding under IT Act §70B(6).
- **NCIIPC guidelines** for Critical Information Infrastructure.

### Weak configurations to flag

DH groups 1/2/5; 3DES; DES; MD5; SHA-1; IKEv1 aggressive mode; missing PFS; AES-CBC without integrity; over-long SA lifetimes; disabled anti-replay.

### Post-quantum layer

- **RFC 8784** — post-quantum preshared keys for IKEv2
- **RFC 9370** — multiple key exchanges in IKEv2, up to 7 KEMs in parallel with classical DH
- **draft-ietf-ipsecme-ikev2-mlkem**
- strongSwan 6.x + liboqs support hybrid `ke1_mlkem768`
- Government timelines: NSA CNSA 2.0 targets PQC capability by 2025 and exclusive use by 2035; Cloudflare targets full IPsec PQC by 2029. India has no published hard PQC-migration deadline — note this as a gap your tool anticipates.

## 2.7 NCIIPC and the Indian government use case

**NCIIPC** was created by gazette notification on 16 January 2014 under Section 70A of the IT Act. It is a unit of **NTRO**, reporting to the PMO via the NSA, and is the nodal agency protecting Critical Information Infrastructure across banking/finance, power/energy, telecom, transport, health, and government/strategic enterprises. It runs a Responsible Vulnerability Disclosure Programme, issues advisories, maintains a 24×7 helpdesk, and connects to 200+ sites.

IPsec is pervasive in exactly these networks — site-to-site tunnels between substations and data centres, remote access, NICNET, defence WANs — so a config-auditing tool is squarely in NCIIPC's remit.

### Real-world relevance

2024–2025 saw mass exploitation of VPN edge devices:

- The Ivanti Connect Secure chain (CVE-2023-46805 + CVE-2024-21887) hit over 1,700 devices worldwide per Volexity's 15 January 2024 report, rising to over 2,100 GIFTEDVISITOR-infected appliances by 16 January.
- Fortinet CVE-2024-21762, Palo Alto CVE-2024-3400, Check Point CVE-2024-24919.
- Much of it by nation-state actors, e.g. China-nexus UNC5221.

This is the strongest possible justification that VPN and tunnel hygiene is a live CII problem.

**Precision note:** those are SSL-VPN appliance RCEs, not IPsec crypto weaknesses per se. Use them to motivate the problem but do not conflate them with the cipher/DH-group auditing your tool performs. A knowledgeable panel will notice.

### Procurement and adoption reality

SIH winners rarely get direct procurement. The realistic path is:

- Incubation via **YUKTI/MIC** — the National Innovation Repository reports 100+ startups and 9,654 SIH alumni
- The NCIIPC RVDP or internship route
- The sponsoring organisation adopting the idea in-house (ISRO, for example, accepted several SIH 2024 solutions for in-house development)

Frame your impact slide around these concrete channels, not a fantasy government contract.

## 2.8 How SIH works and your odds

### Format

National grand finale, **36 continuous hours**, teams of **6 students + 2 mentors**, at ~50 nodal centres. Per PMO/PIB (10 December 2024), SIH 2024 fielded over 1,300 student teams at 51 nodal centres against more than 250 problem statements submitted by 54 Ministries, drawn from 86,000+ institute-level teams (~49,000 advancing internally).

### Per problem statement

The official process allows up to ~500 submissions per statement. Then, per DJSCE's official winners document, the SIH team selected 5–7 colleges for each problem statement for the Grand Finale. Team counts per node vary (e.g. ~20 teams / 4 statements at KCG Chennai; larger at other nodes), evaluated by ~3 jurors, with **one winner (₹1,00,000)** per statement (occasional joint winners). Some statements have no winner if no team meets the bar.

### Judging criteria

Weightings vary by source but cluster around:

| Criterion | Approximate weight |
|---|---|
| Innovation / novelty | ~30% |
| Technical complexity / execution | ~25% |
| Impact / feasibility | ~25% |
| Presentation | ~20% |

Problem understanding and a working prototype dominate in practice.

### What wins

- A well-scoped, deeply-understood problem beats an over-ambitious one
- A live working demo
- Clearly articulated differentiation from existing tools
- Alignment with the sponsoring ministry's real needs

Security/defence statements from NTRO/NCIIPC attract fewer, more serious teams — good news for a technically strong team, bad news if you cannot demo.

### Important caveat on the problem statement

Dedicated search could **not locate this exact IPsec-VPN problem statement in any public SIH 2025 catalogue.** The NTRO cybersecurity block in SIH 2025 (SIH25228–SIH25240) contains crypto-adjacent statements — notably SIH25239, "AI/ML-Based Identification of Cryptographic Primitives and Protocols in Multi-Architecture Firmware Binaries" — but no IPsec-traffic PS and no NCIIPC-branded PS.

It is plausible the IPsec statement exists among unpublished statements or in SIH 2026, or that the organisation or title is slightly different from what was recorded. **Verify the exact PS ID, title, and objective wording on the official SIH portal before committing.** Some strategic advice shifts depending on whether the sponsor is NTRO or NCIIPC and whether the emphasis is passive analysis or active assessment.

## 2.9 Recommended architecture

1. **Testbed and data generation (objective a):** Docker Compose with strongSwan and Libreswan peers; a config matrix script sweeping {IKEv1, IKEv2} × {AES-CBC, AES-GCM, 3DES} × {DH 2, 5, 14, 19, 20, 31} × {PFS on/off} × {tunnel, transport}; tcpdump capture with the generating config written as the label; `save-keys` for decryptable reference captures.

2. **Deterministic IKE parser + active scanner (objective c):** Python (Scapy) or Zeek spicy-ipsec for passive parsing; wrap ike-scan/iker for active transform enumeration; normalise to a common finding schema.

3. **Assessment engine (objective d):** rule engine encoding NIST 800-77r1 / RFC 8221/8247 / CNSA / BSI / ITSAR; each finding gets severity, the violated standard clause, an ATT&CK/CAPEC tag, and matching CVEs.

4. **ML lane:** random forest / XGBoost for in-tunnel application classification on flow-statistical features, with SHAP explanations, calibrated confidence, and an abstention threshold; report closed-world accuracy honestly.

5. **Remediation and reporting:** auto-generate fixed strongSwan/Libreswan/Cisco/Fortinet configs; export a PDF/HTML report; offline/air-gapped deployment; optional SIEM (ELK) integration and drift detection.

## 2.10 High-value differentiating features, ranked by impact-to-effort

1. **Multi-baseline compliance grading including Indian ITSAR/CERT-In/NCIIPC** — highest novelty for an Indian government audience, low technical risk
2. **PQC-readiness assessment** (RFC 8784/9370, ML-KEM/FIPS 203) — timely, forward-looking, easy to score
3. **MITRE ATT&CK/CAPEC mapping + IPsec/strongSwan/Libreswan/racoon CVE threat matrix** — makes findings actionable for a SOC
4. **Auto-generated remediation configs** — concrete, demoable "so what"
5. **Explainable AI (SHAP/LIME) + confidence calibration/abstention** — signals research maturity
6. **Metadata-leakage demonstration** — a memorable live demo
7. **Digital-twin what-if simulation, IPv6 support, drift detection, adversarial robustness** — good stretch goals

## 2.11 Staged recommendations

1. **Before the finale — verify and re-scope.** Confirm the exact PS on sih.gov.in. Rewrite the objectives in your own words, explicitly separating deterministic parsing from ML inference. If a mentor or the PS author is reachable via the NCIIPC helpdesk (1800-11-4430 / helpdesk1@nciipc.gov.in), ask what deployment they envision.

2. **Build the testbed first (day 1).** It is your data source, your demo, and your novelty. If you have a working strongSwan matrix and capture pipeline by hour 12, you have already beaten most teams.

3. **Ship the deterministic auditor before touching ML.** A tool that reliably parses IKE_SA_INIT and grades it against NIST plus ITSAR with remediation output is a complete, demoable product on its own. ML is the differentiator, not the foundation.

4. **Add the India + PQC + ATT&CK layers for the differentiation.**

5. **Demo discipline.** Pre-capture PCAPs and pre-stage a vulnerable gateway (3DES + DH-2 + aggressive mode) so the live demo cannot fail on network issues.

### Benchmarks that should change your plan

- If you cannot get the strongSwan testbed capturing labelled PCAPs within ~12 hours, **drop the ML lane entirely** and double down on the deterministic auditor plus standards engine. That is still a winning entry.
- If in-tunnel classifier test accuracy is below ~85% closed-world, present it as a research finding with honest caveats rather than a headline claim.

## 2.12 Caveats on this assessment

- **Unverified problem statement:** the exact PS ID/title/objectives could not be confirmed in public SIH 2025 sources.
- **Accuracy figures are optimistic:** published 92–99% numbers are overwhelmingly closed-world and dataset-specific; OpenVPN-derived numbers do not transfer cleanly to IPsec/ESP.
- **"AI identifies the DH group/cipher" is mostly false framing:** those come from deterministic parsing of the cleartext IKE handshake.
- **No public IPsec crypto-labelled dataset exists** — a confirmed gap, not an oversight on your part.
- **VPN-appliance CVEs are not IPsec crypto weaknesses.**
- **Judging weightings vary** across nodal centres and years; the ~30/25/25/20 split is indicative, not official.

---
---
# 3. Building your own dataset

> **Original question:** Tell me more about this. Can we create our own realistic dataset to train the model with all the features?

## 3.1 Short answer: yes, and it is the only path

Self-generating the dataset is not a workaround. It is the accepted method in this literature — the 2022 tunnel-classification study cited earlier had to do exactly this because no IPsec data existed.

Two things make it far more tractable than a typical ML data problem:

**Ground truth is free.** You configured the tunnel, so you know the cipher, DH group, mode and PFS setting with certainty. No annotation cost, no label noise. Most ML projects burn weeks here; you get it for nothing.

**The generator is itself a deliverable.** It is objective (a). You are not doing extra work to enable the ML — the data pipeline *is* a graded component.

The word doing all the work is *realistic*. Build it in four layers.

## 3.2 Layer 1 — Configuration sweep (gives you crypto labels)

Docker Compose with strongSwan and/or Libreswan peers, driven by a config matrix.

A full factorial of {IKEv1, IKEv2} × 6 ciphers × 6 DH groups × {PFS on, off} × {tunnel, transport} × {IPv4, IPv6} is **576 combinations** before you add traffic. Too many.

**Prune it.** Many cells are invalid anyway:

- AES-GCM carries its own integrity, so no separate HMAC transform applies
- Transport mode constrains traffic selectors

Cover the *security-relevant spread*: at minimum one deprecated, one acceptable and one strong configuration per family. Parallelise 10–20 container pairs and the sweep runs in hours rather than days.

### Critical detail: read back what was negotiated

**Do not trust your config file.** `swanctl --list-sas` and `ip xfrm state` report what the peers actually agreed on, which is not always what you proposed. Populate your label manifest from those.

## 3.3 Layer 2 — Traffic inside the tunnel (gives you application labels)

This is where realism lives or dies. Ranked best to worst:

### Tier 1 — Real applications (best)

| Traffic type | Tool | Notes |
|---|---|---|
| VoIP | SIPp, or Asterisk + pjsua | **Vary the codec.** G.711 gives constant ~160-byte payloads at 20ms; G.729 gives ~20 bytes. Genuinely different signatures. |
| Video streaming | Self-hosted DASH/HLS origin (nginx) with a headless player | ABR ladder switching produces realistic burst-and-idle patterns |
| Web browsing | Playwright driving headless Chrome across a rotating site list | Rotate content to avoid memorisation |
| Email | Postfix/Dovecot with varied message sizes and attachments, plus IMAP sync | |
| ICMP | ping with varied sizes and intervals | Unmistakable signature |
| File transfer | scp/rsync/HTTP downloads | Sustained one-directional |
| Messaging | Signal-CLI, Matrix/Element, or XMPP | **WhatsApp cannot be scripted.** Use a shape-proxy and say so explicitly rather than claiming WhatsApp. |

### Tier 2 — Traffic replay (the elegant move)

`tcpreplay` the benign traffic from CIC-IDS2017 / CICIoT2023 / MAWI **through** your tunnels as the inner payload.

**This reconciles the problem statement's dataset list with the IPsec requirement.** When a judge asks why you did not use the datasets they specified, the answer is that you did — as inner payload, because those datasets contain no IPsec traffic of their own. That reframes an apparent weakness into evidence you understood the brief better than it understood itself.

*Caveat:* replay preserves packet sizes faithfully but distorts inter-arrival timing depending on replay speed.

### Tier 3 — Synthetic generators (weakest)

iperf3, D-ITG, Ostinato. Fine for volume, poor for realism. Classifiers trained purely on these overfit badly. Use sparingly.

### Also: tap the plaintext side

Capture simultaneously from inside the network namespace, before encryption. This gives you a perfect inner-traffic reference and lets you verify that what you think went into the tunnel actually did.

## 3.4 Layer 3 — Network realism

Without impairment your classifier learns your lab's unnaturally clean network and collapses on anything real.

Apply `tc netem` across runs:

- Delay: 10 / 50 / 150 ms
- Jitter
- Loss: 0.1% / 1% / 3%
- Bandwidth caps

Vary MTU to trigger fragmentation. Include NAT-T scenarios on UDP 4500 alongside plain UDP 500 — the extra 8-byte UDP header shifts size distributions.

## 3.5 Layer 4 — The label manifest

Every capture ships with a JSON sidecar. **This is your ground truth:**

```json
{
  "capture_id": "run_0417",
  "ike_version": "IKEv2",
  "encryption": "ENCR_AES_GCM_16_256",
  "integrity": "none",
  "prf": "PRF_HMAC_SHA2_384",
  "dh_group": 19,
  "pfs": true,
  "child_dh_group": 19,
  "mode": "tunnel",
  "ip_version": 4,
  "nat_t": false,
  "sa_lifetime_ike_s": 10800,
  "sa_lifetime_child_s": 3600,
  "anti_replay": true,
  "inner_traffic": "voip",
  "traffic_source": "sipp_g711_20ms",
  "netem": {
    "delay_ms": 50,
    "jitter_ms": 5,
    "loss_pct": 0.5,
    "rate_mbit": 10
  },
  "duration_s": 120,
  "negotiated_from": "swanctl --list-sas",
  "keys_path": "keys/run_0417.keys"
}
```

## 3.6 The four traps that ruin self-built datasets

### Trap 1 — The confound trap (most common, most fatal)

If VoIP always runs over AES-GCM and video always over AES-CBC, your "application classifier" is really a cipher detector.

**Fully cross traffic type against crypto configuration**, or randomise the pairing. Check for it afterwards with a confusion analysis conditioned on cipher.

### Trap 2 — Session-level leakage

Splitting train/test randomly at the *flow* level lets flows from the same capture session land on both sides, and the model memorises session artifacts.

**Split at the capture level**, ideally hold out entire configurations.

### Trap 3 — No generalisation test

Train on DH groups {2, 5, 14}, test on {19, 20}. Train on tunnel mode, test on transport.

If accuracy collapses, you learned the lab and not the phenomenon. **Reporting this honestly is worth more to a technical panel than a headline accuracy number.**

### Trap 4 — Content memorisation

Always streaming the same video means the classifier learns that video. Rotate content.

## 3.7 Turn padding into a finding

AES-CBC pads to 16-byte boundaries; GCM does not require block padding. So ESP packet-size distributions genuinely differ by cipher.

This cuts both ways:

- **Cipher family is partially inferrable from ESP sizes alone** — a legitimate and interesting result to present
- **Your application classifier may be quietly reading cipher artifacts** instead of traffic shape

Control for it or report it explicitly. Either way, noticing it puts you ahead of most teams.

## 3.8 Scoping for 36 hours

| Parameter | Target |
|---|---|
| Configurations | 24–48 (not 576) |
| Traffic classes | 5–6 |
| Repeats per cell | 3 |
| Duration per run | 60–120 s |
| Parallel container pairs | ~10 |
| Wall-clock capture time | 4–6 hours |
| Resulting labelled flows | Several thousand — ample for random forest / XGBoost |

**Build the harness before the finale if you possibly can.** It is mostly plumbing, and it is the single highest-leverage thing you can pre-build.

## 3.9 Suggested repository structure

```
testbed/
  configs/
    matrix.yaml           # the config sweep definition
  compose/
    strongswan-pair.yml   # docker-compose templates
    libreswan-pair.yml
  traffic/
    voip.py               # per-app generators
    video.py
    web.py
    email.py
    icmp.py
    replay.py             # tcpreplay of external PCAPs
  capture/
    orchestrate.py        # tcpdump start/stop, dual-tap
  netem/
    profiles.yaml         # impairment profiles
  run_sweep.py            # the orchestrator
  dataset/
    pcaps/
    manifests/
    features.parquet
```

## 3.10 Package it as a contribution

Since no public labelled IPsec corpus exists, releasing the dataset plus the generator — call it `IPsecBench` or similar — is itself a novel output.

**"We created the first public labelled IPsec corpus, and here is the reproducible generator"** lands considerably harder with a technical panel than "we achieved 94% accuracy," because the second claim is unverifiable in a 15-minute demo and the first is self-evident.

---
---

# 4. The technical foundations in plain language

> **Original question:** Explain all the technicalities about the project in simple words — with examples.

Running picture for this whole section: **two offices sending documents to each other through a public courier who might open anything he carries.**

## 4.1 What IPsec actually is

Normal internet traffic is a postcard. Every router it passes through can read the message and see who sent it to whom.

IPsec puts that postcard inside a locked steel box before handing it to the courier. The courier still knows which office sent the box and which office receives it, and he can weigh it, but he cannot read what is inside.

Everything else in this project is about answering two questions:

1. **How good is that box?**
2. **What can you still work out about the contents without opening it?**

## 4.2 The handshake (IKE)

Before the two offices can exchange locked boxes, they need matching keys. But the only channel between them is the same public courier. So they have a conversation first, called IKE (Internet Key Exchange):

> **Office A:** I can use AES-256-GCM, AES-128-CBC, or 3DES. For tamper-checking I have SHA-384 or MD5. For key agreement I support groups 14, 19, 20.
>
> **Office B:** Let's go with AES-256-GCM and group 19.

Then they do the actual key agreement, and from that point on everything is encrypted.

**The single most important fact in this entire project:** that opening conversation happens in the clear. It has to, because they do not have a shared key yet. So anyone capturing the traffic can read exactly which cipher and which key-agreement group were chosen.

This is why most of "AI identifies the encryption algorithm" is really just reading a field. It is written down in plain text in the first two packets.

## 4.3 Diffie-Hellman, the paint trick

How do two people agree on a secret colour while shouting across a room full of eavesdroppers?

1. They publicly agree on yellow.
2. A privately adds red and shouts out the resulting orange.
3. B privately adds blue and shouts out the resulting green.
4. A takes B's green and adds her own red.
5. B takes A's orange and adds his own blue.
6. Both end up with exactly the same muddy brown.

The eavesdroppers heard yellow, orange and green, and cannot unmix them to get brown.

That is Diffie-Hellman. It is how two machines agree on a key without ever transmitting it.

### "DH Group" just means how big the numbers are

| Group | What it is | Verdict |
|---|---|---|
| 1, 2 | 768 / 1024-bit MODP | **Broken in practice.** The Logjam research showed a well-funded agency can precompute its way through 1024-bit. |
| 5 | 1536-bit | Deprecated |
| 14 | 2048-bit | Acceptable minimum |
| 19, 20 | Elliptic curve P-256 / P-384 | Good, and faster |
| 31 | Curve25519 | Good |

Finding Group 2 in a capture is like finding that a bank vault has a 4-digit PIN. It is not theoretically broken; it is just small enough that someone with resources will get through it.

## 4.4 ESP, the armoured envelope

Once keys are agreed, the actual data travels in **ESP** packets. An ESP packet has a small readable header and then a scrambled blob.

**Readable on every ESP packet:**

- **SPI** — a locker number. It tells the receiver "use key #A1B2C3D4 to open this." Necessary, because one machine may have dozens of tunnels running.
- **Sequence number** — envelope #1, #2, #3, counting up.

Everything after that is encrypted.

**AH** is the rarely-used sibling. It seals the envelope against tampering but does not encrypt anything. A wax seal on a transparent envelope: you would know if someone altered it, but everyone can still read it. Almost nobody deploys it.

## 4.5 Tunnel mode vs Transport mode

This is about *what* you put in the box.

**Transport mode:** you encrypt the letter, but the envelope still carries the real sender and recipient addresses.

```
From: 10.1.1.5 (Ravi's laptop) → To: 10.2.2.7 (payroll server)
[scrambled contents]
```

**Tunnel mode:** you put the entire original envelope, address and all, inside a bigger envelope addressed gateway-to-gateway.

```
From: 203.0.113.1 (Delhi gateway) → To: 198.51.100.1 (Mumbai gateway)
[scrambled: {From: 10.1.1.5 → To: 10.2.2.7, contents}]
```

Tunnel mode hides who inside the office is really talking to whom. It is what you use for site-to-site VPNs. Transport mode is for two machines talking directly.

**The useful consequence for your project:** wrapping in a second envelope costs an extra **20 bytes on IPv4 (40 on IPv6)** for every single packet. So if a normal packet on that link is 1500 bytes and you are seeing 1480 bytes of payload versus 1460, that overhead difference is a fingerprint.

That is how you *infer* tunnel vs transport, because the actual negotiation of mode happens in the encrypted part of IKE and you cannot read it directly.

## 4.6 AES-128 vs AES-256, and GCM vs CBC

Two separate things get confused here constantly.

### The key size (128 vs 256)

How long the key is. Both are unbroken. 256 is the conservative choice and is required for higher classification levels. **Neither is a finding on its own.**

### The mode of operation (CBC vs GCM)

*How* you apply the cipher to a long message. This matters much more.

**CBC only scrambles.** It gives you secrecy but tells you nothing about whether someone tampered with the message. So you have to bolt on a separate tamper-check, HMAC. Two mechanisms, applied in the right order. Get the order wrong and you get real, exploitable vulnerabilities — this is the family that padding-oracle attacks live in.

**GCM scrambles and seals in one operation.** Fewer moving parts, fewer ways to misconfigure it, and it is faster.

**Analogy:** CBC+HMAC is a padlock plus a tamper-evident sticker you have to remember to apply correctly every time. GCM is a padlock with the sticker built into it.

Modern guidance (RFC 8221) prefers GCM. Seeing "AES-CBC with no integrity algorithm configured" is a serious finding, because it means encrypted but unauthenticated: an attacker can flip bits in your ciphertext and you will not notice.

## 4.7 Perfect Forward Secrecy

**Without PFS:** every session key is derived from one long-term master secret. If an attacker records all your traffic today and steals that master secret in 2031, they can decrypt everything from 2026 onward retroactively.

**With PFS:** every session does a fresh Diffie-Hellman and throws the result away afterwards. Stealing the long-term key gets you nothing about past sessions.

**Hotel analogy:** without PFS there is one master key that opens every room and always has, so stealing it gives you access to everything that ever happened. With PFS each room's lock is re-keyed and the old cylinder is destroyed.

This connects to a real threat called **harvest now, decrypt later**. State actors record encrypted traffic they cannot currently break, storing it against future capability. PFS is the direct defence.

## 4.8 SAs, lifetimes, and replay protection

### Security Association (SA)

Sounds grand but just means "the agreed arrangement for one direction of one tunnel": which key, which algorithm, when it expires. Each tunnel has two, one per direction. The SPI is its label number.

### Key lifetime

How long before you throw the key away and negotiate a fresh one. Shorter is safer, because less data sits under any one key and a compromise has a smaller window.

Typical sane values: **8 hours for the IKE SA, 1 hour for the data SA.** Finding a lifetime of 30 days is a finding.

### Replay protection

Suppose an attacker records ESP packet #47 and re-sends it an hour later. Without protection the receiver decrypts and processes it again. If that packet contained "transfer ₹10,000", it happens twice.

The defence is the sequence number plus a sliding window: the receiver remembers "I have seen 40 through 47" and rejects anything already seen or too old to be plausible.

## 4.9 The critical divide — reading vs guessing

This is the technical spine of the project. Sort everything into two buckets.

### Readable directly from a capture, no keys needed

- IKE version (v1 or v2)
- Every cipher and DH group proposed, and which was accepted
- Integrity algorithm, PRF
- Whether IKEv1 aggressive mode was used
- SPI and sequence numbers on every ESP packet
- The outer IP addresses
- Every packet's size and arrival time

### Encrypted, so you must infer it

- Identities and certificates
- Traffic selectors
- **Tunnel vs transport mode**
- **Everything inside the tunnel**

**So: cipher and DH group are a parsing problem. Mode and inner traffic type are a machine learning problem.** Say this clearly and a technical panel will trust everything else you claim.

## 4.10 Guessing the contents by watching the mail slot

You cannot read the letters. But you can sit outside and watch envelopes go in and out, noting their size and timing. Different activities have completely different rhythms:

| Activity | Signature |
|---|---|
| **VoIP call** | A small envelope every 20 milliseconds, almost identical in size, flowing steadily in both directions. Like a metronome. G.711 = constant 160-byte payload; G.729 ≈ 20 bytes. |
| **Video streaming** | Silence for eight seconds, then a huge burst of maximum-size packets as the player refills its buffer, then silence again. Heavily one-directional. |
| **Web browsing** | Small request out, big response back, then a flurry of medium-sized responses as images and scripts load, then a long quiet gap while the human reads. A sawtooth. |
| **Email sync** | Mostly idle, with occasional modest bursts when new mail arrives. |
| **ICMP ping** | Tiny packets, exactly one per second, perfectly regular. Unmistakable. |
| **File download** | Sustained maximum-size packets in one direction for as long as it takes. |

Your model does not look at packets one at a time. It computes summary statistics over a window:

- Average and spread of packet size
- Average and spread of gaps between packets
- Ratio of upstream to downstream bytes
- Number of bursts
- Flow duration

Feed those to a random forest and it learns rules like *"if 90% of packets are 160±10 bytes with 20ms gaps and traffic is symmetric, that's VoIP."*

**That is the genuine AI contribution in this project.**

## 4.11 Why the datasets you were given do not work

Imagine you are asked to study how well different safes resist drilling, and you are handed a library of burglary photographs. Useful photographs, carefully catalogued, but none of them contain a safe.

CIC-IDS2017, UNSW-NB15, CTU-13 and the rest contain HTTP, SSH, FTP and attack traffic. They contain no IKE negotiations and no ESP packets. And even if they did, they would have no note attached saying *"this session used AES-256 with DH group 14 and PFS enabled"*, which is precisely the label you need to train anything.

That is why you build your own testbed. And it is also why replaying their benign traffic *through* your own tunnels is such a neat move: you get real traffic shapes as your inner payload while your own configuration supplies the labels.

## 4.12 Metadata leakage, the finding hiding in plain sight

Suppose a tunnel is configured perfectly. AES-256-GCM, group 20, PFS on, short lifetimes. Nothing to fix.

An observer still learns:

- Which two gateways are talking
- At what times
- How much data
- Roughly what kind of application

A surge of VoIP-shaped traffic between a headquarters gateway and a border-post gateway at 3am tells you a great deal without decrypting a single byte.

Your tool demonstrating this on its own captures is one of the most memorable things you can show a panel, because it reframes "we're encrypted, we're fine" as an incomplete answer.

## 4.13 The scoring engine

This part is a checklist, not AI, and you should say so. Rules with a citation and a fix attached to each:

| Finding | Severity | Basis |
|---|---|---|
| DH group 1, 2 or 5 | Critical | RFC 8247, Logjam |
| DES or 3DES | Critical | RFC 8221 (MUST NOT) |
| MD5 or SHA-1 for integrity | High | NIST SP 800-77r1 |
| PFS disabled | High | Harvest-now-decrypt-later |
| IKEv1 aggressive mode | High | Leaks identity + offline PSK cracking |
| AES-CBC with no integrity alg | High | Unauthenticated encryption |
| SA lifetime > 24h | Medium | NIST SP 800-77r1 |
| Anti-replay disabled | Medium | RFC 4303 |

The value is not the rules themselves. It is the packaging: a severity, the standard clause it violates, a MITRE ATT&CK technique it enables, and a corrected config block the admin can paste.

## 4.14 The quantum angle, briefly

A future quantum computer breaks Diffie-Hellman and RSA outright (Shor's algorithm) but only halves the effective strength of AES (Grover's), which is why AES-256 remains fine.

**The practical meaning: the key exchange is the vulnerable part, not the encryption.**

Combine that with harvest-now-decrypt-later and traffic recorded today, protected by classical DH alone, is at genuine future risk.

The fix being standardised is a hybrid: run classical DH *and* ML-KEM together, so an attacker must break both. RFC 9370 allows multiple key exchanges in IKEv2, and strongSwan 6.x supports it. A PQC-readiness check in your tool is forward-looking and easy to score.

## 4.15 Putting it together — one worked example

An analyst uploads `statedc-capture.pcap`:

1. **Parser** finds UDP port 500 traffic, decodes IKE_SA_INIT.
   → IKEv1, aggressive mode, 3DES, MD5, DH group 2.

2. **Parser** finds ESP packets, SPI `0xa1b2c3d4`, payloads consistently 20 bytes shorter than the link MTU would allow.
   → **Inference:** tunnel mode, moderate confidence.

3. **Classifier** computes flow statistics: heavily one-directional, 8-second idle gaps then bursts of full-size packets.
   → **Inference:** video streaming, confidence 0.88.

4. **Rule engine** fires six findings, three critical.

5. **Score:** 23/100, grade F.

6. **Output:** an executive page saying "this tunnel uses cryptography deprecated since 2018 and should be treated as readable by a capable adversary", a technical appendix with packet evidence and standard citations, ATT&CK mappings (T1040 Network Sniffing, T1557 Adversary-in-the-Middle), and a corrected `swanctl.conf` using AES-256-GCM with group 20 and PFS enabled.

Every step there is either a documented protocol field or a defensible statistical inference. Nothing is magic, and nothing requires breaking any encryption.

**That is the honest version of the project, and it is a stronger one than the version the problem statement describes.**

---
---
# 5. What exists today, and how your project compares

> **Original question:** What is being used today? How is it different from the one we are building? Explain all similarities and differences. Explain the complete working of the platform the government uses today. Where is it used — give real scenarios from daily life? Compare working, ease of use, impact, adaptation, features, security, and explainability.

## 5.1 The honest headline

**There is no single platform in government use today that does what you are proposing.**

What exists is a *toolbox plus a human*. Understanding that precisely is what will let you position your project credibly instead of claiming to replace something that does not exist.

## 5.2 The five things actually in use today

### Category 1 — Packet inspection tools

**Wireshark, tcpdump, Zeek (formerly Bro), Suricata**

Wireshark already has a complete ISAKMP dissector. If you open an IPsec capture in it right now, it will decode the IKE_SA_INIT and show you the proposed transforms in a tree view: encryption algorithm, integrity, PRF, DH group.

- **What it gives you:** perfect, authoritative visibility.
- **What it does not give you:** any opinion. Wireshark will happily show you `ENCR_3DES` and `DH Group 2` in the same neutral grey font it uses for everything else. It has no idea that is a critical finding.

**This is the core gap: visibility without judgment.**

### Category 2 — Active scanners

**ike-scan, nmap `ike-version`, Nessus, OpenVAS, Qualys**

`ike-scan` sends deliberately crafted IKE proposals at a gateway and records which ones it accepts. Its default probe covers eight transform combinations (DES/3DES × MD5/SHA-1 × DH groups 1/2). If the gateway responds to any, it accepts weak crypto — regardless of what your production tunnels happen to use.

This is genuinely powerful and something passive capture cannot do. **Passive capture shows you what one session negotiated; active scanning shows you the full menu the device is willing to serve.**

*Limitation:* noisy, requires network reachability, and in an OT environment can trip IDS alarms or destabilise old equipment. Many critical-infrastructure operators forbid active scanning of production during business hours.

`ike-scan` also has `psk-crack`, which exploits IKEv1 aggressive mode: the gateway hands out a PSK hash that can be brute-forced offline. A real attack, not a theoretical one.

### Category 3 — Configuration auditors

**Nipper (Titania), CIS-CAT, vendor hardening scripts**

Nipper is closest in spirit to what you are building. Export the running configuration from a Cisco ASA, FortiGate, Juniper SRX or Palo Alto, feed the file to Nipper, and it produces a findings report with severity ratings mapped to standards.

**Critical difference from your project:** Nipper reads the *config file*. That requires administrative credentials, device access, and a change-management ticket. It is a **white-box** audit.

Your tool reads *packets on the wire*. **Black-box.** This is the single most important thing separating your project from what exists.

### Category 4 — Monitoring and SIEM

**Splunk, IBM QRadar, ManageEngine Firewall Analyzer, PRTG, SolarWinds**

These are what actually sit in a government SOC day to day. The standard Indian government SOC stack is Cisco routing/switching, Palo Alto and FortiGate firewalls, Splunk and QRadar for SIEM, and EDR tools for incident response.

ManageEngine Firewall Analyzer delivers per-user VPN session reporting, usage trends, failed authentication tracking, and bandwidth consumption by VPN user, supporting Cisco ASA, Fortinet, Palo Alto, Check Point, SonicWall and Juniper.

**Notice what that list contains and what it does not.** It tracks *whether the tunnel is up*, *who is using it*, *how much data flows*. It does not evaluate *whether the cryptography is sound*.

A tunnel using 3DES with DH Group 2 and no PFS will show up as a healthy green tunnel with 99.9% uptime on every one of these dashboards.

**That is a genuine, demonstrable blind spot, and it makes an excellent opening slide.**

### Category 5 — The human auditor (this is the real "platform")

**CERT-In empanelled auditing organisations**

This is what actually happens in Indian government today, and it is what you are really competing with.

CERT-In empanels private security firms to conduct mandated audits. The published empanelment documents list the tools these organisations use:

- **Commercial:** NetSparker, Core Impact, Nessus Pro, Nipper, Burp Suite
- **Freeware:** Nmap, Nikto, Firewalk, Hping, Dsniff

**Every one of those is a general-purpose tool. None is IPsec-specific.**

The methodology is heavily manual: auditors combine manual testing, security control validation, controlled exploitation, compliance assessment and remediation verification. Manual testing is particularly important for identifying flaws that automated tools may not accurately detect. Configuration review is explicitly a human step — server hardening review, firewall configuration audit, and network architecture assessment, evaluating configurations against CERT-In benchmarks to identify misconfigurations that automated tools often miss.

**Timeline:** a typical CERT-In security audit takes **3 to 6 weeks**.

**Volume:** in FY 2024-25, CERT-In conducted over 9,700 audits:

| Sector | CERT-In audits | NCIIPC audits |
|---|---|---|
| BFSI | 7,547 | — |
| Power & Energy | 1,579 | **46** |
| Transport | 582 | **3** |

Look hard at those numbers, because they are your business case. Power and Energy — the sector where a compromised substation link has physical consequences — got **46 NCIIPC audits in an entire year**. Transport got **three**.

## 5.3 How a government IPsec audit actually works today, step by step

The real workflow for a state power utility being audited:

**Week 0 — Scoping.** The utility signs an engagement with a CERT-In empanelled firm. Scope is negotiated: which sites, which devices, whether active testing is permitted on production.

**Week 1 — Access provisioning.** This is where time evaporates. The auditor needs read-only administrative credentials on every firewall and VPN concentrator. That means change tickets, approvals from the CISO, sometimes vendor involvement if the device is under an AMC. For older SCADA equipment, credentials may be genuinely unknown — the engineer who configured it in 2011 has retired.

**Week 2 — Collection.** An engineer logs into each device and runs `show running-config` (Cisco), `get system` or config backup (Fortinet), or exports the XML (Palo Alto). Configs land in a shared folder. Someone runs Nipper over them. Nessus runs an authenticated scan.

**Week 2–3 — Manual review.** A senior consultant opens the configs in a text editor and reads the crypto stanzas by hand, looking for lines like:

```
crypto isakmp policy 10
 encryption 3des
 hash md5
 group 2
 lifetime 86400
```

They know from experience that this is bad. They write it up.

**Week 3–4 — Correlation and validation.** Findings get triaged, false positives removed, exploitability confirmed. A three-tier review runs L1 auditor → L2 senior consultant → L3 sign-off.

**Week 4–6 — Reporting and retest.** A report is produced, mapped to CERT-In's baseline markers (CSM, PRO, DET, RES, REC, IMP). The utility remediates. The auditor retests. A certificate is issued.

**Then nothing happens for twelve months.**

That last line matters more than anything else in this section. **The audit is a photograph, not a video.** On day 8 after the certificate is issued, a network engineer troubleshooting a flaky tunnel to a vendor adds a fallback proposal with DH Group 2 "just to get it working," intends to remove it, and forgets. That misconfiguration will live for 357 days before anyone looks again.

## 5.4 Where this touches daily life in India

IPsec is not exotic. It is the plumbing under things people use constantly.

| Scenario | What is happening |
|---|---|
| **Withdrawing cash from an ATM in a small town** | The ATM talks to the bank's switch over a leased line or broadband link secured by an IPsec tunnel, terminated on a small Cisco or Fortinet box in the ATM cabin. Thousands per bank, deployed in batches over fifteen years. Ones installed in 2012 were configured with 2012's defaults — 3DES and DH Group 2. Nobody has revisited them because they work. |
| **A state electricity board's load dispatch centre talking to a substation** | SCADA telemetry and control commands ride over IPsec between SLDC and remote terminal units. Highest-consequence case: a compromised link is not a data breach, it is a breaker opening. Also the case where you *cannot* run an active scan or log into the device, because the RTU runs vendor firmware from 2010 that will fall over if you nmap it. |
| **Filing taxes or applying for a passport** | NICNET links government offices, state data centres and district collectorates. Site-to-site IPsec is the standard interconnect. |
| **A bank branch in a district town connecting to head office** | Branch-to-datacentre tunnels, often over dual ISP links with IPsec on both. |
| **A soldier at a forward post sending a report** | Defence WANs use IPsec extensively, frequently with hardware crypto and stricter algorithm mandates. |
| **A mobile VoLTE call** | IPsec secures the interface between the phone and the IMS core, and backhaul links between cell towers and the operator core. |
| **A hospital sending imaging to a diagnostic centre** | Health-sector data links under the ABDM ecosystem. |

**The pattern across all of these:** long-lived tunnels, configured once by whoever installed the equipment, on hardware nobody wants to touch, audited annually at best. That is exactly the failure mode your tool targets.

## 5.5 The comparison, dimension by dimension

### Working method

| | Today's approach | Your platform |
|---|---|---|
| Input | Device configuration files | Packet captures / live traffic |
| Access needed | Admin credentials on every device | A SPAN port or a PCAP file |
| Access model | White-box | Black-box |
| Vendor coupling | Per-vendor config syntax parsers | Protocol-level, vendor-agnostic |
| Coverage | Only devices you own and can log into | Any tunnel you can see traffic for |
| Cadence | Point-in-time, annual | Continuous, or on-demand |
| Inner traffic | Not addressed at all | Statistically inferred |

**The deepest difference is the access model, and you should build your entire pitch around it.**

Nipper needs to log into the FortiGate. Your tool needs to see packets. That sounds like a minor implementation detail; it is not. It changes what is auditable at all:

- **OT and SCADA networks** where logging into a production RTU requires a maintenance window and vendor sign-off, or is simply forbidden. You can passively tap the link.
- **Third-party tunnels.** A bank has an IPsec tunnel to a payment vendor. The bank owns one end. It has no right to audit the vendor's gateway config. But it can capture traffic at its own edge and read the IKE negotiation — which reveals what the vendor's device agreed to.
- **Devices with unknown credentials.** Extremely common on old infrastructure.
- **Incident response.** You have a PCAP from a compromised segment and the devices are already isolated. Config-based tools are useless; packet-based analysis still works.

**The honest counterpoint you must acknowledge:** the config file is *ground truth about capability*, whereas a passive capture only shows *one negotiated session*. If a gateway accepts both AES-256 and 3DES, and the session you captured used AES-256, you will conclude the device is fine. It is not.

This is precisely why you should integrate active `ike-scan` probing as an optional second mode — passive for safety and reach, active for completeness. Presenting both, and explaining exactly when each is appropriate, reads as maturity rather than hedging.

### Ease of use

| | Today | Yours |
|---|---|---|
| Skill required | Deep protocol expertise + standards knowledge | Ability to run tcpdump |
| Time to a finding | 3–6 weeks | Minutes |
| Cost | Lakhs per engagement | Free after deployment |
| Scale limit | Number of trained auditors available | Compute |
| Vendor licensing | Nessus, Nipper, Core Impact licences | None |

The scale point carries policy weight. India has a finite number of people who can look at `crypto isakmp policy` and instantly know what is wrong with it. That is why Transport got three NCIIPC audits in a year.

**You are not replacing the expert; you are letting one expert cover a hundred times more ground by handling the mechanical 80% and escalating the rest.** Frame it that way — panels react badly to "we're replacing your auditors" and well to "we're multiplying your auditors."

### Features

| Capability | Wireshark | ike-scan | Nessus | Nipper | SIEM | **Yours** |
|---|:-:|:-:|:-:|:-:|:-:|:-:|
| Decode IKE | Yes | Partial | Partial | No | No | **Yes** |
| Judge crypto strength | No | Partial | Partial | Yes | No | **Yes** |
| Works without credentials | Yes | Yes | Partial | No | No | **Yes** |
| Multi-vendor | Yes | Yes | Yes | Partial | Partial | **Yes** |
| Grade vs NIST/RFC | No | No | Partial | Yes | No | **Yes** |
| **Grade vs Indian ITSAR/CERT-In** | No | No | No | No | No | **Yes** |
| **Infer tunnel vs transport** | No | No | No | No | No | **Yes** |
| **Classify traffic inside ESP** | No | No | No | No | No | **Yes** |
| **PQC readiness** | No | No | No | No | No | **Yes** |
| **Metadata leakage report** | No | No | No | No | No | **Yes** |
| ATT&CK mapping | No | No | Partial | No | Yes | **Yes** |
| Auto-generate fixed config | No | No | No | Partial | No | **Yes** |
| Continuous monitoring | No | No | No | No | Yes | **Yes** |
| Production-hardened | Yes | Yes | Yes | Yes | Yes | **No** |

The five bolded rows are your defensible novelty. Nothing else in that table does them.

### Impact

**Today's model:** an audit finds problems once a year. Between audits, drift is invisible. NCIIPC issues advisories to CII operators, but compliance verification is periodic and manual.

**Your model:** the same finding surfaces in minutes, and surfaces *again* the day after someone reintroduces it. Continuous compliance rather than annual certification.

**Quantify it in your pitch.** If a state utility has 200 substation tunnels and a manual audit covers 20 in a six-week engagement, you are at 10% coverage annually. A passive collector at the SLDC sees all 200 continuously.

### Security posture of the tool itself

A dimension teams forget, and a panel from NTRO absolutely will not.

| | Today | Yours |
|---|---|---|
| Credential exposure | Auditor holds admin creds for every device | **None required** |
| Risk of disruption | Active scans can destabilise old OT gear | Passive mode is zero-touch |
| Data sensitivity | Config files contain PSKs, ACLs, topology | PCAPs contain metadata, not keys |
| Deployability | Needs network reachability + login | Works fully air-gapped |
| Supply chain | Foreign commercial tools | Indigenous, auditable source |

**The zero-credential property is a security *feature*, not just a convenience.** A tool that must hold administrative credentials for 200 critical devices is itself a high-value target — compromise the audit tool and you own the grid. Your tool never holds a credential and never sends a packet. In an OT context, that argument alone can be decisive.

The indigenous point also lands with an NTRO-adjacent panel: the mandated audit toolchain currently leans on foreign commercial products (Nessus is US, Nipper is UK, Core Impact is US). A capable Indian-built alternative has strategic value beyond its technical merit.

### Explainability

This cuts both ways and needs care.

**Today's explainability is excellent.** A human auditor writes "line 47 of the config specifies `group 2`, which is 1024-bit MODP, deprecated per RFC 8247 and practically attackable per the Logjam research." Fully traceable, defensible in a regulatory proceeding, signed by an accountable professional.

**Your explainability is split:**

*The parsing and rules lane is equally explainable — arguably more so, because it is deterministic and consistent.* It will never have a bad day, never skim a config at 11pm, never miss a stanza. Every finding cites byte offsets in the capture and a clause in a standard.

*The ML lane is inherently less explainable.* "Confidence 0.88 that this is video streaming" is not something you can put in a compliance filing.

**Handle this by segregating the report, not by pretending the problem does not exist:**

- **Section A — Verified findings.** Deterministic. Packet evidence, standard citation, severity. Auditable.
- **Section B — Inferred observations.** Probabilistic. Confidence scores, SHAP feature attributions showing *why* the model decided as it did, and explicit abstention when confidence is low.

Then add the line that wins the room:

> *"Section A is suitable for compliance submission. Section B is intelligence, and is offered as such."*

A panel that has sat through six teams claiming 98% AI accuracy will remember the team that knew which of its outputs were evidence and which were inference.

## 5.6 Where you genuinely lose

Say these out loud before a judge finds them. It converts a weakness into a demonstration of judgment.

1. **No accreditation path.** A CERT-In audit certificate requires an empanelled auditor's signature. Your tool cannot issue one. It is an input to an audit, not a substitute for one.
2. **Passive analysis is incomplete by construction.** You see what was negotiated, not everything the device would accept. Mitigate with the optional active mode.
3. **Vendor breadth.** Nipper parses many vendors' config syntax. You will build and test against strongSwan and Libreswan. Your protocol-level approach is *theoretically* vendor-agnostic — but "theoretically" is doing work there until you have tested against a real Cisco and a real FortiGate.
4. **No process or governance coverage.** A human auditor asks who holds the PSK, whether key rotation is documented, whether this tunnel should exist at all. Your tool sees packets. It has no opinion on governance, and governance is where a lot of real risk lives.
5. **Unvalidated ML.** Your classifier is trained on lab data. Its behaviour on a real substation link is unknown. Never claim otherwise.
6. **Maturity.** Wireshark has twenty-eight years of hardening. You have a hackathon.

## 5.7 The one-sentence positioning

> **Existing tools show analysts what is happening; existing auditors know what it means. Our platform is the first to combine both, and the first that can do it without a single credential, on a link nobody is allowed to log into.**

Accurate, specific, names a real gap, and every claim in it survives scrutiny.

---
---
# 6. IPsec from first principles

> **Original question:** What is IPsec? How is it related to VPNs? How does it work? Why is it necessary in the problem? Where does it lie in our project?

## 6.1 The problem IPsec was invented to solve

The internet protocol — IP — was designed in the 1970s and 80s for a network of people who broadly trusted each other. It has no security whatsoever. An IP packet contains a source address, a destination address, and data, all in plain view. It offers no answer to any of these three questions:

**Confidentiality — can anyone in the middle read this?**
Yes. Every router, every ISP, every person on the same wifi.

**Integrity — did this arrive as it was sent?**
Unknown. There is a checksum, but it detects accidental corruption, not deliberate modification. Anyone in the path can alter the contents and recompute the checksum.

**Authentication — is this really from who it claims?**
No. Source addresses are trivially forged. That is what IP spoofing is.

IPsec is the answer bolted onto IP to fix all three. The name is literally "IP security." It was standardised in the mid-1990s, originally as a mandatory component of IPv6 and later backported to IPv4, where it now does the vast majority of its work.

## 6.2 Where it sits — and why that matters enormously

This is the architectural fact that explains everything else about IPsec, including why governments use it and why your project targets it.

The network stack, bottom to top:

```
Application    HTTP, SMTP, DNS
Transport      TCP, UDP
Network        IP          ← IPsec operates HERE
Link           Ethernet, WiFi
```

**IPsec operates at layer 3, the network layer.** TLS — the thing protecting your browser — operates above the transport layer. That single difference produces almost every practical distinction between them:

| | TLS/HTTPS | IPsec |
|---|---|---|
| Protects | One application's connection | Every packet between two points |
| Application awareness | The app must be written to use it | The app knows nothing |
| Scope of protection | TCP payload only | The entire IP packet, headers included |
| Typical use | Browser to web server | Office to office, host to host |

**The consequence: IPsec is invisible to applications.**

A legacy SCADA program written in 1998 that speaks a plaintext industrial protocol cannot be given TLS without rewriting it. But you can put it behind an IPsec tunnel and it is protected without a single line of code changing.

That is precisely why critical infrastructure runs on IPsec. Power grids, water systems and rail networks are full of equipment that will never be rewritten. IPsec protects them from underneath.

## 6.3 How IPsec relates to VPNs

These get used interchangeably, and they should not be.

**A VPN is a goal.** "Virtual Private Network" means: make two networks that are physically separated, connected only by the public internet, behave as though they were one private network. It is a description of an outcome.

**IPsec is one way of achieving that goal.** So are OpenVPN, WireGuard, L2TP, MPLS, and SSL-VPN products like Ivanti Connect Secure or Cisco AnyConnect.

The relationship is like "transport" versus "railway." A VPN is what you want; IPsec is one vehicle that gets you there.

### Where IPsec dominates

- **Site-to-site connections.** Delhi office ↔ Mumbai office. Gateway to gateway, always on, moving all traffic between two networks.
- **Anything needing multi-vendor interoperability.** IPsec is an open IETF standard, so a Cisco box at one end and a FortiGate at the other will interoperate. Proprietary VPNs will not.
- **Regulated and government environments,** where "must implement an open standard" is often a procurement requirement.
- **Anything requiring hardware crypto acceleration** — IPsec offload is built into most enterprise network silicon.

### Where it loses ground

Remote access for individual laptops, where SSL-VPNs traverse hotel firewalls more easily; and increasingly WireGuard, which is far simpler.

### Why this makes your project matter

IPsec's dominance in the site-to-site and government space means an enormous installed base of tunnels that were configured a decade ago and never revisited.

**WireGuard has one cipher suite and no options — you cannot misconfigure it. IPsec has dozens of negotiable parameters and therefore hundreds of ways to get it wrong.**

Configurability is exactly why it needs auditing.

## 6.4 The four components

IPsec is not one protocol. It is a framework of four cooperating pieces.

### ESP — Encapsulating Security Payload (IP protocol 50)

The workhorse. Encrypts and authenticates the actual data. Over 99% of real deployments use ESP alone.

### AH — Authentication Header (IP protocol 51)

Authenticates but does not encrypt. Proves nothing was tampered with, while leaving everything readable. Almost never deployed — if you are going to the trouble of protecting a packet, you usually want secrecy too. The problem statement correctly marks AH as optional.

### IKE — Internet Key Exchange (UDP port 500, or 4500 with NAT)

The negotiator. Before any data can flow, the two ends must agree on algorithms and derive shared keys. IKE does that.

**This is the component your project depends on most**, because IKE's opening exchange is the only part of the whole system that is legible from outside.

### SA — Security Association

The agreement itself. An SA is a record saying: "for traffic in this direction, use AES-256-GCM with this key, this SPI, expiring at this time." Each tunnel needs two — one per direction — because the keys differ each way.

Two databases hold the state:

- **SPD (Security Policy Database)** — the rules. "Traffic from 10.1.0.0/16 to 10.2.0.0/16 must be protected."
- **SAD (Security Association Database)** — the active agreements, keyed by SPI.

On Linux you can inspect both with `ip xfrm policy` and `ip xfrm state`, which is how you will harvest ground truth in your testbed.

## 6.5 How it actually works, step by step

IPsec deliberately splits the work into two phases. The reason is efficiency: the expensive public-key mathematics happens once, and the cheap symmetric encryption happens millions of times.

### Visual summary of the three stages

```
        Captured traffic
               │
    ┌──────────┴──────────┐
    │                     │
IKE_SA_INIT           IKE_AUTH              ESP data packets
Cleartext,            Sealed with           Header clear,
fully readable        phase-one keys        payload sealed
    │                     │                        │
Cipher, integrity,    Identities, mode,      SPI, sequence,
PRF, DH group         traffic selectors      size, timing
```

**Teal = parseable. Coral = encrypted. Gray = partially visible.**

### Phase 1 in detail — IKE_SA_INIT

Two messages, both entirely in the clear. They must be, because no shared key exists yet.

The initiator sends an SA payload listing every combination it supports:

```
Proposal 1 (ENCR_AES_GCM_16, key length 256, PRF_HMAC_SHA2_384, DH group 20)
Proposal 2 (ENCR_AES_CBC, 256, AUTH_HMAC_SHA2_256, PRF_HMAC_SHA2_256, group 14)
Proposal 3 (ENCR_3DES, AUTH_HMAC_MD5, PRF_HMAC_MD5, group 2)
```

Alongside it goes a KE payload — the initiator's Diffie-Hellman public value — and a random nonce.

The responder picks one proposal, returns its own DH value and nonce. Both sides now independently compute the same shared secret, from which a family of keys is derived (SK_e for encryption, SK_a for authentication, SK_d for deriving child keys, separately for each direction).

**Everything in that exchange is on the wire in plaintext.** That third proposal, with 3DES and MD5 and group 2, is a critical finding sitting in a readable field. No cryptanalysis required.

**This is the single fact your entire parsing engine rests on.**

### Phase 1 continued — IKE_AUTH

Now that keys exist, the second exchange is encrypted. Inside it:

- Each side proves its identity (pre-shared key, certificate, or EAP)
- Traffic selectors are negotiated — which subnets this tunnel covers
- The first Child SA is established
- **Tunnel versus transport mode is agreed here**

Because this is encrypted, mode is not directly observable. Hence inference, hence machine learning.

### Phase 2 — ESP carries the data

With SAs established, actual traffic flows. Every packet gets an ESP wrapper:

```
[ Outer IP header ]                                    ← visible
[ ESP header: SPI (4 bytes), Sequence (4 bytes) ]      ← visible
[ ENCRYPTED: original packet, padding, next-header ]
[ Integrity Check Value ]                              ← visible but opaque
```

The receiver reads the SPI, looks it up in the SAD to find the right key, verifies the ICV, checks the sequence number against its replay window, decrypts, and forwards the recovered inner packet.

Periodically the SA lifetime expires and a rekey happens — a new Child SA, and with PFS enabled, a fresh Diffie-Hellman exchange.

## 6.6 A detail that matters for implementation

IPsec is split across two parts of the operating system, and knowing this will save you time.

**IKE runs in userspace.** On Linux that is the `charon` daemon (strongSwan) or `pluto` (Libreswan). It does the negotiation, certificate validation, and DH mathematics. It is a normal process you can query, log, and instrument.

**ESP runs in the kernel.** The XFRM framework does per-packet encryption at line rate. You never see individual packets in userspace.

### Practical consequences for your testbed

| Command / feature | What it gives you |
|---|---|
| `swanctl --list-sas` | Queries the userspace daemon for what was negotiated. **Your label source.** |
| `ip xfrm state` | Queries the kernel SAD for live SAs, including actual SPIs and algorithms in force |
| `ip xfrm policy` | The SPD — what policy triggered protection |
| strongSwan `save-keys` plugin | Exports session keys so Wireshark can decrypt your own captures — invaluable for validating your parser reads the same values the daemon reports |
| Capture at outer interface | Encrypted ESP |
| Capture inside the netns, before the XFRM hook | Plaintext |

**Do both captures simultaneously** — that is how you get perfect inner-traffic labels.

## 6.7 Why IPsec specifically is necessary in this problem

Four reasons, and they compound.

**One: it is where the deployed base is.** Government, defence, banking and utility interconnects run on IPsec. That is where the risk actually lives, so that is what is worth auditing.

**Two: it is configurable enough to get wrong.** WireGuard has exactly one cipher suite; there is nothing to audit. IPsec lets you negotiate encryption algorithm, key length, mode of operation, integrity algorithm, PRF, DH group, PFS on or off, lifetimes, replay window, tunnel or transport, IKEv1 or IKEv2, main or aggressive mode. That is an enormous configuration space, and defaults from 2010 are still shipping in equipment installed today.

**Three: the negotiation is visible.** This is what makes the project *possible* at all. If IPsec encrypted its handshake from the first byte, you could learn nothing without keys. Because IKE_SA_INIT must be in the clear, a passive observer can audit the cryptography without credentials, without vendor cooperation, and without touching production.

**Four: it is an open standard.** RFC 7296, 4301–4303, 8221, 8247 are public documents. You can build a compliant parser from specifications. You cannot do that for a proprietary VPN.

## 6.8 Where IPsec sits in each part of your project

This is the map from protocol to code.

| IPsec element | Where it appears | What you build |
|---|---|---|
| strongSwan / Libreswan daemons | Objective (a), testbed | Docker containers running the config sweep |
| `swanctl --list-sas`, `ip xfrm state` | Objective (a), labelling | Ground-truth harvester writing the manifest |
| IKE on UDP 500/4500 | Objective (b), capture | tcpdump filters must include both ports |
| IKE_SA_INIT SA payload | Objective (c), **parsing lane** | Deterministic decoder for cipher, integrity, PRF, DH group |
| IKE version, exchange type | Objective (c), parsing | IKEv1 vs v2, main vs aggressive mode detection |
| IKE_AUTH (encrypted) | Objective (c), **inference lane** | Tunnel/transport classifier from size overhead |
| ESP header (SPI, sequence) | Objective (c), flow tracking | Group packets into SAs; sequence gaps reveal loss and replay |
| ESP payload sizes and timing | Objective (c), **ML lane** | Feature extraction for the in-tunnel traffic classifier |
| SA parameters and lifetimes | Objective (d), assessment | Rule engine against NIST 800-77r1, RFC 8221/8247, ITSAR |
| Anti-replay window | Objective (d) | Sequence-number analysis for replay protection |
| PFS / child DH group | Objective (d) | Forward secrecy check; feeds the PQC readiness score |
| Outer IP addresses, volumes | Objective (e), metadata | The leakage report — what an observer learns anyway |

**Read down that table and the architecture of your platform falls out of it directly. The protocol structure *is* the module structure.**

## 6.9 The one paragraph to memorise

> IPsec secures communication at the network layer, so it protects every packet between two points without applications needing to know it exists — which is why it underpins government and critical-infrastructure networks full of equipment that can never be rewritten. Its security depends entirely on parameters negotiated at connection time, and that negotiation happens in cleartext. So the same design decision that makes IPsec interoperable also makes it auditable from the outside, without a single credential. Our platform reads that negotiation, grades it against national and international standards, and infers what it cannot read.

Every clause in that is technically defensible.

---
---

# 7. IKE, ISAKMP, and the negotiation layer

> **Original question:** What is IKE, ISAKMP, etc.? What relevance do they have in our project? How are they related to the problem statement?

## 7.1 Four names, one thing

In the 1990s the IETF working group could not settle on one key exchange design, so they standardised the *framework* and the *mechanisms* separately.

**ISAKMP** — Internet Security Association and Key Management Protocol (RFC 2408). A **container format and a set of procedures**, deliberately generic. It defines how to structure a negotiation message, how to chain payloads together, how to identify a session. It defines **no actual cryptography**. It is an empty envelope specification.

**Oakley** (RFC 2412) — a key determination protocol built on Diffie-Hellman, defining the concept of "modes" and the DH group numbering still used today.

**SKEME** — a separate key exchange design contributing ideas about rekeying and anonymity.

**IKE** (RFC 2409) — the actual deployed protocol, assembled as: the ISAKMP framework, plus a subset of Oakley, plus a subset of SKEME.

**The honest one-liner: ISAKMP is the envelope, IKE is what people actually put in it.**

## 7.2 Why this matters practically

Open a capture in Wireshark and the protocol column says **ISAKMP**, not IKE — even for IKEv2 traffic.

That is not an error. Wireshark's dissector was written in the ISAKMP era and named after the envelope format, which IKEv2 still inherits.

**Every filter you write will be `isakmp.*` even though the protocol you are analysing is IKEv2.**

Your team will trip over this on day one. When you write `tshark -Y "ike"` and get nothing back, the answer is `isakmp`.

## 7.3 IKEv1 versus IKEv2

This distinction is a finding in its own right, so treat it as a first-class output of your parser.

### IKEv1 (1998)

Two phases, and Phase 1 has two variants.

**Main Mode** — six messages. Identity is protected because it is sent after keys are established.

**Aggressive Mode** — three messages. Faster, but identity and a hash derived from the pre-shared key are sent in the clear.

#### Aggressive Mode is the highest-value finding your tool can produce

In message 2, the responder sends a hash computed over the PSK. An attacker captures that hash — passively, by just being on the path, or actively by sending a single IKE probe — and then cracks it offline at whatever speed their hardware allows. No further interaction, no lockout, no logging on the target. `ike-scan`'s `psk-crack` does exactly this.

**If your tool sees Aggressive Mode with PSK authentication, the correct finding is not "weak configuration." It is: assume the pre-shared key is already compromised.**

Then Phase 2 is **Quick Mode**, three messages, establishing the SAs that actually protect data.

### IKEv2 (2005, current spec RFC 7296)

A clean rewrite that discarded the mode zoo:

| Exchange | Messages | Purpose |
|---|---|---|
| `IKE_SA_INIT` | 2 | Negotiate crypto, exchange DH values and nonces. **Cleartext.** |
| `IKE_AUTH` | 2 | Authenticate, establish first Child SA. **Encrypted.** |
| `CREATE_CHILD_SA` | 2 | Additional SAs, rekeying |
| `INFORMATIONAL` | 2 | Deletes, keepalives, errors |

Four messages to a working tunnel instead of nine. It also added NAT traversal as standard, cookie-based DoS protection, MOBIKE for roaming, and EAP authentication.

**For your assessment engine:** IKEv1 alone is a medium finding — legacy, no longer recommended, lacks IKEv2's protections. IKEv1 with Aggressive Mode and PSK is critical.

## 7.4 The payload structure your parser must handle

Every IKE message has a fixed header followed by a **chain** of payloads. Each payload's header contains a "next payload" field naming what follows, so parsing is a linked-list walk until you hit a next-payload value of 0.

### The header

```
Initiator SPI   (8 bytes)   ← identifies the IKE SA
Responder SPI   (8 bytes)   ← zero in the very first message
Next Payload    (1 byte)
Version         (1 byte)    ← 0x10 = v1.0, 0x20 = v2.0
Exchange Type   (1 byte)    ← IKE_SA_INIT, IKE_AUTH, Main, Aggressive...
Flags           (1 byte)
Message ID      (4 bytes)
Length          (4 bytes)
```

**Version detection is two nibbles in one byte.** Exchange type identification is one more byte. Those two fields alone satisfy several bullets of objective (c).

### A common confusion worth flagging

**The 8-byte IKE SPI in this header is not the same thing as the 4-byte SPI in an ESP packet.** The first identifies the negotiation session; the second identifies a data SA. Different fields, different sizes, different databases. People conflate them constantly.

### The SA payload nesting

The payload that matters most is the SA payload, with a four-level nested structure:

```
SA payload  (everything on offer)
 └── Proposal 1
      ├── Transform: Encr  → AES-GCM
      │    └── Attribute: Key Length = 256
      ├── Transform: Integ → none
      ├── Transform: PRF   → SHA2-384
      └── Transform: DH    → Group 20
 └── Proposal 2
      └── ...
```

**Below the transform level sits the attribute level.** Key length is an attribute of the encryption transform, not part of the transform ID itself. So `ENCR_AES_CBC` with attribute `Key Length = 128` and `ENCR_AES_CBC` with `Key Length = 256` are the same transform ID carrying different attributes.

**If your parser stops at the transform level, you cannot distinguish AES-128 from AES-256** — and the problem statement lists both as things to identify. **Parse to the attribute level.**

### The critical audit insight

A real initiator message contains *several* proposals, not one. It is a menu. The responder picks a single item, which comes back in its reply.

**Most people would audit only the accepted proposal. Do not.**

Audit **every proposal offered**, because the full list reveals what that device is willing to fall back to. A gateway that negotiated AES-256-GCM today but also advertised 3DES with DH group 2 will accept 3DES tomorrow, from any peer that only offers that.

**The offer list is the real attack surface; the accepted proposal is just today's outcome.**

That single design decision makes your passive analysis substantially more valuable, and it is a good thing to say out loud in a demo.

## 7.5 The payloads that earn their keep

### KE (Key Exchange)

Contains the raw DH public value. Its *length* independently confirms the group — a 1024-bit value means group 2 regardless of what the transform claimed. Useful as a cross-check.

### Nonce

Random values. Short nonces are a (rare) weakness worth checking.

### Notify (N)

Widely underused, and full of signal:

| Notify type | What it tells you |
|---|---|
| `NAT_DETECTION_SOURCE_IP` / `_DESTINATION_IP` | NAT-T is in play, expect UDP 4500 |
| `COOKIE` | The responder is applying DoS protection — under load or has seen an attack |
| `INVALID_KE_PAYLOAD` | A DH group mismatch, **and the responder tells you which group it actually wanted** — free intelligence about its configuration |
| `NO_PROPOSAL_CHOSEN` | Negotiation failed; surrounding messages show exactly what was offered and rejected |
| `USE_TRANSPORT_MODE` | In IKEv2 this notify requests transport mode, though it travels inside the encrypted `IKE_AUTH` |

### Vendor ID (VID) — build a feature around this

Implementations announce themselves with a vendor ID payload — often an MD5 hash of a version string, sometimes with a version number appended. `ike-scan` maintains a fingerprint database mapping these to specific products and firmware versions. Cisco, Fortinet, strongSwan, Juniper and Check Point all emit recognisable VIDs.

**The feature:** parse the VID, fingerprint the device and version, then query the NVD for CVEs affecting it. You now produce findings like:

> Peer identified as Cisco IOS 12.4 (VID fingerprint). Known CVEs affecting IKE implementation in this version: CVE-XXXX-XXXX (critical). Configuration additionally permits DH group 2.

**That is configuration weakness plus implementation vulnerability, from a passive capture, with no credentials.** Nothing in the current government toolchain does that. It directly feeds the "threat matrix" deliverable, and it is the kind of concrete capability a panel remembers.

### Retransmission backoff fingerprinting

A second fingerprinting channel: when an IKE responder does not get a reply, it retransmits on a schedule, and that schedule differs between implementations. `ike-scan` uses backoff timing as a fingerprint when VIDs are absent.

A nice stretch goal for your ML lane — a genuinely non-obvious classification task on timing data alone.

## 7.6 Direct mapping to the problem statement

Objective (c) lists nine things to identify. Here is where each actually comes from:

| Problem statement asks for | Source | Method |
|---|---|---|
| IPsec protocol | IP proto 50/51, UDP 500/4500 | **Parse** |
| IKE version | Version byte in IKE header | **Parse** |
| Tunnel mode | Packet size overhead, addressing | *Infer* |
| Transport mode | Same | *Infer* |
| Encryption algorithm | SA payload transform + key length attribute | **Parse** |
| Authentication algorithm | SA payload integrity transform | **Parse** |
| Key exchange method | SA payload DH transform, KE payload length | **Parse** |
| SA characteristics | IKE header SPIs, ESP SPI, lifetime notifies | **Parse** |
| Traffic type inside ESP | Packet sizes, timing, direction | *Infer* |

**Seven of nine are parsing. Two are inference.** Building your architecture around that split — and saying so plainly — is what separates a project that understands IPsec from one that has read a summary of it.

For objective (d), the assessment layer, IKE supplies almost everything:

- Cryptographic strength and cipher suite quality → the transforms
- Forward secrecy → whether a DH transform appears in the Child SA proposal
- Key lifetime → lifetime attributes or notifies
- Configuration compliance → grading the whole transform set against RFC 8221/8247, NIST SP 800-77r1 and ITSAR

Only replay protection comes from elsewhere — that is ESP sequence-number analysis.

## 7.7 The summary for your documentation

> ISAKMP defines the message format; IKE is the protocol that fills it. IKEv1 negotiates in two phases with an optional Aggressive Mode that leaks a crackable PSK hash; IKEv2 replaced it with a four-message exchange whose first pair is necessarily in cleartext. That cleartext exchange carries a nested SA payload listing every cipher, integrity algorithm, PRF and Diffie-Hellman group each peer will accept — not merely the one chosen. Our parser reads the full offer list, fingerprints the implementation from its Vendor ID, and grades both against national and international cryptographic baselines, without holding a single credential.

---
---
# 8. How the software works, end to end

> **Original question:** Explain the working of our software in simple terms from start to end. How is it going to be used once built? How is it going to be integrated? Explain adaptation and usability. How can we sell it to the government and other businesses? Where and how will they integrate the software? How will auto-remediation work? Give an end-to-end real-world example.

## 8.1 The one-sentence version

**You plug a small box into the network, it quietly watches the VPN tunnels, and it tells you which ones are protected by outdated locks — along with the exact replacement locks to fit.**

Everything below is detail on that sentence.

## 8.2 How the software works, stage by stage

Think of it as an assembly line with five stations.

### Station 1 — Listening

The software needs to see network traffic. It gets this one of three ways:

**Someone hands it a file.** An analyst has a `.pcap` capture from an incident. They drag it into the web interface. Simplest case.

**It watches a live link.** The software sits on a server connected to a *mirror port* on a switch. A mirror port is a copy machine for network traffic: the switch duplicates everything passing through and sends the copy to your box. Your box can see everything but cannot send anything. **It is physically incapable of interfering.**

**It goes and asks.** Optional mode. The software sends a few harmless probe packets to a VPN gateway and notes which encryption options the gateway is willing to accept. This is the only mode that touches the network at all, and it should be off by default.

*Output of Station 1: raw packets.*

### Station 2 — Sorting

Millions of packets go by. Most are irrelevant. The software filters for just three things:

- Anything on UDP port 500 or 4500 (VPN negotiation)
- Anything with IP protocol number 50 (encrypted VPN data)
- Anything with IP protocol number 51 (authentication-only variant)

It then groups these into **conversations**: "gateway A and gateway B set up a tunnel at 09:14:22, and here are the 40,000 packets that followed."

*Output of Station 2: organised tunnels instead of loose packets.*

### Station 3 — Reading

For each tunnel, the software opens the negotiation messages and reads them.

**The opening handshake is not encrypted.** It cannot be, because the two ends have not agreed on a key yet. So it is sitting there in plain view, and the software reads it like a form:

```
Version:              IKEv1
Mode:                 Aggressive
Encryption offered:   3DES, AES-128
Integrity offered:    MD5, SHA-1
Key exchange group:   2 (1024-bit)
Perfect forward secrecy: not requested
Key lifetime:         86400 seconds
Vendor fingerprint:   matches Cisco IOS 12.x
```

No guessing. No AI. This is reading fields at known byte positions, the same way a program reads a spreadsheet.

*Output of Station 3: a factual profile of each tunnel's security settings.*

### Station 4 — Judging

The software compares that profile against rulebooks it holds:

- International standards (NIST SP 800-77, RFC 8221, RFC 8247)
- Indian telecom security requirements (ITSAR)
- CERT-In's audit baseline
- Optionally the customer's own internal policy

Each rule is simple and stated plainly:

> **Rule:** Diffie-Hellman group must be 14 or higher.
> **Found:** group 2.
> **Verdict:** Critical.
> **Because:** 1024-bit groups are considered breakable by a well-resourced attacker. Reference: RFC 8247 §4.

The software runs perhaps forty such rules and collects the failures.

*Output of Station 4: a list of findings with severities.*

### Station 5 — Guessing (carefully)

Two things cannot be read, only estimated, because they are inside the encrypted part.

**What kind of traffic is inside the tunnel.** The software cannot read the contents, but it can watch the *shape*. A phone call produces a small packet every 20 milliseconds like a heartbeat. A video stream goes quiet for eight seconds then dumps a huge burst. Web browsing looks like a small question followed by a big answer, then a long pause. The trained model looks at these rhythms and says "this looks like video streaming, 88% confident."

**Whether it is tunnel mode or transport mode.** Tunnel mode wraps the original packet in a second envelope, which costs 20 extra bytes per packet. The software measures packet sizes and infers which mode is in use.

*Output of Station 5: inferences with confidence numbers attached — clearly separated from the facts in Station 4.*

### The output

Three documents come out:

| Document | Content |
|---|---|
| **Executive page** | One page, no jargon. "You have 47 VPN tunnels. 6 are using cryptography that should have been retired in 2018. 3 of those connect to substations. Overall grade: D." |
| **Technical report** | Every finding, with the packet evidence, the standard clause it violates, and the corrected configuration. |
| **Metadata page** | "Even your correctly-configured tunnels reveal the following to anyone watching the line..." — the part that surprises people. |

## 8.3 Where the software physically lives

### Mode A — The laptop

An auditor installs it on a laptop. They collect captures at a client site, bring them back, and analyse offline. Nothing connects to anything.

- **Who uses it:** CERT-In empanelled audit firms, incident responders, security researchers
- **Why it matters:** works in classified environments where nothing may be networked

### Mode B — The sensor

A small server — even an industrial mini-PC — sits in the rack next to the firewall. A cable runs from the switch's mirror port to its network card. It watches continuously and updates a dashboard.

- **Who uses it:** a bank's SOC, a state data centre, a power utility's control centre
- **Why it matters:** annual audits find problems once a year. A sensor finds them the same day someone creates them.

### Mode C — The scanner

Scheduled active checks against a list of gateways. Runs monthly, out of hours, with explicit approval.

- **Who uses it:** organisations that own their equipment and want completeness rather than just observation
- **Why it matters:** watching only shows what one session negotiated. Asking shows everything the device would accept.

**Most customers will run A and B.** Mode C should require someone to deliberately switch it on, and should be forbidden by default in operational-technology environments.

## 8.4 Where it connects in a real network

A state power utility's control centre:

```
     Substations (30 sites)
              │
       [ IPsec tunnels ]
              │
      ┌───────▼────────┐
      │  VPN firewall  │
      └───────┬────────┘
              │
      ┌───────▼────────┐
      │  Core switch   │──── mirror port ───► YOUR SENSOR
      └───────┬────────┘
              │
        Control centre servers
```

The sensor takes a copy of the traffic. **That is the entire installation.** No agent on any device. No credentials. No configuration change to anything that is running.

**Why this is such a strong selling point in critical infrastructure:** the standard objection to any new security tool is "will it break my network?" Here the honest answer is that it *cannot*, because it has no path to send anything. In a power control room that objection is often the whole conversation.

For a factory or substation where even a mirror port is unavailable, you use a **network TAP** — a passive splitter, essentially a piece of copper, that duplicates the signal with no active component in the path.

## 8.5 What it plugs into

The tool does not replace anything. It feeds things the customer already has.

| Their system | What you send it | Why they care |
|---|---|---|
| SIEM (Splunk, QRadar) | Syslog messages for each finding | Findings appear beside their other alerts |
| Ticketing (ServiceNow, JIRA) | Auto-created ticket per critical finding | Fixes get assigned and tracked |
| Their reporting | PDF and CSV export | Goes straight into the audit file |
| Their own dashboards | REST API | They build whatever view they want |
| Email | Scheduled digest | The CISO gets a weekly summary |

**Nobody has to change how they work.** The findings just arrive where they already look.

## 8.6 Auto-remediation, explained properly

This is the feature people get most excited about and the one most likely to cause a disaster if built carelessly.

### What it produces

The software identifies a bad configuration and writes the corrected one, in the syntax of that specific device.

**Found on a Cisco:**

```
crypto isakmp policy 10
 encryption 3des
 hash md5
 group 2
 lifetime 86400
```

**Generated replacement:**

```
crypto ikev2 proposal SECURE-PROPOSAL
 encryption aes-gcm-256
 prf sha384
 group 20

crypto ikev2 policy SECURE-POLICY
 proposal SECURE-PROPOSAL
```

Same output for strongSwan, Libreswan, FortiGate, Palo Alto, Juniper. The tool knows the dialect.

### The rule that must never be broken

**The software must never apply the change itself.**

Two reasons, both absolute.

**Reason one — physical consequences.** If your tool reconfigures the VPN between a load dispatch centre and a substation and the change is wrong, the tunnel drops and operators lose telemetry from a live piece of the power grid. That is not a software incident. Nobody in critical infrastructure will install a tool that can do that, and they are right not to.

**Reason two — both ends must change together.** This is the operational detail most people miss. IPsec is a *negotiation*. If you upgrade the Delhi gateway to AES-GCM-256 with group 20, and Mumbai still only offers 3DES with group 2, they can no longer agree on anything and **the tunnel dies immediately.**

So remediation is not "apply this config." It is a coordinated procedure.

### What the software should actually generate

A **change package**, not a change:

1. **Both configurations.** Delhi's and Mumbai's, because both must change.
2. **The order of operations.** Add the new proposal *alongside* the old one first — devices accept multiple proposals. Confirm both ends now negotiate the strong option. **Only then remove the weak one.** This is a zero-downtime path, and getting it right is exactly the expertise your tool is packaging.
3. **A verification step.** "After the change, the tunnel should show AES-GCM-256 and group 20. Confirm with `show crypto ikev2 sa`, or re-run this tool."
4. **A rollback.** The exact commands to restore the previous state if something goes wrong.
5. **A blast radius note.** "This tunnel carries SCADA telemetry from 3 substations. Suggested window: Sunday 02:00–04:00."

Then a human reads it, approves it, and applies it through whatever change process they already have.

### The workflow

```
Tool finds problem
      ↓
Generates change package
      ↓
Creates ticket
      ↓
Engineer reviews  ◄── human decision point
      ↓
Change board approves
      ↓
Engineer applies during window
      ↓
Tool verifies from traffic
      ↓
Finding closes automatically
```

**The verification step at the end is quietly the best part.** Because the tool is already watching the wire, it sees the *next* negotiation after the change and confirms the fix actually took effect. Most tools tell you a problem exists. Yours closes the loop by observing the real-world result.

For a customer who genuinely wants automation, you can offer an optional integration with their existing automation platform (Ansible, or the vendor's own manager) — but **the tool hands over the change, it does not execute it.** Keep that line clean.

## 8.7 Who uses it, and how hard is it to learn

| User | What they do | Training needed |
|---|---|---|
| **Network engineer** | Opens the dashboard, sees three red items, clicks one, copies the corrected config, raises a change ticket. Needs no cryptography knowledge. | Five minutes |
| **Auditor** | Uploads captures from a client, exports the technical report, uses it as the evidence base. Replaces roughly two weeks of manual configuration review. | One afternoon |
| **CISO** | Gets a one-page monthly summary with a grade and a trend line. Wants to see the number go up. | None |

**The design principle: the person using it should never need to know what a Diffie-Hellman group is.** The tool knows. It says "this one is too weak, here's the replacement, here's the standard that says so." Expertise is baked into the rules, not required from the user.

## 8.8 How you sell it

### To government

**The strongest argument is a number.** In FY 2024-25, the entire Power and Energy sector received 46 NCIIPC audits and Transport received 3. A typical CERT-In audit takes three to six weeks. There are not enough qualified auditors in India to cover critical infrastructure at the depth it needs.

**Your pitch is therefore not "replace your auditors." It is "let one auditor cover fifty sites instead of five."** Government buyers respond well to capacity multiplication and badly to replacement narratives.

Four supporting arguments:

**It is indigenous.** The mandated audit toolchain currently leans on Nessus (US), Nipper (UK) and Core Impact (US). An Indian-built alternative with auditable source code has strategic value beyond its features, particularly for defence-adjacent networks.

**It works where nothing else can.** Old SCADA equipment that cannot be logged into, third-party tunnels you do not own, air-gapped facilities. Configuration-based tools need credentials; yours needs a cable.

**It is continuous, not annual.** An audit certificate is a photograph. Your tool is a video.

**It is already looking at the quantum problem.** Traffic recorded today can be decrypted later once quantum computers mature. Your tool flags which tunnels are exposed and which are ready for the new hybrid key exchanges. Government buyers are starting to be asked about this and mostly have no answer.

**Routes to market:**

- GeM listing for procurement
- STQC certification for credibility
- CERT-In empanelled firms as channel partners (they benefit most directly)
- NCIIPC's responsible disclosure programme as a way in
- PSU utilities, NIC, state data centres and sector CSIRTs as first customers

### To business

| Segment | The pitch |
|---|---|
| **Banks** | RBI mandates regular security audits. Every branch has a tunnel. Every ATM has a tunnel. Most were configured when installed and never revisited. Audit cost reduction plus continuous coverage. |
| **Telecom** | Equipment sold to Indian operators requires ITSAR certification through NCCS. A tool that pre-checks compliance before submission saves a failed certification cycle, which is expensive. |
| **Audit firms** | Your highest-margin customer. If your tool turns two weeks of manual review into one day, they can take on more engagements with the same staff. Sell per-seat licences to firms CERT-In has already empanelled. |
| **Managed security providers** | They monitor many clients. One sensor per client, one dashboard. |

### Business model

**Government will not accept SaaS for this data, so build for on-premises from the start.**

Suggested shape: **open-source core** (builds trust, gets adopted, and matters enormously for a security tool people must be able to inspect), with revenue from:

- Support contracts
- Compliance rule packs
- Per-sensor licensing for continuous monitoring
- Integration work

The open-source decision is also strategically right for a government pitch. Nobody in a defence network wants to install a black box that watches their traffic.

## 8.9 End to end — a real scenario

### The setting

**Rajasthan Rajya Vidyut Prasaran Nigam** — a state transmission utility. A load dispatch centre in Jaipur connected to 34 substations across the state. Each substation sends telemetry — voltage, current, breaker status — and receives control commands. Every link is an IPsec tunnel.

The tunnels were configured between 2011 and 2019 by three different contractors. Nobody has a complete inventory. The last audit covered 8 sites.

### Day 1 — Installation

An engineer runs one cable from the core switch's mirror port to your sensor. **Ten minutes.** Nothing else changes. No downtime, no change ticket beyond "install monitoring appliance."

### Day 1, hour 4 — Discovery

The dashboard populates:

> **41 IPsec tunnels detected.**

The utility believed it had 34. **Seven tunnels exist that nobody at the control centre knew about.** Three turn out to be vendor maintenance links installed during commissioning and never removed.

**That discovery alone justifies the purchase**, and it happens before a single security rule runs. Unknown tunnels into a grid control network are a serious finding in themselves.

### Day 2 — The findings

> **Overall grade: D (34/100)**
>
> **Critical — 6 tunnels**
> Substations Bhilwara, Kota-2, Ajmer-East, Sikar, Bharatpur, Alwar-3
> IKEv1 Aggressive Mode with pre-shared key. DH group 2. 3DES encryption.
> *Assume the pre-shared key for these tunnels is recoverable by any observer.*
>
> **High — 11 tunnels**
> Perfect forward secrecy not enabled. Recorded traffic is decryptable retroactively if the long-term key is ever compromised.
>
> **Medium — 19 tunnels**
> Key lifetime set to 24 hours or longer.
>
> **Informational**
> Traffic pattern analysis suggests the Bhilwara link carries a video stream in addition to SCADA telemetry (confidence 0.81). No video feed is documented for this site.

**That last line deserves attention.** The tool cannot see inside the tunnel. But the traffic *shape* — long idle periods then large bursts, heavily one-directional — does not match telemetry, which is small and steady. Something else is riding that link. Possibly an undocumented CCTV feed installed by a contractor. Possibly not. Either way, someone should look.

**That is the moment the ML lane earns its place in the product.** Not by classifying traffic for its own sake, but by noticing that a link is carrying something nobody documented.

### Day 3 — The fix package

For each critical finding, the tool produces:

- Corrected configuration for the substation router
- Corrected configuration for the Jaipur concentrator
- A three-step sequence: add the strong proposal on both ends, verify negotiation switches to it, then remove the weak proposal
- Rollback commands
- A note: "This tunnel carries live telemetry. Coordinate with grid operations."

The engineer reads it, the change board approves it, and it goes into the next maintenance window.

### Day 10 — Verification

The change is applied to Bhilwara. Roughly forty minutes later the tunnel rekeys naturally. The sensor observes the new negotiation, sees AES-256-GCM with group 20 and PFS enabled, and **closes the finding automatically.**

Nobody had to log in and check. The evidence came off the wire.

### Month 3 — The reason they renew

An engineer troubleshooting a flaky link at Jhunjhunu adds a fallback proposal with DH group 2 to get the tunnel up. He means to remove it. He forgets.

**Fourteen minutes later** the dashboard raises a new critical finding and opens a ticket.

Under the old model, that misconfiguration would have survived until the next annual audit — if that audit happened to cover Jhunjhunu, which statistically it would not have.

**That single catch is the whole product argument, and it is the story to tell at the end of your demo.**

## 8.10 The pitch in three lines

> **Today:** an expert spends three to six weeks reading configuration files from devices they need credentials for, and produces a snapshot that is stale within a week.
>
> **With this:** a cable produces a complete inventory in four hours, a graded assessment in two days, fixes written in the device's own syntax, and an alert the same afternoon anyone weakens a tunnel.
>
> **And it can be installed on a network nobody is allowed to log into.**

---
---

# 9. Where the AI actually lives

> **Original question:** Where does "AI-driven" come into the project structure and working? How does it impact the problem and the solution?

## 9.1 The tension you have to resolve

The problem statement says "AI-driven." Most of the crypto identification is deterministic parsing. Those two facts sit uncomfortably together, and how you handle that discomfort is one of the more consequential decisions in this project.

**Bad option one — pretend.** Wrap the parser in a neural network, report "97% accuracy at identifying encryption algorithms," and hope nobody asks. A panel with anyone who has read RFC 7296 will ask, and the answer will be that your model achieves 97% accuracy at reading a field that a `struct` read achieves 100% on. You would have built something *worse* than the obvious solution and dressed it up.

**Bad option two — deny.** Say "actually this does not need AI" and build a pure rules engine. Technically defensible, but you have failed the brief and thrown away the parts that are genuinely novel.

**The good option:** show that you know exactly which parts require intelligence and which require correctness, and build each properly. That is not a compromise — it is the actual answer, and it is what a serious engineer would do.

## 9.2 Where AI genuinely belongs

### Tier 1 — AI is irreplaceable. Nothing else works.

**1. Classifying traffic inside the ESP tunnel.**

The payload is encrypted with AES. There is no algorithm, no parser, no clever trick that reads it. The only information available is the *shape* of the flow: packet sizes, gaps between packets, direction ratios, burst structure.

Turning those observations into "this is a voice call" is irreducibly a statistical inference problem. You cannot write an if-statement for it, because the boundary between a VoIP flow and a small periodic telemetry flow is fuzzy and lives in a high-dimensional feature space. **This is what machine learning is for.**

**2. Inferring tunnel versus transport mode.**

Mode is negotiated inside the encrypted `IKE_AUTH` exchange. You cannot read it.

You could write a heuristic: *if median payload ≈ MTU − 20 − ESP overhead, it is tunnel mode*. That works in a clean lab. It falls apart with variable MTU, fragmentation, IPv6, NAT-T's extra header, and mixed traffic where packet sizes vary wildly. A model trained on the actual joint distribution of sizes handles the mess.

**Present the heuristic as your baseline and the model as the improvement** — that comparison is itself a good result to show.

**3. Fingerprinting the implementation when it does not announce itself.**

Vendor ID payloads identify most devices, but some strip or spoof them. When that happens, implementations still betray themselves through behaviour: retransmission timing when a reply is late, the order in which payloads are chained, nonce lengths, which notify types they use.

`ike-scan` handles this with a hand-built pattern database. A classifier generalises to implementations nobody catalogued. Genuinely a learning problem with no closed-form answer.

### Tier 2 — AI adds real value that rules cannot

**4. Anomaly detection over configurations.**

Your rule engine has maybe forty rules. **Rules only catch what you thought of in advance.**

Consider: a utility has 41 tunnels. Forty use AES-256-GCM with group 20. One uses AES-256-CBC with group 14.

**No rule fires.** CBC is acceptable. Group 14 is acceptable. Nothing is violated.

But it is an outlier in an otherwise uniform estate, and outliers like that almost always mean someone configured a device by hand, outside the standard build, probably in a hurry, probably during an incident. That is exactly the kind of thing worth a second look — and only an unsupervised model over the configuration space finds it.

**This is the difference between checking against a rulebook and understanding what normal looks like for this organisation.**

**5. Temporal drift detection.**

Continuous monitoring gives you a time series per tunnel. A link that has carried steady, small, symmetric SCADA telemetry for six months suddenly shifts to a different traffic shape.

No compliance rule covers "the traffic changed." A change-point detector catches it immediately. This is what turns continuous monitoring from *repeatedly running the same check* into something that actually learns the environment.

### Tier 3 — LLM as the interface, not the analyst

**6. Report generation.** Converting structured findings into an executive narrative a non-technical director can act on.

**7. Natural language query.** "Show me every substation tunnel using anything weaker than AES-256." Translated into a query over your findings database.

**8. Contextual remediation guidance.** Given the finding, the device fingerprint and the deployment context, drafting the change procedure and the blast-radius warning.

**The absolute guardrail on this tier:** the LLM writes *about* findings. It never *produces* them. Every fact it states must trace to a parsed field or a fired rule.

**A hallucinated security finding is worse than no finding at all**, because it burns the analyst's trust in everything else the tool says. Constrain generation to the structured data and validate the output against it.

## 9.3 How this looks in the architecture

```
                  Captured traffic
                         │
          ┌──────────────┴──────────────┐
          │                             │
    IKE handshake                  ESP packets
    Sent in cleartext              Encrypted payload
          │                             │
          ▼                             ▼
  Deterministic parser            ML models
  Facts, no confidence            Inference with confidence
          │                             │
          └──────────────┬──────────────┘
                         ▼
                 Assessment engine
                 Rules, scoring, reporting
```

**The two lanes never mix.** Findings from the left carry no confidence score because they are facts. Findings from the right always carry one because they are estimates. That separation propagates all the way into the report, where Section A is evidence suitable for a compliance filing and Section B is intelligence.

## 9.4 What the AI explicitly does not do

Put this on a slide. Volunteering it is worth more than being caught out on it.

- **It does not identify the encryption algorithm.** That is read from the SA payload.
- **It does not identify the DH group.** Same.
- **It does not determine IKE version.** One byte in the header.
- **It does not decide compliance.** That is a rule with a citation to RFC 8247.
- **It does not break any encryption.** Nothing in this project attempts cryptanalysis.

Every one of those is *better* handled deterministically, and saying so demonstrates that you chose the right tool for each job rather than reaching for the fashionable one.

## 9.5 The framing that makes "AI-driven" honest

A self-driving car is AI-driven. Its perception system — reading the road from camera pixels — is deep learning, because there is no other way to do it. Its braking is a solenoid responding to a control loop, because that is a solved problem and a neural network would only make it less reliable.

**Nobody argues the car is not AI-driven because the brakes are not a transformer.**

Your system is the same shape. The AI does the perceptual work — seeing through the encryption, spotting what does not belong, noticing change over time. The deterministic parts do the parts that must be exactly right, every time, with no probability attached.

**"AI-driven" describes where the intelligence is, not that every component is a model.**

## 9.6 What the AI changes about the problem

Strip out the AI lane entirely and ask what you have left.

You would have a very good passive configuration auditor. Genuinely useful — works without credentials, covers third-party tunnels, runs continuously, grades against Indian standards. **But it belongs to an existing category. It is Nipper, over the wire.**

The AI lane adds three capabilities with no equivalent anywhere:

**One — visibility into what is otherwise invisible.** Every existing tool stops at the encryption boundary. Yours reasons past it. That single capability is the difference between "your tunnel's cryptography is weak" and "your tunnel's cryptography is weak *and* it is carrying something you did not know about."

**Two — finding what nobody wrote a rule for.** Rules catch known-bad. Anomaly detection catches *unusual*, which is where the interesting problems actually live. A config that violates no standard but differs from every one of its 40 peers is a signal a rules engine is structurally incapable of producing.

**Three — understanding change.** A snapshot tells you the state. A model over time tells you the *trajectory* — which is what you need to know whether the estate is improving or drifting.

## 9.7 The proof point

Return to the Rajasthan scenario, and specifically this finding:

> Traffic pattern analysis suggests the Bhilwara link carries a video stream in addition to SCADA telemetry (confidence 0.81). No video feed is documented for this site.

Trace where that came from:

- The **parser** cannot produce it — the payload is encrypted.
- The **rule engine** cannot produce it — no standard says "SCADA links shall not carry video."
- **Wireshark** cannot produce it, **Nessus** cannot, **Nipper** cannot, the **SIEM** cannot.

It exists *only* because a model learned what telemetry traffic looks like and noticed that this link does not match.

And it may well be the most operationally important line in the whole report. Weak ciphers are a risk. **An undocumented data flow into a grid control network is a live question that someone needs to answer today.**

**That single finding is your entire argument for the AI lane.** When a judge asks "why do you need machine learning for this?", do not give an architecture lecture. Show them that line and ask which existing tool would have produced it.

## 9.8 Building in trustworthiness

The AI lane's value depends entirely on it being trustworthy, and trust is easier to lose than to build.

Three things protect it:

**Calibration.** A model that reports 0.99 on everything is useless. Check that when it says 80% confident, it is right about 80% of the time.

**Abstention.** Below a threshold, output "insufficient signal" rather than a guess. A tool that admits uncertainty gets believed when it does not.

**Attribution.** SHAP values showing *which* features drove the decision. "Classified as VoIP because 91% of packets fall in a 20-byte band at consistent 20ms intervals" is a claim an analyst can evaluate. "Confidence 0.88" alone is a claim they can only accept or reject.

Those three turn the ML lane from a black box into an instrument.

## 9.9 The line to use

> The cryptographic parameters are read, not predicted — reading them is a solved problem and machine learning would only make it less reliable. The AI is aimed at the three things that cannot be read: what a tunnel is carrying behind its encryption, which configurations are strange rather than merely non-compliant, and when an estate starts to drift. Those are the problems no existing tool addresses, and they are the reason this platform is worth building.

---
---
# 10. Additional features and winning the panel

> **Original question:** Apart from the objectives, what additional features should be in the software that will strengthen the project and security, and will also help and have an impact? How can we impress the panels and judges?

This splits into two different problems. First: what genuinely makes the software better. Second: what makes a panel remember you. There is overlap, but they are not the same list, and confusing them is how teams end up with impressive demos and hollow products.

## PART 1 — Features that genuinely strengthen the software

### Tier A — High impact, low risk. Build these.

#### A1. Tunnel discovery and inventory

Before any security assessment, answer the question nobody asked: **how many IPsec tunnels do you actually have?**

Almost every organisation gets this wrong. Contractors install maintenance tunnels during commissioning and never remove them. Sites get decommissioned but the tunnel stays. Someone builds a temporary link for a migration project in 2019.

Your tool sees every tunnel on the wire, whether or not anyone documented it. Output a live inventory with first-seen dates, endpoints, traffic volume, and a flag for anything not in the customer's own list.

- **Why it matters:** delivers value in hour four, before a single security rule runs, and it is the finding most likely to make a customer sit up. An undocumented tunnel into a control network is not a compliance issue — it is an incident.
- **Effort:** low. You are already parsing everything you need.

#### A2. Post-quantum readiness scoring

Traffic captured today can be decrypted in the future once quantum computers mature. This is called harvest-now-decrypt-later, and it is a real programme run by real state actors.

Grade every tunnel:

| Grade | Meaning |
|---|---|
| **Exposed** | Classical DH only, and PFS disabled. Past traffic is retroactively at risk. |
| **At risk** | Classical DH with PFS. Future traffic vulnerable once quantum arrives. |
| **Transitional** | Post-quantum pre-shared key in use (RFC 8784). |
| **Ready** | Hybrid key exchange with ML-KEM (RFC 9370). |

- **Why it matters:** government CISOs are starting to be asked "what is your PQC migration plan?" and almost none can answer, because nobody has told them which of their tunnels are exposed. You are producing the inventory that migration planning requires.
- **Effort:** low. A handful of rules over data you already parse. Disproportionately high payoff.

#### A3. Vendor ID fingerprinting linked to CVEs

Parse the Vendor ID payload, identify the device and firmware version, cross-reference the NVD.

You now produce findings that combine two independent axes of risk:

> Peer identified as Cisco IOS 12.4. Configuration permits DH group 2 (weak). Firmware version has 3 known CVEs affecting IKE processing, one rated critical.

- **Why it matters:** every other tool tells you *either* that your config is weak *or* that your firmware is vulnerable. Combining them from a passive capture, with no credentials, is genuinely new. Directly satisfies the "threat matrix" deliverable.
- **Effort:** medium. `ike-scan`'s fingerprint database gives you a head start; the NVD has a public API.

#### A4. Both-ends coordination in remediation

IPsec is a negotiation. Change one end without the other and the tunnel dies. So your remediation output must contain both configurations, sequenced to be applied without downtime: add the strong proposal alongside the old one, verify it is being selected, then remove the weak one.

- **Why it matters:** a network engineer will immediately test whether your tool understands this. If it hands them a single config that would break production, they stop trusting it. If it hands them a safe sequence, they conclude you have actually done this before.

#### A5. Automatic verification loop

After a fix is applied, the tunnel rekeys naturally within its lifetime. Your sensor observes the new negotiation and closes the finding on its own.

- **Why it matters:** every audit tool tells you what is wrong. Almost none confirm the fix worked, because they would have to come back and look. You are already looking. Closing the loop from observed evidence rather than someone ticking a box is a real workflow improvement.

#### A6. Deviation from the organisation's own baseline

Separate from standards compliance. Learn what is normal for *this* estate and flag departures — even when nothing is technically violated.

Forty tunnels on AES-256-GCM with group 20, one on AES-256-CBC with group 14: no rule fires, both are acceptable, and the odd one out is still worth a look.

- **Why it matters:** uniformity is a security property in itself, because it means everything came from a controlled build.

### Tier B — Strong differentiators. Build if time allows.

#### B1. Metadata exposure report

For a *correctly configured* tunnel, show what an observer still learns: endpoints, timing, volumes, and the inferred application type.

- **Why it matters:** reframes "we're encrypted, we're fine" as incomplete. And it is the one place where your ML lane becomes a *demonstration of risk* rather than a feature. Showing a customer you determined their tunnel carries voice traffic, without any key, lands hard.

#### B2. Configuration what-if simulator

Let an analyst change a parameter and see the score move before touching anything. "If we upgrade these six tunnels from group 2 to group 20, the estate grade goes from D to B."

- **Why it matters:** turns your tool from a judge into a planning instrument. Security teams have to justify maintenance windows to operations teams, and this gives them the argument.

#### B3. Multi-baseline comparative grading

Grade the same estate against NIST SP 800-77r1, RFC 8221/8247, BSI TR-02102-3, CNSA and Indian ITSAR simultaneously — and show where they disagree.

- **Why it matters:** an organisation exporting to Europe or working with defence has multiple compliance obligations. Nothing else grades against Indian requirements at all.

#### B4. Rekey behaviour analysis

Watch whether tunnels actually rekey at their stated lifetime. A configured lifetime of one hour means nothing if the implementation is buggy and rekeys every twelve.

- **Why it matters:** this is the gap between *configured* and *actual*, and it is only visible from the wire. A config auditor cannot see it by construction. Genuinely exclusive to your approach.

#### B5. Offline-first, air-gapped operation

No cloud dependency, no telemetry home, everything on-premises, installable from media.

- **Why it matters:** for defence and classified networks this is not a preference, it is a hard requirement. Many commercial tools fail here immediately.

### Tier C — Nice, but do not let them eat your time

Federated learning across organisations, blockchain-anchored audit logs, mobile apps, chatbot interfaces.

Each sounds impressive in the abstract and delivers little. **If your core does not work, no amount of this saves you. If your core does work, none of it is needed.**

## PART 2 — How to impress the panel

### P1. The single highest-leverage thing: name the flaw in the problem statement

Early in your presentation, say something like:

> "The problem statement asks us to use CIC-IDS2017 and UNSW-NB15. We examined both. Neither contains a single IKE negotiation or ESP packet, and neither carries labels for cipher or DH group. So we built the testbed that generates the data this problem actually requires — and we then replayed the benign traffic from those datasets *through* our tunnels as inner payload, which is the only way they are genuinely useful here."

This does four things at once:

1. Proves you read the brief critically rather than accepting it
2. Demonstrates you actually opened the datasets
3. Reframes an apparent shortfall as a deliberate contribution
4. Uses the specified datasets after all, in the only technically sound way

**Most teams will either quietly ignore the datasets or pretend to have used them. Being the team that examined them and explains precisely why they do not fit is an enormous credibility differentiator.**

### P2. Separate what you read from what you guess

Show the slide with the nine identification targets and mark seven as parsed and two as inferred.

> "Seven of these come from reading cleartext fields in the IKE handshake. Applying a classifier there would be less accurate than a struct read, so we did not. Two of them are inside the encrypted portion and cannot be read at all — those are where our models operate."

A panel that includes anyone who knows IPsec will have been waiting to see whether you understand this. **Volunteering it before they ask reverses the dynamic entirely:** instead of testing you, they start listening to you.

### P3. One finding no other tool could produce

Build your demo around the undocumented traffic case. Show the analyst discovering that a link believed to carry only telemetry is carrying something else, then ask directly:

> "Which existing tool would have found that? Wireshark cannot — it stops at the encryption. Nessus cannot. Nipper reads configs, not traffic. This finding exists only because a model learned what telemetry looks like and noticed this does not match."

**One concrete, unanswerable question is worth more than five slides of architecture.**

### P4. Report a failure

Somewhere in your presentation, show a result that did not work.

> "We trained on DH groups 2, 5 and 14, then tested on 19 and 20. Accuracy dropped from 94% to 71%. That tells us the model partially learned our lab rather than the underlying phenomenon, so we report application classification with calibrated confidence and an abstention threshold rather than as a definitive answer."

Every team claims high accuracy. Almost none report a generalisation test, because it makes their numbers worse. **The team that does is the team the panel believes about everything else.** Counter-intuitive, and it works.

### P5. The zero-credential argument

State it plainly:

> "This tool holds no passwords, has no login to any device, and in passive mode is physically incapable of sending a packet. A tool that must hold administrative credentials for two hundred critical devices is itself a high-value target — compromise the auditor and you own the grid. Ours cannot be used that way, because it has nothing to steal and no path to act."

For an NTRO-adjacent panel this reframes a limitation as a security property. It is the argument that gets you into networks nobody is allowed to log into.

## The demo, structured

Ten minutes, roughly:

| Time | Content |
|---|---|
| **0:00** | Open a real capture in Wireshark. Point at the ISAKMP line showing `3DES`, `DH group 2`, `Aggressive Mode`. Say: "Everything needed to assess this is on screen right now, in plain text. It takes an expert to know that this is critical, and there are not enough experts." |
| **1:30** | Same file in your tool. Grade F, six findings, each with its standard citation. |
| **3:00** | The inventory. "41 tunnels found. The customer documented 34." |
| **4:30** | The undocumented traffic finding, with SHAP attribution showing which features drove it. |
| **6:00** | The remediation package. Both ends, sequenced, with rollback. |
| **7:30** | Apply the fix in the live testbed. Wait for the rekey. Watch the finding close by itself. |
| **9:00** | The PQC readiness page and the ITSAR compliance view. |

**Rehearse it until it runs without you thinking.** Pre-capture every PCAP. Have a fallback video. A demo that fails on network issues costs more than three missing features.

## What to prioritise if you are short on time

Build in this order:

1. The testbed and dataset generator — everything depends on it
2. The parser and rules engine — a complete product on its own
3. Tunnel inventory — highest value per hour of work
4. Remediation with both-ends sequencing — what makes it usable
5. The traffic classifier — your novelty
6. PQC readiness — cheap and memorable
7. Everything else

**A team that ships items one through four with a polished demo beats a team that half-builds all twelve.**

## The thing to actually remember

The panel is not deciding whether you built impressive software in 36 hours. They know what is possible in 36 hours.

**They are deciding whether you understand the problem well enough that the software would keep getting better.**

Everything above — naming the dataset flaw, separating parsing from inference, reporting your failure case, understanding that both ends must change together — signals understanding rather than output. **That is what they are actually scoring.**

---
---

# 11. Appendices

## Appendix A — The assessment rule set

Starting point for your rules engine. Each rule carries severity, the standard it derives from, and an ATT&CK mapping where applicable.

| ID | Finding | Severity | Standard basis | ATT&CK |
|---|---|---|---|---|
| CRY-01 | DH group 1 (768-bit MODP) | Critical | RFC 8247, Logjam | T1040 |
| CRY-02 | DH group 2 (1024-bit MODP) | Critical | RFC 8247, Logjam | T1040 |
| CRY-03 | DH group 5 (1536-bit MODP) | High | RFC 8247 | T1040 |
| CRY-04 | DES encryption | Critical | RFC 8221 MUST NOT | T1040 |
| CRY-05 | 3DES encryption | Critical | RFC 8221 MUST NOT | T1040 |
| CRY-06 | MD5 integrity | High | NIST SP 800-77r1 | T1565 |
| CRY-07 | SHA-1 integrity | High | NIST SP 800-77r1, BSI TR-02102-3 | T1565 |
| CRY-08 | AES-CBC with no integrity algorithm | High | RFC 8221 | T1565 |
| CRY-09 | Key length below 128 bits | High | NIST SP 800-57 | T1040 |
| CRY-10 | AES-128 where CNSA/ITSAR requires 256 | Medium | CNSA, ITSAR | — |
| IKE-01 | IKEv1 in use | Medium | RFC 8247 | — |
| IKE-02 | IKEv1 Aggressive Mode | High | NIST SP 800-77r1 | T1110 |
| IKE-03 | IKEv1 Aggressive Mode with PSK | **Critical** | ike-scan/psk-crack attack path | T1110 |
| IKE-04 | Weak proposal offered but not selected | Medium | Fallback attack surface | T1040 |
| PFS-01 | Perfect forward secrecy disabled | High | NIST SP 800-77r1 | T1040 |
| PFS-02 | Child SA DH group weaker than IKE SA | Medium | RFC 7296 | — |
| SA-01 | IKE SA lifetime > 24 hours | Medium | NIST SP 800-77r1 | — |
| SA-02 | Child SA lifetime > 8 hours | Low | NIST SP 800-77r1 | — |
| SA-03 | Anti-replay protection disabled | Medium | RFC 4303 | T1499 |
| SA-04 | Replay window smaller than 64 | Low | RFC 4303 | T1499 |
| PQC-01 | No post-quantum protection, PFS also off | High | Harvest-now-decrypt-later | T1040 |
| PQC-02 | No post-quantum protection, PFS on | Medium | RFC 9370 | T1040 |
| MET-01 | Identity exposed in cleartext (IKEv1 AM) | High | RFC 7296 rationale | T1592 |
| CFG-01 | Configuration deviates from estate baseline | Informational | Anomaly detection | — |
| INV-01 | Tunnel not present in customer inventory | High | — | T1133 |
| VID-01 | Implementation with known CVEs | Varies | NVD | Varies |

## Appendix B — RFC and standards reference

### Core IPsec

| Document | Title |
|---|---|
| RFC 4301 | Security Architecture for the Internet Protocol |
| RFC 4302 | IP Authentication Header (AH) |
| RFC 4303 | IP Encapsulating Security Payload (ESP) |
| RFC 7296 | Internet Key Exchange Protocol Version 2 (IKEv2) |
| RFC 2408 | ISAKMP (historical, but explains the envelope format) |
| RFC 2409 | IKEv1 (historical) |
| RFC 2412 | The OAKLEY Key Determination Protocol |

### Algorithm requirements

| Document | Title |
|---|---|
| RFC 8221 | Cryptographic Algorithm Implementation Requirements for ESP and AH |
| RFC 8247 | Algorithm Implementation Requirements and Usage Guidance for IKEv2 |

### Post-quantum

| Document | Title |
|---|---|
| RFC 8784 | Mixing Preshared Keys in IKEv2 for Post-quantum Security |
| RFC 9370 | Multiple Key Exchanges in IKEv2 |
| draft-ietf-ipsecme-ikev2-mlkem | ML-KEM in IKEv2 |
| FIPS 203 | ML-KEM (Module-Lattice Key Encapsulation) |
| FIPS 204 | ML-DSA (Module-Lattice Digital Signature) |

### Government and national guidance

| Document | Origin | Notes |
|---|---|---|
| NIST SP 800-77 Rev. 1 | US NIST | Guide to IPsec VPNs, published 30 June 2020, DOI 10.6028/NIST.SP.800-77r1 |
| NIST SP 800-57 | US NIST | Key management recommendations |
| CNSSP-15 / CNSA 2.0 | US NSA | National security algorithm suite; CNSA 2.0 mandates ML-KEM-1024 / ML-DSA-87 |
| BSI TR-02102-3 | Germany | IPsec crypto guideline; (EC)DH sole use recommended only until end of 2031 |
| ANSSI IPsec recommendations | France | |
| **ITSAR** | **India — NCCS/DoT** | Indian Telecom Security Assurance Requirements; certification valid 10 years |
| **CERT-In Directions 2022** | **India** | 6-hour incident reporting, 180-day log retention, 5-year VPN subscriber logs; IT Act §70B(6) |
| **NCIIPC guidelines** | **India — NTRO** | Critical Information Infrastructure protection |

## Appendix C — Tools reference

| Tool | Purpose | Relevance to you |
|---|---|---|
| **strongSwan** | IPsec implementation (charon daemon) | Primary testbed peer; `swanctl --list-sas`, `save-keys` plugin |
| **Libreswan** | IPsec implementation (pluto daemon) | Second testbed peer for interop diversity |
| **Wireshark / tshark** | Packet analysis | ISAKMP dissector; filter is `isakmp.*` not `ike.*` |
| **tcpdump** | Capture | Filter: `udp port 500 or udp port 4500 or ip proto 50 or ip proto 51` |
| **Scapy** | Packet crafting/parsing in Python | Building your own IKE parser |
| **Zeek + zeek-spicy-ipsec** | Network monitoring | Already logs transforms, DH groups, proposals, notify messages, vendor IDs |
| **ike-scan** | Active IKE probing | Transform enumeration, VID fingerprint DB, backoff fingerprinting, psk-crack |
| **iker / IKESS** | ike-scan wrappers | Risk-rated JSON/HTML output |
| **nmap `ike-version`** | Active probe | Version and vendor detection |
| **tcpreplay** | Traffic replay | Replaying CIC-IDS2017 benign traffic through your tunnels |
| **SIPp** | VoIP generation | Vary codec: G.711 vs G.729 |
| **Playwright** | Browser automation | Realistic web browsing traffic |
| **tc netem** | Network impairment | Delay, jitter, loss, bandwidth caps |
| **ip xfrm** | Kernel IPsec state | `ip xfrm state` (SAD), `ip xfrm policy` (SPD) |

## Appendix D — Key commands

```bash
# Capture IPsec traffic
tcpdump -i eth0 -w capture.pcap \
  'udp port 500 or udp port 4500 or ip proto 50 or ip proto 51'

# What did strongSwan actually negotiate?
swanctl --list-sas

# Kernel view of active SAs
ip xfrm state

# Kernel view of policy
ip xfrm policy

# Filter IKE in tshark (note: isakmp, not ike)
tshark -r capture.pcap -Y "isakmp"

# Extract transform details
tshark -r capture.pcap -Y "isakmp" -T fields \
  -e isakmp.version -e isakmp.exchangetype \
  -e isakmp.tf.id -e isakmp.tf.attr

# Active transform enumeration
ike-scan --showbackoff --multiline <target>

# Aggressive mode PSK capture
ike-scan --aggressive --pskcrack=out.psk <target>

# Apply network impairment
tc qdisc add dev eth0 root netem delay 50ms 5ms loss 0.5%
```

## Appendix E — Glossary

| Term | Meaning |
|---|---|
| **AH** | Authentication Header. IP protocol 51. Authenticates but does not encrypt. Rarely deployed. |
| **Aggressive Mode** | IKEv1 3-message Phase 1 variant. Leaks identity and a crackable PSK hash. Critical finding. |
| **CNSA** | Commercial National Security Algorithm suite (US NSA). CNSA 2.0 mandates post-quantum. |
| **DH group** | Diffie-Hellman parameter set. Determines key exchange strength. Groups 1/2/5 are weak. |
| **ESP** | Encapsulating Security Payload. IP protocol 50. Encrypts and authenticates. 99%+ of deployments. |
| **GCM** | Galois/Counter Mode. Combines encryption and integrity in one operation. Preferred over CBC. |
| **ICV** | Integrity Check Value. The authentication tag at the end of an ESP packet. |
| **IKE** | Internet Key Exchange. The negotiation protocol. UDP 500, or 4500 with NAT. |
| **IKE_AUTH** | IKEv2's second exchange. Encrypted. Contains identities, traffic selectors, mode. |
| **IKE_SA_INIT** | IKEv2's first exchange. **Cleartext.** Contains all crypto proposals. Your primary data source. |
| **ISAKMP** | The message container format IKE uses. Wireshark's dissector is named after it. |
| **ITSAR** | Indian Telecom Security Assurance Requirements. NCCS/DoT. Your India differentiator. |
| **KE payload** | Key Exchange payload. Carries the raw DH public value. Length confirms the group. |
| **MOBIKE** | IKEv2 extension for mobility and multihoming. |
| **ML-KEM** | Module-Lattice Key Encapsulation Mechanism. FIPS 203. The post-quantum key exchange. |
| **NAT-T** | NAT Traversal. Moves IPsec to UDP 4500 with an extra 8-byte header. |
| **NCIIPC** | National Critical Information Infrastructure Protection Centre. Unit of NTRO. Created 16 Jan 2014 under IT Act §70A. |
| **Notify payload** | IKE payload carrying status/error information. Rich source of intelligence. |
| **PFS** | Perfect Forward Secrecy. Fresh DH per session. Defends against harvest-now-decrypt-later. |
| **PRF** | Pseudo-Random Function. Used in key derivation. Negotiated in IKEv2. |
| **SA** | Security Association. The agreed parameters for one direction of one tunnel. |
| **SAD** | Security Association Database. Kernel table of active SAs, keyed by SPI. |
| **SPD** | Security Policy Database. Rules determining which traffic must be protected. |
| **SPI** | Security Parameter Index. 8 bytes in IKE header (session), 4 bytes in ESP header (data SA). **Different things.** |
| **Transform** | One negotiable algorithm choice within a proposal (encryption, integrity, PRF, or DH). |
| **Transport mode** | Encrypts payload only; original IP addresses remain visible. Host-to-host. |
| **Tunnel mode** | Encapsulates the whole original packet. +20 bytes IPv4, +40 IPv6. Site-to-site. |
| **VID** | Vendor ID payload. Fingerprints the implementation. Route to CVE correlation. |
| **XFRM** | Linux kernel framework doing per-packet IPsec processing. |

## Appendix F — Build checklist

### Pre-hackathon (do this before the finale if possible)

- [ ] Verify the exact problem statement ID and wording on sih.gov.in
- [ ] Docker Compose templates for strongSwan and Libreswan peers
- [ ] Config matrix definition (24–48 configurations, not 576)
- [ ] Sweep orchestrator: spin up, generate traffic, capture, tear down, label
- [ ] Ground-truth harvester using `swanctl --list-sas` and `ip xfrm state`
- [ ] Dual-tap capture (encrypted outer + plaintext inner)
- [ ] Traffic generators for at least 5 classes
- [ ] `tc netem` impairment profiles

### Hour 0–12

- [ ] Run the sweep, produce labelled PCAPs and manifests
- [ ] Feature extraction pipeline → parquet
- [ ] Deterministic IKE parser: version, exchange type, transforms, attributes
- [ ] **Decision gate:** if no labelled data by hour 12, drop the ML lane

### Hour 12–24

- [ ] Rules engine with the Appendix A rule set
- [ ] Tunnel inventory view
- [ ] Random forest / XGBoost classifier for in-tunnel traffic
- [ ] Held-out configuration generalisation test (report honestly)
- [ ] Remediation generator with both-ends sequencing

### Hour 24–36

- [ ] Dashboard
- [ ] Executive + technical report export
- [ ] PQC readiness scoring
- [ ] SHAP explanations wired into inferred findings
- [ ] ITSAR/CERT-In baseline view
- [ ] **Rehearse the demo at least three times**
- [ ] Record a fallback demo video

---

## Document ends

**Compiled reference for the AI-Driven IPsec VPN Protocol Analysis Platform.**

Key reminders:

1. Verify the problem statement on the official portal — the exact PS could not be confirmed in public SIH 2025 sources.
2. The named datasets contain no IPsec traffic. Build the testbed. Replay their benign traffic as inner payload.
3. Seven of nine identification targets are parsing, not ML. Say so.
4. The AI lane exists for what cannot be read: inner traffic, anomalies, drift.
5. Never let the tool apply a configuration change. Both ends must change together.
6. A working demo of four features beats a broken demo of twelve.
