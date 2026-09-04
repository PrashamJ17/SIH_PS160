# AI-Driven IPsec VPN Protocol Analysis Platform (SIH): Feasibility, Impact, and Winning Assessment

## TL;DR
- **Yes, a strong version is buildable in a hackathon timeframe with heavy AI/LLM coding help — but only if you re-scope it honestly:** the deterministic parts (parsing IKE negotiations, auditing crypto parameters against NIST/BSI/Indian baselines, auto-generating remediation configs) are the winnable core, while the "AI classifies encryption algorithm and DH group from captured traffic" framing is largely a myth for ESP and should be reframed as ML for *application-inside-tunnel* classification plus deterministic parsing of the cleartext IKE handshake.
- **The datasets named in the problem statement (CIC-IDS2017/2018, UNSW-NB15, CTU-13, CICIoT2023, LANL, DARPA) contain essentially no labelled IPsec traffic and cannot support the stated crypto-identification objective;** no public IPsec PCAP corpus with ground-truth labels for cipher/DH-group/mode/PFS exists, so a winning team must *generate its own testbed captures* (strongSwan/Libreswan in Docker) — which is exactly objective (a) and should be treated as a feature, not a chore.
- **Realistic odds are moderate-to-good but not high:** a security/defence problem statement from NCIIPC/NTRO draws fewer but more serious teams; the official SIH selection process nominates roughly 5–7 colleges per problem statement for the grand finale, with one ₹1 lakh winner per statement. Your edge comes from clear-eyed scoping, mapping to Indian standards (ITSAR, CERT-In, NCIIPC), PQC-readiness, and a working demo — not from over-promising an AI that "breaks" IPsec.

## Key Findings

### 1. The dataset premise in the problem statement is misleading (this is the single most important thing to get right)
The problem statement points to a list of well-known network-security datasets. Every one of them was built for **intrusion/anomaly detection**, not IPsec analysis:
- **CIC-IDS2017**: ~50 GB PCAP + 80-feature CSVs (CICFlowMeter), 5 days, benign + brute-force/DoS/DDoS/web/infiltration/botnet. Benign profiles use HTTP, HTTPS, FTP, SSH, SMTP only. No IPsec.
- **CSE-CIC-IDS2018**: extension of 2017, same methodology, adds Heartbleed/botnet/DDoS. No IPsec.
- **UNSW-NB15**: 100 GB PCAP, 2.54M records, 49 features, 9 attack families (Fuzzers, Exploits, Generic, DoS, etc.), IXIA-generated. No IPsec.
- **CTU-13**: 13 botnet capture scenarios (IRC, spam, click-fraud, DDoS, port-scan) as PCAP. No IPsec.
- **CICIoT2023**: 46.7M records / 99 GB / 79 PCAPs, IoT DDoS/DoS/Mirai/recon/spoofing. No IPsec.
- **LANL / DARPA**: authentication logs and legacy 1998–2000 intrusion captures respectively — not IPsec.
- **MITRE ATT&CK / CAPEC / CVE-NVD**: these are knowledge bases, not traffic. They are genuinely useful, but for *mapping and enrichment* (see below), not training a traffic classifier.

**None of these contain IKEv1/IKEv2 negotiations (UDP 500/4500), ESP (IP proto 50) or AH (IP proto 51) packets with ground-truth labels for encryption algorithm, DH group, tunnel-vs-transport mode, or PFS.** My dedicated follow-up research confirmed that **no public IPsec-specific PCAP corpus with crypto-parameter ground-truth labels exists at all.** The closest public VPN datasets are:
- **ISCXVPN2016 (UNB)** — the canonical VPN/non-VPN dataset (7 traffic categories: browsing, email, chat, streaming, file transfer, VoIP, P2P) — but its "VPN" captures are **OpenVPN**, not IPsec, and researchers have documented serious quality problems: per Aceto et al.'s DISTILLER analysis (2021), roughly 65% of the biflows "have only one UDP packet and destination (255.255.255.255,10505)" — network broadcasts sent every two seconds by default by BlueStacks — and later work (FlowCLIP) notes 98.9% of some of its traffic is actually unencrypted. It must be cleaned before use.
- **VNAT** — 165 PCAPs / 36.1 GB / ~272 hours — VPN side is **OpenVPN**, no IPsec, no crypto labels.
- **USBVPN2022 (Naas & Fesl, Data in Brief 2023)** — includes an **L2TP-IPSEC** subset (2.5 GB, 1,955 flows) among 6 VPN protocols, but stored as JSON flow records (not raw PCAP), labelled only by VPN-protocol type — no cipher/DH/mode/PFS ground truth.
- A 2022 ML tunnel-classification study explicitly states its authors "could [not] find any data for IPsec, OpenVPN or Wireguard" and had to **build their own testbed** to capture IPsec tunnel traffic.

**Implication:** objective (a) "testbed generation" is not optional busywork — it is the *only* way to obtain labelled IPsec data, and it should be the backbone of your project. Build a reproducible strongSwan/Libreswan testbed (Docker Compose) that spins up tunnels across a matrix of ciphers, DH groups, PFS on/off, tunnel/transport, IKEv1/IKEv2, then captures PCAPs *with the configuration as the label*. That single artifact simultaneously solves your data problem and demonstrates rigour to judges.

### 2. Most of "AI-based protocol identification of crypto parameters" is deterministic parsing, not ML
This is a crucial technical truth that will impress security-literate judges if you state it plainly, and will sink you if you pretend otherwise.

**What is readable in cleartext (no ML, no keys needed):**
- **IKEv2 IKE_SA_INIT (RFC 7296)** is sent in the clear. Its **SA payload** contains the proposed/accepted **transforms**: encryption algorithm (e.g. ENCR_AES_GCM_16), integrity algorithm, **PRF**, and **DH group**. The **KE payload** (Diffie-Hellman value) and **nonces** are also visible. So the negotiated cipher suite and DH group are **directly parseable** from a packet capture of the handshake. (RFC 7296 §1.2: the first pair of messages "negotiate cryptographic algorithms, exchange nonces, and do a Diffie-Hellman exchange.")
- **IKEv1** main/aggressive mode SA payloads similarly expose transform sets; aggressive mode additionally leaks the identity and a PSK hash (the basis for ike-scan/psk-crack attacks).
- **ESP headers**: **SPI** and **sequence number** are always in cleartext; everything after (payload, next-header, padding, and — in tunnel mode — the inner IP header) is encrypted.

**What is encrypted (requires the key, or must be inferred):**
- IKE_AUTH exchange: identities, certificates, **traffic selectors**, and crucially the **tunnel-vs-transport mode** negotiation are inside the encrypted+integrity-protected portion (RFC 7296: "Parts of these messages are encrypted and integrity protected with keys established through the IKE_SA_INIT exchange, so the identities are hidden from eavesdroppers"). So mode is *not* directly readable from a passive capture of a real (non-instrumented) session.
- The actual data inside ESP.

**Relevant RFCs to cite in your report/deck:** RFC 7296 (IKEv2), RFC 4301/4302/4303 (architecture/AH/ESP), RFC 8221 (ESP/AH algorithm requirements), RFC 8247 (IKEv2 algorithm requirements). Wireshark can decrypt IKE/ESP only if you supply keys (e.g. strongSwan's `save-keys` plugin or `ip xfrm state`) — which is fine in your own testbed but impossible for a passive auditor of someone else's tunnel.

**So the honest architecture is a three-lane system:**
1. **Deterministic IKE parser** (the bulk of objective c): read IKE_SA_INIT, extract cipher/integrity/PRF/DH group, IKEv1-vs-v2, aggressive-mode detection. This is a solved-in-principle problem (Wireshark ISAKMP dissector, Zeek's corelight/zeek-spicy-ipsec analyzer already log `transforms`, `ke_dh_groups`, `proposals`, `notify_messages`), so your value-add is the *assessment layer*, not the parsing.
2. **Active probing** (optional, powerful): integrate `ike-scan`/`iker`/`IKESS` to enumerate *all* transforms a gateway will accept (not just what one client negotiated) — this is how you find that a device still accepts 3DES/DH-2/aggressive mode even if the observed session used AES. (ike-scan's default probe sends 8 transforms covering DES/3DES × MD5/SHA-1 × DH groups 1/2.)
3. **ML lane** for the genuinely-inferential parts: (a) classifying the *application inside* an ESP tunnel from side-channel features, and (b) inferring tunnel-vs-transport from packet-size overhead/address structure heuristics.

### 3. Encrypted-traffic classification inside tunnels: state of the art and what's realistic
The academic literature is large and the accuracy numbers look impressive but come with heavy caveats:
- Classic time-related-feature work on ISCXVPN2016 (Draper-Gil et al.) reports ~92% recall over six traffic classes using kNN/C4.5; many later papers report 96–99%+ (e.g. random-forest and CNN/autoencoder approaches, up to 99.2% non-VPN / 98.3% VPN in the Semi-2DCAE work).
- **Directly relevant to IPsec:** Okada et al. (IEEE CQR 2011 and ICMLA 2011) classified applications *inside IPsec/PPTP tunnels* using statistical features + SVM. Per the MDPI *Applied Sciences* review (13(3):1974), "the best EFM [Estimated Feature Method] using SVM was found to identify IPSec tunnel traffic with 97.2% accuracy" (Okada selected 29 features with correlation >0.7), and a further **28.5% improvement** in protocol identification accuracy "when mixed with HTTP, FTP, SMTP and SSH passenger protocols." Kumano et al. (ICNC 2014) achieved 92.5% in a real-time variant. A 2022 study found IPsec/WireGuard are actually *easier* to classify inside than SSH/OpenVPN, with random forest / decision tree performing best, using packet-size-with-direction and byte-burst features.
- ET-BERT, 1D-CNN, LSTM and flow-image transformer approaches report the highest headline numbers but are the least practical for a 36-hour finale and the most prone to dataset overfitting.

**Methodological caveats you must state (judges from NTRO/NCIIPC will know these):** most numbers are **closed-world** (fixed known app set); open-world generalisation collapses; cross-dataset validation is notoriously poor; and IPsec differs from OpenVPN/TLS in ways that matter — **ESP padding, ESP/tunnel-mode encapsulation overhead, and block-cipher padding blur packet-size features**, so figures from OpenVPN datasets do not transfer directly. **Recommended stack for a hackathon: random forest / XGBoost on flow-statistical features (fast, explainable, defensible), with a 1D-CNN as an optional "stretch" comparison.** Add SHAP/LIME for explainability and confidence calibration + abstention so the tool says "I don't know" rather than guessing — this is exactly the kind of maturity that wins.

### 4. Existing tools & the real gap
Parts of this already exist: `ike-scan` (transform enumeration, backoff/VID fingerprinting, PSK cracking via psk-crack), `iker`/`IKESS` wrappers (risk-rated JSON/HTML reports), nmap `ike-version`, Wireshark ISAKMP/ESP dissectors, **Zeek's corelight/zeek-spicy-ipsec** analyzer (logs transforms, DH groups, proposals, notify messages, vendor IDs), strongSwan's own diagnostics/`save-keys`, and Nessus/OpenVAS IKE plugins. There are commercial VPN/firewall auditors too.

**The genuine gap your project can fill:** none of these is a *unified, AI-assisted, India-standard-aware assessment platform* that (i) ingests both passive PCAP and active scan results, (ii) grades a configuration against **multiple baselines simultaneously** (NIST SP 800-77r1, RFC 8221/8247, CNSA, BSI TR-02102-3, ANSSI, **and Indian ITSAR/CERT-In/NCIIPC**), (iii) maps findings to MITRE ATT&CK/CAPEC and pulls relevant strongSwan/Libreswan/racoon CVEs, (iv) assesses **PQC-readiness**, and (v) auto-generates fixed configs. That integration + Indian-context layer is defensibly novel for SIH even though no individual component is.

### 5. Security-assessment baselines to encode as your rule engine
- **NIST SP 800-77 Rev.1** — Barker, Dang, Frankel, Scarfone & Wouters, "Guide to IPsec VPNs," published June 30, 2020 (DOI 10.6028/NIST.SP.800-77r1); the primary reference.
- **RFC 8221 (ESP/AH)** and **RFC 8247 (IKEv2)** — MUST/SHOULD/SHOULD NOT algorithm tables; deprecate 3DES, DES, MD5, DH-1/2/5.
- **CNSA / CNSSP-15** — US national-security suite: AES-256, SHA-384/512, ECDSA P-384, RSA-3072+, and **CNSA 2.0** now mandates ML-KEM-1024 / ML-DSA-87 (FIPS 203/204).
- **BSI TR-02102-3** — German IPsec crypto guideline; recommends PFS, flags SHA-1, and states (EC)DH "sole use" is only recommended **until end of 2031** with ml-kem-768/1024 as the quantum-safe path.
- **ANSSI** IPsec recommendations and **CIS Benchmarks** for vendor configs.
- **Indian standards (your differentiator):** **ITSAR** (Indian Telecom Security Assurance Requirements) from **NCCS** under DoT mandate NIST-recommended crypto (IPSec/TLS/SSH, AES/DH/RSA/SHA) and ITSAR certification is valid 10 years; **CERT-In 2022 Directions** (6-hour incident reporting, 180-day log retention, 5-year VPN subscriber logs, binding under IT Act §70B(6)); **NCIIPC** guidelines for CII.
- **Weak/deprecated configs to flag:** DH groups 1/2/5, 3DES, DES, MD5, SHA-1, IKEv1 aggressive mode, missing PFS, AES-CBC without integrity, over-long SA lifetimes, disabled anti-replay.
- **PQC layer:** RFC 8784 (post-quantum preshared keys), RFC 9370 (multiple key exchanges, up to 7 KEMs in parallel with classical DH), draft-ietf-ipsecme-ikev2-mlkem; note strongSwan 6.x + liboqs support hybrid `ke1_mlkem768`; and government timelines (NSA CNSA 2.0 targets PQC capability by 2025 and exclusive use by 2035; Cloudflare targets full IPsec PQC by 2029). India has no published hard PQC-migration deadline, which you should note as a gap your tool anticipates.

### 6. NCIIPC / Indian government use case
**NCIIPC** was created by gazette notification on 16 January 2014 under Section 70A of the IT Act, is a unit of **NTRO** (reporting to the PMO via the NSA), and is the nodal agency protecting **Critical Information Infrastructure** across banking/finance, power/energy, telecom, transport, health, and government/strategic enterprises. It runs a **Responsible Vulnerability Disclosure Programme**, issues advisories, maintains a 24×7 helpdesk, and connects to 200+ sites. IPsec is pervasive in exactly these networks (site-to-site tunnels between substations/data centres, remote access, NICNET, defence WANs), so a config-auditing tool is squarely in NCIIPC's remit.

**Real-world relevance:** 2024–2025 saw mass exploitation of VPN edge devices — the Ivanti Connect Secure chain (CVE-2023-46805 + CVE-2024-21887) hit over 1,700 devices worldwide per Volexity's 15 Jan 2024 report, rising to over 2,100 GIFTEDVISITOR-infected appliances by 16 Jan; plus Fortinet CVE-2024-21762, Palo Alto CVE-2024-3400 and Check Point CVE-2024-24919 — much of it by nation-state actors (e.g. China-nexus UNC5221). This is the strongest possible justification that VPN/tunnel hygiene is a live CII problem. (Note: those are SSL-VPN appliance RCEs, not IPsec crypto weaknesses per se; be precise about this distinction rather than conflating them.)

**Procurement/adoption reality:** SIH winners rarely get direct procurement. The realistic path is incubation via **YUKTI/MIC** (the National Innovation Repository reports 100+ startups and 9,654 SIH alumni), the NCIIPC RVDP/internship route, or the sponsoring org adopting the idea in-house (ISRO, for example, accepted several SIH 2024 solutions for in-house development). Frame your "impact" slide around these concrete channels, not a fantasy government contract.

### 7. How SIH works and your odds
- **Format:** national grand finale, **36 continuous hours**, teams of **6 students + 2 mentors**, at ~50 nodal centres. Per PMO/PIB (10 Dec 2024), SIH 2024 fielded "over 1300 student teams" at 51 nodal centres against "more than 250 problem statements...submitted by 54 Ministries," drawn from 86,000+ institute-level teams (~49,000 advancing internally).
- **Per problem statement:** the official process allows up to ~500 submissions per statement, then (per DJSCE's official winners document) "SIH team then selected 5–7 colleges for each problem statement for Grand Finale." Team counts per node vary (e.g. ~20 teams / 4 statements at KCG Chennai; larger at other nodes), evaluated by ~3 jurors, with **one winner (₹1,00,000)** per statement (occasional joint winners); some statements have *no* winner if no team meets the bar.
- **Judging criteria (weightings vary by source but cluster around):** innovation/novelty ~30%, technical complexity/execution ~25%, impact/feasibility ~25%, presentation ~20%. Problem understanding and a *working prototype* dominate in practice.
- **What wins:** a well-scoped, deeply-understood problem beats an over-ambitious one; a live working demo; clearly articulated differentiation from existing tools; and alignment with the sponsoring ministry's real needs. Security/defence statements (NTRO/NCIIPC) attract fewer, more serious teams — good news for a technically strong team, bad news if you can't demo.

**Caveat on the problem statement itself:** my dedicated search could **not locate this exact IPsec-VPN problem statement in any public SIH 2025 catalogue.** The NTRO cybersecurity block in SIH 2025 (SIH25228–SIH25240) contains crypto-adjacent statements — notably **SIH25239, "AI/ML-Based Identification of Cryptographic Primitives and Protocols in Multi-Architecture Firmware Binaries"** — but no IPsec-traffic PS and no NCIIPC-branded PS. It is plausible the IPsec statement exists among unpublished statements or in SIH 2026, or that the organisation/title is slightly misremembered. **Verify the exact PS ID, title, and objective wording on the official SIH portal before committing** — some of the strategic advice above shifts depending on whether the sponsor is NTRO or NCIIPC and whether the emphasis is passive analysis vs. active assessment.

## Details: recommended architecture
1. **Testbed & data generation (objective a):** Docker Compose with strongSwan and Libreswan peers; a config matrix script sweeping {IKEv1,IKEv2} × {AES-CBC, AES-GCM, 3DES} × {DH 2,5,14,19,20,31} × {PFS on/off} × {tunnel,transport}; `tcpdump` capture with the generating config written as the label; `save-keys` for decryptable reference captures.
2. **Deterministic IKE parser + active scanner (objective c):** Python (scapy) or Zeek spicy-ipsec for passive parsing; wrap `ike-scan`/`iker` for active transform enumeration; normalise to a common finding schema.
3. **Assessment engine (objective d):** rule engine encoding NIST 800-77r1 / RFC 8221/8247 / CNSA / BSI / ITSAR; each finding gets severity, the violated standard clause, an ATT&CK/CAPEC tag, and matching CVEs.
4. **ML lane:** random forest / XGBoost for in-tunnel application classification on flow-statistical features, with SHAP explanations, calibrated confidence, and an abstention threshold; report closed-world accuracy honestly.
5. **Remediation & reporting:** auto-generate fixed strongSwan/Libreswan/Cisco/Fortinet configs; export a PDF/HTML report; offline/air-gapped deployment; optional SIEM (ELK) integration and drift detection.

### High-value differentiating features (ranked by impact-to-effort)
- **Multi-baseline compliance grading incl. Indian ITSAR/CERT-In/NCIIPC** — highest novelty for an Indian government audience, low technical risk.
- **PQC-readiness assessment** (RFC 8784/9370, ML-KEM/FIPS 203) — timely, forward-looking, easy to score.
- **MITRE ATT&CK/CAPEC mapping + IPsec/strongSwan/Libreswan/racoon CVE threat matrix** — makes findings actionable for a SOC.
- **Auto-generated remediation configs** — concrete, demoable "so what."
- **Explainable AI (SHAP/LIME) + confidence calibration/abstention** — signals research maturity.
- **Metadata-leakage demonstration** (what an eavesdropper learns from IKE cleartext + ESP sizes) — a memorable live demo.
- **Digital-twin/"what-if" config simulation, IPv6 support, drift/differential detection, adversarial robustness of the classifier** — good stretch goals if time remains.

## Recommendations (staged)
1. **Before the finale — verify and re-scope.** Confirm the exact PS on sih.gov.in. Rewrite the objectives in your own words, explicitly separating *deterministic parsing* from *ML inference*. If a mentor or the PS author is reachable via the NCIIPC helpdesk (1800-11-4430 / helpdesk1@nciipc.gov.in), ask what deployment they envision (passive monitoring vs. active audit).
2. **Build the testbed first (day 1).** It is your data source, your demo, and your novelty. If you have a working strongSwan matrix + capture pipeline by hour 12, you have already beaten most teams.
3. **Ship the deterministic auditor before touching ML.** A tool that reliably parses IKE_SA_INIT and grades it against NIST + ITSAR with remediation output is a *complete, demoable product* on its own. ML is the differentiator, not the foundation.
4. **Add the India + PQC + ATT&CK layers for the "wow".** Multi-baseline grading (including ITSAR/CERT-In), PQC-readiness scoring (RFC 8784/9370/ML-KEM), MITRE mapping, and auto-remediation are high-value, low-risk additions.
5. **Demo discipline.** Pre-capture PCAPs and pre-stage a vulnerable gateway (3DES + DH-2 + aggressive mode) so the live demo can't fail on network issues. Show the tool flagging it, mapping to ATT&CK, and emitting a fixed config.
- **Benchmarks that should change your plan:** if you cannot get the strongSwan testbed capturing labelled PCAPs within ~12 hours, drop the ML lane entirely and double down on the deterministic auditor + standards engine (still a winning entry). If in-tunnel classifier test accuracy is <~85% closed-world, present it as a *research finding with honest caveats* rather than a headline claim.

## Caveats
- **Unverified problem statement:** I could not confirm the exact PS ID/title/objectives in public SIH 2025 sources; treat the "four objectives" framing as approximate and verify officially.
- **Accuracy figures are optimistic:** published 92–99% numbers are overwhelmingly closed-world and dataset-specific; real-world/open-world performance is materially worse, and OpenVPN-derived numbers do not transfer cleanly to IPsec/ESP.
- **"AI identifies the DH group/cipher" is mostly false framing:** those come from deterministic parsing of the cleartext IKE handshake, not ML; ML's real role is in-tunnel application classification and mode inference. Judges will respect you for saying so.
- **No public IPsec crypto-labelled dataset exists** — this is a confirmed gap, not an oversight on your part; self-generated testbed data is the accepted workaround in the literature.
- **VPN-appliance CVEs ≠ IPsec crypto weaknesses:** the 2024 Ivanti/Fortinet incidents were SSL-VPN software RCEs; use them to motivate the problem but don't conflate them with the cipher/DH-group auditing your tool performs.
- **Weightings vary:** SIH judging percentages differ across nodal centres and years; the ~30/25/25/20 split is indicative, not official.