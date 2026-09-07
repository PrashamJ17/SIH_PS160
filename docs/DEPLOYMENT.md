# Deployment

The tool analyses captures. Everything below is about getting it packets that are worth
analysing, and about the fact that **the capture is the ceiling** — no amount of analysis
recovers a negotiation the sensor did not see.

---

## What you actually need to capture

Far less than most capture deployments, which is the useful part.

IPsec assessment needs the **IKE control plane**: UDP 500 and UDP 4500. Those carry the
negotiation, and that is where every deterministic finding comes from. They are also a
tiny fraction of the traffic — an IKE exchange is a handful of packets per tunnel per
rekey interval.

ESP itself (IP protocol 50) is needed only for the inventory, the traffic profile and the
inference lane. It is encrypted and never decrypted; only sizes, timings and directions
are used.

A sensible starting filter:

```
udp port 500 or udp port 4500 or ip proto 50 or ip6 proto 50
```

If storage is tight, drop ESP and keep IKE. You lose Section B, the traffic profile and
the undocumented-tunnel detection, and you keep every compliance finding. That is a
reasonable trade and the report will be explicit about what is missing rather than quietly
thinner.

---

## Where to put the sensor

### SPAN / mirror port

The common choice, and the right one for most sites. Configure a mirror on the switch
carrying traffic to and from the VPN gateway, and point the sensor's interface at it.

**Mirror both directions.** A one-directional mirror sees the initiator's proposals and
not the responder's selection, which is precisely the half that determines what was
actually agreed. The result is a capture that looks complete and assesses nothing.

**Mirror ports drop silently under load.** A switch oversubscribing a mirror discards
frames without telling anyone, and a dropped IKE_SA_INIT is a tunnel that vanishes from
the inventory. The tool cannot distinguish that from a quiet network. If the mirrored
links can exceed the mirror port's capacity, filter at the switch to the IKE ports rather
than mirroring everything and filtering at the sensor.

### Network TAP

Better where it is affordable. A passive TAP is a physical device on the link: it cannot
be oversubscribed by a busy switch, it cannot be misconfigured into one-directional
capture, and it fails open. An aggregating TAP combines both directions onto one interface
and can drop under load exactly as a mirror port does — a non-aggregating TAP with two
capture interfaces does not.

For an assessment that will be shown to an auditor, a TAP is the defensible choice.

### On the gateway itself

Sometimes the only option, and acceptable. Run `tcpdump` on the VPN gateway's outside
interface with the filter above. It captures exactly the right traffic and costs no
switch configuration.

The caveats are operational rather than technical: you are running a capture on a
production security device, it consumes CPU and disk there, and many organisations
prohibit it. Rotate captures with `-C`/`-W`, and never write them to the same filesystem
as the gateway's logs.

### Inline

No. Nothing in this project is inline, and nothing in it should be. It is a passive
analyser and there is no code path that forwards, drops, or modifies a packet.

---

## Sensor sizing

The engine's measured throughput is far above what a mirror of IKE traffic produces, so
sizing is dominated by storage rather than by CPU.

| Resource | Guidance |
|---|---|
| CPU | 2 cores is comfortable. Parsing a 100 MB capture takes about 0.5 s; assessing 1000 tunnels about 0.1 s. |
| Memory | 4 GB. A 1 GB capture peaks at about 0.40 GB because the parser streams rather than loading the file. |
| Disk | The variable. See below. |
| Network | One capture interface, in promiscuous mode, with no IP address configured on it. |

### Estimating storage

IKE-only capture is small and predictable. Per tunnel, per rekey:

- IKEv2: `IKE_SA_INIT` plus `IKE_AUTH`, roughly 2–4 KB including retransmissions.
- IKEv1 main mode: six messages, roughly 3–6 KB.

For 200 tunnels rekeying every 8 hours, that is on the order of **5 MB per day**. Keeping
90 days of IKE costs under a gigabyte.

Adding ESP changes the problem entirely: ESP is the production traffic, and capturing it
means capturing your VPN throughput. If you want the inference lane, capture ESP in
**windows** rather than continuously — 45 seconds per tunnel is enough for the classifier
to commit, and a shorter window legitimately produces an abstention. The demo captures are
45 seconds for exactly this reason.

### Capture windows and what they cost you

The tool reads what negotiated during the window. A tunnel that did not rekey is reported
as `ESP-01` — ESP traffic with no observed negotiation — which is a statement that it
could not be judged, not a pass.

Two ways to shorten the wait:

- **`sentinel watch --device-state`** parses `ip xfrm state` or `swanctl --list-sas`
  output that an operator collected, which says what is *installed now* regardless of
  whether the negotiation was seen. This is what closes the rekey blind spot: a
  CREATE_CHILD_SA is encrypted, so its proposals are unreadable on the wire. The tool
  reads the file; it never connects to the device.
- **`sentinel scan --i-have-authorisation`** actively enumerates what a responder accepts.
  It transmits, it shows up in the target's logs as failed negotiations, and it can
  disturb a fragile IKE daemon. Use it deliberately.

---

## Running it

### Container

```bash
docker compose up -d
```

Brings up the engine on `127.0.0.1:8000` and the dashboard on `127.0.0.1:8080`. Drop
captures into `./captures`, which is mounted read-only.

The engine runs as uid 10001 with a read-only root filesystem, all capabilities dropped
and `no-new-privileges`. **The API has no authentication** — it is meant for a host the
operator controls, and the port bindings are deliberately loopback-only. Exposing it more
widely is a decision this project does not make for you.

The `sensor` service is behind a profile and does **not** start by default, because it
needs `NET_ADMIN` and host networking:

```bash
SENTINEL_SENSOR_INTERFACE=eth1 docker compose --profile sensor up -d
```

One-shot analysis without the server:

```bash
docker compose run --rm engine analyse /data/capture.pcap --json /tmp/report.json
```

### Bare metal

```bash
bash scripts/install.sh --prefix /opt/ipsec-sentinel
export PATH="/opt/ipsec-sentinel/bin:$PATH"
```

### Air-gapped

Build the bundle on a host with network access, carry it across, install with no package
index:

```bash
bash scripts/build_offline_bundle.sh --platform manylinux2014_x86_64 --python-version 3.11
```

```bash
tar xzf ipsec-sentinel-offline-*.tar.gz && cd ipsec-sentinel-offline-*
sha256sum -c MANIFEST.txt
bash install.sh --offline --prefix /opt/ipsec-sentinel
```

**The bundle is specific to one platform and one interpreter version.** Wheels are
compiled for both, so a bundle built on macOS for Python 3.11 installs on neither Linux
nor Python 3.12. The tarball is named for both, `BUNDLE.json` records them, and
`install.sh` refuses a mismatched interpreter before it creates the virtualenv rather than
failing partway through a dependency resolve. Build for the target with `--platform` and
`--python-version`.

Everything works with no outbound access — see the air-gap tests in
`tests/integration/test_offline.py`. What degrades is enrichment: without the local ATT&CK
bundle and CVE cache, technique IDs appear unexpanded and no vendor advisories are listed.
The report says so rather than looking complete, and the threat matrix's protocol CVEs are
compiled in and unaffected.

---

## Continuous monitoring

```bash
sentinel watch eth1 --state /var/lib/sentinel/drift.json --syslog siem.example.net:514
```

Drift is measured against each tunnel's **own past**, not against the baseline: a tunnel
that was always mediocre is a finding `analyse` already made, while one that *was* strong
and is now mediocre is news. The state file makes that survive a restart; `--since` seeds
it from a previous assessment's capture.

Alerts leave as RFC 5424 syslog, and reports export as CEF or LEEF for ArcSight and
QRadar.

---

## Handling the output

Reports contain endpoint addresses, traffic volumes, the hours a link is busy, and which
tunnels are weak. That is the product, and it is also a map of where to attack. Handle
them like any other assessment output.

The engine holds them in memory and does not persist them —
[SECURITY.md](SECURITY.md) explains why that is deliberate.
