# Security posture of the tool itself

An IPsec analyser is a security product, so the first questions a buyer should ask are
about the analyser, not the tunnels. This document answers them, and every claim names
the test that checks it. The tests live in
[`tests/unit/test_security.py`](../tests/unit/test_security.py) and run in `make verify`
like everything else, so a claim here that stopped being true would break the build.

Where the honest answer is a caveat rather than a guarantee, it is written as a caveat.

---

## What this tool is

It reads captured packets and produces documents. Nothing it emits is applied
automatically; a person reads the configuration and applies it.

It has three modes, and only one of them transmits:

| Mode | Transmits? | Needs credentials? |
|---|---|---|
| **Analysis** — a capture in, a report out | No | No |
| **Watch** — an interface or state files in, drift alerts out | No | No |
| **Scan** — active IKE transform enumeration | **Yes**, and refuses without `--i-have-authorisation` | No |

---

## No credential is stored, transmitted, or read

There is no configuration field, environment variable, command-line flag or prompt for a
password, key, token or community string anywhere in the product. Not because they are
handled carefully — because they are never handled.

This is possible because the tool never authenticates to anything. It reads packets it is
given and text a device produced. Where device state is useful — see below — the operator
collects it with whatever access they already have and passes a file.

**Checked by:**

- `test_no_credential_like_name_is_assigned_a_literal` — walks the AST of every module in
  `src/` and fails on any assignment of a credential-shaped name to a string literal. AST
  rather than grep, so a comment discussing passwords is not a finding and an actual one
  is.
- `test_no_module_reads_a_credential_from_the_environment` — the same check for
  `os.getenv` / `os.environ` lookups.
- `test_no_key_material_is_pasted_into_the_source` — PEM headers.
- `test_the_generated_configurations_carry_no_secret` — the documents an operator pastes
  into a change ticket contain no `secret =` or `psk =` line. The pre-shared key reaches a
  testbed peer through the environment at run time and is never written to disk by this
  project.
- `test_no_session_key_survives_state_parsing` — `ip xfrm state` prints session keys
  inline. The parser reads the algorithm name and ICV length and discards the key bytes
  without ever placing them in a returned object. Also checked against a **real kernel's
  output** in `tests/integration/test_collect_live.py`, because a fixture only proves the
  regex drops the field it was aimed at.

---

## The tool never writes to a network device

The remediation lane produces configuration text for six vendors. It cannot apply any of
it. There is no SSH client, no NETCONF client, no vendor REST client, and no code path
that could grow one without failing a test.

This is the claim a network team will care about most: an analyser that can reconfigure a
production gateway is an outage waiting for a bad inference. This one never writes
anything to a device, so a wrong finding costs a wasted review and nothing else.

**Checked by:**

- `test_no_remote_access_client_is_imported_anywhere` — no module in the product imports
  `paramiko`, `netmiko`, `napalm`, `scrapli`, `asyncssh`, `fabric`, `pexpect` or
  `telnetlib`.
- `test_no_device_write_method_is_called` — no call to `send_config_set`,
  `load_merge_candidate`, `commit_config` or `sendline`.
- `test_the_cli_offers_no_way_to_reach_a_device` — no command offers `--host`, `--ssh`,
  `--username`, `--password` or `--api-key`.
- `test_the_forbidden_list_covers_what_it_should` — because a list that omits `netmiko`
  proves nothing.

---

## Passive mode opens no outbound socket

Analysis and reporting are run with `socket.socket`, `socket.create_connection` and
`socket.getaddrinfo` replaced by functions that raise, and they complete.

**Checked by:**

- `test_analysis_opens_nothing` and `test_reporting_opens_nothing`.
- `test_only_two_modules_transmit_at_all` — an AST sweep finds socket construction in
  exactly two modules: `probe.py`, which is the active scanner, and `siem.py`, which
  delivers alerts to a collector the operator configured. Neither is reachable from the
  analysis path, and a third module appearing in that set fails the test.
- `test_the_prober_refuses_without_authorisation` — the gate is in the library, not only
  in the CLI, so it does not depend on the command line being the only caller.

The API is a server: it accepts connections, and it opens none.

---

## Reading device state does not change any of this

Watch mode can read `ip xfrm state` and `swanctl --list-sas` to see what a gateway has
installed, which closes a blind spot the wire cannot: an IKE rekey is encrypted, so a
passive observer cannot read what it agreed.

**The tool parses this; it does not fetch it.** It reads a file, a directory of files a
collector dropped, or — with `--local-state` — the machine it is running on, which needs
no credential and opens no socket. Collecting state from a *remote* device is deliberately
not a feature: that is the operator's existing access, used by their existing tooling.

The division is what keeps the no-credentials claim true rather than aspirational.

---

## Uploaded files are bounded and confined

The API's upload endpoint is the largest attack surface in the project.

- The uploaded **filename is never used as a path**. It is reduced to a printable label —
  no separators, no dot runs, no terminal escapes, bounded to 96 characters — and the
  bytes go to a `tempfile.mkstemp` path this service chooses.
- The **size limit is enforced while reading**, in 1 MB chunks. Trusting `Content-Length`
  would let a client that lies about it exhaust memory anyway.
- The temporary file is removed on the **failure** path as well as the success path.
- Every response carries `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer` and a Content Security Policy, applied by middleware so a
  route added later cannot forget them.

**Checked by:** `TestUploadsAreBoundedAndConfined` here, and `TestSecurity` in
[`tests/unit/test_api.py`](../tests/unit/test_api.py), where the traversal test uploads a
file named `../../../../../../<tmp>/etc/crontab` and asserts that directory stays empty.

---

## External data is parsed defensively

Everything from outside is hostile until parsed: captures arrive from a network, baselines
and documented-tunnel lists from a file somebody edited.

- **YAML is always `yaml.safe_load`.** `yaml.load` without a safe loader executes
  arbitrary Python; an AST test fails on any occurrence.
- **There is no `eval` and no `exec`** anywhere in the product.
- **Captures are fuzzed.** Step 4.9 put 10,000 malformed inputs through the parser with
  zero crashes and zero hangs, across four aimed corpora — random bytes almost never name
  a payload type the parser handles, so a purely random corpus tests very little.
- A malformed capture, baseline or tunnel list raises a typed error rather than crashing.

The report renderer **escapes everything**. Vendor IDs, peer identities and algorithm
names are attacker-controlled text read off the wire, and autoescaping is enabled
explicitly rather than left to a default that a file rename could switch off. The
dashboard is served under a Content Security Policy with **no `unsafe-inline` at all** —
its stylesheet and script were split out of the single HTML file specifically so the
policy could forbid inline execution rather than permit it.

---

## The one place this project unpickles

`joblib` is pickle-based, so **loading a trained model executes code from that file**.
That is a property of the format and cannot be checked away.

The policy is that a model is a **local artefact the operator produced** with
`sentinel model train`, from a dataset they built. It is not untrusted input in the way a
capture is. Anyone who can write the model file already has whatever access writing files
on that host implies.

What follows, and is worth saying plainly: **do not load a model somebody sent you.** A
pre-trained model is a program. Retrain instead — the dataset checksum recorded in
`models/traffic.metadata.json` is what makes a retrained model comparable to the one whose
results were published.

Analysis does not require a model at all. `analyse` without `--model` produces a report
that says *nothing* about traffic class, rather than one that quietly says "unknown".

**Checked by:**

- `test_the_only_pickle_based_load_is_the_model` — no `pickle.load`, and no `joblib.load`
  outside the model loader.
- `test_a_capture_is_never_unpickled` — the parser directory contains no reference to
  `pickle` or `joblib` at all. Untrusted input meets the parser, never the deserialiser.
- `test_the_model_loader_says_what_loading_costs` — the docstring states the caveat, so it
  cannot be quietly dropped.

---

## Dependencies

`pip-audit` reports **zero advisories across 107 packages**.

**Checked by:** `test_pip_audit_reports_no_vulnerability`, which runs the audit against the
environment the tool actually uses rather than against a lockfile.

---

## What this document does not claim

- **The tool has not been penetration-tested by a third party.** These are the developer's
  own assertions, made checkable. That is better than prose and is not the same as an
  independent review.
- **Active scanning is genuinely active.** `sentinel scan` transmits, appears in the
  target's logs as failed negotiations, and can disturb a fragile IKE daemon on an OT
  network. It refuses without an explicit flag and prints what it is about to do, and
  that is a speed bump rather than a safety guarantee.
- **The API has no authentication.** It is meant to run on a host the operator controls,
  reachable only by people who are already allowed to see the reports. Exposing it more
  widely is a deployment decision this project does not make for you, and there is no
  configuration here that would make it safe to.
- **Reports contain sensitive material by their nature** — endpoint addresses, traffic
  volumes, the hours a link is used, and which tunnels are weak. That is the product. They
  should be handled like any other assessment output.

See [`LIMITATIONS.md`](LIMITATIONS.md) for what the tool cannot do.
