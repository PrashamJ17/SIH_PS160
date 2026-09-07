"""The command line.

Two properties are load-bearing and both are tested.

**A bad input produces a sentence, not a traceback.** A stack trace tells the reader
that the tool broke; a message tells them what to do. Every command catches the errors
its inputs can actually cause and exits non-zero with a line an operator can act on.
Everything else is left to propagate, because an unexpected exception genuinely is a bug
and hiding it behind a friendly message would be worse.

**Only ``scan`` transmits, and only when told to.** It refuses without
``--i-have-authorisation`` and prints what active probing does before doing it. The
library refuses too, so the gate does not depend on this file being the only caller.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import NoReturn

import click

from ipsec_sentinel.version import describe, git_sha, tool_version

EXIT_USAGE = 2
EXIT_REFUSED = 3


def fail(message: str, code: int = 1) -> NoReturn:
    """Report a problem the way a command-line tool should: to stderr, with an exit code."""
    click.secho(f"error: {message}", err=True, fg="red")
    raise SystemExit(code)


def _load_device_states(path: Path) -> list:  # type: ignore[type-arg]
    """Read one state file or a directory of them.

    A directory is the shape a real deployment takes: something the operator already runs
    drops `<host>.swanctl.txt` and `<host>.xfrm.txt` per gateway, and the whole estate is
    read in one pass.
    """
    from ipsec_sentinel.collect import StateError, read_state, read_state_directory

    try:
        if path.is_dir():
            return read_state_directory(path)
        if path.name.endswith(".xfrm.txt"):
            return [read_state(xfrm=path)]
        return [read_state(swanctl=path)]
    except StateError as exc:
        # `fail` does not return, so there is no fall-through path to write here.
        fail(str(exc), EXIT_USAGE)


def _load_known(path: Path | None) -> list:  # type: ignore[type-arg]
    """Read an operator's documented tunnel list."""
    if path is None:
        return []
    import yaml

    from ipsec_sentinel.assess.inventory import KnownTunnel

    try:
        raw = yaml.safe_load(path.read_text())
    except (OSError, yaml.YAMLError) as exc:
        fail(f"could not read the documented tunnel list {path}: {exc}")
    entries = raw.get("tunnels", raw) if isinstance(raw, dict) else raw
    if not isinstance(entries, list):
        fail(
            f"{path} should hold a list of tunnels, or a mapping with a 'tunnels' key; "
            f"found {type(entries).__name__}"
        )
    known = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or "endpoints" not in entry:
            fail(f"{path}: entry {index + 1} has no 'endpoints'")
        endpoints = entry["endpoints"]
        if not isinstance(endpoints, list) or len(endpoints) != 2:
            fail(f"{path}: entry {index + 1} needs exactly two endpoints")
        known.append(
            KnownTunnel(
                endpoints=(str(endpoints[0]), str(endpoints[1])),
                name=entry.get("name"),
                owner=entry.get("owner"),
            )
        )
    return known


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(
    version=tool_version(),
    message=f"%(prog)s %(version)s ({git_sha() or 'revision unknown'})",
)
def main() -> None:
    """IPsec Sentinel — passive IPsec analysis and remediation.

    Reads captured traffic and produces documents. It never writes to a network device
    and stores no credential. The one command that transmits is `scan`, which refuses
    to run without explicit authorisation.
    """


@main.command()
@click.argument("pcap", type=click.Path(path_type=Path))
@click.option("--baseline", default="nist_800_77r1", show_default=True, help="Compliance baseline.")
@click.option("--known", type=click.Path(path_type=Path), help="Documented tunnel list (YAML).")
@click.option("--out", type=click.Path(path_type=Path), help="Write an HTML report here.")
@click.option("--json", "json_out", type=click.Path(path_type=Path), help="Write JSON here.")
@click.option("--pdf", type=click.Path(path_type=Path), help="Write a PDF here.")
@click.option(
    "--model",
    "model_path",
    type=click.Path(path_type=Path),
    help="Classify traffic with this model. Without it the report makes no inferences.",
)
@click.option(
    "--device-state",
    type=click.Path(path_type=Path),
    help="Device state to cross-check the capture against (`swanctl --list-sas`).",
)
@click.option("--quiet", is_flag=True, help="Print nothing but errors.")
def analyse(
    pcap: Path,
    baseline: str,
    known: Path | None,
    out: Path | None,
    json_out: Path | None,
    pdf: Path | None,
    model_path: Path | None,
    device_state: Path | None,
    quiet: bool,
) -> None:
    """Analyse a capture and produce a report."""
    from ipsec_sentinel.analyse import analyse_capture

    if not pcap.exists():
        fail(f"no such capture: {pcap}", EXIT_USAGE)
    if pcap.is_dir():
        fail(f"{pcap} is a directory; give the path to a capture file", EXIT_USAGE)

    from ipsec_sentinel.ml.classify import ClassifierUnavailableError

    states = _load_device_states(device_state) if device_state is not None else []

    try:
        report = analyse_capture(
            pcap,
            baseline=baseline,
            known=_load_known(known),
            model_path=model_path,
            device_states=states,
        )
    except ClassifierUnavailableError as exc:
        fail(str(exc), EXIT_USAGE)
    except FileNotFoundError as exc:
        fail(str(exc), EXIT_USAGE)
    except ValueError as exc:
        fail(f"{pcap} could not be analysed: {exc}")

    if out:
        from ipsec_sentinel.report.render_html import write_html

        write_html(report, out)
    if json_out:
        from ipsec_sentinel.report.export_json import write_json

        write_json(report, json_out)
    if pdf:
        from ipsec_sentinel.report.render_pdf import PDFExportError, write_pdf

        try:
            write_pdf(report, pdf)
        except PDFExportError as exc:
            fail(str(exc))

    if device_state is not None:
        _report_state_agreement(pcap, device_state, baseline=baseline, quiet=quiet)

    if quiet:
        return
    summary = report.executive
    click.echo(report.metadata.provenance)
    click.echo("")
    click.echo(click.style(summary.headline, bold=True))
    click.echo("")
    click.echo(f"  tunnels assessed     {summary.tunnels_assessed}")
    click.echo(f"  estate score         {summary.estate_score}/100 (grade {summary.estate_grade})")
    click.echo(f"  verified (section A) {summary.verified_findings}")
    click.echo(f"  inferred (section B) {summary.inferred_findings}")
    for severity, count in sorted(summary.findings_by_severity.items(), key=lambda kv: kv[0].rank):
        if count:
            click.echo(f"  {severity.value:<20} {count}")
    for path, label in ((out, "HTML"), (json_out, "JSON"), (pdf, "PDF")):
        if path:
            click.echo(f"\n{label} written to {path}")


def _report_state_agreement(pcap: Path, device_state: Path, *, baseline: str, quiet: bool) -> None:
    """Compare what the wire showed against what the device says about itself.

    Two independent observations of the same tunnel, and the interesting case is when
    they differ. A device whose self-report does not match its own traffic is either
    misconfigured in a way nobody has noticed, or not telling the truth; averaging the
    two would hide both. So the disagreement is printed, not resolved.

    Compared as reconstructed configurations rather than as display strings: the wire
    carries IANA names and the daemon its own, and matching those textually would report
    a disagreement on every tunnel.
    """
    from ipsec_sentinel.analyse import read_tunnels
    from ipsec_sentinel.collect import StateError, config_from_state, read_state
    from ipsec_sentinel.remediate.observed import config_from_exchange

    try:
        if device_state.name.endswith(".xfrm.txt"):
            reported = read_state(xfrm=device_state)
        else:
            reported = read_state(swanctl=device_state)
    except StateError as exc:
        fail(str(exc), EXIT_USAGE)

    from_state = config_from_state(reported)
    if from_state is None:
        if not quiet:
            click.echo(f"\ndevice state ({reported.source}): {reported.describe()}")
            click.echo("  nothing comparable — no established SA, or an unmapped algorithm")
        return

    if not quiet and from_state.esp is not None:
        # The kernel's half: what is installed right now, whichever way it was collected.
        click.echo(f"\ninstalled ESP ({from_state.esp_source}): {from_state.esp.suite()}")
        details = [
            f"mode {from_state.esp.mode}" if from_state.esp.mode else "",
            f"replay window {from_state.esp.replay_window}"
            if from_state.esp.replay_window is not None
            else "",
            f"spi {from_state.esp.spi}" if from_state.esp.spi else "",
        ]
        click.echo("  " + ", ".join(part for part in details if part))

        from ipsec_sentinel.assess.esp import assess_esp
        from ipsec_sentinel.assess.scoring import score_tunnel

        esp_findings = assess_esp(
            from_state.esp,
            source=reported.source,
            origin=from_state.esp_source or "kernel",
            baseline=baseline,
        )
        score, grade = score_tunnel(esp_findings)
        colour = "green" if grade in ("A", "B") else "yellow" if grade in ("C", "D") else "red"
        click.secho(f"  installed SA scores {score}/100 (grade {grade})", fg=colour, bold=True)
        for finding in esp_findings:
            click.echo(f"    [{finding.severity.upper():<8}] {finding.rule_id}  {finding.title}")
            click.echo(f"               {finding.standard_ref}")
        if not esp_findings:
            click.echo("    nothing to report against this baseline")

    if from_state.config is None:
        if not quiet:
            click.echo(
                "  no IKE parameters in this state, so there is nothing to compare "
                "against the capture: " + ", ".join(sorted(from_state.unknown))
            )
        return

    reported_suite = from_state.config.proposal_string()  # type: ignore[attr-defined]
    if not quiet:
        click.echo(f"\ndevice state ({reported.source}): {reported_suite}")

    endpoints = reported.endpoints
    matched = False
    for tunnel in read_tunnels(pcap):
        if tunnel.ike is None:
            continue
        if endpoints is not None and tunnel.endpoints != endpoints:
            continue
        recovered = config_from_exchange(tunnel.ike)
        if not recovered.ok or recovered.config is None:
            continue
        matched = True
        wire_suite = recovered.config.proposal_string()
        if wire_suite == reported_suite:
            click.echo(f"  agrees with the capture for {tunnel.tunnel_id}")
        else:
            click.secho(
                f"  DISAGREES with the capture for {tunnel.tunnel_id}: "
                f"the wire negotiated {wire_suite}, the device reports {reported_suite}. "
                f"One of the two is not describing the tunnel that is running.",
                fg="red",
                bold=True,
            )
    if not matched and not quiet:
        click.echo("  no tunnel in the capture matches this device's endpoints")


@main.command()
@click.argument("pcap", type=click.Path(path_type=Path))
@click.option("--known", type=click.Path(path_type=Path), help="Documented tunnel list (YAML).")
def inventory(pcap: Path, known: Path | None) -> None:
    """List the tunnels a capture contains."""
    from ipsec_sentinel.analyse import read_tunnels
    from ipsec_sentinel.assess.inventory import build_inventory

    if not pcap.exists():
        fail(f"no such capture: {pcap}", EXIT_USAGE)
    try:
        found = build_inventory(read_tunnels(pcap), _load_known(known))
    except ValueError as exc:
        fail(f"{pcap} could not be read: {exc}")

    if not found.entries:
        click.echo("No tunnels were observed in this capture.")
    for entry in found.entries:
        marker = "!" if entry.is_undocumented else " "
        suite = entry.negotiated_suite or "(no negotiation observed)"
        click.echo(
            f"{marker} {entry.tunnel_id}  {entry.endpoints[0]} <-> {entry.endpoints[1]}  "
            f"{entry.status.value}  {suite}"
        )
    if found.undocumented:
        click.echo(
            f"\n{len(found.undocumented)} tunnel(s) marked ! are not on the documented list."
        )
    for missing in found.unobserved:
        click.echo(
            f"  documented but not observed: {missing.endpoints[0]} <-> {missing.endpoints[1]}"
        )


@main.command()
@click.argument("pcap", type=click.Path(path_type=Path))
@click.option("--tunnel", help="Only this tunnel. Defaults to every tunnel with something to fix.")
@click.option(
    "--vendor",
    type=click.Choice(["strongswan", "libreswan", "cisco", "fortigate", "juniper", "paloalto"]),
    default="strongswan",
    show_default=True,
)
@click.option("--baseline", default="nist_800_77r1", show_default=True, help="Compliance baseline.")
@click.option("--out", type=click.Path(path_type=Path), help="Write the configurations here.")
def remediate(pcap: Path, tunnel: str | None, vendor: str, baseline: str, out: Path | None) -> None:
    """Generate a change package from an observed capture.

    The configuration is reconstructed from the negotiation, so the package corrects
    what the peer actually offered rather than what a document says it offers.
    """
    from ipsec_sentinel.analyse import assess_tunnel, read_tunnels
    from ipsec_sentinel.assess.framework import UnknownBaselineError
    from ipsec_sentinel.remediate.generators.strongswan import (
        GenerationError,
        generate_change_package,
    )
    from ipsec_sentinel.remediate.observed import config_from_exchange

    if vendor != "strongswan":
        fail(
            f"only strongswan change packages can be generated from a capture today. "
            f"The {vendor} generator renders a configuration from a known TunnelConfig; "
            f"reconstructing one from the wire is implemented for strongswan only.",
            EXIT_USAGE,
        )
    if not pcap.exists():
        fail(f"no such capture: {pcap}", EXIT_USAGE)

    tunnels = [t for t in read_tunnels(pcap) if tunnel is None or t.tunnel_id == tunnel]
    if not tunnels:
        fail(f"no tunnel {tunnel!r} in {pcap}" if tunnel else f"no tunnels in {pcap}")

    produced = 0
    for found in tunnels:
        if found.ike is None:
            click.echo(f"{found.tunnel_id}: no negotiation observed, nothing to correct")
            continue
        recovered = config_from_exchange(found.ike)
        if not recovered.ok or recovered.config is None:
            click.echo(f"{found.tunnel_id}: {recovered.reason}")
            continue

        # The findings the assessment actually raised, not a fixed rule id. A package
        # claiming to address CRY-05 on a tunnel whose problem is a weak PRF is a
        # document an operator cannot check against the report beside it.
        try:
            assessed = assess_tunnel(found, baseline)
        except UnknownBaselineError as exc:
            fail(str(exc), EXIT_USAGE)
        findings = [finding.rule_id for finding in assessed.findings]
        if not findings:
            click.echo(
                f"{found.tunnel_id}: nothing found against baseline {baseline}; "
                f"no change package to generate"
            )
            continue
        try:
            package = generate_change_package(
                found.tunnel_id, recovered.config, findings, observed=assessed
            )
        except GenerationError as exc:
            click.echo(f"{found.tunnel_id}: {exc}")
            continue

        produced += 1
        click.echo(click.style(f"\n=== {found.tunnel_id} ===", bold=True))
        click.echo(package.summary())
        for note in recovered.assumptions:
            click.echo(f"  assumption: {note}")
        for step in package.sequence:
            click.echo(f"  {step.order}. [{step.role.value}] {step.description}")
        if out:
            out.mkdir(parents=True, exist_ok=True)
            for document in (package.local_config, package.peer_config):
                target = out / f"{found.tunnel_id}.{document.role.value}.{document.filename}"
                target.write_text(document.content)
                click.echo(f"  written: {target}")
    if not produced:
        fail("no change package could be produced from this capture")


@main.command()
@click.argument("target")
@click.option("--port", default=500, show_default=True)
@click.option("--timeout", "timeout_s", default=2.0, show_default=True)
@click.option(
    "--i-have-authorisation",
    "authorised",
    is_flag=True,
    help="Confirm you have permission to probe this target.",
)
def scan(target: str, port: int, timeout_s: float, authorised: bool) -> None:
    """Actively enumerate which proposals a gateway accepts.

    This TRANSMITS to the target. Passive analysis sees only the proposals used in the
    sessions that were captured, which is a lower bound on what a device will accept.
    """
    from ipsec_sentinel.probe import (
        AUTHORISATION_REQUIRED,
        AuthorisationError,
        enumerate_transforms,
        weak_acceptances,
    )

    if not authorised:
        click.secho("refusing to probe without authorisation.", err=True, fg="red", bold=True)
        click.echo(AUTHORISATION_REQUIRED, err=True)
        raise SystemExit(EXIT_REFUSED)

    click.secho(
        f"Actively probing {target}:{port}. This transmits to the target and will appear "
        f"in its logs as failed negotiations.",
        fg="yellow",
    )
    try:
        outcomes = enumerate_transforms(target, authorised=True, port=port, timeout_s=timeout_s)
    except AuthorisationError as exc:  # pragma: no cover - the flag is checked above
        fail(str(exc), EXIT_REFUSED)

    for outcome in outcomes:
        colour = "red" if outcome.accepted else "green"
        click.secho(outcome.summary(), fg=colour if outcome.accepted else None)

    silent = [o for o in outcomes if o.verdict == "no-response"]
    if len(silent) == len(outcomes):
        click.echo(
            "\nNothing answered. The target may be filtered, down, or not running IKE on "
            "this port. No conclusion can be drawn about what it accepts."
        )
        return
    weak = weak_acceptances(outcomes)
    if weak:
        click.secho(
            f"\n{len(weak)} weak proposal(s) accepted. A peer offering only these would be "
            f"accepted, whatever the device negotiated when it was last observed.",
            fg="red",
            bold=True,
        )
    else:
        click.echo("\nNo weak proposal was accepted.")


@main.command()
@click.argument("interface")
@click.option("--baseline", default="nist_800_77r1", show_default=True)
@click.option("--poll", "poll_s", default=2.0, show_default=True, help="Seconds between polls.")
@click.option("--for", "duration_s", type=float, help="Stop after this many seconds.")
@click.option("--syslog", help="Send alerts to this collector as host:port.")
@click.option("--from-capture", type=click.Path(path_type=Path), help="Read a file instead.")
@click.option(
    "--state",
    type=click.Path(path_type=Path),
    help="Remember what each tunnel was last seen negotiating, across restarts.",
)
@click.option(
    "--since",
    type=click.Path(path_type=Path),
    help="Seed the baseline from a previous assessment's capture.",
)
@click.option(
    "--device-state",
    type=click.Path(path_type=Path),
    help=(
        "A file or directory of device state (`ip xfrm state`, `swanctl --list-sas`). "
        "Closes the rekey blind spot: state says what is installed now, whether or "
        "not the negotiation was seen. Read, never fetched."
    ),
)
@click.option(
    "--local-state",
    is_flag=True,
    help="Read this machine's own IPsec state. For a sensor on the gateway itself.",
)
@click.option(
    "--stale-after",
    type=float,
    default=86400.0,
    show_default=True,
    help="Report tunnels not seen negotiating for this many seconds.",
)
def watch_command(
    interface: str,
    baseline: str,
    poll_s: float,
    duration_s: float | None,
    syslog: str | None,
    from_capture: Path | None,
    device_state: Path | None,
    local_state: bool,
    state: Path | None,
    since: Path | None,
    stale_after: float,
) -> None:
    """Watch an interface and alert when a tunnel gets weaker.

    Drift is measured against each tunnel's own past, not against the baseline: a tunnel
    that was always mediocre is a finding `analyse` already made, while one that *was*
    strong and is now mediocre is news.

    A tunnel's parameters are only readable at IKE_SA_INIT, so drift is seen when a
    tunnel next establishes rather than at its next rekey — a rekey's proposals are
    inside the encrypted exchange.
    """
    from ipsec_sentinel.assess.framework import UnknownBaselineError
    from ipsec_sentinel.watch import (
        DriftDetector,
        ExchangeSource,
        LiveInterfaceSource,
        PcapPollSource,
        alerts_as_syslog,
    )

    # Device state is read once, up front. It answers a different question from the
    # wire — "what is installed now" rather than "what was negotiated while we watched" —
    # and where it is available the rekey blind spot does not exist.
    states = []
    if device_state is not None or local_state:
        from ipsec_sentinel.collect import (
            StateError,
            read_state,
            read_state_directory,
        )
        from ipsec_sentinel.collect import local_state as read_local_state

        try:
            if local_state:
                states.append(read_local_state())
            if device_state is not None:
                if device_state.is_dir():
                    states.extend(read_state_directory(device_state))
                elif device_state.name.endswith(".xfrm.txt"):
                    states.append(read_state(xfrm=device_state))
                else:
                    states.append(read_state(swanctl=device_state))
        except StateError as exc:
            fail(str(exc), EXIT_USAGE)

    source: ExchangeSource
    if from_capture is not None:
        if not from_capture.exists():
            fail(f"no such capture: {from_capture}", EXIT_USAGE)
        source = PcapPollSource(from_capture)
    else:
        import shutil

        if shutil.which("tcpdump") is None:
            fail(
                "tcpdump is not installed, and watch mode uses it to read the interface. "
                "Install it, or pass --from-capture to watch a file another process is "
                "writing.",
                EXIT_USAGE,
            )
        try:
            source = LiveInterfaceSource(interface)
        except OSError as exc:
            fail(f"could not capture on {interface}: {exc}")

    emitter = None
    if syslog:
        from ipsec_sentinel.report.siem import SyslogEmitter

        host, _, port = syslog.partition(":")
        if not host:
            fail("--syslog wants host:port", EXIT_USAGE)
        emitter = SyslogEmitter(host, int(port) if port else 514)

    try:
        detector = DriftDetector(baseline)
        detector.resolve_baseline()
    except UnknownBaselineError as exc:
        source.close()
        fail(str(exc), EXIT_USAGE)

    remembered = detector.load(state) if state else 0
    state_alerts = []
    for reported in states:
        alert = detector.observe_state(reported)
        if alert is not None:
            state_alerts.append(alert)
        click.echo(f"device state: {reported.describe()}")
    if since is not None:
        if not since.exists():
            source.close()
            fail(f"no such capture: {since}", EXIT_USAGE)
        remembered += detector.seed_from_capture(since)

    click.echo(
        f"Watching {from_capture or interface} against baseline {baseline}. "
        f"A tunnel seen for the first time sets its own baseline; "
        f"only a later weakening is reported."
    )
    if remembered:
        click.echo(f"{remembered} tunnel(s) remembered from earlier; drift is measured from those.")
    elif state or since:
        click.echo("No earlier state was found, so every tunnel starts from its next sighting.")
    seen = 0
    for alert in state_alerts:
        seen += 1
        click.secho(f"DRIFT  {alert.summary()}", fg="red", bold=True)
    try:
        for alert in watch_alerts(source, detector, poll_s, duration_s):
            seen += 1
            click.secho(f"DRIFT  {alert.summary()}", fg="red", bold=True)
            for weakening in alert.weakenings:
                click.echo(f"       {weakening.describe()}")
            if emitter is not None:
                result = emitter.emit(alerts_as_syslog([alert]))
                if not result.complete:
                    click.secho(f"       siem: {result.summary()}", err=True, fg="yellow")
    except KeyboardInterrupt:
        click.echo("stopped")
    finally:
        source.close()
        if state is not None:
            detector.save(state)

    click.echo(f"{seen} drift alert(s).")
    # An empty alert log and a quiet network look identical unless something says which.
    stale = detector.stale(stale_after)
    if stale:
        click.secho(
            f"\n{len(stale)} tunnel(s) have not been seen negotiating recently. Their "
            f"current parameters are unverified, not confirmed unchanged:",
            fg="yellow",
        )
        for entry in stale:
            click.echo(f"  {entry.describe()}")


def watch_alerts(source: object, detector: object, poll_s: float, duration_s: float | None):  # type: ignore[no-untyped-def]
    from ipsec_sentinel.watch import watch as watch_loop

    return watch_loop(source, detector=detector, poll_s=poll_s, until=duration_s)  # type: ignore[arg-type]


@main.group()
def dataset() -> None:
    """Build, package and audit the machine-learning dataset."""


@dataset.command("build")
@click.option("--root", type=click.Path(path_type=Path), default=Path("data/raw/sweep"))
@click.option(
    "--out", type=click.Path(path_type=Path), default=Path("data/processed/ml_dataset.parquet")
)
def dataset_build(root: Path, out: Path) -> None:
    """Extract flow features from a sweep corpus."""
    from ipsec_sentinel.features.dataset import build_ml_dataset, find_manifests

    if not root.is_dir():
        fail(f"no such corpus directory: {root}", EXIT_USAGE)
    manifests = find_manifests(root)
    if not manifests:
        fail(f"no manifests under {root}; is this a sweep corpus?")
    frame = build_ml_dataset(manifests)
    out.parent.mkdir(parents=True, exist_ok=True)
    frame.to_parquet(out)
    click.echo(f"{len(frame)} rows from {len(manifests)} captures written to {out}")


@dataset.command("audit")
@click.option(
    "--dataset",
    "path",
    type=click.Path(path_type=Path),
    default=Path("data/processed/ml_dataset.parquet"),
)
def dataset_audit(path: Path) -> None:
    """Summarise a built dataset."""
    import pandas as pd

    from ipsec_sentinel.features.dataset import dataset_summary

    if not path.exists():
        fail(f"no dataset at {path}; run `sentinel dataset build` first", EXIT_USAGE)
    for key, value in dataset_summary(pd.read_parquet(path)).items():
        click.echo(f"{key}: {value}")


@main.group()
def model() -> None:
    """Train and evaluate the traffic classifier."""


@model.command("train")
@click.option(
    "--dataset",
    "path",
    type=click.Path(path_type=Path),
    default=Path("data/processed/ml_dataset.parquet"),
)
@click.option("--out", type=click.Path(path_type=Path), default=Path("models/traffic.joblib"))
@click.option("--seed", default=42, show_default=True)
def model_train(path: Path, out: Path, seed: int) -> None:
    """Train a classifier and persist it with its metadata."""
    import pandas as pd

    from ipsec_sentinel.ml.train import train_and_persist

    if not path.exists():
        fail(f"no dataset at {path}; run `sentinel dataset build` first", EXIT_USAGE)
    out.parent.mkdir(parents=True, exist_ok=True)
    metadata = train_and_persist(pd.read_parquet(path), out, seed=seed)
    click.echo(f"model written to {out}")
    click.echo(
        f"  trained on {metadata.dataset_rows} rows, "
        f"{len(metadata.feature_names)} features, {len(metadata.class_names)} classes"
    )
    click.echo(f"  dataset checksum {metadata.dataset_checksum}")
    click.echo(f"  built at {metadata.git_sha}")


@model.command("evaluate")
@click.option(
    "--dataset",
    "path",
    type=click.Path(path_type=Path),
    default=Path("data/processed/ml_dataset.parquet"),
)
def model_evaluate(path: Path) -> None:
    """Cross-validate with capture-level splitting and report honestly."""
    import pandas as pd

    from ipsec_sentinel.ml.train import cross_validate

    if not path.exists():
        fail(f"no dataset at {path}; run `sentinel dataset build` first", EXIT_USAGE)
    result = cross_validate(pd.read_parquet(path))
    click.echo(result.summary())


@main.command()
def version() -> None:
    """Print the build identity."""
    click.echo(describe())


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
