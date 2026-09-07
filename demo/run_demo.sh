#!/usr/bin/env bash
# The scripted demo. Seven beats, roughly ten minutes, no live capture anywhere.
#
# Everything runs from pre-captured files in demo/pcaps/. That is deliberate: a demo that
# depends on a tunnel establishing while you are talking is a demo that fails in front of
# judges, and the failure looks like a broken product rather than a broken network.
#
# The one genuinely live thing — remediating a tunnel on a running strongSwan pair with
# zero packet loss — is behind --with-testbed, because it needs Docker and takes minutes.
# Without it, beat 6 shows the change package and points at the integration test that
# proves the zero-loss property. See SCRIPT.md for the narration.
#
#   bash demo/run_demo.sh                  # the full sequence, into demo/output/
#   bash demo/run_demo.sh --out /tmp/demo  # somewhere else
#   bash demo/run_demo.sh --quiet          # no pauses, for the test that runs this
#   bash demo/run_demo.sh --with-testbed   # include the live remediation

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$REPO_ROOT/demo/output"
QUIET=0
WITH_TESTBED=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --out)          OUT="$2"; shift 2 ;;
        --quiet)        QUIET=1; shift ;;
        --with-testbed) WITH_TESTBED=1; shift ;;
        -h|--help)      sed -n '2,18p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) echo "run_demo.sh: unknown option: $1" >&2; exit 2 ;;
    esac
done

PCAPS="$REPO_ROOT/demo/pcaps"
ESTATE="$PCAPS/04-estate.pcap"
WORST="$PCAPS/01-worst-ikev1-aggressive-3des-voip.pcap"
STRONG="$PCAPS/03-strong-ikev2-aes256-ecp384-voip.pcap"
KNOWN="$REPO_ROOT/demo/tunnels.yaml"
MODEL="$REPO_ROOT/models/traffic.joblib"

# Prefer the checkout's venv; fall back to whatever `sentinel` is on PATH.
if [[ -x "$REPO_ROOT/.venv/bin/sentinel" ]]; then
    SENTINEL="$REPO_ROOT/.venv/bin/sentinel"
elif command -v sentinel >/dev/null 2>&1; then
    SENTINEL="$(command -v sentinel)"
else
    echo "run_demo.sh: no 'sentinel' on PATH and no .venv in the checkout" >&2
    exit 1
fi

mkdir -p "$OUT"

beat() {
    printf '\n\033[1;36m━━━ BEAT %s — %s\033[0m\n\n' "$1" "$2"
}
say()  { printf '  %s\n' "$*"; }
pause() { [[ $QUIET -eq 1 ]] || { printf '\n  \033[2m[enter]\033[0m '; read -r _; }; }

model_args=()
if [[ -f "$MODEL" ]]; then
    model_args=(--model "$MODEL")
else
    say "note: models/traffic.joblib is absent, so this run makes no inferences."
fi

printf '\n\033[1mIPsec Sentinel — demo\033[0m\n'
say "artefacts: $OUT"

# ---------------------------------------------------------------------------------------
beat 1 "The same capture, in a protocol analyser"
say "tshark sees the negotiation. Every field is there, and nothing is judged."
if command -v tshark >/dev/null 2>&1; then
    tshark -r "$WORST" -Y isakmp -T fields \
        -e frame.number -e ip.src -e ip.dst -e isakmp.exchangetype 2>/dev/null \
        | head -6 | sed 's/^/    /'
    say ""
    say "Exchange type 4 is IKEv1 Aggressive Mode. Nothing here says that is a problem,"
    say "which standard forbids it, or what to do about it."
else
    say "(tshark is not installed; the point is that a protocol analyser shows fields,"
    say " not judgements.)"
fi
pause

# ---------------------------------------------------------------------------------------
beat 2 "The same capture, in Sentinel"
"$SENTINEL" analyse "$WORST" \
    --baseline nist_800_77r1 \
    "${model_args[@]}" \
    --out "$OUT/worst.html" --json "$OUT/worst.json" --quiet
"$REPO_ROOT/.venv/bin/python" - "$OUT/worst.json" <<'PY'
import json, sys
report = json.loads(open(sys.argv[1]).read())
executive = report["executive"]
print(f"    grade {executive['estate_grade']}  score {executive['estate_score']}/100")
print(f"    {executive['verified_findings']} verified findings, "
      f"{executive['inferred_findings']} inferred\n")
for finding in report["section_a_verified"][:5]:
    print(f"    [{finding['severity'].upper():<8}] {finding['rule_id']}  {finding['title']}")
    print(f"               {finding['standard_ref']}")
PY
say ""
say "Every line cites the clause it comes from. That is the difference."
pause

# ---------------------------------------------------------------------------------------
beat 3 "The estate, and the tunnel nobody documented"
"$SENTINEL" analyse "$ESTATE" \
    --baseline nist_800_77r1 --known "$KNOWN" \
    "${model_args[@]}" \
    --out "$OUT/estate.html" --json "$OUT/estate.json" --quiet
"$REPO_ROOT/.venv/bin/python" - "$OUT/estate.json" <<'PY'
import json, sys
report = json.loads(open(sys.argv[1]).read())
executive = report["executive"]
print(f"    {executive['tunnels_assessed']} tunnels, "
      f"{executive['tunnels_undocumented']} undocumented. "
      f"Estate grade {executive['estate_grade']} ({executive['estate_score']}/100).\n")
for entry in report["inventory"]["entries"]:
    mark = "  <-- nobody documented this" if entry["status"] == "undocumented" else ""
    print(f"    {entry['status']:<13} {' <-> '.join(entry['endpoints'])}{mark}")
PY
say ""
say "The operator's list has two tunnels. The wire has three."
pause

# ---------------------------------------------------------------------------------------
beat 4 "What the undocumented tunnel is carrying"
"$REPO_ROOT/.venv/bin/python" - "$OUT/estate.json" <<'PY'
import json, sys
report = json.loads(open(sys.argv[1]).read())
undocumented = {
    entry["tunnel_id"] for entry in report["inventory"]["entries"]
    if entry["status"] == "undocumented"
}
for entry in report["metadata_exposure"]["entries"]:
    if entry["tunnel_id"] not in undocumented:
        continue
    confidence = entry["inferred_traffic_confidence"]
    print(f"    inferred traffic: {entry['inferred_traffic']}  "
          f"confidence {confidence['value']:.2f}")
    print(f"    method: {confidence['method']}")
    explanation = entry.get("explanation")
    if explanation:
        print(f"\n    {explanation['sentence']}\n")
        print("    what the model actually weighed:")
        for name, contribution in explanation["contributions"][:5]:
            bar = "#" * max(1, round(abs(contribution) * 60))
            print(f"      {name:<18} {contribution:+.3f}  {bar}")
print("\n    The payload is encrypted and stays encrypted. This is packet size,")
print("    timing and direction — and it is Section B, never Section A.")
PY
pause

# ---------------------------------------------------------------------------------------
beat 5 "The change package, both ends, sequenced"
"$SENTINEL" remediate "$ESTATE" --vendor strongswan --out "$OUT/change-package" >/dev/null
say ""
find "$OUT/change-package" -type f | sort | sed "s|$OUT/change-package|    change-package|"
say ""
say "Configuration for both ends, and an ordered sequence to apply it. The tool"
say "generates it; a person applies it. There is no code path here that writes to"
say "a device, and a test asserts that."
pause

# ---------------------------------------------------------------------------------------
beat 6 "Proving the fix landed"
if [[ $WITH_TESTBED -eq 1 ]]; then
    say "Running the live remediation on a real strongSwan pair. This takes a few minutes."
    "$REPO_ROOT/.venv/bin/pytest" -q -p no:randomly \
        "$REPO_ROOT/tests/integration/test_sequence_live.py" \
        "$REPO_ROOT/tests/integration/test_verify_live.py"
else
    say "Verification reads a follow-up capture and closes the finding only when the fix"
    say "is on the wire. Here is what the same estate looks like once the strong"
    say "configuration is in place:"
    "$SENTINEL" analyse "$STRONG" --baseline nist_800_77r1 \
        --json "$OUT/after.json" --quiet
    "$REPO_ROOT/.venv/bin/python" - "$OUT/worst.json" "$OUT/after.json" <<'PY'
import json, sys
before = json.loads(open(sys.argv[1]).read())
after = json.loads(open(sys.argv[2]).read())
print(f"\n    before: grade {before['executive']['estate_grade']} "
      f"({before['executive']['estate_score']}/100), "
      f"{before['executive']['verified_findings']} findings")
print(f"    after:  grade {after['executive']['estate_grade']} "
      f"({after['executive']['estate_score']}/100), "
      f"{after['executive']['verified_findings']} finding(s)")
remaining = {finding['rule_id'] for finding in after['section_a_verified']}
print(f"    what is left: {', '.join(sorted(remaining)) or 'nothing'}")
PY
    say ""
    say "The zero-packet-loss property is measured on a live pair in"
    say "tests/integration/test_sequence_live.py. Re-run this with --with-testbed to"
    say "watch it happen."
fi
pause

# ---------------------------------------------------------------------------------------
beat 7 "Post-quantum readiness, and a different authority's baseline"
"$SENTINEL" analyse "$ESTATE" --baseline itsar --known "$KNOWN" \
    "${model_args[@]}" \
    --json "$OUT/estate-itsar.json" --quiet
"$REPO_ROOT/.venv/bin/python" - "$OUT/estate.json" "$OUT/estate-itsar.json" <<'PY'
import json, sys
nist = json.loads(open(sys.argv[1]).read())
itsar = json.loads(open(sys.argv[2]).read())
print("    Post-quantum readiness:\n")
for entry in nist["pqc"]["entries"]:
    print(f"      {entry['tunnel_id']}  {entry['grade'].upper()}")
    print(f"        {entry['rationale'][:96]}...")
print(f"\n    Same capture under ITSAR (India): grade "
      f"{itsar['executive']['estate_grade']}, "
      f"{itsar['executive']['verified_findings']} findings.")
print("    One capture, one parse, whichever authority you have to answer to.")
PY

printf '\n\033[1;32mDemo complete.\033[0m Artefacts in %s\n\n' "$OUT"
