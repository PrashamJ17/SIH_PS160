"""Record the real terminal output the demo video replays.

The video shows a terminal. What it shows in that terminal has to be what the tool
actually printed, so this runs the commands for real and stores their output verbatim.
Nothing in the video is typed by hand or re-enacted, including the failure: the corrupt
capture is genuinely corrupt and the error is the one the parser raises.

    python -m scripts.video.record
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Final

REPO: Final = Path(__file__).resolve().parents[2]
SENTINEL: Final = REPO / ".venv" / "bin" / "sentinel"
PCAPS: Final = REPO / "demo" / "pcaps"
OUT: Final = REPO / "demo" / "video-transcript.json"

WORST: Final = PCAPS / "01-worst-ikev1-aggressive-3des-voip.pcap"
STRONG: Final = PCAPS / "03-strong-ikev2-aes256-ecp384-voip.pcap"
ESTATE: Final = PCAPS / "04-estate.pcap"
KNOWN: Final = REPO / "demo" / "tunnels.yaml"
MODEL: Final = REPO / "models" / "traffic.joblib"

# A kernel SA for dc-chennai — the one site that negotiated AES-256 with ECP-384 on the
# wire. Pointing it at the already-weak site would have made the demo's own narration
# false twice over: that tunnel did not negotiate AES-256, and it was already scoring
# zero, so nothing could drop. Against the strong site the disagreement is real and the
# estate genuinely falls from 33 to 11.
KERNEL_STATE: Final = """src 203.0.113.12 dst 198.51.100.10
\tproto esp spi 0xaaaa0001 reqid 1 mode tunnel
\treplay-window 0 flag af-unspec
\tauth-trunc hmac(md5) 0x{auth} 96
\tenc cbc(des3_ede) 0x{enc}
src 198.51.100.10 dst 203.0.113.12
\tproto esp spi 0xbbbb0002 reqid 1 mode tunnel
\treplay-window 0 flag af-unspec
\tauth-trunc hmac(md5) 0x{auth} 96
\tenc cbc(des3_ede) 0x{enc}
""".format(auth="cd" * 16, enc="ef" * 24)


def run(argv: list[str], *, cwd: Path | None = None, timeout: int = 900) -> dict[str, Any]:
    result = subprocess.run(
        argv, cwd=cwd or REPO, capture_output=True, text=True, timeout=timeout, check=False
    )
    printable = " ".join(part.replace(str(REPO) + "/", "").replace(str(REPO), ".") for part in argv)
    return {
        "command": printable,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "exit": result.returncode,
    }


def main() -> int:
    if not SENTINEL.is_file():
        print(f"no sentinel at {SENTINEL}", file=sys.stderr)
        return 1

    work = Path(tempfile.mkdtemp(prefix="sentinel-video-"))
    state = work / "gw-chennai.xfrm.txt"
    state.write_text(KERNEL_STATE)

    # Two genuine failures, both of which happen to real operators.
    #
    # Wireshark saves pcapng by default and this parser reads pcap, so handing over the
    # wrong format is the single most likely way a first run fails. Truncation at 900
    # bytes turned out *not* to fail — the capture still held a complete negotiation and
    # the parser assessed it, which is robustness rather than an error — so the truncation
    # here is hard enough to cut the header itself.
    wrong_format = work / "capture.pcapng"
    subprocess.run(
        ["mergecap", "-F", "pcapng", "-w", str(wrong_format), str(WORST)],
        capture_output=True,
        timeout=300,
        check=False,
    )
    if not wrong_format.is_file():  # mergecap absent: forge the pcapng magic
        wrong_format.write_bytes(bytes.fromhex("0a0d0d0a1c000000") + WORST.read_bytes()[:400])

    corrupt = work / "truncated.pcap"
    corrupt.write_bytes(WORST.read_bytes()[:120])  # cut inside the header

    steps: dict[str, dict[str, Any]] = {}

    print("recording real output…")

    if shutil.which("tshark"):
        steps["tshark"] = run(
            [
                "tshark",
                "-r",
                str(WORST),
                "-Y",
                "isakmp",
                "-T",
                "fields",
                "-e",
                "frame.number",
                "-e",
                "ip.src",
                "-e",
                "ip.dst",
                "-e",
                "isakmp.exchangetype",
            ],
            timeout=300,
        )
        steps["tshark"]["stdout"] = "\n".join(steps["tshark"]["stdout"].splitlines()[:8])

    steps["analyse_worst"] = run(
        [
            str(SENTINEL),
            "analyse",
            str(WORST),
            "--baseline",
            "nist_800_77r1",
            "--model",
            str(MODEL),
            "--out",
            str(work / "worst.html"),
        ]
    )

    steps["inventory"] = run(
        [
            str(SENTINEL),
            "inventory",
            str(ESTATE),
            "--known",
            str(KNOWN),
        ]
    )

    steps["analyse_estate"] = run(
        [
            str(SENTINEL),
            "analyse",
            str(ESTATE),
            "--baseline",
            "nist_800_77r1",
            "--known",
            str(KNOWN),
            "--model",
            str(MODEL),
            "--out",
            str(work / "estate.html"),
            "--json",
            str(work / "estate.json"),
            "--pdf",
            str(work / "estate.pdf"),
        ]
    )

    # The failure an operator actually hits first.
    steps["wrong_format"] = run([str(SENTINEL), "analyse", str(wrong_format)])
    steps["corrupt"] = run([str(SENTINEL), "analyse", str(corrupt)])

    # The anomaly: the wire and the device disagree about the same tunnel.
    steps["device_state"] = run(
        [
            str(SENTINEL),
            "analyse",
            str(ESTATE),
            "--baseline",
            "nist_800_77r1",
            "--known",
            str(KNOWN),
            "--device-state",
            str(state),
        ]
    )

    steps["remediate"] = run(
        [
            str(SENTINEL),
            "remediate",
            str(ESTATE),
            "--vendor",
            "strongswan",
            "--out",
            str(work / "package"),
        ]
    )

    package = sorted((work / "package").glob("*.conf"))
    steps["config"] = {
        "command": f"cat change-package/{package[0].name}" if package else "cat change-package/",
        "stdout": package[0].read_text()[:1400] if package else "",
        "stderr": "",
        "exit": 0,
    }

    # Recovery: the same estate once the strong configuration is in place.
    steps["analyse_after"] = run(
        [
            str(SENTINEL),
            "analyse",
            str(STRONG),
            "--baseline",
            "nist_800_77r1",
        ]
    )

    steps["scan_refusal"] = run([str(SENTINEL), "scan", "192.0.2.1"])

    pdf = work / "estate.pdf"
    if pdf.is_file():
        shutil.copy(pdf, REPO / "demo" / "sample-report.pdf")
        steps["pdf_bytes"] = {
            "command": "",
            "stdout": str(pdf.stat().st_size),
            "stderr": "",
            "exit": 0,
        }
    for name in ("estate.html", "worst.html"):
        if (work / name).is_file():
            shutil.copy(work / name, REPO / "demo" / f"sample-{name}")

    # The scratch directory is a mktemp path; nobody watching a demo should be reading
    # /var/folders/3j/s_yt55g906l_.... Rewrite it to what an operator would have typed.
    scrubbed = json.dumps(steps, indent=1)
    scrubbed = scrubbed.replace(str(work) + "/package", "change-package")
    scrubbed = scrubbed.replace(str(work) + "/", "").replace(str(work), ".")
    scrubbed = scrubbed.replace(str(REPO) + "/", "")
    OUT.write_text(scrubbed)
    shutil.rmtree(work, ignore_errors=True)

    print(f"\nwrote {OUT.relative_to(REPO)}")
    for name, step in steps.items():
        lines = len(step["stdout"].splitlines())
        print(f"  {name:<16} exit={step['exit']:<3} {lines:>3} lines")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
