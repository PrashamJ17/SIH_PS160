#!/usr/bin/env bash
# Build a tarball that installs IPsec Sentinel on a host with no package index.
#
# What goes in: every dependency wheel, the project's own wheel, the trained model and
# its datacard, the demo captures, the documentation, the JSON schemas, an installer, and
# a MANIFEST.txt of sha256 sums so the receiving side can tell a truncated transfer from
# a complete one. Optionally the container image as well.
#
# **The bundle is platform-specific.** Wheels are built for one interpreter version and
# one architecture; a bundle built on macOS will not install on Linux. Pass --platform
# and --python-version to build for a target that is not this machine, which is the
# normal case — the host that has internet access is rarely the air-gapped one.

set -euo pipefail

OUTPUT="dist"
WITH_IMAGE=1
IMAGE="ipsec-sentinel:latest"
PLATFORM=""
PYTHON_VERSION=""
EXTRAS="ml,api,report"

usage() {
    cat <<'USAGE'
Usage: build_offline_bundle.sh [options]

  --output DIR            Where to write the tarball (default: dist)
  --no-image              Skip the container image (much smaller, much faster)
  --image REF             Image to include (default: ipsec-sentinel:latest)
  --platform TAG          Target wheel platform, e.g. manylinux2014_x86_64
  --python-version VER    Target interpreter, e.g. 3.11
  --extras LIST           Extras to resolve (default: ml,api,report)
  -h, --help              This message

Building for a foreign platform requires --python-version as well, because pip cannot
infer an ABI it is not running on.
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output)         OUTPUT="$2"; shift 2 ;;
        --no-image)       WITH_IMAGE=0; shift ;;
        --image)          IMAGE="$2"; shift 2 ;;
        --platform)       PLATFORM="$2"; shift 2 ;;
        --python-version) PYTHON_VERSION="$2"; shift 2 ;;
        --extras)         EXTRAS="$2"; shift 2 ;;
        -h|--help)        usage; exit 0 ;;
        *) echo "build_offline_bundle.sh: unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python="${SENTINEL_PYTHON:-$repo/.venv/bin/python}"
[[ -x "$python" ]] || python="python3"

say() { printf '  %s\n' "$*"; }
die() { printf 'build_offline_bundle.sh: %s\n' "$*" >&2; exit 1; }

version="$("$python" - <<'PY'
import tomllib, pathlib
print(tomllib.loads(pathlib.Path("pyproject.toml").read_text())["project"]["version"])
PY
)"
[[ -n "$version" ]] || die "could not read the project version from pyproject.toml"

if [[ -n "$PLATFORM" && -z "$PYTHON_VERSION" ]]; then
    die "--platform needs --python-version; pip cannot infer an ABI it is not running on"
fi

tag="${PLATFORM:-$("$python" -c 'import sysconfig; print(sysconfig.get_platform().replace("-", "_").replace(".", "_"))')}"
# The wheels are compiled for one interpreter version as well as one architecture, so
# the bundle is named for both. A bundle that records only the platform installs
# silently against the wrong Python and fails on the first extension module, which on
# an air-gapped host is an expensive way to learn the version.
pyver="${PYTHON_VERSION:-$("$python" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')}"
name="ipsec-sentinel-offline-${version}-py${pyver}-${tag}"

mkdir -p "$OUTPUT"
staging="$(mktemp -d)"
trap 'rm -rf "$staging"' EXIT
root="$staging/$name"
mkdir -p "$root/wheels"

say "version:  $version"
say "platform: $tag"
say "python:   $pyver"

# --- the project wheel ------------------------------------------------------------------

say "building the project wheel"
"$python" -m pip wheel --no-deps --wheel-dir "$root/wheels" "$repo" >/dev/null

# --- every dependency ---------------------------------------------------------------------

download=(--dest "$root/wheels" --only-binary=:all:)
if [[ -n "$PLATFORM" ]]; then
    download+=(--platform "$PLATFORM" --python-version "$PYTHON_VERSION")
fi

target="ipsec-sentinel"
if [[ -n "$EXTRAS" ]]; then
    target="ipsec-sentinel[$EXTRAS]"
fi

say "downloading dependency wheels (this needs the network; the install will not)"
requirements="$staging/requirements.txt"
"$python" - "$repo" "$EXTRAS" > "$requirements" <<'PY'
import pathlib
import sys
import tomllib

repo, extras = pathlib.Path(sys.argv[1]), [e for e in sys.argv[2].split(",") if e]
project = tomllib.loads((repo / "pyproject.toml").read_text())["project"]
requirements = list(project["dependencies"])
optional = project.get("optional-dependencies", {})
for extra in extras:
    requirements += optional.get(extra, [])
print("\n".join(requirements))
PY

"$python" -m pip download "${download[@]}" --requirement "$requirements" >/dev/null \
    || die "a dependency has no wheel for $tag; build on the target platform or pass --platform"

say "wheels: $(find "$root/wheels" -name '*.whl' | wc -l | tr -d ' ')"

# --- everything else ----------------------------------------------------------------------

install -m 0755 "$repo/scripts/install.sh" "$root/install.sh"

for directory in docs schemas demo/pcaps; do
    if [[ -d "$repo/$directory" ]]; then
        mkdir -p "$root/$(dirname "$directory")"
        cp -R "$repo/$directory" "$root/$directory"
    fi
done

mkdir -p "$root/models"
for artefact in "$repo"/models/*.joblib "$repo"/models/*.json; do
    [[ -e "$artefact" ]] && cp "$artefact" "$root/models/"
done

if [[ $WITH_IMAGE -eq 1 ]]; then
    if command -v docker >/dev/null 2>&1 && docker image inspect "$IMAGE" >/dev/null 2>&1; then
        say "saving image $IMAGE"
        mkdir -p "$root/images"
        docker save "$IMAGE" -o "$root/images/ipsec-sentinel.tar"
    else
        say "image $IMAGE is not present locally; skipping it"
    fi
fi

# What the receiving side reads before it starts: install.sh refuses an interpreter
# whose version does not match, rather than discovering it wheel by wheel.
"$python" - "$root/BUNDLE.json" "$version" "$pyver" "$tag" "$EXTRAS" <<'PYBUNDLE'
import json
import pathlib
import sys
from datetime import UTC, datetime

destination, version, python_version, platform_tag, extras = sys.argv[1:6]
root = pathlib.Path(destination).parent
wheels = sorted(path.name for path in (root / "wheels").glob("*.whl"))
pathlib.Path(destination).write_text(
    json.dumps(
        {
            "project": "ipsec-sentinel",
            "version": version,
            "python_version": python_version,
            "platform": platform_tag,
            "extras": [extra for extra in extras.split(",") if extra],
            "wheels": len(wheels),
            "built_at": datetime.now(UTC).isoformat(),
        },
        indent=2,
    )
    + "\n"
)
PYBUNDLE

cat > "$root/README.txt" <<EOF
IPsec Sentinel ${version} — offline bundle
Built for: Python ${pyver} on ${tag}

  bash install.sh --offline --prefix /opt/ipsec-sentinel

Verify the contents first:

  (cd "\$(dirname "\$0")" && shasum -a 256 -c MANIFEST.txt)   # or sha256sum -c

The wheels here are built for Python ${pyver} on ${tag}. They will not install
against another interpreter version or another architecture, and install.sh refuses
rather than failing halfway through. Rebuild with --platform and --python-version on a
host that has network access.
EOF

# --- the manifest --------------------------------------------------------------------------

say "writing MANIFEST.txt"
(
    cd "$root"
    printf '# sha256  path — %s\n' "$name"
    find . -type f ! -name MANIFEST.txt -print0 \
        | sort -z \
        | while IFS= read -r -d '' file; do
            if command -v sha256sum >/dev/null 2>&1; then
                sha256sum "$file" | sed 's|\*\?\./||'
            else
                shasum -a 256 "$file" | sed 's|\*\?\./||'
            fi
        done
) > "$root/MANIFEST.txt"

# --- the tarball ---------------------------------------------------------------------------

tarball="$(cd "$OUTPUT" && pwd)/${name}.tar.gz"
tar -czf "$tarball" -C "$staging" "$name"

size="$(du -h "$tarball" | awk '{print $1}')"
printf '\nBundle: %s (%s)\n' "$tarball" "$size"
