#!/usr/bin/env bash
# Bare-metal install for IPsec Sentinel.
#
# Two modes, one script. Run from a checkout it installs from source and resolves
# dependencies normally; run with --offline it installs from a wheels/ directory next to
# it and never touches a package index. The offline mode is what ships inside the bundle
# produced by build_offline_bundle.sh, which is why this script is copied into it.
#
# The interpreter check is up front and fatal on purpose. A venv created with 3.10 and
# then failed halfway through a dependency resolve leaves a directory that looks
# installed and is not, and the person who has to debug that is on an air-gapped host
# with no way to search for the error.

set -euo pipefail

MINIMUM_MINOR=11
PREFIX="${SENTINEL_PREFIX:-$HOME/.local/share/ipsec-sentinel}"
PYTHON="${SENTINEL_PYTHON:-python3}"
OFFLINE=0
WHEELS=""
EXTRAS="ml,api,report"
SOURCE=""

usage() {
    cat <<'USAGE'
Usage: install.sh [options]

  --prefix DIR     Install the virtualenv here
                   (default: $HOME/.local/share/ipsec-sentinel)
  --python PATH    Interpreter to build the virtualenv with (default: python3)
  --offline        Install from ./wheels with no package index
  --wheels DIR     Wheel directory for --offline (default: ./wheels)
  --extras LIST    Comma-separated extras (default: ml,api,report; "" for none)
  --source PATH    Project directory or wheel to install (default: auto-detect)
  -h, --help       This message

After a successful install, add PREFIX/bin to PATH or invoke PREFIX/bin/sentinel
directly.
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix)  PREFIX="$2"; shift 2 ;;
        --python)  PYTHON="$2"; shift 2 ;;
        --offline) OFFLINE=1; shift ;;
        --wheels)  WHEELS="$2"; shift 2 ;;
        --extras)  EXTRAS="$2"; shift 2 ;;
        --source)  SOURCE="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "install.sh: unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

say() { printf '  %s\n' "$*"; }
die() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }

# --- the interpreter ------------------------------------------------------------------

command -v "$PYTHON" >/dev/null 2>&1 || die "no interpreter at '$PYTHON'"

version="$("$PYTHON" --version 2>&1 | awk '{print $2}')"
major="${version%%.*}"
rest="${version#*.}"
minor="${rest%%.*}"

if [[ "$major" != "3" || "$minor" -lt "$MINIMUM_MINOR" ]]; then
    die "Python 3.${MINIMUM_MINOR} or newer is required; '$PYTHON' is $version"
fi
say "interpreter: $PYTHON ($version)"

# --- what to install ------------------------------------------------------------------

if [[ -z "$SOURCE" ]]; then
    if [[ -f "$here/pyproject.toml" ]]; then
        SOURCE="$here"                      # a bundle laid out with the project inside
    elif [[ -f "$here/../pyproject.toml" ]]; then
        SOURCE="$here/.."                   # scripts/install.sh in a checkout
    elif [[ $OFFLINE -eq 1 ]]; then
        SOURCE=""                           # resolved from the wheel directory below
    else
        die "no project found; pass --source"
    fi
fi

if [[ $OFFLINE -eq 1 ]]; then
    WHEELS="${WHEELS:-$here/wheels}"
    [[ -d "$WHEELS" ]] || die "--offline needs a wheel directory; '$WHEELS' is not one"
    project_wheel="$(find "$WHEELS" -maxdepth 1 -name 'ipsec_sentinel-*.whl' | head -n 1)"
    [[ -n "$project_wheel" ]] || die "no ipsec_sentinel wheel in '$WHEELS'"

    # A bundle's wheels are compiled for one interpreter version. Installing against
    # another one does not fail at the venv, or at the first wheel; it fails partway
    # through the resolve with "no matching distribution", which reads like a corrupt
    # bundle rather than the wrong Python. Refuse up front and name both versions.
    if [[ -f "$here/BUNDLE.json" ]]; then
        wanted="$("$PYTHON" -c 'import json,sys; print(json.load(open(sys.argv[1]))["python_version"])' \
                  "$here/BUNDLE.json" 2>/dev/null || true)"
        if [[ -n "$wanted" && "$wanted" != "${major}.${minor}" ]]; then
            die "this bundle was built for Python $wanted; '$PYTHON' is ${major}.${minor}. \
Pass --python /path/to/python$wanted, or rebuild the bundle with --python-version ${major}.${minor}"
        fi
        say "bundle: built for Python $wanted"
    fi
    say "offline install from $WHEELS"
fi

# --- the virtualenv -------------------------------------------------------------------

if [[ -e "$PREFIX" && ! -d "$PREFIX" ]]; then
    die "'$PREFIX' exists and is not a directory"
fi

say "prefix: $PREFIX"
"$PYTHON" -m venv "$PREFIX"
pip="$PREFIX/bin/pip"

target="ipsec-sentinel"
if [[ -n "$EXTRAS" ]]; then
    target="ipsec-sentinel[$EXTRAS]"
fi

if [[ $OFFLINE -eq 1 ]]; then
    # --no-index is the guarantee; --find-links is where it looks instead. Upgrading pip
    # is skipped deliberately: on an air-gapped host it is one more thing to fail.
    "$pip" install --no-index --find-links "$WHEELS" --no-cache-dir "$target"
else
    "$pip" install --upgrade pip
    source_target="$SOURCE"
    if [[ -n "$EXTRAS" ]]; then
        source_target="$SOURCE[$EXTRAS]"
    fi
    "$pip" install --no-cache-dir "$source_target"
fi

# --- prove it ---------------------------------------------------------------------------

if ! "$PREFIX/bin/sentinel" version >/dev/null 2>&1; then
    die "the install completed but '$PREFIX/bin/sentinel version' does not run"
fi

printf '\nInstalled. %s\n' "$("$PREFIX/bin/sentinel" version)"
printf 'Add it to your PATH:\n\n    export PATH="%s/bin:$PATH"\n\n' "$PREFIX"
