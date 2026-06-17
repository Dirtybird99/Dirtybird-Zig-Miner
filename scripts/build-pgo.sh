#!/usr/bin/env bash
#
# Two-pass profile-guided release build for the Dirtybird Zig Miner.
#
# WHY: the suffix-array translation units (vendor/libsais + vendor/v114) are
# most of the per-hash cost and are compiled as C/C++ through Zig's C interop.
# build.zig exposes a two-pass PGO knob for exactly these objects:
#   -Dpgo=gen  instruments them (counters written to _pgo/*.profraw at runtime)
#   -Dpgo=use  folds a merged profile (_pgo/merged.profdata) back in, with LTO
# Shipping the PGO build is what the README's ~10%-over-reference figure was
# measured with, so this script automates the whole gen -> run -> merge -> use
# dance the same way every time.
#
# Three steps, mirroring the manual flow documented in README.md:
#   1. instrumented build      zig build ... -Dpgo=gen -Dprofile_rt=<rt.a>
#   2. collect a profile       run the miner's --selftest in a short loop so the
#                              SA hot path executes; counters land in _pgo/
#   3. merge + optimized build llvm-profdata merge ...  then  zig build -Dpgo=use
#
# The instrumented pass needs your Clang profile runtime (libclang_rt.profile-*),
# the same static archive your LLVM/MinGW ships. Pass its path as $1 or via the
# PROFILE_RT env var.
#
# Env knobs (all optional):
#   PROFILE_RT=<path>     libclang_rt.profile-x86_64.a   (or pass as $1)
#   TRAIN_SECS=20         wall-clock budget for profile collection
#   PROFDATA=llvm-profdata  llvm-profdata binary (e.g. llvm-profdata-18)
#   ZIG=zig               zig binary (override to pin 0.14.1, e.g. .tools/zig/zig)
#   CPU=native            -Dcpu= value passed to every build
#
# Usage:
#   scripts/build-pgo.sh /path/to/libclang_rt.profile-x86_64.a
#   PROFILE_RT=/path/to/...profile-x86_64.a scripts/build-pgo.sh
#
set -euo pipefail

# Run from the repo root regardless of where we were invoked from.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PROFILE_RT="${1:-${PROFILE_RT:-}}"
TRAIN_SECS="${TRAIN_SECS:-20}"
PROFDATA="${PROFDATA:-llvm-profdata}"
ZIG="${ZIG:-zig}"
CPU="${CPU:-native}"

# Shared optimize/cpu flags so all three passes agree.
COMMON=(-Doptimize=ReleaseFast "-Dcpu=$CPU")

# --- preflight ---------------------------------------------------------------
command -v "$ZIG" >/dev/null 2>&1 || {
    echo "[build-pgo] ERROR: '$ZIG' not found on PATH. Install Zig 0.14.1 (or set ZIG=)." >&2
    exit 1
}

if [ -z "$PROFILE_RT" ]; then
    echo "[build-pgo] ERROR: missing Clang profile runtime path." >&2
    echo "    -Dpgo=gen needs libclang_rt.profile-x86_64.a (shipped by your LLVM/MinGW)." >&2
    echo "    Pass it as the first argument or via the PROFILE_RT env var:" >&2
    echo "        scripts/build-pgo.sh /path/to/libclang_rt.profile-x86_64.a" >&2
    echo "        PROFILE_RT=/path/to/...profile-x86_64.a scripts/build-pgo.sh" >&2
    exit 2
fi
if [ ! -f "$PROFILE_RT" ]; then
    echo "[build-pgo] ERROR: profile runtime not found: $PROFILE_RT" >&2
    exit 2
fi

# llvm-profdata must match the instrumenting clang's major version. On Ubuntu it
# is often suffixed (llvm-profdata-18); fall back to that if the bare name is
# missing and we can read clang's version.
if ! command -v "$PROFDATA" >/dev/null 2>&1; then
    CLANG_MAJ="$(clang --version 2>/dev/null | grep -oE 'version [0-9]+' | grep -oE '[0-9]+' | head -1 || true)"
    if [ -n "${CLANG_MAJ:-}" ] && command -v "llvm-profdata-${CLANG_MAJ}" >/dev/null 2>&1; then
        PROFDATA="llvm-profdata-${CLANG_MAJ}"
    fi
fi
command -v "$PROFDATA" >/dev/null 2>&1 || {
    echo "[build-pgo] ERROR: llvm-profdata not found (tried '$PROFDATA'). Set PROFDATA=." >&2
    exit 3
}

echo "================================================"
echo "Dirtybird Zig Miner -- PGO build"
echo "  zig         : $ZIG"
echo "  profile rt  : $PROFILE_RT"
echo "  profdata    : $PROFDATA"
echo "  train secs  : $TRAIN_SECS"
echo "================================================"

# Resolve a possibly-.exe binary path (Windows vs POSIX).
resolve_bin() { local b="$1"; if [ -f "$b.exe" ]; then echo "$b.exe"; else echo "$b"; fi; }

# --- step 1/3: instrumented build -------------------------------------------
# build.zig embeds -fprofile-generate=_pgo into the SA C/C++ objects and links
# the profile runtime you point at with -Dprofile_rt.
echo "[build-pgo] step 1/3: instrumented build (-Dpgo=gen)"
rm -rf _pgo
mkdir -p _pgo
"$ZIG" build "${COMMON[@]}" -Dpgo=gen -Dprofile_rt="$PROFILE_RT"

BIN="$(resolve_bin "zig-out/bin/zig-miner")"
[ -f "$BIN" ] || { echo "[build-pgo] ERROR: instrumented build produced no binary" >&2; exit 4; }

# --- step 2/3: collect a profile --------------------------------------------
# The miner needs a daemon to mine, but --selftest runs the *entire* AstroBWTv3
# pipeline (including the suffix-array hot path we want to profile) with no
# network. Loop it for ~TRAIN_SECS so the instrumented SA objects accumulate
# realistic counts; each run appends to the _pgo/*.profraw counters.
echo "[build-pgo] step 2/3: collecting profile (~${TRAIN_SECS}s of --selftest)"
deadline=$(( $(date +%s) + TRAIN_SECS ))
runs=0
while [ "$(date +%s)" -lt "$deadline" ]; do
    "$BIN" --selftest >/dev/null 2>&1 || {
        echo "[build-pgo] ERROR: --selftest failed (KAT mismatch?); aborting" >&2
        exit 5
    }
    runs=$((runs + 1))
done
echo "[build-pgo] ran --selftest x$runs"

shopt -s nullglob
profraws=(_pgo/*.profraw)
shopt -u nullglob
[ "${#profraws[@]}" -gt 0 ] || {
    echo "[build-pgo] ERROR: no _pgo/*.profraw emitted -- is the profile runtime correct?" >&2
    exit 6
}
echo "[build-pgo] collected ${#profraws[@]} profraw file(s)"

# --- step 3/3: merge + optimized build --------------------------------------
echo "[build-pgo] step 3/3: merge profile, then optimized build (-Dpgo=use)"
"$PROFDATA" merge -output=_pgo/merged.profdata "${profraws[@]}"
echo "[build-pgo] merged profile: $(wc -c < _pgo/merged.profdata) bytes (_pgo/merged.profdata)"

# build.zig picks up _pgo/merged.profdata for -Dpgo=use (also enables -flto on
# the SA objects). Wipe the instrumented artifacts so the use-build relinks clean.
rm -rf zig-out
"$ZIG" build "${COMMON[@]}" -Dpgo=use

FINAL="$(resolve_bin "zig-out/bin/zig-miner")"
echo "================================================"
echo "[build-pgo] done: $FINAL (PGO + LTO)"
echo "================================================"
