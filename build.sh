#!/usr/bin/env bash
# Dirtybird Zig Miner -- native build script.
# Run from the source root (the directory containing this script).
#
# Usage:
#   ./build.sh                 # Standard ReleaseFast + native-CPU build
#   ./build.sh -Dpgo=gen \
#     -Dprofile_rt=<path to libclang_rt.profile-x86_64.a>
#                              # PGO instrumentation build (step 1)
#   ./build.sh -Dpgo=use       # PGO optimized build (step 2, after profiling)
#
# Any extra arguments are passed straight through to `zig build`, so the whole
# PGO workflow (-Dpgo=gen|use, -Dprofile_rt=...) rides in as pass-through args.
set -euo pipefail
cd "$(dirname "$0")"

if ! command -v zig >/dev/null 2>&1; then
    echo "error: 'zig' is not on your PATH. Install Zig 0.14.1 and retry." >&2
    exit 1
fi

echo "=== Building: ReleaseFast + native CPU (SHA-NI + AVX2) ==="
zig build -Doptimize=ReleaseFast -Dcpu=native "$@"

# Report where the binary landed (.exe suffix on Windows).
BIN="zig-out/bin/zig-miner"
[ -f "${BIN}.exe" ] && BIN="${BIN}.exe"

echo ""
if [ -f "$BIN" ]; then
    echo "=== Binary: $(pwd)/$BIN ==="
    ls -la "$BIN"
else
    echo "warning: build finished but zig-out/bin/zig-miner was not found." >&2
fi

echo ""
echo "Test run:"
echo "  $BIN -d pool.example:10100 -w dero1q...your_wallet... -t 20"
