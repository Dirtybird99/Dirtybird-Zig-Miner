#!/usr/bin/env bash
#
# Build the optimized Dirtybird Zig Miner and package a release.
#
# Produces a self-contained release directory and a matching .zip under dist/:
#
#   dist/dirtybird-zig-miner-<os>-v<version>/
#       zig-miner[.exe]        the optimized miner
#       README.md
#       LICENSE
#       THIRD-PARTY-LICENSES
#       config/                HiveOS / launcher config (if present in the repo)
#       script.sh              interactive launcher
#   dist/dirtybird-zig-miner-<os>-v<version>.zip
#
# Unlike the reference C release.sh, there is nothing to patchelf/ldd here: the
# Zig build links libc/libc++ through Zig's toolchain, so the binary ships as a
# single file with no side-car .so/.dll to bundle.
#
# Usage:
#   scripts/release.sh [version] [build-dir-unused] [output-dir]
#     version     release tag, e.g. 0.1.0 or v0.1.0 (default: binary's own -v)
#     output-dir  staging root for the package + zip (default: dist)
#
# Env knobs (all optional):
#   ZIG=zig         zig binary (override to pin 0.14.1, e.g. .tools/zig/zig)
#   CPU=native      -Dcpu= value
#   SKIP_BUILD=0    set to 1 to package an already-built zig-out/bin binary
#
set -euo pipefail

# Always operate from the repo root.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

OUTPUT_DIR="${3:-dist}"
ZIG="${ZIG:-zig}"
CPU="${CPU:-native}"
SKIP_BUILD="${SKIP_BUILD:-0}"

# --- build the optimized binary ----------------------------------------------
# We package whatever is in zig-out/bin. If you want the headline PGO build,
# run scripts/build-pgo.sh first and then `SKIP_BUILD=1 scripts/release.sh`.
if [ "$SKIP_BUILD" != "1" ]; then
    command -v "$ZIG" >/dev/null 2>&1 || {
        echo "error: '$ZIG' not found on PATH. Install Zig 0.14.1 (or set ZIG=)." >&2
        exit 1
    }
    echo "[release] building optimized binary (ReleaseFast, -Dcpu=$CPU)"
    "$ZIG" build -Doptimize=ReleaseFast "-Dcpu=$CPU"
fi

# Resolve the produced binary (.exe on Windows).
if   [ -f "zig-out/bin/zig-miner.exe" ]; then BINARY_NAME="zig-miner.exe"
elif [ -f "zig-out/bin/zig-miner"     ]; then BINARY_NAME="zig-miner"
else
    echo "error: zig-out/bin/zig-miner not found. Build first (or unset SKIP_BUILD)." >&2
    exit 1
fi
BINARY_PATH="zig-out/bin/$BINARY_NAME"

# --- resolve version ---------------------------------------------------------
# Default to the version the binary reports (zig-miner v0.1.0); allow override.
VERSION="${1:-}"
if [ -z "$VERSION" ]; then
    # The miner prints its version line via std.debug.print (stderr), so fold
    # stderr into stdout before scraping it.
    VERSION="$("$BINARY_PATH" -v 2>&1 | grep -oE 'v?[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
fi
VERSION="${VERSION#v}"
[ -n "$VERSION" ] || { echo "error: could not determine version; pass it as the first argument." >&2; exit 1; }
ASSET_VERSION="v$VERSION"

# OS tag for the package name (mirrors dirtybird's win64/amd64 naming).
case "$(uname -s 2>/dev/null || echo unknown)" in
    MINGW*|MSYS*|CYGWIN*|Windows_NT) OS_TAG="win64" ;;
    Darwin)                          OS_TAG="macos" ;;
    Linux)                           OS_TAG="linux-amd64" ;;
    *)                               OS_TAG="amd64" ;;
esac

PACKAGE_NAME="dirtybird-zig-miner-$OS_TAG-$ASSET_VERSION"
STAGE_ROOT="$REPO_ROOT/$OUTPUT_DIR"
PACKAGE_DIR="$STAGE_ROOT/$PACKAGE_NAME"

echo "================================================"
echo "Dirtybird Zig Miner -- release packaging"
echo "  version : $ASSET_VERSION"
echo "  binary  : $BINARY_NAME"
echo "  package : $PACKAGE_NAME"
echo "================================================"

# --- stage the package -------------------------------------------------------
mkdir -p "$STAGE_ROOT"
rm -rf "$PACKAGE_DIR"
mkdir -p "$PACKAGE_DIR"

cp "$BINARY_PATH" "$PACKAGE_DIR/"
chmod +x "$PACKAGE_DIR/$BINARY_NAME" 2>/dev/null || true

# Docs + license bundle (THIRD-PARTY-LICENSES is required by the bundled libsais
# Apache-2.0 / v114 MIT terms).
for doc in README.md LICENSE THIRD-PARTY-LICENSES; do
    if [ -f "$REPO_ROOT/$doc" ]; then
        cp "$REPO_ROOT/$doc" "$PACKAGE_DIR/"
    else
        echo "[release] warning: $doc not found in repo root; skipping" >&2
    fi
done

# HiveOS / launcher config, if the repo carries one.
if [ -d "$REPO_ROOT/config" ]; then
    cp -r "$REPO_ROOT/config" "$PACKAGE_DIR/config"
else
    echo "[release] note: no config/ directory in repo; skipping" >&2
fi

# Interactive launcher.
if [ -f "$REPO_ROOT/script.sh" ]; then
    cp "$REPO_ROOT/script.sh" "$PACKAGE_DIR/script.sh"
    chmod +x "$PACKAGE_DIR/script.sh" 2>/dev/null || true
else
    echo "[release] warning: script.sh not found in repo root; skipping" >&2
fi

# Short quick-start so the archive is usable on its own.
cat > "$PACKAGE_DIR/QUICKSTART.txt" <<EOF
Dirtybird Zig Miner $ASSET_VERSION
==================================

Contents:
- $BINARY_NAME       the miner (single, self-contained binary)
- README.md
- LICENSE
- THIRD-PARTY-LICENSES
- config/            HiveOS / launcher config (if included)
- script.sh          interactive launcher (run with: bash script.sh)

Quick start:
  ./$BINARY_NAME -d pool.example:10100 -w dero1q...your_wallet... -t 10
or, interactively:
  bash script.sh

Replace the host/wallet with your own DERO pool and a valid checksummed
DERO wallet address. -t defaults to your logical CPU count.

Notes:
- Requires a 64-bit CPU with SHA-NI + AVX2 for the accelerated path.
- On startup the miner runs a pow("a") self-test; it must say PASS.
  Run it standalone with:  ./$BINARY_NAME --selftest
EOF

# --- archive -----------------------------------------------------------------
ARCHIVE_PATH="$STAGE_ROOT/$PACKAGE_NAME.zip"
rm -f "$ARCHIVE_PATH"
if command -v zip >/dev/null 2>&1; then
    ( cd "$STAGE_ROOT" && zip -qr "$PACKAGE_NAME.zip" "$PACKAGE_NAME" )
    echo "[release] created archive: $ARCHIVE_PATH"
elif command -v powershell >/dev/null 2>&1; then
    # Windows without the zip tool: fall back to PowerShell's Compress-Archive.
    # PowerShell can't open MSYS /c/.. paths, so hand it Windows-style paths.
    PS_DIR="$PACKAGE_DIR"; PS_ARCHIVE="$ARCHIVE_PATH"
    if command -v cygpath >/dev/null 2>&1; then
        PS_DIR="$(cygpath -w "$PACKAGE_DIR")"
        PS_ARCHIVE="$(cygpath -w "$ARCHIVE_PATH")"
    fi
    powershell -NoProfile -Command \
        "Compress-Archive -Path '$PS_DIR' -DestinationPath '$PS_ARCHIVE' -Force"
    echo "[release] created archive: $ARCHIVE_PATH"
else
    echo "[release] note: no 'zip' or 'powershell' found; leaving the staged dir only." >&2
fi

echo "================================================"
echo "[release] package ready: $PACKAGE_DIR"
echo "================================================"
