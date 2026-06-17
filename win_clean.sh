#!/usr/bin/env bash
# Dirtybird Zig Miner -- remove Zig build artifacts.
# Run from the source root (the directory containing this script).
#
# Deletes the Zig build outputs, the PGO profile directory, and stray object /
# debug files, leaving the tracked source tree untouched.
set -u
cd "$(dirname "$0")"

echo "=== Cleaning Zig build artifacts in $(pwd) ==="

# Build outputs and caches.
rm -rf zig-out/ .zig-cache/ zig-cache/

# PGO profiles (regenerate locally; see README).
rm -rf _pgo/

# Stray compiler / linker leftovers.
rm -f ./*.obj ./*.pdb

echo "Done."
