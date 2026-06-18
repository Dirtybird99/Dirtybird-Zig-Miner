#!/usr/bin/env bash
#
# Dirtybird Zig Miner -- launcher.
#
# Your settings live in config.json next to the binary. Edit config.json directly, OR
# answer "y" below to set pool/wallet/threads interactively -- either way persists to the
# same config.json the miner reads. On Windows, run from Git Bash:  bash script.sh
set -euo pipefail
cd "$(dirname "$0")"

# --- locate the miner binary (release folder first, then dev tree, else build) -------
if   [ -f "./zig-miner.exe" ];            then BIN="./zig-miner.exe"
elif [ -f "./zig-miner" ];                then BIN="./zig-miner"
elif [ -f "zig-out/bin/zig-miner.exe" ];  then BIN="zig-out/bin/zig-miner.exe"
elif [ -f "zig-out/bin/zig-miner" ];      then BIN="zig-out/bin/zig-miner"
else
    echo "zig-miner not found; building (best-performance defaults)..."
    command -v zig >/dev/null 2>&1 || { echo "error: install Zig 0.14.1 and retry." >&2; exit 1; }
    zig build
    if   [ -f "zig-out/bin/zig-miner.exe" ]; then BIN="zig-out/bin/zig-miner.exe"
    elif [ -f "zig-out/bin/zig-miner" ];     then BIN="zig-out/bin/zig-miner"
    else echo "error: build did not produce zig-out/bin/zig-miner" >&2; exit 1
    fi
fi

# --- optional interactive edit (persists to config.json), then mine ------------------
read -rp "Change pool/wallet/threads? (y/N): " EDIT
case "${EDIT:-}" in [yY]*) "$BIN" --setup ;; esac

echo
echo "Starting miner (Ctrl-C to stop)..."
echo
exec "$BIN"
