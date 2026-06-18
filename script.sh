#!/usr/bin/env bash
#
# Dirtybird Zig Miner -- launcher.
#
# Presets (pool + wallet + threads) live in config.json next to the miner. The fastest
# way to use this: edit config.json once with YOUR wallet, then just run the binary.
# This script is a convenience: press Enter at a prompt to keep the config.json value,
# or type a value to override it for this run. On Windows, run from Git Bash:
#   bash script.sh
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

# --- optional overrides (Enter = use config.json / built-in defaults) ----------------
echo "Presets come from config.json (edit it to set your own wallet). Press Enter to use them."
read -rp "Daemon/pool host:port [Enter=config.json]: " DAEMON
read -rp "DERO wallet           [Enter=config.json]: " WALLET
read -rp "Threads               [Enter=config.json]: " THREADS

ARGS=()
[ -n "${DAEMON:-}" ]  && ARGS+=(-d "$DAEMON")
[ -n "${WALLET:-}" ]  && ARGS+=(-w "$WALLET")
[ -n "${THREADS:-}" ] && ARGS+=(-t "$THREADS")

echo
echo "Starting: ${BIN} ${ARGS[*]:-(config.json defaults)}"
echo "(Ctrl-C to stop)"
echo
exec "$BIN" "${ARGS[@]}"
