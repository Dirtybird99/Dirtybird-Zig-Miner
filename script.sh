#!/usr/bin/env bash
#
# Dirtybird Zig Miner -- interactive launcher.
#
# Builds the miner if needed, then prompts you for your daemon/pool address and
# DERO wallet and starts mining. On Windows run it from Git Bash: `bash script.sh`.
#
set -euo pipefail
cd "$(dirname "$0")"

# --- locate or build the miner binary ---------------------------------------
BIN="zig-out/bin/zig-miner"
[ -f "${BIN}.exe" ] && BIN="${BIN}.exe"

if [ ! -f "$BIN" ]; then
    echo "zig-miner not found; building (ReleaseFast, native)..."
    if ! command -v zig >/dev/null 2>&1; then
        echo "error: 'zig' is not on your PATH. Install Zig 0.14.1 and retry." >&2
        exit 1
    fi
    zig build -Doptimize=ReleaseFast -Dcpu=native
    if   [ -f "zig-out/bin/zig-miner.exe" ]; then BIN="zig-out/bin/zig-miner.exe"
    elif [ -f "zig-out/bin/zig-miner"     ]; then BIN="zig-out/bin/zig-miner"
    else echo "error: build did not produce zig-out/bin/zig-miner" >&2; exit 1
    fi
fi

# --- collect mining config ---------------------------------------------------
read -rp "Daemon/pool address (host:port): " DAEMON
read -rp "DERO wallet address: " WALLET
read -rp "Threads [10]: " THREADS
THREADS="${THREADS:-10}"

if [ -z "${DAEMON}" ] || [ -z "${WALLET}" ]; then
    echo "error: both a daemon address and a wallet are required." >&2
    exit 1
fi

# --- go ----------------------------------------------------------------------
echo
echo "Starting: ${BIN} -d ${DAEMON} -w ${WALLET} -t ${THREADS}"
echo "(Ctrl-C to stop)"
echo
exec "${BIN}" -d "${DAEMON}" -w "${WALLET}" -t "${THREADS}"
