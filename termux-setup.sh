#!/usr/bin/env bash
#
# Dirtybird Zig Miner -- one-shot Termux (Android) installer.
#
#   curl -fsSL https://raw.githubusercontent.com/Dirtybird99/Dirtybird-Zig-Miner/main/termux-setup.sh | bash
#   # ...or download it and run:  bash termux-setup.sh
#
# Fetches the latest GitHub release, installs the matching static-PIE binary into
# $HOME (an exec-capable filesystem -- /sdcard is noexec on Android), wires up
# config.json, and starts mining.
#
# The arm64 release is built PIE (ET_DYN) so Android's loader / Termux's
# system_linker_exec path accepts it. A non-PIE (ET_EXEC) binary fails on
# Android 10+ with: error: "...zig-miner" has unexpected e_type: 2
set -euo pipefail

REPO="Dirtybird99/Dirtybird-Zig-Miner"
NAME="Dirtybird-Zig-Miner"
INSTALL_DIR="$HOME/$NAME"
DEFAULT_ADDR="community-pools.mysrv.cloud:10300"

# ---- pretty output (degrade gracefully when not a tty / NO_COLOR) -------------
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; C=$'\033[36m'; B=$'\033[1m'; Z=$'\033[0m'
else
  G=; Y=; R=; C=; B=; Z=
fi
info() { printf '%s[*]%s %s\n' "$G" "$Z" "$*"; }
warn() { printf '%s[!]%s %s\n' "$Y" "$Z" "$*"; }
die()  { printf '%s[x]%s %s\n' "$R" "$Z" "$*" >&2; exit 1; }

# ---- 1. dependencies ---------------------------------------------------------
info "Checking Termux dependencies..."
have() { command -v "$1" >/dev/null 2>&1; }
PKG=""
if have pkg; then PKG="pkg"; elif have apt; then PKG="apt"; fi
ensure() { # $1 = command, $2 = package
  have "$1" && return 0
  warn "$1 not found -- installing..."
  [ -n "$PKG" ] || die "$1 is required but '$PKG' package manager is unavailable. Install $2 manually."
  "$PKG" install -y "$2" >/dev/null 2>&1 || die "failed to install $2"
}
# Need a downloader (curl or wget) and tar.
if ! have curl && ! have wget; then ensure wget wget; fi
ensure tar tar
DL=""
if have curl; then DL="curl"; elif have wget; then DL="wget"; fi
info "Dependencies OK."

fetch() { # $1 = url  -> stdout
  if [ "$DL" = "curl" ]; then curl -fsSL "$1"; else wget -qO- "$1"; fi
}
fetch_to() { # $1 = url  $2 = dest file (shows progress)
  if [ "$DL" = "curl" ]; then curl -fL --progress-bar -o "$2" "$1"
  else wget -O "$2" "$1"; fi
}

# ---- 2. detect architecture --------------------------------------------------
case "$(uname -m)" in
  aarch64|arm64)        ARCH="arm64"  ;;
  x86_64|amd64)         ARCH="amd64"  ;;
  *) die "unsupported CPU architecture: $(uname -m) (only arm64 / amd64 are released)" ;;
esac

# ---- 3. resolve the latest release tag --------------------------------------
info "Fetching latest release from GitHub..."
API="https://api.github.com/repos/$REPO/releases/latest"
# Parse "tag_name": "vX.Y.Z" without requiring jq.
TAG="$(fetch "$API" | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')"
[ -n "$TAG" ] || die "could not determine the latest release tag (GitHub API unreachable / rate-limited)"
info "Latest release: ${B}${TAG}${Z}"

ASSET="${NAME}-${ARCH}-${TAG}.tar.gz"
URL="https://github.com/$REPO/releases/download/$TAG/$ASSET"

# ---- 4. download + extract into $HOME (exec-capable; /sdcard is noexec) ------
TMP="$(mktemp -d "${TMPDIR:-/tmp}/dbz.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
info "Downloading $ASSET ..."
fetch_to "$URL" "$TMP/$ASSET" || die "download failed: $URL"

info "Extracting..."
tar -xzf "$TMP/$ASSET" -C "$TMP" || die "extract failed (corrupt download?)"

# The tarball expands to a folder ($NAME-$ARCH-$TAG). Install its contents into
# $INSTALL_DIR, replacing any previous install but preserving an existing config.
SRC="$TMP/${NAME}-${ARCH}-${TAG}"
[ -d "$SRC" ] || SRC="$(find "$TMP" -maxdepth 1 -type d -name "${NAME}-*" | head -n1)"
[ -n "$SRC" ] && [ -d "$SRC" ] || die "unexpected archive layout"
[ -f "$SRC/zig-miner" ] || die "archive did not contain a zig-miner binary"

mkdir -p "$INSTALL_DIR"
# Don't clobber a config.json the user already tuned.
[ -f "$INSTALL_DIR/config.json" ] && [ -f "$SRC/config.json" ] && rm -f "$SRC/config.json"
cp -rf "$SRC"/. "$INSTALL_DIR"/
chmod +x "$INSTALL_DIR/zig-miner"   # <-- the step ad-hoc installs forget
cd "$INSTALL_DIR"

# ---- 5. sanity: confirm the binary is PIE (ET_DYN) before we try to run it ---
# A non-PIE binary on Android dies with "unexpected e_type: 2"; catch it early
# with a clear message instead of a cryptic loader error.
if have readelf; then
  if ! readelf -h ./zig-miner 2>/dev/null | grep -q 'Type:.*DYN'; then
    warn "this zig-miner is not a PIE (ET_DYN) binary -- Android may reject it with 'e_type: 2'."
    warn "make sure you're on the latest release (PIE arm64 ships from v0.1.4)."
  fi
fi

# ---- 6. configure (prompts default to any existing config.json) --------------
jget() { # $1 = key -> current value from config.json (empty if absent)
  [ -f config.json ] || return 0
  grep -m1 "\"$1\"" config.json | sed -E 's/.*:[[:space:]]*"?([^",}]*)"?.*/\1/' | tr -d ' '
}
CORES="$( (nproc 2>/dev/null) || echo 1 )"
SUGGEST_T=$(( CORES > 1 ? CORES - 1 : 1 ))

CUR_ADDR="$(jget 'daemon-address')"; CUR_ADDR="${CUR_ADDR:-$DEFAULT_ADDR}"
CUR_WALLET="$(jget 'wallet')"
CUR_THREADS="$(jget 'threads')"; CUR_THREADS="${CUR_THREADS:-$SUGGEST_T}"

if [ -t 0 ]; then
  printf '\n%sDaemon/pool address%s [scheme://]host:port\n' "$C" "$Z"
  printf '  Press Enter to use: %s%s%s\n' "$G" "$CUR_ADDR" "$Z"
  read -rp "  Address: " IN_ADDR || true
  ADDR="${IN_ADDR:-$CUR_ADDR}"

  printf '\n%sDERO wallet address%s (for solo/pool payouts)\n' "$C" "$Z"
  [ -n "$CUR_WALLET" ] && printf '  Press Enter to keep: %s%s%s\n' "$G" "$CUR_WALLET" "$Z"
  read -rp "  Wallet: " IN_WALLET || true
  WALLET="${IN_WALLET:-$CUR_WALLET}"

  printf '\n%sThreads%s (%s cores detected, 1 reserved for OS)\n' "$C" "$Z" "$CORES"
  read -rp "  Threads [${SUGGEST_T}]: " IN_T || true
  THREADS="${IN_T:-$CUR_THREADS}"
else
  warn "non-interactive shell -- using existing/default config."
  ADDR="$CUR_ADDR"; WALLET="$CUR_WALLET"; THREADS="$CUR_THREADS"
fi

# integer-guard threads
case "$THREADS" in ''|*[!0-9]*) THREADS="$SUGGEST_T" ;; esac

# ---- 7. write config.json the miner reads ------------------------------------
printf '{\n  "daemon-address": "%s",\n  "wallet": "%s",\n  "threads": %s\n}\n' \
  "$ADDR" "$WALLET" "$THREADS" > config.json
info "Wrote $INSTALL_DIR/config.json (threads: $THREADS, daemon: $ADDR)"

# ---- 8. mine -----------------------------------------------------------------
printf '\n'
info "Starting miner... (Ctrl-C to stop)"
printf '\n'
exec ./zig-miner
