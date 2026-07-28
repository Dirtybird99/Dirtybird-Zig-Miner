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
COMMUNITY_ADDR="community-pools.mysrv.cloud:10300"
RABID_ADDR="dero.rabidmining.com:10300"
DERO_NODE_ADDR="dero-node.net:10100"
FOUNDATION_ADDR="node.derofoundation.org:10100"
DEFAULT_ADDR="$COMMUNITY_ADDR"

# ---- pretty output (degrade gracefully when not a tty / NO_COLOR) -------------
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; C=$'\033[36m'; B=$'\033[1m'; Z=$'\033[0m'
else
  G=; Y=; R=; C=; B=; Z=
fi
info() { printf '%s[*]%s %s\n' "$G" "$Z" "$*"; }
warn() { printf '%s[!]%s %s\n' "$Y" "$Z" "$*"; }
die()  { printf '%s[x]%s %s\n' "$R" "$Z" "$*" >&2; exit 1; }

valid_endpoint() {
  local value="$1" host port label
  local -a labels
  if [[ "$value" =~ ^(wss?://)?([A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?):([0-9]{1,5})$ ]]; then
    host="${BASH_REMATCH[2]}"
    port="${BASH_REMATCH[4]}"
    [[ "$host" != *..* && "$host" != *.-* && "$host" != *-.* ]] || return 1
    (( ${#host} <= 253 )) || return 1
    IFS='.' read -r -a labels <<< "$host"
    for label in "${labels[@]}"; do (( ${#label} <= 63 )) || return 1; done
    (( 10#$port >= 1 && 10#$port <= 65535 ))
  else
    return 1
  fi
}

choose_endpoint() {
  local current="$1" choice custom
  while true; do
    printf '\n%sDaemon/pool%s\n' "$C" "$Z"
    printf '  1. Community Pools (recommended for phones) - %s\n' "$COMMUNITY_ADDR"
    printf '  2. Rabid Mining - %s\n' "$RABID_ADDR"
    printf '  3. dero-node.net solo - %s\n' "$DERO_NODE_ADDR"
    printf '  4. DERO Foundation solo/full-block - %s\n' "$FOUNDATION_ADDR"
    printf '  5. Custom\n'
    printf '  Pools provide steadier phone-friendly payouts; solo rewards arrive less often.\n'
    read -r -u "$PROMPT_FD" -p "  Selection [Enter keeps $current]: " choice || choice=
    case "$choice" in
      "") ADDR="$current"; return ;;
      1) ADDR="$COMMUNITY_ADDR"; return ;;
      2) ADDR="$RABID_ADDR"; return ;;
      3) ADDR="$DERO_NODE_ADDR"; return ;;
      4) ADDR="$FOUNDATION_ADDR"; return ;;
      5)
        while true; do
          read -r -u "$PROMPT_FD" -p "  Custom [ws://|wss://]host:port [Enter keeps $current]: " custom || custom=
          [ -n "$custom" ] || { ADDR="$current"; return; }
          if valid_endpoint "$custom"; then ADDR="$custom"; return; fi
          warn "Invalid endpoint; use [ws://|wss://]host:port with port 1-65535."
        done
        ;;
      *) warn "Invalid selection; choose 1-5." ;;
    esac
  done
}

json_escape() {
  local value="$1"
  [[ ! "$value" =~ [[:cntrl:]] ]] || return 1
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  printf '%s' "$value"
}

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

# ---- 4a. verify the download before anything executes it --------------------
# Every release publishes SHA256SUMS.txt; not checking it meant gzip's CRC was
# the only thing standing between a truncated or corrupted transfer and a
# binary that then runs unattended for days. Same-origin, so this is integrity
# rather than compromise resistance -- but it is the check the release already
# ships the data for.
if have sha256sum; then
  info "Verifying checksum..."
  SUMS_URL="https://github.com/$REPO/releases/download/$TAG/SHA256SUMS.txt"
  if fetch "$SUMS_URL" > "$TMP/SHA256SUMS.txt" 2>/dev/null && [ -s "$TMP/SHA256SUMS.txt" ]; then
    # Match the asset name exactly: a substring grep would also accept a line
    # for a different artifact that happens to contain this name.
    EXPECTED="$(awk -v f="$ASSET" '$2 == f || $2 == "*" f {print; exit}' "$TMP/SHA256SUMS.txt")"
    [ -n "$EXPECTED" ] || die "SHA256SUMS.txt has no entry for $ASSET"
    ( cd "$TMP" && printf '%s\n' "$EXPECTED" | sha256sum -c - >/dev/null 2>&1 ) \
      || die "checksum mismatch for $ASSET -- corrupt or tampered download; not installing"
    info "Checksum OK."
  else
    warn "could not fetch SHA256SUMS.txt; skipping integrity check"
  fi
else
  warn "sha256sum not available; skipping integrity check"
fi

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

  TLS_ALIGN="$(readelf -l ./zig-miner 2>/dev/null | awk '$1 == "TLS" { getline; print $NF; exit }')"
  if [ -n "$TLS_ALIGN" ] && [ "$((TLS_ALIGN))" -lt 64 ]; then
    die "this zig-miner has PT_TLS alignment $TLS_ALIGN; ARM64 Bionic requires at least 0x40. Install a newer arm64 release."
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

PROMPT_FD=0
if [ ! -t "$PROMPT_FD" ]; then
  if { exec 3</dev/tty; } 2>/dev/null; then PROMPT_FD=3; fi
fi

if [ -t "$PROMPT_FD" ]; then
  choose_endpoint "$CUR_ADDR"
  printf '\n%sDERO wallet address%s (for solo/pool payouts)\n' "$C" "$Z"
  [ -n "$CUR_WALLET" ] && printf '  Press Enter to keep: %s%s%s\n' "$G" "$CUR_WALLET" "$Z"
  read -r -u "$PROMPT_FD" -p "  Wallet: " IN_WALLET || true
  WALLET="${IN_WALLET:-$CUR_WALLET}"

  printf '\n%sThreads%s (%s cores detected, 1 reserved for OS)\n' "$C" "$Z" "$CORES"
  read -r -u "$PROMPT_FD" -p "  Threads [${SUGGEST_T}]: " IN_T || true
  THREADS="${IN_T:-$CUR_THREADS}"
else
  warn "non-interactive shell -- using existing/default config."
  ADDR="$CUR_ADDR"; WALLET="$CUR_WALLET"; THREADS="$CUR_THREADS"
fi

# integer-guard threads
case "$THREADS" in ''|*[!0-9]*) THREADS="$SUGGEST_T" ;; esac

# ---- 7. write config.json the miner reads ------------------------------------
ADDR_JSON="$(json_escape "$ADDR")" || die "endpoint contains unsupported control characters"
WALLET_JSON="$(json_escape "$WALLET")" || die "wallet contains unsupported control characters"
printf '{\n  "daemon-address": "%s",\n  "wallet": "%s",\n  "threads": %s\n}\n' \
  "$ADDR_JSON" "$WALLET_JSON" "$THREADS" > config.json
info "Wrote $INSTALL_DIR/config.json (threads: $THREADS, daemon: $ADDR)"

# ---- 8. wake-lock ------------------------------------------------------------
# Without one, Android Doze suspends the process as soon as the screen sleeps:
# the miner quietly stops earning and nothing tells the user it happened.
WAKE_LOCKED=0
release_wake_lock() {
  if [ "$WAKE_LOCKED" -eq 1 ]; then
    WAKE_LOCKED=0
    termux-wake-unlock >/dev/null 2>&1 || true
    info "Wake-lock released."
  fi
}
# Registered before acquiring, so a Ctrl-C landing in between still cleans up.
# INT/TERM/HUP must EXIT rather than return -- a returning trap would resume the
# script -- and HUP matters because closing the Termux session sends it, and an
# untrapped fatal signal skips the EXIT trap entirely, leaking the lock.
trap 'rm -rf "$TMP"; release_wake_lock' EXIT
trap 'release_wake_lock; exit 130' INT TERM HUP

if have termux-wake-lock; then
  # timeout: the termux-api shim blocks forever when its companion app is not
  # installed, and `have` only proves the shim exists.
  if timeout 5 termux-wake-lock >/dev/null 2>&1; then
    WAKE_LOCKED=1
    info "Wake-lock acquired (Android Doze will not suspend the miner)."
  else
    warn "could not acquire a wake-lock -- Android Doze may pause the miner in the background."
  fi
else
  warn "termux-api not installed -- Android Doze may pause the miner in the background."
  warn "enable wake-locks with: pkg install termux-api"
fi

# ---- 9. mine -----------------------------------------------------------------
printf '\n'
info "Starting miner... (Ctrl-C to stop)"
printf '\n'
# Not `exec`: the shell has to outlive the miner to release the wake-lock.
./zig-miner
