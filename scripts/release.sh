#!/usr/bin/env bash
#
# Dirtybird Zig Miner -- build all release binaries + packages into dist/.
#
# Usage:  scripts/release.sh [version]
#   version defaults to the latest git tag, else v0.0.0-dev.
#   Override the Zig binary with ZIG=/path/to/zig.
#
# Produces, for each platform, an archive containing the binary plus README,
# LICENSE, THIRD-PARTY-LICENSES, the launcher (script.sh / start.bat), and (Linux)
# the HiveOS config/. Plus a HiveOS/MMPOS package and a SHA256SUMS.txt.
#
# x86-64 builds target an AVX2 + SHA-NI baseline (x86_64_v3+sha). The miner is pure
# Zig (no C/C++, no PGO) -- ReleaseFast is the shipped configuration on every target.
set -euo pipefail
cd "$(dirname "$0")/.."

VER="${1:-$(git describe --tags --abbrev=0 2>/dev/null || echo v0.0.0-dev)}"
ZIG="${ZIG:-zig}"
DIST="dist"
NAME="Dirtybird-Zig-Miner"
# x86-64 build flags: AVX2 + SHA-NI baseline (the SHA-NI asm is comptime-gated on +sha).
X86="-Dcpu=x86_64_v3+sha"

rm -rf "$DIST" _build
mkdir -p "$DIST"

stage_common() { cp README.md LICENSE THIRD-PARTY-LICENSES script.sh config.json "$1"/; }

find_readelf() {
  command -v readelf || command -v llvm-readelf || return 1
}

verify_bionic_arm64_elf() { # $1 = executable path
  local bin="$1" readelf_bin tls_align
  readelf_bin="$(find_readelf)" || {
    echo "error: readelf or llvm-readelf is required to verify the Android/Termux arm64 binary" >&2
    return 1
  }

  if ! "$readelf_bin" -h "$bin" | grep -q 'Type:[[:space:]]*DYN'; then
    echo "error: $bin is not PIE (ELF Type DYN); Android/Termux will reject it" >&2
    return 1
  fi

  tls_align="$("$readelf_bin" -l "$bin" | awk '$1 == "TLS" { getline; print $NF; exit }')"
  if [ -n "$tls_align" ] && [ "$((tls_align))" -lt 64 ]; then
    echo "error: $bin has PT_TLS alignment $tls_align; ARM64 Bionic requires at least 0x40" >&2
    return 1
  fi
}

PY="$(command -v python3 || command -v python)"
zipdir() { # $1 = folder name under $DIST to zip (folder name = archive stem)
  "$PY" - "$DIST" "$1" <<'PY'
import sys, shutil, os
dist, name = sys.argv[1], sys.argv[2]
shutil.make_archive(os.path.join(dist, name), "zip", root_dir=dist, base_dir=name)
PY
}

mk_tar() { # $1=archive-name  $2=zig-target  $3=cpu-flags
  local name="$1" d="$DIST/$1"
  mkdir -p "$d"
  "$ZIG" build -Doptimize=ReleaseFast -Dtarget="$2" $3 -p "_build/$name"
  cp "_build/$name/bin/zig-miner" "$d/zig-miner"
  chmod +x "$d/zig-miner"
  if [ "$2" = "aarch64-linux-musl" ]; then verify_bionic_arm64_elf "$d/zig-miner"; fi
  stage_common "$d"
  cp -r config "$d/config"
  tar -C "$DIST" --mode='u+rwx,go+rx' -czf "$DIST/$name.tar.gz" "$name"
  rm -rf "$d"
}

# ---- Linux + macOS tarballs (static musl = runs on any Linux) ----------------
mk_tar "${NAME}-amd64-${VER}"       x86_64-linux-musl  "$X86"
mk_tar "${NAME}-arm64-${VER}"       aarch64-linux-musl ""
mk_tar "${NAME}-macos-arm64-${VER}" aarch64-macos      ""

# ---- Windows zip -------------------------------------------------------------
"$ZIG" build -Doptimize=ReleaseFast -Dtarget=x86_64-windows-gnu $X86 -p _build/win
wd="$DIST/${NAME}-win64-${VER}"
mkdir -p "$wd"
cp _build/win/bin/zig-miner.exe "$wd/"
stage_common "$wd"
cp start.bat "$wd/"
zipdir "${NAME}-win64-${VER}"
rm -rf "$wd"

# ---- HiveOS / MMPOS package (static amd64 binary + h-scripts) ----------------
hd="$DIST/hive/zig-miner"
mkdir -p "$hd"
cp config/h-manifest.conf config/h-run.sh config/h-config.sh config/h-stats.sh README.md LICENSE "$hd/"
"$ZIG" build -Doptimize=ReleaseFast -Dtarget=x86_64-linux-musl $X86 -p _build/hive
cp _build/hive/bin/zig-miner "$hd/zig-miner"
chmod +x "$hd/zig-miner" "$hd"/*.sh
tar -C "$DIST/hive" --mode='u+rwx,go+rx' -czf "$DIST/dirtybird-zig-miner-${VER}.hiveos_mmpos.amd64.tar.gz" zig-miner
rm -rf "$DIST/hive"

# ---- checksums ---------------------------------------------------------------
( cd "$DIST" && sha256sum *.zip *.tar.gz > SHA256SUMS.txt )
rm -rf _build

# ---- mirror archives into the repo tree (browsable releases/<version>/) -------
# DeroLuna-style: the same archives that go on the Release page also live in-tree.
# (git add releases/<version> && commit to publish them.)
REL="releases/$VER"
mkdir -p "$REL"
cp "$DIST"/*.zip "$DIST"/*.tar.gz "$DIST/SHA256SUMS.txt" "$REL"/
echo "mirrored archives into $REL/"

echo "=== built into $DIST/ ==="
ls -1 "$DIST"
