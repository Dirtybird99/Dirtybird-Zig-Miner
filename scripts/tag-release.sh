#!/usr/bin/env bash
# Sign and push the release tag for the version currently on origin/main.
#
# The Release workflow publishes only from a tag that is annotated, points at the
# commit it builds, and carries a signature GitHub reports as verified. That last
# one is why this step is a local script and not a workflow: the key belongs to a
# person. Everything around it -- working out the version, bumping the two files,
# opening the PR -- is handled by .github/workflows/release-prep.yml.
#
#   bash scripts/tag-release.sh            # tag whatever origin/main says
#   DRY_RUN=1 bash scripts/tag-release.sh  # print the plan, touch nothing
set -euo pipefail

cd "$(dirname "$0")/.."
DRY_RUN="${DRY_RUN:-0}"

git fetch origin --tags --quiet

ZON="$(git show origin/main:build.zig.zon | sed -n 's/.*\.version = "\([^"]*\)".*/\1/p')"
MANIFEST="$(git show origin/main:config/h-manifest.conf | sed -n 's/^CUSTOM_VERSION=//p')"
TARGET="$(git rev-parse origin/main)"
V="v$ZON"

if [ -z "$ZON" ]; then
  echo "error: could not read .version from build.zig.zon on origin/main" >&2
  exit 1
fi

# Same gate scripts/release.sh applies, checked here so a mismatch costs a second
# rather than a failed release build.
if [ "$ZON" != "$MANIFEST" ]; then
  echo "error: build.zig.zon ($ZON) and the Hive manifest ($MANIFEST) disagree." >&2
  echo "       Merge the release-prep bump PR first." >&2
  exit 1
fi

if git rev-parse "$V" >/dev/null 2>&1 || git ls-remote --exit-code --tags origin "$V" >/dev/null 2>&1; then
  echo "error: $V already exists. Published releases are never overwritten;" >&2
  echo "       bump to the next version instead." >&2
  exit 1
fi

# An unsigned tag builds nothing -- the workflow rejects it -- so fail here, where
# the fix is obvious, rather than 40 minutes into a release build.
if [ "$(git config --get tag.gpgSign || echo false)" != "true" ] && [ -z "$(git config --get user.signingkey || true)" ]; then
  echo "error: no signing key configured (tag.gpgSign / user.signingkey)." >&2
  echo "       The Release workflow requires verification.verified == true." >&2
  exit 1
fi

echo "  version : $ZON  (build.zig.zon and Hive manifest agree)"
echo "  tag     : $V"
echo "  target  : $(git log --format='%h %s' -1 "$TARGET")"

if [ "$DRY_RUN" = "1" ]; then
  echo "DRY_RUN=1 -- stopping before tagging."
  exit 0
fi

git tag -a "$V" "$TARGET" -m "Dirtybird Zig Miner $V"

if ! git cat-file -p "$V" | grep -qE 'BEGIN (SSH|PGP) SIGNATURE'; then
  git tag -d "$V" >/dev/null
  echo "error: the tag came out unsigned; the workflow would reject it. Tag removed." >&2
  exit 1
fi

git push origin "$V"
echo "Pushed $V. The Release workflow builds and publishes from here."
