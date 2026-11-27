#!/usr/bin/env bash
# scripts/release.sh — Tag the current commit and draft a GitHub release with
# notes extracted from the relevant CHANGELOG.md section.
#
# Usage:
#   ./scripts/release.sh [--dry-run]
#
# Requirements:
#   - The version in Cargo.toml [workspace.package] is the release version.
#   - CHANGELOG.md has an entry matching "## [<version>]".
#   - The GitHub CLI (gh) is installed and authenticated.
#   - A GITHUB_TOKEN env var or gh login is available for `gh release create`.
#
# Exit codes:
#   0 — release tag created (or dry-run completed without errors)
#   1 — missing dependency, version not in changelog, or gh command failed
#
# Examples:
#   ./scripts/release.sh            # tag + draft release
#   ./scripts/release.sh --dry-run  # validate only, no tag/release created

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

DRY_RUN=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    *) echo "error: unknown argument '$arg'" >&2; exit 1 ;;
  esac
done

# ---------------------------------------------------------------------------
# Dependency checks
# ---------------------------------------------------------------------------
for cmd in git gh; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "error: '$cmd' is required but not found in PATH" >&2
    exit 1
  fi
done

# ---------------------------------------------------------------------------
# Resolve the release version from Cargo.toml
# ---------------------------------------------------------------------------
VERSION=$(grep -A 50 '^\[workspace\.package\]' Cargo.toml \
  | grep -E '^version = ' \
  | head -1 \
  | sed 's/version = "\(.*\)"/\1/')

if [ -z "$VERSION" ]; then
  echo "error: could not parse version from Cargo.toml [workspace.package]" >&2
  exit 1
fi

TAG="v${VERSION}"
echo "Release version : $VERSION"
echo "Git tag         : $TAG"

# ---------------------------------------------------------------------------
# Regenerate per-contract changelog sections with git-cliff
# ---------------------------------------------------------------------------
# Each contract keeps its own section in CHANGELOG.md, delimited by markers:
#   <!-- contract:<name>:start -->
#   ...generated content...
#   <!-- contract:<name>:end -->
# The generated content is produced by git-cliff using the per-package
# configuration at contracts/<name>/cliff.toml.
CONTRACTS_DIR="contracts"
CLIFF_BIN="${CLIFF_BIN:-git-cliff}"

if ! command -v "$CLIFF_BIN" &>/dev/null; then
  echo "error: '$CLIFF_BIN' is required to generate per-contract changelogs" >&2
  echo "       Install it with: cargo install git-cliff" >&2
  exit 1
fi

if [ ! -d "$CONTRACTS_DIR" ]; then
  echo "error: contracts directory '$CONTRACTS_DIR' not found" >&2
  exit 1
fi

# Collect contract names (subdirectories containing a cliff.toml).
CONTRACTS=()
for cliff_cfg in "$CONTRACTS_DIR"/*/cliff.toml; do
  [ -e "$cliff_cfg" ] || continue
  CONTRACTS+=("$(basename "$(dirname "$cliff_cfg")")")
done

if [ "${#CONTRACTS[@]}" -eq 0 ]; then
  echo "error: no per-contract cliff.toml files found under '$CONTRACTS_DIR/*/'" >&2
  exit 1
fi

# Regenerate each contract's section in place.
for contract in "${CONTRACTS[@]}"; do
  cliff_cfg="$CONTRACTS_DIR/$contract/cliff.toml"
  start_marker="<!-- contract:${contract}:start -->"
  end_marker="<!-- contract:${contract}:end -->"

  if ! grep -qF "$start_marker" CHANGELOG.md || ! grep -qF "$end_marker" CHANGELOG.md; then
    echo "error: CHANGELOG.md is missing markers for contract '$contract'" >&2
    echo "       Expected: $start_marker ... $end_marker" >&2
    exit 1
  fi

  contract_notes=$("$CLIFF_BIN" \
    --config "$cliff_cfg" \
    --tag-pattern "^${contract}-v[0-9].*" \
    --unreleased \
    --strip header 2>/dev/null || true)

  if [ -z "$contract_notes" ]; then
    contract_notes="_No changes for this contract._"
  fi

  # Replace the content between the markers with the freshly generated notes.
  awk \
    -v start="$start_marker" \
    -v end="$end_marker" \
    -v notes="$contract_notes" \
    'BEGIN{in_block=0}
     $0 == start {print; print notes; in_block=1; next}
     $0 == end   {in_block=0; print; next}
     !in_block   {print}' \
    CHANGELOG.md > CHANGELOG.md.tmp
  mv CHANGELOG.md.tmp CHANGELOG.md

  echo "Regenerated changelog section for contract: $contract"
done

# ---------------------------------------------------------------------------
# Extract the changelog section for this version
# ---------------------------------------------------------------------------
# Looks for a block that starts with "## [<version>]" and ends just before the
# next "## [" heading (or end of file).
CHANGELOG_SECTION=$(awk \
  -v ver="$VERSION" \
  'BEGIN{found=0}
   /^## \[/{
     if(found) exit
     if($0 ~ "\\[" ver "\\]") found=1
     next
   }
   found{print}' \
  CHANGELOG.md)

if [ -z "$CHANGELOG_SECTION" ]; then
  echo "error: no CHANGELOG.md section found for version $VERSION" >&2
  echo "       Expected a heading like:  ## [$VERSION]" >&2
  exit 1
fi

# Fail if any per-contract section is missing from the release notes.
for contract in "${CONTRACTS[@]}"; do
  if ! grep -qF "<!-- contract:${contract}:start -->" <<<"$CHANGELOG_SECTION"; then
    echo "error: release notes for $VERSION are missing the section for contract '$contract'" >&2
    exit 1
  fi
done

echo ""
echo "--- Changelog section ---"
echo "$CHANGELOG_SECTION"
echo "-------------------------"
echo ""

# ---------------------------------------------------------------------------
# Dry-run exit point
# ---------------------------------------------------------------------------
if [ "$DRY_RUN" -eq 1 ]; then
  echo "dry-run: would create tag '$TAG' and draft release with the notes above"
  exit 0
fi

# ---------------------------------------------------------------------------
# Guard: fail if the working tree is dirty
# ---------------------------------------------------------------------------
if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "error: working tree has uncommitted changes — commit or stash before releasing" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Verify contract metadata (contractmeta! version + source) in built WASM
# ---------------------------------------------------------------------------
# Every contract must embed `contractmeta!(key = "version", ...)` and
# `contractmeta!(key = "source", ...)`. We build the workspace to wasm and
# inspect each artifact, failing the release if either key is missing.
echo "Verifying contract metadata in wasm artifacts..."

if ! command -v cargo &>/dev/null; then
  echo "error: 'cargo' is required to verify contract metadata" >&2
  exit 1
fi

WASM_TARGET_DIR="${CARGO_TARGET_DIR:-target}"
WASM_OUT_DIR="${WASM_TARGET_DIR}/wasm32-unknown-unknown/release"

cargo build --release --target wasm32-unknown-unknown --workspace

shopt -s nullglob
WASM_FILES=("$WASM_OUT_DIR"/*.wasm)
shopt -u nullglob

if [ "${#WASM_FILES[@]}" -eq 0 ]; then
  echo "error: no wasm artifacts found in '$WASM_OUT_DIR'" >&2
  exit 1
fi

META_FAILED=0
for wasm in "${WASM_FILES[@]}"; do
  name="$(basename "$wasm")"

  # Dump the contract metadata section. `stellar contract info` prints the
  # embedded meta entries; fall back to a raw string scan of the binary if the
  # CLI is unavailable.
  if command -v stellar &>/dev/null; then
    META_DUMP=$(stellar contract info meta \
      --wasm "$wasm" 2>/dev/null || true)
  else
    META_DUMP=$(strings "$wasm" 2>/dev/null || true)
  fi

  MISSING=""
  if ! grep -q 'version' <<<"$META_DUMP"; then
    MISSING="${MISSING} version"
  fi
  if ! grep -q 'source' <<<"$META_DUMP"; then
    MISSING="${MISSING} source"
  fi

  if [ -n "$MISSING" ]; then
    echo "error: $name is missing contractmeta key(s):$MISSING" >&2
    META_FAILED=1
  else
    echo "  ok: $name has version + source metadata"
  fi
done

if [ "$META_FAILED" -ne 0 ]; then
  echo "error: one or more contracts lack required contractmeta entries" >&2
  echo "       Add contractmeta!(key = \"version\", val = env!(\"CARGO_PKG_VERSION\"))" >&2
  echo "       and contractmeta!(key = \"source\", val = env!(\"CARGO_PKG_REPOSITORY\"))" >&2
  exit 1
fi

echo "Contract metadata verification passed."
echo ""

# ---------------------------------------------------------------------------
# Create the annotated git tag (idempotent if it already exists)
# ---------------------------------------------------------------------------
if git rev-parse "$TAG" &>/dev/null; then
  echo "info: tag '$TAG' already exists — skipping tag creation"
else
  git tag -a "$TAG" -m "Release $VERSION"
  echo "Created git tag: $TAG"
fi

# ---------------------------------------------------------------------------
# Push the tag to origin
# ---------------------------------------------------------------------------
git push origin "$TAG"
echo "Pushed tag '$TAG' to origin"

# ---------------------------------------------------------------------------
# Create a draft GitHub release with the extracted changelog notes
# ---------------------------------------------------------------------------
# Write notes to a temp file so multi-line content passes cleanly to gh.
NOTES_FILE=$(mktemp)
trap 'rm -f "$NOTES_FILE"' EXIT
echo "$CHANGELOG_SECTION" > "$NOTES_FILE"

gh release create "$TAG" \
  --repo "$(gh repo view --json nameWithOwner -q .nameWithOwner)" \
  --title "Release $VERSION" \
  --notes-file "$NOTES_FILE" \
  --draft

echo ""
echo "✓ Draft release '$TAG' created. Review it on GitHub before publishing."
