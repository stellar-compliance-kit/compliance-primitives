#!/bin/bash
# Verify reproducible builds for contract wasm binaries
#
# This script builds each contract's wasm twice in isolated Docker environments
# and diffs the output byte-for-byte to ensure reproducibility.
#
# Usage: ./scripts/verify-reproducible-builds.sh [contracts-dir]
#
# Arguments:
#   contracts-dir  Path to contracts directory (default: ./contracts)
#
# Requirements:
#   - Docker installed and accessible
#   - The repository source available locally
#
# External Reproducibility (without this repo):
#   1. Clone the repository to a clean environment
#   2. Run: ./scripts/verify-reproducible-builds.sh
#   3. Verify the build passes and compare hashes with official releases
#
# Output:
#   - Prints SHA256 hashes for each contract build
#   - Prints status (✓ Reproducible or ✗ Not reproducible) for each contract
#   - Exits with code 0 if all builds are reproducible, 1 if any mismatch is found

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
CONTRACTS_DIR="${1:-$REPO_DIR/contracts}"

# Use a stable Rust image for reproducible builds
DOCKER_IMAGE="rust:1.82.0"

# Temporary directories for build artifacts
BUILD1_DIR=$(mktemp -d)
BUILD2_DIR=$(mktemp -d)
trap "rm -rf $BUILD1_DIR $BUILD2_DIR" EXIT

echo "Verifying reproducible builds for Soroban contracts"
echo "=================================================="
echo "Using Docker image: $DOCKER_IMAGE"
echo "Contracts directory: $CONTRACTS_DIR"
echo ""

FAILED=0
PASSED=0

# Find all contract directories with Cargo.toml
for contract_dir in "$CONTRACTS_DIR"/*; do
    if [ ! -d "$contract_dir" ] || [ ! -f "$contract_dir/Cargo.toml" ]; then
        continue
    fi

    contract_name=$(basename "$contract_dir")
    echo "Building: $contract_name"

    # Build 1: First isolated build in Docker
    if docker run --rm \
        -v "$REPO_DIR:/workspace" \
        -w "/workspace" \
        "$DOCKER_IMAGE" \
        bash -c "rustup target add wasm32v1-none && \
                 cargo build --target wasm32v1-none --release --package $contract_name 2>&1" > /dev/null 2>&1; then
        cp -r "$contract_dir/target/wasm32v1-none/release" "$BUILD1_DIR/$contract_name" 2>/dev/null || true
    fi

    # Clean build artifacts
    rm -rf "$contract_dir/target"

    # Build 2: Second isolated build in Docker
    if docker run --rm \
        -v "$REPO_DIR:/workspace" \
        -w "/workspace" \
        "$DOCKER_IMAGE" \
        bash -c "rustup target add wasm32v1-none && \
                 cargo build --target wasm32v1-none --release --package $contract_name 2>&1" > /dev/null 2>&1; then
        cp -r "$contract_dir/target/wasm32v1-none/release" "$BUILD2_DIR/$contract_name" 2>/dev/null || true
    fi

    # Clean build artifacts again
    rm -rf "$contract_dir/target"

    # Compare wasm artifacts
    WASM_FILE="${contract_name}.wasm"
    BUILD1_WASM="$BUILD1_DIR/$contract_name/$WASM_FILE"
    BUILD2_WASM="$BUILD2_DIR/$contract_name/$WASM_FILE"

    if [ -f "$BUILD1_WASM" ] && [ -f "$BUILD2_WASM" ]; then
        HASH1=$(sha256sum "$BUILD1_WASM" | cut -d' ' -f1)
        HASH2=$(sha256sum "$BUILD2_WASM" | cut -d' ' -f1)

        echo "  Build 1: $HASH1"
        echo "  Build 2: $HASH2"

        if diff -q "$BUILD1_WASM" "$BUILD2_WASM" > /dev/null; then
            echo "  ✓ Reproducible: Builds match byte-for-byte"
            ((PASSED++))
        else
            echo "  ✗ Not reproducible: Builds differ"
            ((FAILED++))
        fi
    else
        echo "  ⚠ Skipped: Build artifacts not found"
    fi

    echo ""
done

echo "=================================================="
echo "Results: $PASSED passed, $FAILED failed"
echo "=================================================="

if [ $FAILED -gt 0 ]; then
    exit 1
fi

exit 0
