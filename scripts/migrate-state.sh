#!/usr/bin/env bash
#
# migrate-state.sh — shared two-step upgrade/migration CLI for the compliance
# primitives contracts (allowlist-token, denylist-gate, jurisdiction-flag).
#
# Issue #115. Once the upgradeability pattern (issues #113 / #114, plus the
# already-present jurisdiction-flag::upgrade) lands on all three contracts, this
# script drives a coordinated migration:
#
#   1. For each contract, call `propose_upgrade(new_wasm, delay_ledgers)`.
#      The contract stores a PendingUpgrade that only becomes committable after
#      `delay_ledgers` ledgers (the review window).
#   2. Wait out the review window (or let an operator run step 2 later).
#   3. For each contract, call `commit_upgrade()` to install the new Wasm.
#
# This keeps the three contracts on a single, auditable migration cadence and
# never installs Wasm without the built-in delay the contracts enforce.
#
# Usage:
#   ./scripts/migrate-state.sh propose <network> <identity> <wasm_hash> <delay_ledgers> \
#       <allowlist_id> <denylist_id> <jurisdiction_id>
#   ./scripts/migrate-state.sh commit  <network> <identity> \
#       <allowlist_id> <denylist_id> <jurisdiction_id>
#
# Requires the `soroban` CLI on PATH.

set -euo pipefail

cmd="${1:-}"
network="${2:-}"
identity="${3:-}"

propose() {
  local wasm_hash="$1"; shift
  local delay="$1"; shift
  local contracts=("$@")  # allowlist, denylist, jurisdiction

  for id in "${contracts[@]}"; do
    echo "==> [propose] $id"
    soroban contract invoke \
      --network "$network" \
      --id "$id" \
      -- \
      propose_upgrade \
      --admin "$identity" \
      --new_wasm "$wasm_hash" \
      --delay_ledgers "$delay"
  done
  echo
  echo "Proposed on all three contracts. Wait >= $delay ledgers, then run:"
  echo "  $0 commit $network $identity ${contracts[*]}"
}

commit() {
  local contracts=("$@")
  for id in "${contracts[@]}"; do
    echo "==> [commit] $id"
    soroban contract invoke \
      --network "$network" \
      --id "$id" \
      -- \
      commit_upgrade \
      --admin "$identity"
  done
  echo
  echo "Migration committed on all three contracts."
}

case "$cmd" in
  propose)
    shift 3
    wasm_hash="${1:-}"; delay="${2:-}"; shift 2
    [ -n "$wasm_hash" ] && [ -n "$delay" ] && [ "$#" -eq 3 ] || {
      echo "usage: $0 propose <network> <identity> <wasm_hash> <delay_ledgers> <allowlist_id> <denylist_id> <jurisdiction_id>" >&2
      exit 2
    }
    propose "$wasm_hash" "$delay" "$@"
    ;;
  commit)
    shift 3
    [ "$#" -eq 3 ] || {
      echo "usage: $0 commit <network> <identity> <allowlist_id> <denylist_id> <jurisdiction_id>" >&2
      exit 2
    }
    commit "$@"
    ;;
  *)
    echo "usage: $0 <propose|commit> ..." >&2
    exit 2
    ;;
esac
