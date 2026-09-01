#!/usr/bin/env bash
# Build and deploy all nine workspace contracts to Stellar testnet, wiring
# the composable ones together, and print a summary of contract IDs plus a
# sample transaction to try against the result.
#
# Deployment/dependency order:
#   1. No-dependency primitives (any order): allowlist-token, denylist-gate,
#      jurisdiction-flag, audit-log, circuit-breaker, multisig-admin
#   2. Composers that reference the level-1 addresses: compliance-aggregator
#      (denylist-gate + jurisdiction-flag), policy-engine (same two, wired
#      in via add_check after initialize)
#
# `pausable` is the ninth crate in the workspace but is a compile-time-only
# helper library (no `#[contract]` macro, no wasm exports — see
# contracts/pausable/src/lib.rs) — there's nothing to deploy for it, so it's
# not listed below.
#
# `multisig-admin` is deployed and initialized standalone here (signers =
# [issuer], threshold = 1) to demonstrate the pattern without complicating
# this script's single-signer testnet flow. To actually put it in control of
# one of the other primitives, re-initialize that primitive with
# `--admin "$MULTISIG_ID"` instead of the issuer address — see
# contracts/multisig-admin/src/lib.rs's module doc for how `__check_auth`
# picks that up with no changes needed to the primitive itself.
#
# Usage:
#   STELLAR_SOURCE=<your-testnet-identity> ./scripts/deploy-full-stack-testnet.sh
#
# Optional:
#   STELLAR_NETWORK=testnet      (default)
#   ALLOWED_CODES='["US","CA"]'  — JSON array; used by jurisdiction-flag and
#                                  compliance-aggregator/policy-engine wiring
#
# Requires stellar-cli compatible with soroban-sdk 27 (cli ≥ 23 / ideally 27.x).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

SOURCE_IDENTITY="${STELLAR_SOURCE:-default}"
NETWORK="${STELLAR_NETWORK:-testnet}"
ALLOWED_CODES="${ALLOWED_CODES:-[\"US\",\"CA\"]}"

need_wasm() {
  local path="$1"
  if [ ! -f "$path" ]; then
    echo "error: expected build artifact not found at $path" >&2
    exit 1
  fi
}

deploy_one() {
  local label="$1"
  local wasm="$2"
  echo "==> Deploying ${label}..." >&2
  stellar contract deploy \
    --wasm "$wasm" \
    --source "$SOURCE_IDENTITY" \
    --network "$NETWORK"
}

echo "==> Building workspace contracts to wasm..."
stellar contract build

WASM_DIR="target/wasm32v1-none/release"
ALLOWLIST_WASM="$WASM_DIR/allowlist_token.wasm"
GATE_WASM="$WASM_DIR/denylist_gate.wasm"
JURISDICTION_WASM="$WASM_DIR/jurisdiction_flag.wasm"
AUDIT_LOG_WASM="$WASM_DIR/audit_log.wasm"
CIRCUIT_BREAKER_WASM="$WASM_DIR/circuit_breaker.wasm"
MULTISIG_WASM="$WASM_DIR/multisig_admin.wasm"
AGGREGATOR_WASM="$WASM_DIR/compliance_aggregator.wasm"
POLICY_ENGINE_WASM="$WASM_DIR/policy_engine.wasm"

for wasm in "$ALLOWLIST_WASM" "$GATE_WASM" "$JURISDICTION_WASM" "$AUDIT_LOG_WASM" \
  "$CIRCUIT_BREAKER_WASM" "$MULTISIG_WASM" "$AGGREGATOR_WASM" "$POLICY_ENGINE_WASM"; do
  need_wasm "$wasm"
done

ISSUER="$(stellar keys address "$SOURCE_IDENTITY")"

# ---------------------------------------------------------------------------
# Step 1: no-dependency primitives
# ---------------------------------------------------------------------------

ALLOWLIST_ID="$(deploy_one allowlist-token "$ALLOWLIST_WASM")"
GATE_ID="$(deploy_one denylist-gate "$GATE_WASM")"
JURISDICTION_ID="$(deploy_one jurisdiction-flag "$JURISDICTION_WASM")"
AUDIT_LOG_ID="$(deploy_one audit-log "$AUDIT_LOG_WASM")"
CIRCUIT_BREAKER_ID="$(deploy_one circuit-breaker "$CIRCUIT_BREAKER_WASM")"
MULTISIG_ID="$(deploy_one multisig-admin "$MULTISIG_WASM")"

# Placeholder underlying token address for allowlist-token.initialize — this
# script doesn't deploy a real SEP-41 token, and allowlist-token only calls
# is_allowed()-adjacent logic in this demo, so any valid address works. We
# reuse the allowlist contract id itself as a stable placeholder.
UNDERLYING_PLACEHOLDER="$ALLOWLIST_ID"

echo "==> Initializing allowlist-token..."
stellar contract invoke \
  --id "$ALLOWLIST_ID" --source "$SOURCE_IDENTITY" --network "$NETWORK" \
  -- initialize --admin "$ISSUER" --token "$UNDERLYING_PLACEHOLDER"

echo "==> Initializing denylist-gate..."
stellar contract invoke \
  --id "$GATE_ID" --source "$SOURCE_IDENTITY" --network "$NETWORK" \
  -- initialize --admin "$ISSUER"

echo "==> Initializing jurisdiction-flag..."
stellar contract invoke \
  --id "$JURISDICTION_ID" --source "$SOURCE_IDENTITY" --network "$NETWORK" \
  -- initialize --issuer "$ISSUER"

echo "==> Initializing audit-log..."
stellar contract invoke \
  --id "$AUDIT_LOG_ID" --source "$SOURCE_IDENTITY" --network "$NETWORK" \
  -- initialize --admin "$ISSUER"

echo "==> Initializing circuit-breaker..."
stellar contract invoke \
  --id "$CIRCUIT_BREAKER_ID" --source "$SOURCE_IDENTITY" --network "$NETWORK" \
  -- initialize --admin "$ISSUER"

echo "==> Initializing multisig-admin (signers=[issuer], threshold=1)..."
stellar contract invoke \
  --id "$MULTISIG_ID" --source "$SOURCE_IDENTITY" --network "$NETWORK" \
  -- initialize --signers "[\"$ISSUER\"]" --threshold 1

# ---------------------------------------------------------------------------
# Step 2: composers wired to the primitives deployed above
# ---------------------------------------------------------------------------

AGGREGATOR_ID="$(deploy_one compliance-aggregator "$AGGREGATOR_WASM")"
POLICY_ENGINE_ID="$(deploy_one policy-engine "$POLICY_ENGINE_WASM")"

echo "==> Initializing compliance-aggregator, wired to denylist-gate + jurisdiction-flag..."
stellar contract invoke \
  --id "$AGGREGATOR_ID" --source "$SOURCE_IDENTITY" --network "$NETWORK" \
  -- initialize --admin "$ISSUER" --denylist_gate "$GATE_ID" --jurisdiction_flag "$JURISDICTION_ID"

echo "==> Initializing policy-engine (op=All)..."
stellar contract invoke \
  --id "$POLICY_ENGINE_ID" --source "$SOURCE_IDENTITY" --network "$NETWORK" \
  -- initialize --admin "$ISSUER" --op All

echo "==> Registering denylist-gate check on policy-engine..."
stellar contract invoke \
  --id "$POLICY_ENGINE_ID" --source "$SOURCE_IDENTITY" --network "$NETWORK" \
  -- add_check --admin "$ISSUER" --check "{\"Denylist\":{\"contract\":\"$GATE_ID\"}}"

echo "==> Registering jurisdiction-flag check on policy-engine..."
stellar contract invoke \
  --id "$POLICY_ENGINE_ID" --source "$SOURCE_IDENTITY" --network "$NETWORK" \
  -- add_check --admin "$ISSUER" \
  --check "{\"Jurisdiction\":{\"contract\":\"$JURISDICTION_ID\",\"allowed_codes\":$ALLOWED_CODES}}"

# NOTE: policy-engine's CheckKind only covers denylist-gate and
# jurisdiction-flag (see contracts/policy-engine/src/lib.rs) — allowlist-token
# isn't a registerable check kind there, so it's deployed and initialized
# above but not wired into policy-engine or compliance-aggregator, both of
# which only compose the other two primitives today.

cat <<EOF

============================================================
Full-stack testnet deployment ($NETWORK)
============================================================
Issuer / admin:        $ISSUER
allowlist-token:       $ALLOWLIST_ID
denylist-gate:         $GATE_ID
jurisdiction-flag:     $JURISDICTION_ID
audit-log:              $AUDIT_LOG_ID
circuit-breaker:        $CIRCUIT_BREAKER_ID
multisig-admin:         $MULTISIG_ID (signers=[issuer], threshold=1)
compliance-aggregator:  $AGGREGATOR_ID (wired to denylist-gate + jurisdiction-flag)
policy-engine:          $POLICY_ENGINE_ID (op=All, wired to denylist-gate + jurisdiction-flag)
pausable:               not deployed (compile-time helper library only)
allowed_codes:          $ALLOWED_CODES
============================================================

Sample transaction to try — run compliance-aggregator's batched check
against the issuer address (expect denylist to pass, jurisdiction to fail
since the issuer has no jurisdiction code set yet):

  stellar contract invoke \\
    --id $AGGREGATOR_ID --source $SOURCE_IDENTITY --network $NETWORK \\
    -- check_address --address $ISSUER --allowed_jurisdictions '$ALLOWED_CODES'

Set a jurisdiction for the issuer first to see it pass both checks:

  stellar contract invoke \\
    --id $JURISDICTION_ID --source $SOURCE_IDENTITY --network $NETWORK \\
    -- set_jurisdiction --issuer $ISSUER --address $ISSUER --code US

See docs/full-stack-testnet-walkthrough.md for the full walkthrough,
including the policy-engine and audit-log sample calls.
EOF
