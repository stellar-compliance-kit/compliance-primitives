#!/usr/bin/env bash
# Migrate contract state across an upgrade.
#
# This script provides the plumbing to:
#   1. Read existing state from a deployed contract (backup)
#   2. Upgrade the contract WASM
#   3. Write the state back into the upgraded contract (restore)
#
# Migration-specific logic is supplied via per-contract-type hooks below,
# so this same script works for allowlist-token, denylist-gate, and
# jurisdiction-flag with different data shapes.
#
# Usage:
#   scripts/migrate-state.sh backup   <contract-type> <contract-address> [network] [source]
#   scripts/migrate-state.sh restore  <contract-type> <contract-address> <backup-file> [network] [source]
#   scripts/migrate-state.sh upgrade  <contract-type> <contract-address> <new-wasm-path> [network] [source]
#   scripts/migrate-state.sh migrate <contract-type> <contract-address> <new-wasm-path> [network] [source]
#
# Contract types: allowlist-token, denylist-gate, jurisdiction-flag
#
# Environment:
#   STELLAR_SOURCE   — identity used for admin-authenticated calls
#                      (default: "default")
#   MIGRATE_HOOK     — path to an optional hook script that transforms
#                      the backup data during a `migrate` run. If set,
#                      the hook is called as:
#                        $MIGRATE_HOOK <tmp-backup> <tmp-transformed>
#                      and the transformed file is used for restore.
#
# Examples:
#   # Backup all allowlist state for known addresses
#   scripts/migrate-state.sh backup \
#     allowlist-token \
#     CAAAA... \
#     testnet \
#     issuer-admin
#
#   # Upgrade the contract and restore state
#   scripts/migrate-state.sh migrate \
#     jurisdiction-flag \
#     CBBBB... \
#     target/wasm32v1-none/release/jurisdiction_flag.wasm \
#     testnet \
#     issuer-admin
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ---------------------------------------------------------------------------
# Per-contract-type hooks
#
# Each hook receives:
#   stdin  — one line per storage entry (format specific to the contract)
#   stdout — one line per storage entry (possibly transformed)
#
# The default hook (identity) is used when MIGRATE_HOOK is unset.
# ---------------------------------------------------------------------------

# Backup hook: reads all known state keys via contract view functions.
# Input (stdin): one address per line (the "known addresses" file).
# Output (stdout): one line per entry as "<address> <value>".
run_backup() {
    local contract_type="$1"
    local contract_address="$2"
    local network="$3"
    local identity="$4"
    shift 4
    # Remaining args are per-contract: for denylist-gate the backup is
    # implicit (only denied addresses), for allowlist-token we need an
    # addresses file, for jurisdiction-flag we need addresses file.

    case "$contract_type" in
        allowlist-token)
            # Reads: user provides a list of addresses to check via stdin.
            # Output format: "<address> 1" for allowlisted, silent for others.
            while IFS= read -r addr; do
                result=$(stellar contract invoke \
                    --id "$contract_address" \
                    --network "$network" \
                    --source "$identity" \
                    -- is_allowed \
                    --address "$addr" 2>/dev/null)
                if [ "$result" = "true" ]; then
                    echo "$addr 1"
                fi
            done
            ;;
        denylist-gate)
            # Same pattern: stdin provides addresses to check.
            # Output: "<address> 1" for denied addresses.
            while IFS= read -r addr; do
                result=$(stellar contract invoke \
                    --id "$contract_address" \
                    --network "$network" \
                    --source "$identity" \
                    -- check \
                    --address "$addr" 2>/dev/null)
                if [ "$result" = "false" ]; then
                    echo "$addr 1"
                fi
            done
            ;;
        jurisdiction-flag)
            # Reads: user provides addresses. Output: "<address> <code>"
            while IFS= read -r addr; do
                result=$(stellar contract invoke \
                    --id "$contract_address" \
                    --network "$network" \
                    --source "$identity" \
                    -- get_jurisdiction \
                    --address "$addr" 2>/dev/null)
                # result is like: Some("US") or: None
                if echo "$result" | grep -q 'Some('; then
                    code=$(echo "$result" | sed 's/Some("\(.*\)")/\1/')
                    echo "$addr $code"
                fi
            done
            ;;
        *)
            echo "error: unknown contract type '$contract_type'" >&2
            exit 1
            ;;
    esac
}

# Restore hook: writes state entries back into the upgraded contract.
# Input (stdin): one line per entry as "<address> <value>" (same format as backup output).
run_restore() {
    local contract_type="$1"
    local contract_address="$2"
    local network="$3"
    local identity="$4"

    case "$contract_type" in
        allowlist-token)
            while IFS=' ' read -r addr _value; do
                stellar contract invoke \
                    --id "$contract_address" \
                    --network "$network" \
                    --source "$identity" \
                    -- add_to_allowlist \
                    --admin "$identity" \
                    --address "$addr" >/dev/null
                echo "  restored allowlist entry: $addr"
            done
            ;;
        denylist-gate)
            while IFS=' ' read -r addr _value; do
                stellar contract invoke \
                    --id "$contract_address" \
                    --network "$network" \
                    --source "$identity" \
                    -- add_to_denylist \
                    --admin "$identity" \
                    --address "$addr" >/dev/null
                echo "  restored denylist entry: $addr"
            done
            ;;
        jurisdiction-flag)
            while IFS=' ' read -r addr code; do
                stellar contract invoke \
                    --id "$contract_address" \
                    --network "$network" \
                    --source "$identity" \
                    -- set_jurisdiction \
                    --issuer "$identity" \
                    --address "$addr" \
                    --code "$code" >/dev/null
                echo "  restored jurisdiction: $addr -> $code"
            done
            ;;
        *)
            echo "error: unknown contract type '$contract_type'" >&2
            exit 1
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Core operations
# ---------------------------------------------------------------------------

usage() {
    cat >&2 <<EOF
Usage:
  $0 backup   <contract-type> <contract-address> [network] [source]
  $0 restore  <contract-type> <contract-address> <backup-file> [network] [source]
  $0 upgrade  <contract-type> <contract-address> <new-wasm-path> [network] [source]
  $0 migrate  <contract-type> <contract-address> <new-wasm-path> [network] [source]

Read addresses from stdin (one per line) for backup.
EOF
    exit 1
}

cmd_backup() {
    local contract_type="$1"
    local contract_address="$2"
    local network="${3:-testnet}"
    local identity="${4:-${STELLAR_SOURCE:-default}}"

    echo "==> Backing up state from ${contract_type} at ${contract_address} (${network})" >&2
    run_backup "$contract_type" "$contract_address" "$network" "$identity"
    echo "==> Backup complete" >&2
}

cmd_restore() {
    local contract_type="$1"
    local contract_address="$2"
    local backup_file="$3"
    local network="${4:-testnet}"
    local identity="${5:-${STELLAR_SOURCE:-default}}"

    if [ ! -f "$backup_file" ]; then
        echo "error: backup file not found: $backup_file" >&2
        exit 1
    fi

    echo "==> Restoring state to ${contract_type} at ${contract_address} (${network})" >&2
    run_restore "$contract_type" "$contract_address" "$network" "$identity" < "$backup_file"
    echo "==> Restore complete" >&2
}

cmd_upgrade() {
    local contract_type="$1"
    local contract_address="$2"
    local new_wasm_path="$3"
    local network="${4:-testnet}"
    local identity="${5:-${STELLAR_SOURCE:-default}}"

    if [ ! -f "$new_wasm_path" ]; then
        echo "error: wasm file not found: $new_wasm_path" >&2
        exit 1
    fi

    # Upload the new WASM and get its hash
    echo "==> Uploading new WASM for ${contract_type}..." >&2
    wasm_hash=$(stellar contract upload \
        --wasm "$new_wasm_path" \
        --source "$identity" \
        --network "$network" |
        tr -d '[:space:]')

    echo "  wasm hash: ${wasm_hash}" >&2

    # Call upgrade with the admin/issuer identity
    case "$contract_type" in
        allowlist-token | denylist-gate)
            echo "==> Upgrading ${contract_type} (admin auth)..." >&2
            stellar contract invoke \
                --id "$contract_address" \
                --network "$network" \
                --source "$identity" \
                -- upgrade \
                --admin "$identity" \
                --new_wasm_hash "$wasm_hash" >/dev/null
            ;;
        jurisdiction-flag)
            echo "==> Upgrading ${contract_type} (issuer auth)..." >&2
            stellar contract invoke \
                --id "$contract_address" \
                --network "$network" \
                --source "$identity" \
                -- upgrade \
                --issuer "$identity" \
                --new_wasm_hash "$wasm_hash" >/dev/null
            ;;
    esac
    echo "==> Upgrade complete" >&2
}

cmd_migrate() {
    local contract_type="$1"
    local contract_address="$2"
    local new_wasm_path="$3"
    local network="${4:-testnet}"
    local identity="${5:-${STELLAR_SOURCE:-default}}"

    local tmp_backup
    tmp_backup=$(mktemp /tmp/migrate-backup-XXXXX)
    local tmp_restore
    tmp_restore=$(mktemp /tmp/migrate-restore-XXXXX)
    trap 'rm -f "$tmp_backup" "$tmp_restore"' EXIT

    # Step 1: Backup
    echo ">>> Step 1: Backup" >&2
    # Read addresses from stdin (or skip if none provided)
    if [ ! -t 0 ]; then
        run_backup "$contract_type" "$contract_address" "$network" "$identity" > "$tmp_backup"
        entry_count=$(wc -l < "$tmp_backup")
        echo "  backed up ${entry_count} entries" >&2
    else
        echo "  no addresses on stdin; backup file will be empty" >&2
        touch "$tmp_backup"
    fi

    # Step 2: Apply transformation hook if provided
    if [ -n "${MIGRATE_HOOK:-}" ]; then
        echo ">>> Step 2: Applying migration hook (${MIGRATE_HOOK})" >&2
        "$MIGRATE_HOOK" "$tmp_backup" "$tmp_restore"
    else
        echo ">>> Step 2: No migration hook — using backup as-is" >&2
        cp "$tmp_backup" "$tmp_restore"
    fi

    # Step 3: Upgrade
    echo ">>> Step 3: Upgrade" >&2
    cmd_upgrade "$contract_type" "$contract_address" "$new_wasm_path" "$network" "$identity"

    # Step 4: Restore
    echo ">>> Step 4: Restore" >&2
    entry_count=$(wc -l < "$tmp_restore")
    if [ "$entry_count" -gt 0 ]; then
        run_restore "$contract_type" "$contract_address" "$network" "$identity" < "$tmp_restore"
    fi
    echo ">>> Migration complete (${entry_count} entries restored)" >&2
}

# ---------------------------------------------------------------------------
# Main dispatch
# ---------------------------------------------------------------------------

if [ "$#" -lt 3 ]; then
    usage
fi

cmd="$1"
contract_type="$2"
contract_address="$3"
shift 3

case "$cmd" in
    backup)
        cmd_backup "$contract_type" "$contract_address" "$@"
        ;;
    restore)
        if [ "$#" -lt 1 ]; then usage; fi
        cmd_restore "$contract_type" "$contract_address" "$@"
        ;;
    upgrade)
        if [ "$#" -lt 1 ]; then usage; fi
        cmd_upgrade "$contract_type" "$contract_address" "$@"
        ;;
    migrate)
        if [ "$#" -lt 1 ]; then usage; fi
        cmd_migrate "$contract_type" "$contract_address" "$@"
        ;;
    *)
        usage
        ;;
esac
