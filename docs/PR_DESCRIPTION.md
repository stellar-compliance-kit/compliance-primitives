## Summary

This PR implements two features:

1. **Add upgradeability pattern to denylist-gate** — extends the Soroban-native contract upgrade support to the last contract in the workspace, following the same pattern proven in jurisdiction-flag (#27) and allowlist-token (#113). All three contracts now support `upgrade()` gated behind admin auth (#114).

2. **Shared state-migration CLI script** — a `scripts/migrate-state.sh` script that provides the plumbing to back up contract state, upgrade the WASM, and restore state into the upgraded contract. Works with all three contract types and accepts a pluggable migration hook for data transformations (#115).

---

## Changes

### Contracts

#### `contracts/denylist-gate/src/lib.rs`
- Added `upgrade(env, admin, new_wasm_hash) -> Result<(), Error>` — gated behind `require_admin`, uses `env.deployer().update_current_contract_wasm` to swap the contract WASM behind the same contract ID. Denylist entries stored under `DataKey::Denied(Address)` are persistent storage and survive the upgrade. References the security-model writeup from jurisdiction-flag (#27).

#### `contracts/denylist-gate/src/test.rs`
- Added `test_upgrade_by_admin_preserves_storage` — uploads the contract's own compiled WASM, upgrades, and verifies denylist entries survive and the contract still functions.
- Added `test_upgrade_rejects_non_admin` — confirms a non-admin gets `NotAuthorized` when calling `upgrade`.

### Scripts

#### `scripts/migrate-state.sh` (new)
A shared CLI script providing end-to-end state migration plumbing:

| Command | Description |
|---------|-------------|
| `backup` | Reads state from a deployed contract via its view functions (one address per line on stdin) and outputs a portable backup format |
| `restore` | Writes state from a backup file back into a contract via admin-authorized calls |
| `upgrade` | Uploads a new WASM blob and invokes the contract's `upgrade()` function |
| `migrate` | Runs all three steps (backup → transform → upgrade → restore) in sequence |

**Pluggable transformation**: set `MIGRATE_HOOK` to a script path that transforms the backup data before restore — allowing migration-specific logic (e.g., re-keying `DataKey` variants, changing value formats) without modifying the core plumbing.

**Per-contract support**: handles all three contract types with their different data shapes:
- `allowlist-token` — reads via `is_allowed`, writes via `add_to_allowlist`
- `denylist-gate` — reads via `check`, writes via `add_to_denylist`
- `jurisdiction-flag` — reads via `get_jurisdiction`, writes via `set_jurisdiction`

See the script's header documentation for usage examples and the `MIGRATE_HOOK` interface.

---

## Testing

All 32 tests pass across the workspace:
- 12 allowlist-token tests
- 8 denylist-gate tests (including 2 new upgrade tests)
- 2 denylist-gate-consumer tests
- 10 jurisdiction-flag tests

Clippy passes with zero warnings (`cargo clippy --workspace --all-targets -- -D warnings`).

---

## Upgrade design notes

All three contracts now follow the same Soroban-native upgrade pattern:

1. **Auth**: `upgrade()` requires the admin/issuer key (same `require_admin`/`require_issuer` pattern used by all state-mutating functions).
2. **Mechanism**: `env.deployer().update_current_contract_wasm(new_wasm_hash)` — a Soroban host function that atomically replaces the contract code behind the same contract ID.
3. **Storage**: All instance storage (admin/issuer, token address) and persistent storage (allowlist entries, denylist entries, jurisdiction flags) survive the upgrade. The contract ID does not change.
4. **Security**: There is no timelock or multi-sig requirement on `upgrade()`. A compromised admin/issuer key can replace the contract code immediately.

---

closes #114
closes #115
