## Summary

This PR implements two features:

1. **Add upgradeability pattern to jurisdiction-flag and allowlist-token** — adds Soroban-native contract upgrade support (`update_current_contract_wasm` host function) gated behind admin/issuer auth to both contracts. jurisdiction-flag serves as the pilot (#27); allowlist-token follows the same design (#113).

2. **Threat model document** — a comprehensive `docs/THREAT_MODEL.md` covering griefing, front-running, and admin-key-compromise scenarios for all three contracts, with severity/likelihood ratings and cross-references to existing mitigations (#112).

---

## Changes

### Contracts

#### `contracts/jurisdiction-flag/src/lib.rs`
- Added `upgrade(env, issuer, new_wasm_hash) -> Result<(), Error>` — gated behind `require_issuer`, uses `env.deployer().update_current_contract_wasm` to swap the contract WASM behind the same contract ID. All existing storage (issuer address, jurisdiction flags) is preserved.

#### `contracts/jurisdiction-flag/src/test.rs`
- Added `test_upgrade_by_issuer_preserves_storage` — uploads the contract's own compiled WASM, upgrades the running contract, and verifies jurisdiction flags survive and the contract still functions.
- Added `test_upgrade_rejects_non_issuer` — confirms a non-issuer address gets `NotAuthorized` when calling `upgrade`.
- Removed inline `V2JurisdictionFlag` test double (replaced by uploading the compiled contract WASM directly).

#### `contracts/allowlist-token/src/lib.rs`
- Added `upgrade(env, admin, new_wasm_hash) -> Result<(), Error>` — same design as jurisdiction-flag, gated behind `require_admin`. References the jurisdiction-flag security writeup. Notes that the wrapped token address (`DataKey::Token`) is instance storage and survives upgrades without special handling.

#### `contracts/allowlist-token/src/test.rs`
- Added `test_upgrade_by_admin_preserves_storage` — verifies allowlist entries, admin, and token address survive an upgrade; confirms the contract still functions afterward.
- Added `test_upgrade_rejects_non_admin` — confirms a non-admin gets `NotAuthorized`.
- Removed inline `V2AllowlistToken` test double (replaced by uploading the compiled contract WASM directly).
- Removed unused `Bytes` import.

### Documentation

#### `docs/THREAT_MODEL.md`
New file covering three threat categories for each contract:

| Contract | Griefing | Front-running | Admin-key-compromise |
|----------|----------|---------------|---------------------|
| allowlist-token | Low severity (caller-pays fees; no public writes) | Low-medium (one-ledger window) | High-Critical (upgrade path, key compromise) |
| denylist-gate | Low severity (caller-pays; no public writes) | Medium (one-ledger window for denylist adds) | High (full denylist control) |
| jurisdiction-flag | Low severity (caller-pays; issuer-only writes) | Low (one-ledger window for reads) | High-Critical (jurisdiction + upgrade) |

Each scenario is rated for severity/likelihood and cross-referenced to existing mitigation tests, documented invariants, or pending issues (#74/#75/#76, #84/#85).

---

## Testing

All 30 tests pass across the workspace:
- 12 allowlist-token tests (including 2 new upgrade tests)
- 6 denylist-gate tests
- 2 denylist-gate-consumer tests
- 10 jurisdiction-flag tests (including 2 new upgrade tests)

Clippy passes with zero warnings (`cargo clippy --workspace --all-targets -- -D warnings`).

---

## Upgrade design notes

Both contracts follow the same Soroban-native upgrade pattern:

1. **Auth**: `upgrade()` requires the admin/issuer key (same `require_admin`/`require_issuer` pattern used by all state-mutating functions).
2. **Mechanism**: `env.deployer().update_current_contract_wasm(new_wasm_hash)` — a Soroban host function that atomically replaces the contract code behind the same contract ID.
3. **Storage**: All instances storage (admin/issuer, token address) and persistent storage (allowlist entries, jurisdiction flags) survive the upgrade. The contract ID does not change.
4. **Security**: There is no timelock or multi-sig requirement on `upgrade()`. A compromised admin/issuer key can replace the contract code immediately. This is documented in the threat model as a critical-severity scenario with pending mitigation (timelock/multi-sig).

---

closes #112
closes #113
