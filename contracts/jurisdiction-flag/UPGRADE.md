# Upgrade Design Notes

Both contracts follow the same Soroban-native upgrade pattern:

1. **Auth**: `upgrade()` requires the admin/issuer key (same `require_admin`/`require_issuer` pattern used by all state-mutating functions).
2. **Mechanism**: `env.deployer().update_current_contract_wasm(new_wasm_hash)` — a Soroban host function that atomically replaces the contract code behind the same contract ID.
3. **Storage**: All instances storage (admin/issuer, token address) and persistent storage (allowlist entries, jurisdiction flags) survive the upgrade. The contract ID does not change.
4. **Security**: There is no timelock or multi-sig requirement on `upgrade()`. A compromised admin/issuer key can replace the contract code immediately. This is documented in the threat model as a critical-severity scenario with pending mitigation (timelock/multi-sig).
