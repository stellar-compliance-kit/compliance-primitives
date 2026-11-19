# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **allowlist-token**: `add_to_allowlist_until(admin, address, valid_until)`
  allowlists an address through ledger `valid_until` (inclusive). Expiry is
  enforced by both `is_allowed` and `transfer` (#756).
- **allowlist-token**: allowlist entries record `added_by` and
  `added_at_ledger`, returned by `get_allowlist_entry` as the new
  `AllowlistEntryInfo`. Entries approved before this change report `None`
  (#757).
- **compliance-ttl**: new `crates/ttl-policy` crate holding the shared
  storage TTL constants (#754).

### Changed

- **allowlist-token**: `get_allowlist_entry` returns `AllowlistEntryInfo`
  instead of `AllowlistEntry`. The `expiration_ledger` field is unchanged
  (#757).
- Contracts that extended TTLs with duplicated local constants now use the
  shared `compliance-ttl` values; public constant names are unchanged (#754).
- **denylist-gate**: `add_to_denylist` uses the shared denylist TTL policy
  instead of constants local to the function (#754).

- **allowlist-token** (breaking): `add_to_allowlist_delegated` takes a new
  `valid_until_ledger: u32` argument, and the signed payload is now
  `allowlist-delegated-v2:<target>:add_to_allowlist:<nonce>:<expiry>:<valid_until_ledger>`.
  Calls submitted after `valid_until_ledger` are rejected with
  `ExpiredSignature`, so a leaked unsubmitted signature can no longer be
  used indefinitely. Signers must move to the v2 payload; v1 signatures are
  no longer accepted (#765).

### Fixed

- **allowlist-token**: `remove_from_allowlist` and
  `remove_multiple_from_allowlist` skip absent addresses without writing or
  emitting `AllowRemove`, so event streams only record real removals (#755).
- **allowlist-token**: `is_allowed_and_extend_ttl` did not compile, and
  transfers ignored allowlist expiry. Transfers now enforce expiry (#756).
- **allowlist-token**: `pause` now blocks `add_to_allowlist`,
  `add_to_allowlist_delegated`, and `remove_from_allowlist`, matching the
  doc comment "Pause all mutating operations". Previously only `transfer`
  checked the pause flag, so a compromised key could keep mutating the
  allowlist while the contract appeared paused. Admin rotation
  (`propose_admin` / `accept_admin` / `transfer_admin`) and `unpause`
  remain available while paused so an operator can always recover
  (fixes #583, matching the behaviour of `denylist-gate`).

### Added

- **allowlist-token**: `get_delegated_admin_key() -> Option<BytesN<32>>`
  view returning the ed25519 key set by `set_delegated_admin_key` (#764).
- **allowlist-token**: Admin-only `clawback(admin, from, amount)` forwarded
  to the underlying SEP-41 token's `clawback`, emitting a `Clawback` event.
  `set_clawback_requires_freeze` / `get_clawback_requires_freeze` optionally
  require the target to be frozen first (`ClawbackRequiresFreeze`) (#763).
- **allowlist-token**: `freeze(caller, address)` / `unfreeze(caller, address)`
  callable by the admin or compliance officer, plus an `is_frozen` view. A
  frozen address cannot send or receive (`transfer` returns
  `AddressFrozen`) but keeps its allowlist entry. Emits `AddressFrozen` /
  `AddressUnfrozen` events (#762).
- **circuit-breaker**: Guardian set for faster incident response. Admin-managed
  `add_guardian` / `remove_guardian` / `is_guardian`; guardians can call
  `freeze`, while `unfreeze` remains admin-only. `Frozen` event topic renamed
  from `admin` to `caller`.
- **compliance-aggregator**: Admin-gated `upgrade(admin, new_wasm_hash)`
  entrypoint with an `UpgradePerformed` event, a migration test that
  deploys, writes state, upgrades, and verifies state is intact and callable,
  and module-level upgrade documentation (#195)
- **compliance-aggregator**: `check_address` budget-regression benchmark
  with a `[compliance-aggregator.check_address]` entry in
  `budget-baselines.toml` (#196)
- **multisig-admin**: Expanded module-level docs covering purpose, callers,
  and composition with the other contracts in the repo (#197)
- **multisig-admin**: Instance TTL is extended on every write path
  (`INSTANCE_TTL_THRESHOLD` / `INSTANCE_TTL_EXTEND_TO`), with tests that
  advance the ledger past the original TTL (#198)
- **multisig-admin**: `upgrade(new_wasm_hash)` entrypoint, gated by the M-of-N
  threshold, with a migration test confirming state survives the upgrade
- **multisig-admin**: `__check_auth` resource-fee benchmark and
  `[multisig-admin.__check_auth]` baseline in `budget-baselines.toml`
- **policy-engine**: Instance-storage TTL extension on every write path
  (threshold ~7 days, extend-to ~90 days)

### Changed

- **policy-engine**: Expanded module-level docs covering purpose, callers,
  composition with the other contracts, and the TTL policy

## [0.1.0] — 2026-08-27

### Added

- **multisig-admin**: Proposal workflow with ledger-sequence-based expiry
  - `propose()` — Create a new governance proposal with an expiry ledger
  - `approve()` — Approve a proposal (restricted to registered signers)
  - `execute()` — Execute a proposal once threshold is met
  - `get_proposal()` — Query proposal details and current approvals
  - `ExpiredProposal` error variant — Rejects approval/execution after expiry

- **multisig-audit-trail**: New example demonstrating governance audit trail
  - Shows how to integrate `multisig-admin` proposals with `audit-log`
  - Pattern for recording proposal creation, approvals, execution, and expiry
  - Test suite covering successful proposal flow, expiry handling, and approval history

- **CI**: Changelog version sync check
  - `scripts/check-changelog.sh` enforces CHANGELOG.md updates alongside version bumps
  - New GitHub Actions job `changelog-version-sync` validates in CI

- **Documentation**: QUICKSTART.md
  - Step-by-step guide from clone → build → test → example → testnet → web playground
  - Linked prominently from README.md
  - Includes troubleshooting and key file reference

### Changed

- README.md: Added prominent link to QUICKSTART.md for new contributors
- CONTRIBUTING.md: Documented CHANGELOG.md requirement for version bumps
