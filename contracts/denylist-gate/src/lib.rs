// Copyright (c) 2026 Stellar Compliance Kit contributors
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

//! `denylist-gate` is a `#![no_std]` Soroban contract that maintains a
//! standalone on-chain denylist.
//!
//! **Purpose**: give issuers a shared, independently auditable place to
//! record addresses that must never transact (sanctions hits, fraud, court
//! orders, etc.), decoupled from any single token contract's own storage.
//!
//! **Callers**: an `admin` address manages the denylist through
//! `add_to_denylist`/`remove_from_denylist`/`remove_multiple_from_denylist`. Other contracts — typically a
//! token's `transfer` function — call the read-only `check(address)` via a
//! cross-contract call before moving funds, so the denylist can be updated
//! without redeploying or touching the token contract itself.
//!
//! **Composition**: this contract is meant to be called into, not deployed
//! as a token itself. See `/examples/denylist-gate-consumer` for a worked
//! example of a token contract wiring `check()` into its `transfer` path.
//!
//! # Authorization model
//!
//! The contract starts in single-admin mode: `admin` (set in `initialize`)
//! authorizes every denylist mutation via `require_auth()`.
//!
//! Denylist entry mutations (`add_to_denylist`, `remove_from_denylist`, and
//! `remove_multiple_from_denylist`) also accept the compliance officer, if one
//! is set. Single and batch removal share the same authority check, so an
//! officer never needs admin rights to do a batch what it can do one by one.
//! Officer assignment, audit-log configuration, pause, and signer governance
//! remain admin-only.
//!
//! `initialize_multisig` (admin-only, callable once) additionally installs an
//! M-of-N signer set. From then on the signer set gates denylist mutations:
//!
//! - `add_to_denylist`, `remove_from_denylist` and
//!   `remove_multiple_from_denylist` take the calling `caller` explicitly.
//!   Each call runs `caller.require_auth()` and then requires `caller` to be in
//!   the *current* signer set; any other address is rejected with
//!   `NotAuthorized`. The `Admin` and `ComplianceOfficer` no longer have
//!   unilateral denylist authority once multisig mode is enabled.
//! - A denylist mutation does not take effect on a single signer's say-so.
//!   Each call records one approval from `caller` for that exact action
//!   (`DenyAdd(X)` / `DenyRemove(X)`), de-duplicated per signer. The mutation
//!   is applied, and its pending approvals cleared, only once `threshold`
//!   distinct current signers have approved it. Until then the call returns
//!   `Ok(())` with the mutation still pending.
//! - `Admin` keeps every admin-only power (pause, officer assignment,
//!   audit-log configuration, upgrades, admin rotation, signer governance).
//!   `ComplianceOfficer` keeps its role but has no denylist authority while
//!   multisig mode is enabled.
//!
//! The signer set governs its own membership as follows:
//!
//! - `add_signer` and `remove_signer` take the calling `caller` explicitly.
//!   Each call runs `caller.require_auth()` and then requires `caller` to be in
//!   the *current* signer set; any other address is rejected with
//!   `NotAuthorized`.
//! - A change does not take effect on a single signer's say-so. Each call
//!   records one approval from `caller` for that exact action (add X / remove
//!   X). Approvals are per action and de-duplicated per signer, so one signer
//!   calling twice still counts once. The change is applied, and its pending
//!   approvals cleared, only once `threshold` distinct current signers have
//!   approved it.
//! - Removals are validated before an approval is recorded: the set can never
//!   shrink to empty, nor below the threshold (`InvalidSignerSet` /
//!   `InvalidThreshold`). To remove a signer from a set that is already at its
//!   threshold, lower the threshold first.
//! - `set_threshold` goes through the same approval flow. Each call records an
//!   approval of `SetThreshold(n)`, applied once `threshold` distinct current
//!   signers have approved it. When applied, `n` must satisfy
//!   `1 <= n <= signers.len()` (`InvalidThreshold`), and a `ThresholdChanged`
//!   event is emitted. The threshold can therefore be raised or lowered, e.g. a
//!   3-of-3 set can lower to 2-of-3 and then remove a lost key.
#![no_std]

use soroban_sdk::{
    contract, contractclient, contracterror, contractevent, contractimpl, contractmeta,
    contracttype, Address, BytesN, Env, String, Symbol, Vec,
};

contractmeta!(key = "version", val = env!("CARGO_PKG_VERSION"));
contractmeta!(key = "source", val = env!("CARGO_PKG_REPOSITORY"));

/// Batch operations are capped to reduce the chance of a single invocation
/// exceeding Soroban instruction/resource limits. Set to 45 to fit comfortably
/// within Soroban's default per-invocation write-entry budget of ~50.
const MAX_BATCH_SIZE: u32 = 45;

/// Minimum upgrade review window, approximately one day at five seconds per ledger.
pub const MIN_UPGRADE_DELAY_LEDGERS: u32 = 17_280;

/// Instance-storage TTL policy: whenever the remaining instance TTL drops
/// below [`INSTANCE_TTL_THRESHOLD`], it is bumped back up to
/// [`INSTANCE_TTL_EXTEND_TO`]. Matches `compliance-aggregator`.
pub const INSTANCE_TTL_THRESHOLD: u32 = compliance_ttl::TTL_THRESHOLD; // ~7 days
/// Target instance TTL after an extension.
pub const INSTANCE_TTL_EXTEND_TO: u32 = compliance_ttl::TTL_EXTEND_TO; // ~90 days

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone)]
enum DataKey {
    /// The admin address, set once in `initialize`. Instance storage.
    Admin,
    /// Admin proposed by `propose_admin`, awaiting `accept_admin`. Instance storage.
    PendingAdmin,
    Paused,
    ComplianceOfficer,
    AuditLog,
    SignerSet,
    /// Legacy denylist flag (`true`) written before entries carried metadata.
    /// Still honoured by `check()`; superseded by `DenyEntry` on the next
    /// add or removal. Never written by current code.
    Denied(Address),
    /// Denylist entry with its metadata (`DenyEntry`). Persistent storage.
    DenyEntry(Address),
    /// Number of addresses currently on the denylist. Instance storage.
    DenylistCount,
    /// Sanctions list an entry came from (e.g. `OFAC`). Persistent storage.
    DeniedSource(Address),
    PendingUpgrade,
    /// Approvals collected so far for one pending signer-set change.
    /// Persistent storage (not instance), so abandoned proposals do not bloat
    /// the instance entry that every call, including `check()`, loads.
    PendingSignerAction(SignerAction),
}

/// Delayed upgrade proposal state.
#[contracttype]
#[derive(Clone)]
pub struct UpgradeState {
    pub new_wasm: BytesN<32>,
    pub activated_at: u64,
}

/// Metadata recorded when an address is added to the denylist.
///
/// `added_at` is the ledger timestamp (seconds since the Unix epoch) of the
/// first add. `added_by` is the admin or compliance officer that made it.
/// Re-adding an address that is already denied keeps the original values.
///
/// **Migration.** Entries written before this struct existed are stored as a
/// bare `true` flag and have no `DenyEntry`. They remain denylisted (`check`
/// still reports them), but `get_denylist_entry` returns `None` for them and
/// they are not included in `denylist_count`. To give such an entry metadata
/// and count it, re-add it with `add_to_denylist`; that writes a `DenyEntry`
/// and drops the legacy flag.
#[contracttype]
#[derive(Clone)]
pub struct DenyEntry {
    pub added_at: u64,
    pub added_by: Address,
    /// Ledger sequence at which the entry stops applying. The address is
    /// denylisted while `current ledger < expires_at_ledger`. `None` means the
    /// entry lasts until it is removed. Set by `add_to_denylist_until`, and
    /// reset to `None` by `add_to_denylist`.
    pub expires_at_ledger: Option<u32>,
}

/// Current on-chain schema version for this contract instance.
pub const SCHEMA_VERSION: u32 = 1;

/// Version of the shared `ComplianceCheck` interface implemented by this
/// contract. Bumped whenever the trait's method set or result shape changes.
///
/// Callers must compare this against the version they were built against
/// (see [`DenylistGate::interface_version`]) before calling `is_compliant`.
pub const INTERFACE_VERSION: u32 = 2;

/// Reason code returned in [`CheckResult::code`] when an address is clear to
/// transact.
pub const REASON_ALLOWED: u32 = 0;
/// Reason code returned when the address is on the denylist.
pub const REASON_DENYLISTED: u32 = 1;

/// Result of the shared `ComplianceCheck` interface.
///
/// `allowed` is the pass/fail verdict; `code` explains it. A `code` of
/// [`REASON_ALLOWED`] (0) always accompanies `allowed == true`. Non-zero codes
/// accompany `allowed == false` and identify the reason:
///
/// - [`REASON_DENYLISTED`] (1): the address is on the denylist.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckResult {
    pub allowed: bool,
    pub code: u32,
}

/// The M-of-N signer set, stored under `DataKey::SignerSet` in instance
/// storage once `initialize_multisig` has run.
///
/// **Scope of the multisig layer.** Once installed, the signer set gates
/// denylist mutations as well as its own membership:
///
/// - `add_to_denylist`, `remove_from_denylist` and
///   `remove_multiple_from_denylist` each need `threshold` distinct approvals
///   from current `signers` before they take effect. The single-admin
///   `require_compliance_authority` check is bypassed entirely in this mode.
/// - `add_signer`, `remove_signer` and `set_threshold` each need `threshold`
///   distinct approvals from current `signers` before they take effect.
/// - `Admin` keeps every admin-only power (pause, officer assignment,
///   audit-log configuration, upgrades, admin rotation). `ComplianceOfficer`
///   keeps its role but has no denylist authority while multisig is enabled.
/// - Signers have no admin rights by virtue of being signers.
///
/// Treat the signer set as the governance layer for denylist mutations, not
/// as a replacement for the admin key for the remaining admin operations.
#[contracttype]
#[derive(Clone)]
pub struct SignerSet {
    /// Distinct addresses allowed to approve signer-set and denylist changes.
    pub signers: Vec<Address>,
    /// Number of distinct current signers whose approval applies a change
    /// (`1 <= threshold <= signers.len()`).
    pub threshold: u32,
}

/// Approvals collected for one pending `SignerAction`, stored in persistent
/// storage under `DataKey::PendingSignerAction(action)`.
#[contracttype]
#[derive(Clone)]
pub struct PendingApproval {
    /// Signers that have approved the action so far.
    pub approvals: Vec<Address>,
    /// Ledger sequence at which the first approval was recorded.
    pub created_ledger: u32,
}

/// Number of ledgers a pending signer-set approval stays valid after its
/// first approval (~7 days at 5s per ledger). Once expired, collected
/// approvals no longer count towards the threshold and the next approval
/// starts a fresh proposal.
pub const APPROVAL_TTL_LEDGERS: u32 = 120_960;

/// An action that needs `threshold` distinct signer approvals to apply.
#[contracttype]
#[derive(Clone)]
pub enum SignerAction {
    Add(Address),
    Remove(Address),
    SetThreshold(u32),
    /// Add `address` to the denylist (multisig mode only).
    DenyAdd(Address),
    /// Remove `address` from the denylist (multisig mode only).
    DenyRemove(Address),
}

#[contractclient(name = "AuditLogClient")]
pub trait AuditLogInterface {

    fn record(env: Env, source: Address, kind: Symbol, subject: Address, detail: String);
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

#[contractevent]
pub struct DenyAdd {
    #[topic]
    pub address: Address,
    /// Admin or compliance officer that authorized the change.
    pub by: Address,
}

/// Emitted alongside [`DenyAdd`] when an entry is tagged with its source list.
#[contractevent]
pub struct DenyAddSourced {
    #[topic]
    pub address: Address,
    #[topic]
    pub source: Symbol,
}

/// View of a single denylist entry.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DenylistEntry {
    pub address: Address,
    /// Sanctions list the entry came from, if tagged.
    pub source: Option<Symbol>,
}

#[contractevent]
pub struct DenyRemove {
    #[topic]
    pub address: Address,
    /// Admin or compliance officer that authorized the change.
    pub by: Address,
}

/// Emitted when the optional audit-log write fails (paused, archived, or
/// reverting). The denylist mutation itself still succeeds; see
/// `docs/fail-open-fail-closed-audit.md`.
#[contractevent]
pub struct AuditLogFailed {
    pub kind: Symbol,
    #[topic]
    pub subject: Address,
}

#[contractevent]
pub struct MultisigInitialized {
    pub threshold: u32,
    pub signer_count: u32,
}

#[contractevent]
pub struct SignerApproved {
    #[topic]
    pub signer: Address,
}

#[contractevent]
pub struct SignerAdded {
    #[topic]
    pub signer: Address,
}

#[contractevent]
pub struct SignerRemoved {
    #[topic]
    pub signer: Address,
}

#[contractevent]
pub struct ThresholdChanged {
    pub old_threshold: u32,
    pub new_threshold: u32,
}

#[contractevent]
pub struct AdminTransferred {
    #[topic]
    pub old_admin: Address,
    #[topic]
    pub new_admin: Address,
}

#[contractevent]
pub struct AdminProposed {
    #[topic]
    pub current: Address,
    #[topic]
    pub proposed: Address,
}

#[contractevent]
pub struct AdminProposalCancelled {
    #[topic]
    pub current: Address,
}

#[contractevent]
pub struct UpgradeProposed {
    #[topic]
    pub admin: Address,
    pub new_wasm: BytesN<32>,
    pub activated_at: u64,
}

#[contractevent]
pub struct UpgradeCancelled {
    #[topic]
    pub admin: Address,
}

#[contractevent]
pub struct UpgradeCommitted {
    #[topic]
    pub admin: Address,
    pub new_wasm: BytesN<32>,
}

#[contractevent]
pub struct Paused {
    #[topic]
    pub admin: Address,
}

#[contractevent]
pub struct Unpaused {
    #[topic]
    pub admin: Address,
}

#[contractevent]
pub struct ComplianceOfficerSet {
    #[topic]
    pub officer: Address,
}

#[contractevent]
pub struct ComplianceOfficerRevoked {
    #[topic]
    pub officer: Address,
}

#[contractevent]
pub struct AuditLogSet {
    #[topic]
    pub audit_log: Address,
}

/// Emitted when `clear_audit_log` detaches the audit log, so denylist
/// mutations stop being recorded. `previous` is the audit-log contract that
/// was detached, if one was configured.
#[contractevent]
pub struct AuditLogCleared {
    #[topic]
    pub admin: Address,
    pub previous: Option<Address>,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    NotInitialized = 1,
    AlreadyInitialized = 2,
    NotAuthorized = 3,
    ContractPaused = 4,
    BatchTooLarge = 5,
    ThresholdNotMet = 6,
    InvalidThreshold = 7,
    InvalidSignerSet = 8,
    SignerNotInSet = 9,
    UpgradeNotReady = 10,
    SignerAlreadyExists = 11,
    MultisigNotEnabled = 12,
    NoPendingAdmin = 13,
    PendingAdminMismatch = 14,
    UpgradeDelayTooShort = 15,
    InvalidExpiry = 16,
    /// `check_pair`: the sender (`from`) is denylisted.
    SenderDenied = 17,
    /// `check_pair`: the receiver (`to`) is denylisted.
    ReceiverDenied = 18,
    /// The caller is not a current signer, or multisig mode is required for
    /// this operation but has not been enabled.
    SignerApprovalRequired = 19,
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contract]
pub struct DenylistGate;

#[contractimpl]
impl DenylistGate {
    /// One-time setup. Stores `admin` as the only address allowed to update
    /// the denylist afterward.
    pub fn initialize(env: Env, admin: Address) -> Result<(), Error> {
        Self::extend_instance_ttl(&env);
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Paused, &false);
        env.storage().instance().set(&DataKey::DenylistCount, &0u32);
        Ok(())
    }

    /// Return the configured admin address.
    pub fn get_admin(env: Env) -> Result<Address, Error> {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)
    }

    /// Assign the compliance-officer role. Admin-only.
    pub fn set_compliance_officer(
        env: Env,
        admin: Address,
        officer: Address,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::ComplianceOfficer, &officer);
        ComplianceOfficerSet {
            officer: officer.clone(),
        }
        .publish(&env);
        Ok(())
    }

    /// Revoke the compliance-officer role. Admin-only.
    pub fn revoke_compliance_officer(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        if let Some(officer) = env
            .storage()
            .instance()
            .get::<DataKey, Address>(&DataKey::ComplianceOfficer)
        {
            env.storage().instance().remove(&DataKey::ComplianceOfficer);
            ComplianceOfficerRevoked { officer }.publish(&env);
        }
        Ok(())
    }

    /// Return the currently assigned compliance officer, if any.
    pub fn get_compliance_officer(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::ComplianceOfficer)
    }

    /// Configure the optional append-only audit log. Admin-only.
    pub fn set_audit_log(env: Env, admin: Address, audit_log: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::AuditLog, &audit_log);
        AuditLogSet {
            audit_log: audit_log.clone(),
        }
        .publish(&env);
        Ok(())
    }

    /// Propose a new admin. The current admin remains active until the
    /// proposed admin calls `accept_admin`. Replaces any earlier proposal.
    pub fn propose_admin(env: Env, current_admin: Address, new_admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &current_admin)?;
        env.storage().instance().set(&DataKey::PendingAdmin, &new_admin);
        AdminProposed {
            current: current_admin,
            proposed: new_admin,
        }
        .publish(&env);
        Ok(())
    }

    /// Accept a pending admin transfer. Must be called by the proposed admin.
    pub fn accept_admin(env: Env, new_admin: Address) -> Result<(), Error> {
        Self::extend_instance_ttl(&env);
        new_admin.require_auth();
        let pending_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::PendingAdmin)
            .ok_or(Error::NoPendingAdmin)?;
        if pending_admin != new_admin {
            return Err(Error::PendingAdminMismatch);
        }
        let old_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        env.storage().instance().set(&DataKey::Admin, &new_admin);
        env.storage().instance().remove(&DataKey::PendingAdmin);
        AdminTransferred { old_admin, new_admin }.publish(&env);
        Ok(())
    }

    /// Withdraw a pending admin proposal. Admin-only.
    pub fn cancel_admin_proposal(env: Env, current_admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &current_admin)?;
        if !env.storage().instance().has(&DataKey::PendingAdmin) {
            return Err(Error::NoPendingAdmin);
        }
        env.storage().instance().remove(&DataKey::PendingAdmin);
        AdminProposalCancelled {
            current: current_admin,
        }
        .publish(&env);
        Ok(())
    }

    /// Disconnect the audit log so denylist mutations stop calling it. Admin-only.
    ///
    /// Emits `AuditLogCleared { admin, previous }` so that silencing the audit
    /// trail is itself visible off-chain.
    pub fn clear_audit_log(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        let previous: Option<Address> = env.storage().instance().get(&DataKey::AuditLog);
        env.storage().instance().remove(&DataKey::AuditLog);
        AuditLogCleared { admin, previous }.publish(&env);
        Ok(())
    }

    /// Return the currently configured audit-log address, if any.
    pub fn get_audit_log(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::AuditLog)
    }

    /// Reassign the admin role to `new_admin` immediately. Requires auth from
    /// `current_admin`, which must be the stored admin.
    ///
    /// Single-step, for emergency rotation: the old admin loses all privileges
    /// as soon as this call succeeds, and `new_admin`'s key is not checked
    /// first. Use `propose_admin` / `accept_admin` for routine handovers.
    /// Clears any pending proposal from `propose_admin`. Deliberately *not*
    /// blocked by `pause`, so a compromised or rotated admin key can always be
    /// replaced.
    ///
    /// Emits `AdminTransferred { old_admin, new_admin }`.
    pub fn transfer_admin(
        env: Env,
        current_admin: Address,
        new_admin: Address,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &current_admin)?;
        env.storage().instance().set(&DataKey::Admin, &new_admin);
        env.storage().instance().remove(&DataKey::PendingAdmin);
        AdminTransferred {
            old_admin: current_admin,
            new_admin,
        }
        .publish(&env);
        Ok(())
    }

    /// Propose a two-step upgrade to `new_wasm_hash` (the hash of the
    /// already-uploaded replacement contract Wasm).
    ///
    /// Admin-only. The upgrade does **not** take effect immediately: it becomes
    /// committable only once the ledger sequence reaches `activated_at`, which
    /// `propose_upgrade` sets to `current_ledger + delay_ledgers`. This gives the
    /// admin, the compliance officer, and any external watchguard a
    /// `delay_ledgers`-long window to review the proposed Wasm and call
    /// `cancel_upgrade` before it can be installed — the safe "migration path"
    /// required by issue #114, in contrast to `jurisdiction-flag::upgrade`, which
    /// is single-step and issuer-only (see threat model J6).
    pub fn propose_upgrade(
        env: Env,
        admin: Address,
        new_wasm: BytesN<32>,
        delay_ledgers: u32,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        if delay_ledgers < MIN_UPGRADE_DELAY_LEDGERS {
            return Err(Error::UpgradeDelayTooShort);
        }
        let state = UpgradeState {
            new_wasm: new_wasm.clone(),
            activated_at: u64::from(env.ledger().sequence())
                .saturating_add(delay_ledgers as u64),
        };
        env.storage().instance().set(&DataKey::PendingUpgrade, &state);
        UpgradeProposed {
            admin,
            new_wasm,
            activated_at: state.activated_at,
        }
        .publish(&env);
        Ok(())
    }

    /// Commit a previously proposed upgrade, installing `new_wasm_hash`.
    ///
    /// Admin-only. Errors with `UpgradeNotReady` if no upgrade is pending or if
    /// the current ledger has not yet reached `activated_at`.
    pub fn commit_upgrade(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        let state: UpgradeState = env
            .storage()
            .instance()
            .get(&DataKey::PendingUpgrade)
            .ok_or(Error::UpgradeNotReady)?;
        if u64::from(env.ledger().sequence()) < state.activated_at {
            return Err(Error::UpgradeNotReady);
        }
        env.deployer()
            .update_current_contract_wasm(state.new_wasm.clone());
        env.storage().instance().remove(&DataKey::PendingUpgrade);
        UpgradeCommitted {
            admin,
            new_wasm: state.new_wasm,
        }
        .publish(&env);
        Ok(())
    }

    /// Cancel a pending upgrade. Admin-only.
    pub fn cancel_upgrade(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().remove(&DataKey::PendingUpgrade);
        UpgradeCancelled { admin }.publish(&env);
        Ok(())
    }

    /// Return the pending admin proposal, if one exists.
    pub fn get_pending_admin(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::PendingAdmin)
    }

    /// Return the pending upgrade and activation ledger, if one exists.
    pub fn get_pending_upgrade(env: Env) -> Option<UpgradeState> {
        env.storage().instance().get(&DataKey::PendingUpgrade)
    }

    /// Current on-chain schema version (see [`SCHEMA_VERSION`]).
    pub fn schema_version(_env: Env) -> u32 {
        SCHEMA_VERSION
    }

    /// Pause admin mutations (`add_to_denylist` / `remove_from_denylist`).
    /// `check()` continues to work while paused. Admin-only.
    pub fn pause(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::Paused, &true);
        Paused {
            admin: admin.clone(),
        }
        .publish(&env);
        Ok(())
    }

    /// Resume admin mutations after a `pause`. Admin-only.
    pub fn unpause(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::Paused, &false);
        Unpaused {
            admin: admin.clone(),
        }
        .publish(&env);
        Ok(())
    }

    /// Returns `true` while admin mutations are paused. Mirrors
    /// `allowlist-token::is_paused`. Reads `false` before `initialize` and
    /// after `unpause`.
    pub fn is_paused(env: Env) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::Paused)
            .unwrap_or(false)
    }

    /// Add `address` to the denylist.
    ///
    /// **Single-admin mode** (no signer set installed): `caller` must be the
    /// `Admin` or the `ComplianceOfficer`.
    ///
    /// **Multisig mode** (signer set installed): `caller` must authorize the
    /// call and be in the current signer set. The entry is added once
    /// `threshold` distinct current signers have approved this exact action;
    /// until then the call returns `Ok(())` with the mutation still pending.
    ///
    /// Uses persistent storage with a long TTL to avoid fail-open archival.
    ///
    /// Persistent denylist entries receive an explicit long TTL because their
    /// reads can happen independently of instance-storage activity. Instance
    /// configuration keys (admin, pause flag, signer set, ...) are kept alive
    /// separately: Soroban never extends instance TTL implicitly, so every
    /// write path (and `check`) calls `extend_instance_ttl` explicitly.
    pub fn add_to_denylist(env: Env, caller: Address, address: Address) -> Result<(), Error> {
        Self::reject_if_paused(&env)?;
        if let Some(signer_set) = Self::require_denylist_authority(&env, &caller)? {
            return Self::approve(&env, caller, SignerAction::DenyAdd(address), signer_set);
        }
        Self::deny(&env, &caller, &address, None, None)
    }

    /// Add `address` to the denylist, tagged with the sanctions list it came
    /// from (e.g. `OFAC`, `UN`, `EU`). Admin or compliance-officer.
    ///
    /// Emits [`DenyAdd`] and [`DenyAddSourced`]; the tag is returned by
    /// [`get_entry`](Self::get_entry) and cleared on removal.
    pub fn add_to_denylist_with_source(
        env: Env,
        admin: Address,
        address: Address,
        source: Symbol,
    ) -> Result<(), Error> {
        Self::deny(&env, &admin, &address, None, Some(source))
    }

    /// Return the denylist entry for `address`, or `None` if not denylisted.
    pub fn get_entry(env: Env, address: Address) -> Option<DenylistEntry> {
        if !Self::is_denied(&env, &address) {
            return None;
        }
        let source = env
            .storage()
            .persistent()
            .get(&DataKey::DeniedSource(address.clone()));
        Some(DenylistEntry { address, source })
    }

    /// Add `address` to the denylist for a limited time. Admin or compliance-officer.
    ///
    /// The address is denylisted while the current ledger sequence is below
    /// `until_ledger`, and clear from `until_ledger` onwards. `until_ledger`
    /// must be in the future (`InvalidExpiry` otherwise). Calling this on an
    /// address that is already denylisted replaces its expiry.
    ///
    /// Expired entries are not removed from storage, so they still count in
    /// `denylist_count` until `remove_from_denylist` is called for them.
    pub fn add_to_denylist_until(
        env: Env,
        admin: Address,
        address: Address,
        until_ledger: u32,
    ) -> Result<(), Error> {
        Self::deny(&env, &admin, &address, Some(until_ledger), None)
    }

    /// Shared body of the add entry points.
    fn deny(
        env: &Env,
        admin: &Address,
        address: &Address,
        expires_at_ledger: Option<u32>,
        source: Option<Symbol>,
    ) -> Result<(), Error> {
        const MAX_TTL: u32 = compliance_ttl::DENYLIST_ENTRY_TTL_EXTEND_TO;
        const THRESHOLD: u32 = compliance_ttl::DENYLIST_ENTRY_TTL_THRESHOLD;

        Self::reject_if_paused(env)?;
        Self::require_compliance_authority(env, admin)?;
        if let Some(until) = expires_at_ledger {
            if until <= env.ledger().sequence() {
                return Err(Error::InvalidExpiry);
            }
        }

        Self::record_entry(env, admin, address, expires_at_ledger);

        let source_key = DataKey::DeniedSource(address.clone());
        match &source {
            Some(src) => {
                env.storage().persistent().set(&source_key, src);
                env.storage()
                    .persistent()
                    .extend_ttl(&source_key, THRESHOLD, MAX_TTL);
            }
            None => env.storage().persistent().remove(&source_key),
        }

        DenyAdd {
            address: address.clone(),
            by: admin.clone(),
        }
        .publish(env);
        if let Some(source) = source {
            DenyAddSourced {
                address: address.clone(),
                source,
            }
            .publish(env);
        }
        Self::record_audit(env, Symbol::new(env, "deny_add"), address, "address added to denylist");
        Ok(())
    }

    /// Remove `address` from the denylist.
    ///
    /// **Single-admin mode**: `caller` must be the `Admin` or the
    /// `ComplianceOfficer`. **Multisig mode**: `caller` must be a current
    /// signer and `threshold` distinct signers must approve the removal before
    /// it takes effect.
    pub fn remove_from_denylist(env: Env, caller: Address, address: Address) -> Result<(), Error> {
        Self::reject_if_paused(&env)?;
        if let Some(signer_set) = Self::require_denylist_authority(&env, &caller)? {
            return Self::approve(&env, caller, SignerAction::DenyRemove(address), signer_set);
        }
        Self::remove_entry(&env, &address);
        DenyRemove {
            address: address.clone(),
            by: caller,
        }
        .publish(&env);
        Self::record_audit(&env, Symbol::new(&env, "deny_remove"), &address, "address removed from denylist");
        Ok(())
    }

    /// Remove every address in `addresses` from the denylist.
    ///
    /// **Single-admin mode**: `caller` must be the `Admin` or the
    /// `ComplianceOfficer`. **Multisig mode**: `caller` must be a current
    /// signer and `threshold` distinct signers must approve the removal of
    /// each address before it takes effect.
    pub fn remove_multiple_from_denylist(
        env: Env,
        caller: Address,
        addresses: Vec<Address>,
    ) -> Result<(), Error> {
        Self::reject_if_paused(&env)?;
        if addresses.len() > MAX_BATCH_SIZE {
            return Err(Error::BatchTooLarge);
        }
        if let Some(signer_set) = Self::require_denylist_authority(&env, &caller)? {
            for address in addresses.iter() {
                Self::approve(
                    &env,
                    caller.clone(),
                    SignerAction::DenyRemove(address),
                    signer_set.clone(),
                )?;
            }
            return Ok(());
        }

        for address in addresses.iter() {
            Self::remove_entry(&env, &address);
            DenyRemove { address, by: admin.clone() }.publish(&env);
        }
        Ok(())
    }

    /// Return the metadata recorded for a denylist entry, if one exists.
    ///
    /// Returns `None` for addresses that are not denylisted and for legacy
    /// entries written before `DenyEntry` existed (see [`DenyEntry`]).
    pub fn get_denylist_entry(env: Env, address: Address) -> Option<DenyEntry> {
        env.storage()
            .persistent()
            .get(&DataKey::DenyEntry(address))
    }

    /// Number of addresses currently on the denylist.
    ///
    /// Counts entries recorded as a `DenyEntry`. Legacy entries (see
    /// [`DenyEntry`]) are not counted until they are re-added.
    ///
    /// Maintained on actual state changes only: an add counts only when the
    /// address was not already denied, and a removal counts only when the
    /// address was denied. Repeated adds/removes and removals of non-denied
    /// addresses leave the count unchanged.
    pub fn denylist_count(env: Env) -> u32 {
        Self::extend_instance_ttl(&env);
        env.storage()
            .instance()
            .get(&DataKey::DenylistCount)
            .unwrap_or(0)
    }

    /// Returns `true` if `address` is clear to transact, i.e. it is NOT on
    /// the denylist. This is the function other contracts should call via
    /// cross-contract invocation before proceeding with a transfer.
    ///
    /// **Not** affected by pause state — reads always succeed.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // `gate` is a `DenylistGateClient` for the deployed contract.
    /// if !gate.check(&recipient) {
    ///     panic!("recipient is denylisted");
    /// }
    /// ```
    pub fn check(env: Env, address: Address) -> bool {
        Self::extend_instance_ttl(&env);
        !Self::is_denied(&env, &address)
    }

    /// Batched form of [`is_denylisted`]: returns one flag per input address,
    /// in the same order, where `true` means the address IS on the denylist.
    ///
    /// Intended for screening many counterparties in one call. Fails with
    /// `BatchTooLarge` if more than `MAX_BATCH_SIZE` addresses are passed.
    ///
    /// **Not** affected by pause state — reads always succeed.
    pub fn is_denylisted_batch(env: Env, addresses: Vec<Address>) -> Result<Vec<bool>, Error> {
        if addresses.len() > MAX_BATCH_SIZE {
            return Err(Error::BatchTooLarge);
        }
        Self::extend_instance_ttl(&env);
        let mut flags = Vec::new(&env);
        for address in addresses.iter() {
            flags.push_back(Self::is_denied(&env, &address));
        }
        Ok(flags)
    }

    /// Check both sides of a transfer in one call.
    ///
    /// Returns `Ok(())` if neither address is denylisted, otherwise
    /// [`Error::SenderDenied`] (checked first) or [`Error::ReceiverDenied`].
    /// **Not** affected by pause state.
    pub fn check_pair(env: Env, from: Address, to: Address) -> Result<(), Error> {
        if !Self::check(env.clone(), from) {
            return Err(Error::SenderDenied);
        }
        if !env
            .storage()
            .persistent()
            .get(&DataKey::Denied(to))
            .unwrap_or(false)
        {
            return Ok(());
        }
        Err(Error::ReceiverDenied)
    }

    /// Unified compliance check — returns a [`CheckResult`] describing whether
    /// `address` is clear to transact and, if not, why.
    ///
    /// This entry point implements the shared `ComplianceCheck` interface
    /// (`is_compliant(address) -> CheckResult`) so external contracts can call
    /// any of the three compliance primitives through the same pattern.
    ///
    /// `allowed` is `true` (with `code == REASON_ALLOWED`) when the address is
    /// not on the denylist, and `false` (with `code == REASON_DENYLISTED`)
    /// when it is.
    ///
    /// Callers should check [`interface_version`] against the version they
    /// were built against before calling this method.
    ///
    /// **Not** affected by pause state — reads always succeed.
    pub fn is_compliant(env: Env, address: Address) -> CheckResult {
        if Self::check(env, address) {
            CheckResult {
                allowed: true,
                code: REASON_ALLOWED,
            }
        } else {
            CheckResult {
                allowed: false,
                code: REASON_DENYLISTED,
            }
        }
    }

    /// Version of the shared `ComplianceCheck` interface implemented by this
    /// contract (see [`INTERFACE_VERSION`]). Callers must verify this matches
    /// the version they were built against before calling `is_compliant`.
    pub fn interface_version(_env: Env) -> u32 {
        INTERFACE_VERSION
    }

    /// Return whether `address` is currently stored on the denylist.
    pub fn is_denylisted(env: Env, address: Address) -> bool {
        !Self::check(env, address)
    }

    /// Install an M-of-N signer set. Admin-only; callable once.
    ///
    /// `signers` must be non-empty and free of duplicates, and `threshold`
    /// must be between 1 and `signers.len()`.
    ///
    /// Installing a signer set switches the contract into multisig mode for
    /// denylist mutations: `add_to_denylist` / `remove_from_denylist` /
    /// `remove_multiple_from_denylist` then require `threshold` distinct
    /// signer approvals instead of the single-admin (`Admin` or
    /// `ComplianceOfficer`) check. `Admin` retains all admin-only operations.
    /// See [`SignerSet`].
    pub fn initialize_multisig(
        env: Env,
        admin: Address,
        signers: Vec<Address>,
        threshold: u32,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        if env.storage().instance().has(&DataKey::SignerSet) {
            return Err(Error::AlreadyInitialized);
        }
        if signers.is_empty() {
            return Err(Error::InvalidSignerSet);
        }
        if threshold == 0 || threshold > signers.len() {
            return Err(Error::InvalidThreshold);
        }
        for (i, signer) in signers.iter().enumerate() {
            for other in signers.iter().skip(i + 1) {
                if signer == other {
                    return Err(Error::InvalidSignerSet);
                }
            }
        }

        let signer_count = signers.len();
        env.storage()
            .instance()
            .set(&DataKey::SignerSet, &SignerSet { signers, threshold });
        MultisigInitialized {
            threshold,
            signer_count,
        }
        .publish(&env);
        Ok(())
    }

    /// Approve adding `new_signer` to the signer set. `caller` must authorize
    /// the call and be in the current signer set. The signer is added once
    /// `threshold` distinct signers have approved this exact action.
    pub fn add_signer(env: Env, caller: Address, new_signer: Address) -> Result<(), Error> {
        let signer_set = Self::require_signer(&env, &caller)?;
        if Self::contains(&signer_set.signers, &new_signer) {
            return Err(Error::SignerAlreadyExists);
        }
        Self::approve(&env, caller, SignerAction::Add(new_signer), signer_set)
    }

    /// Approve removing `signer_to_remove` from the signer set. `caller` must
    /// authorize the call and be in the current signer set. The signer is
    /// removed once `threshold` distinct signers have approved this exact
    /// action. The set may never become empty or smaller than the threshold.
    pub fn remove_signer(
        env: Env,
        caller: Address,
        signer_to_remove: Address,
    ) -> Result<(), Error> {
        let signer_set = Self::require_signer(&env, &caller)?;
        if !Self::contains(&signer_set.signers, &signer_to_remove) {
            return Err(Error::SignerNotInSet);
        }
        if signer_set.signers.len() <= 1 {
            return Err(Error::InvalidSignerSet);
        }
        if signer_set.threshold > signer_set.signers.len() - 1 {
            return Err(Error::InvalidThreshold);
        }
        Self::approve(&env, caller, SignerAction::Remove(signer_to_remove), signer_set)
    }

    /// Approve changing the signing threshold to `new_threshold`. `caller` must
    /// authorize the call and be in the current signer set. The threshold is
    /// changed once `threshold` distinct signers have approved this exact
    /// action; `new_threshold` must be between 1 and the signer count at that
    /// point.
    pub fn set_threshold(env: Env, caller: Address, new_threshold: u32) -> Result<(), Error> {
        let signer_set = Self::require_signer(&env, &caller)?;
        Self::approve(&env, caller, SignerAction::SetThreshold(new_threshold), signer_set)
    }

    /// Withdraw `caller`'s approval of a pending `action`. `caller` must
    /// authorize the call and be in the current signer set. A no-op if there
    /// is no pending approval from `caller`.
    pub fn revoke_approval(env: Env, caller: Address, action: SignerAction) -> Result<(), Error> {
        Self::require_signer(&env, &caller)?;
        let key = DataKey::PendingSignerAction(action);
        if let Some(mut pending) = Self::load_pending(&env, &key) {
            let mut remaining = Vec::new(&env);
            for approver in pending.approvals.iter() {
                if approver != caller {
                    remaining.push_back(approver);
                }
            }
            if remaining.is_empty() {
                env.storage().persistent().remove(&key);
            } else {
                pending.approvals = remaining;
                env.storage().persistent().set(&key, &pending);
            }
        }
        Ok(())
    }

    /// Signers whose approval of `action` is currently pending and unexpired.
    pub fn pending_approvals(env: Env, action: SignerAction) -> Vec<Address> {
        Self::load_pending(&env, &DataKey::PendingSignerAction(action))
            .map(|p| p.approvals)
            .unwrap_or_else(|| Vec::new(&env))
    }

    /// The current signer set, or empty when multisig is not enabled.
    pub fn signers(env: Env) -> Vec<Address> {
        env.storage()
            .instance()
            .get::<_, SignerSet>(&DataKey::SignerSet)
            .map(|set| set.signers)
            .unwrap_or_else(|| Vec::new(&env))
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Extends the instance entry TTL. Soroban does not extend instance TTL
    /// implicitly on invocation, so every write path calls this explicitly.
    fn extend_instance_ttl(env: &Env) {
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);
    }

    fn contains(signers: &Vec<Address>, address: &Address) -> bool {
        signers.iter().any(|s| s == *address)
    }

    /// Requires `caller`'s authorization and membership in the current signer
    /// set; returns that set.
    fn require_signer(env: &Env, caller: &Address) -> Result<SignerSet, Error> {
        Self::extend_instance_ttl(&env);
        caller.require_auth();
        let signer_set: SignerSet = env
            .storage()
            .instance()
            .get(&DataKey::SignerSet)
            .ok_or(Error::MultisigNotEnabled)?;
        if !Self::contains(&signer_set.signers, caller) {
            return Err(Error::NotAuthorized);
        }
        Ok(signer_set)
    }

    /// Loads the pending approval at `key`, treating it as absent once it is
    /// older than [`APPROVAL_TTL_LEDGERS`].
    fn load_pending(env: &Env, key: &DataKey) -> Option<PendingApproval> {
        let pending: PendingApproval = env.storage().persistent().get(key)?;
        if env.ledger().sequence() > pending.created_ledger.saturating_add(APPROVAL_TTL_LEDGERS) {
            return None;
        }
        Some(pending)
    }

    /// Records `caller`'s approval of `action` and applies it once `threshold`
    /// distinct signers have approved.
    fn approve(
        env: &Env,
        caller: Address,
        action: SignerAction,
        mut signer_set: SignerSet,
    ) -> Result<(), Error> {
        let key = DataKey::PendingSignerAction(action.clone());
        let mut pending = Self::load_pending(env, &key).unwrap_or_else(|| PendingApproval {
            approvals: Vec::new(env),
            created_ledger: env.ledger().sequence(),
        });
        if !Self::contains(&pending.approvals, &caller) {
            pending.approvals.push_back(caller.clone());
        }
        SignerApproved { signer: caller }.publish(env);

        // Only approvals from signers still in the set count towards the threshold.
        let mut valid = 0u32;
        for approver in pending.approvals.iter() {
            if Self::contains(&signer_set.signers, &approver) {
                valid += 1;
            }
        }
        if valid < signer_set.threshold {
            env.storage().persistent().set(&key, &pending);
            env.storage()
                .persistent()
                .extend_ttl(&key, APPROVAL_TTL_LEDGERS, APPROVAL_TTL_LEDGERS * 2);
            return Ok(());
        }

        env.storage().persistent().remove(&key);
        match action {
            SignerAction::Add(new_signer) => {
                signer_set.signers.push_back(new_signer.clone());
                env.storage().instance().set(&DataKey::SignerSet, &signer_set);
                SignerAdded { signer: new_signer }.publish(env);
            }
            SignerAction::Remove(removed) => {
                let mut remaining = Vec::new(env);
                for signer in signer_set.signers.iter() {
                    if signer != removed {
                        remaining.push_back(signer);
                    }
                }
                signer_set.signers = remaining;
                env.storage().instance().set(&DataKey::SignerSet, &signer_set);
                SignerRemoved { signer: removed }.publish(env);
            }
            SignerAction::SetThreshold(new_threshold) => {
                if new_threshold == 0 || new_threshold > signer_set.signers.len() {
                    return Err(Error::InvalidThreshold);
                }
                let old_threshold = signer_set.threshold;
                signer_set.threshold = new_threshold;
                env.storage().instance().set(&DataKey::SignerSet, &signer_set);
                ThresholdChanged {
                    old_threshold,
                    new_threshold,
                }
                .publish(env);
            }
            SignerAction::DenyAdd(address) => {
                // Approved by the signer set: record the entry with the
                // contract itself as the approver.
                Self::record_entry(env, &env.current_contract_address(), &address, None);
                env.storage()
                    .persistent()
                    .remove(&DataKey::DeniedSource(address.clone()));
                DenyAdd {
                    address: address.clone(),
                    by: env.current_contract_address(),
                }
                .publish(env);
                Self::record_audit(
                    env,
                    Symbol::new(env, "deny_add"),
                    &address,
                    "address added to denylist",
                );
            }
            SignerAction::DenyRemove(address) => {
                Self::remove_entry(env, &address);
                DenyRemove {
                    address: address.clone(),
                    by: env.current_contract_address(),
                }
                .publish(env);
                Self::record_audit(
                    env,
                    Symbol::new(env, "deny_remove"),
                    &address,
                    "address removed from denylist",
                );
            }
        }
        Ok(())
    }

    fn require_admin(env: &Env, admin: &Address) -> Result<(), Error> {
        Self::extend_instance_ttl(&env);
        admin.require_auth();
        let stored_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        if stored_admin != *admin {
            return Err(Error::NotAuthorized);
        }
        Ok(())
    }

    /// Authorizes a denylist mutation.
    ///
    /// Returns `Ok(Some(set))` when multisig mode is enabled, in which case
    /// `caller` has been verified as a current signer and the caller must
    /// route the mutation through [`Self::approve`]. Returns `Ok(None)` in
    /// single-admin mode after verifying `caller` is the `Admin` or
    /// `ComplianceOfficer`.
    fn require_denylist_authority(
        env: &Env,
        caller: &Address,
    ) -> Result<Option<SignerSet>, Error> {
        if env.storage().instance().has(&DataKey::SignerSet) {
            return Self::require_signer(env, caller).map(Some);
        }
        Self::require_compliance_authority(env, caller)?;
        Ok(None)
    }

    fn require_compliance_authority(env: &Env, caller: &Address) -> Result<(), Error> {
        Self::extend_instance_ttl(&env);
        caller.require_auth();
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        if admin == *caller {
            return Ok(());
        }
        if env.storage().instance().get::<DataKey, Address>(&DataKey::ComplianceOfficer)
            == Some(caller.clone())
        {
            return Ok(());
        }
        Err(Error::NotAuthorized)
    }

    /// Best-effort audit write. A paused, archived, or reverting audit-log must
    /// not block denylist mutations (fail-open on the audit dependency), so
    /// failures are surfaced as an `AuditLogFailed` event instead of reverting.
    fn record_audit(env: &Env, kind: Symbol, subject: &Address, detail: &str) {
        if let Some(audit_log) = env
            .storage()
            .instance()
            .get::<DataKey, Address>(&DataKey::AuditLog)
        {
            let written = AuditLogClient::new(env, &audit_log)
                .try_record(
                    &env.current_contract_address(),
                    &kind,
                    subject,
                    &String::from_str(env, detail),
                )
                .is_ok_and(|inner| inner.is_ok());
            if !written {
                AuditLogFailed {
                    kind,
                    subject: subject.clone(),
                }
                .publish(env);
            }
        }
    }

    /// Adjust the denylist counter by one. Saturates at the bounds so a
    /// bookkeeping mismatch can never wrap around.
    fn bump_denylist_count(env: &Env, increment: bool) {
        let count: u32 = env
            .storage()
            .instance()
            .get(&DataKey::DenylistCount)
            .unwrap_or(0);
        let updated = if increment {
            count.saturating_add(1)
        } else {
            count.saturating_sub(1)
        };
        env.storage().instance().set(&DataKey::DenylistCount, &updated);
    }

    /// Whether `address` is currently denylisted.
    fn is_denied(env: &Env, address: &Address) -> bool {
        if let Some(entry) = env
            .storage()
            .persistent()
            .get::<DataKey, DenyEntry>(&DataKey::DenyEntry(address.clone()))
        {
            return match entry.expires_at_ledger {
                Some(until) => env.ledger().sequence() < until,
                None => true,
            };
        }
        env.storage()
            .persistent()
            .get(&DataKey::Denied(address.clone()))
            .unwrap_or(false)
    }

    /// Record `address` as denylisted with the given expiry. An existing
    /// `DenyEntry` keeps its original `added_at`/`added_by`; a new one is
    /// stamped with the current ledger time and `by`. The expiry is always
    /// replaced. Any legacy flag for the address is dropped, since the
    /// `DenyEntry` supersedes it.
    fn record_entry(
        env: &Env,
        by: &Address,
        address: &Address,
        expires_at_ledger: Option<u32>,
    ) {
        const MAX_TTL: u32 = compliance_ttl::DENYLIST_ENTRY_TTL_EXTEND_TO;
        const THRESHOLD: u32 = compliance_ttl::DENYLIST_ENTRY_TTL_THRESHOLD;

        let key = DataKey::DenyEntry(address.clone());
        let mut entry = match env.storage().persistent().get::<DataKey, DenyEntry>(&key) {
            Some(existing) => existing,
            None => {
                Self::bump_denylist_count(env, true);
                DenyEntry {
                    added_at: env.ledger().timestamp(),
                    added_by: by.clone(),
                    expires_at_ledger: None,
                }
            }
        };
        entry.expires_at_ledger = expires_at_ledger;
        env.storage().persistent().set(&key, &entry);
        env.storage()
            .persistent()
            .extend_ttl(&key, THRESHOLD, MAX_TTL);
        env.storage()
            .persistent()
            .remove(&DataKey::Denied(address.clone()));
    }

    /// Remove `address` from the denylist, whether it is stored as a
    /// `DenyEntry` or as a legacy flag. Only a `DenyEntry` was counted, so
    /// only that removal decrements `denylist_count`.
    fn remove_entry(env: &Env, address: &Address) {
        let key = DataKey::DenyEntry(address.clone());
        if env.storage().persistent().has(&key) {
            env.storage().persistent().remove(&key);
            Self::bump_denylist_count(env, false);
        }
        env.storage()
            .persistent()
            .remove(&DataKey::Denied(address.clone()));
        env.storage()
            .persistent()
            .remove(&DataKey::DeniedSource(address.clone()));
    }

    fn reject_if_paused(env: &Env) -> Result<(), Error> {
        if env
            .storage()
            .instance()
            .get(&DataKey::Paused)
            .unwrap_or(false)
        {
            return Err(Error::ContractPaused);
        }
        Ok(())
    }
}

#[cfg(test)]
mod test;

#[cfg(test)]
mod fuzz_test;
