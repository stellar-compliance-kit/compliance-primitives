//! `multisig-admin` is a `#![no_std]` Soroban contract that implements
//! **M-of-N multisig authorization** using Soroban's custom-account
//! (`CustomAccountInterface`) pattern.
//!
//! ## Purpose
//!
//! Single-admin control is a known operational and security liability. This
//! contract can be set as the `admin` (or `issuer`) address of any of the
//! three compliance primitives — `allowlist-token`, `denylist-gate`,
//! `jurisdiction-flag` — because those contracts accept any `Address` as
//! their admin, and Soroban's auth model satisfies `require_auth()` for a
//! contract address by invoking `__check_auth` on that contract. No changes
//! to the primitives are needed.
//!
//! ## Tradeoff vs. #26 (built-in multisig)
//!
//! | Aspect | This contract (standalone) | #26 (built-in) |
//! |---|---|---|
//! | Primitive changes needed | None | Each primitive modified |
//! | Reusability | Shared across all three primitives | Per-primitive |
//! | Deployment | Extra contract to deploy | None |
//! | Upgrade path | Swap admin address | Redeploy primitive |
//! | Auth overhead | One cross-contract call per admin op | Inline |
//!
//! **When to use this contract**: you want a single multisig policy to govern
//! multiple deployed primitives, or you don't control the primitive's source
//! and cannot add built-in multisig. **When to use #26's approach**: you want
//! the tightest possible integration with a single primitive and don't mind
//! modifying it; one fewer deployment step.
//!
//! ## How `__check_auth` is invoked
//!
//! When any primitive calls `admin.require_auth()` and `admin` is the address
//! of this contract, the Soroban host calls
//! `MultisigAdmin::__check_auth(env, payload, signatures, context)`. The
//! `signatures` value is the `Vec<Address>` of approving signers provided by
//! the invoker. If at least `threshold` of those addresses are in the stored
//! signer set, authorization succeeds; otherwise it is rejected.
//!
//! ## Signer-set management
//!
//! `add_signer`, `remove_signer`, and `update_threshold` themselves go
//! through the multisig: they call `env.current_contract_address().require_auth()`
//! which re-enters `__check_auth`, ensuring no single signer can unilaterally
//! change the policy.
//!
//! ## Who calls this contract
//!
//! There are three distinct kinds of caller, and each touches a different
//! part of the surface:
//!
//! - **The deployer / issuer operations team** calls [`MultisigAdmin::initialize`]
//!   exactly once with the initial signer set and threshold. After that the
//!   deployer has no special privileges — every later change goes through
//!   the multisig itself.
//! - **The Soroban host** calls `__check_auth` on behalf of any contract
//!   that runs `admin.require_auth()` where `admin` is this contract's
//!   address. Signers never call `__check_auth` directly; they sign the
//!   authorization entry for the outer operation (e.g. `denylist-gate.add_to_denylist`)
//!   and the submitter attaches the list of approving signer addresses as the
//!   `signatures` value.
//! - **Individual signers** call `propose`, `approve`, and `execute` to
//!   coordinate an off-chain-visible approval trail before submitting the
//!   final transaction, and collectively (via `__check_auth`) call
//!   `add_signer`, `remove_signer`, `update_threshold`, `pause`, and
//!   `unpause` to govern this contract's own configuration.
//!
//! Read-only accessors (`get_signers`, `get_threshold`, `get_proposal`,
//! `is_paused`) may be called by anyone, including off-chain tooling such as
//! `tools/indexer` and other contracts deciding whether to trust this
//! contract as an admin.
//!
//! ## Composition with the other contracts in this repo
//!
//! This contract never calls the other contracts itself — composition is
//! entirely by *address*: you pass this contract's ID wherever another
//! contract asks for an admin/issuer `Address`, and Soroban's auth framework
//! routes the `require_auth()` back here.
//!
//! | Contract | Role this contract plays | Operations it gates |
//! |---|---|---|
//! | `allowlist-token` | `admin` | allowlist add/remove, timelocked upgrade |
//! | `denylist-gate` | `admin` | denylist add/remove, timelocked upgrade |
//! | `jurisdiction-flag` | `issuer` | setting/clearing jurisdiction flags, upgrade |
//! | `policy-engine` | `admin` | registering/removing checks, combine op |
//! | `compliance-aggregator` | `admin` | wiring gate/flag/breaker addresses, pause |
//! | `circuit-breaker` | `admin` | `freeze` / `unfreeze` (emergency stop) |
//! | `audit-log` | `admin` | audit-log administration |
//! | `pausable` (shared crate) | — | used *internally* here to back `pause`/`unpause` |
//!
//! Typical deployment: deploy `multisig-admin` first, initialize it with the
//! operations team's signer keys, then initialize each primitive with the
//! multisig's contract ID as its admin. One multisig can govern every
//! primitive in a deployment, giving a single auditable M-of-N policy. A
//! common pattern is to pair it with `audit-log` (record proposal creation,
//! approvals, and execution — see the `multisig-audit-trail` example) and to
//! make it the admin of `circuit-breaker` so that an emergency freeze still
//! requires quorum.
//!
//! ## Storage and TTL policy
//!
//! All state (signer set, threshold, pending proposals, next proposal ID,
//! pause flag) lives in **instance storage**, which shares a single TTL with
//! the contract instance entry. Every write path calls
//! `extend_instance_ttl`, which extends that TTL to
//! [`INSTANCE_TTL_EXTEND_TO`] ledgers (~30 days at ~5s/ledger) whenever the
//! remaining TTL has fallen below [`INSTANCE_TTL_THRESHOLD`] ledgers
//! (~1 day). A multisig that is written to at least once a month therefore
//! never becomes archived; one that sits idle longer must be restored (e.g.
//! `stellar contract restore`) before its admin powers can be exercised,
//! otherwise every governed primitive's `require_auth()` would fail.
//!
//! ## Upgradeability
//!
//! `upgrade(new_wasm_hash)` moves the contract's code to a new WASM hash via
//! `env.deployer().update_current_contract_wasm`, following the same
//! admin-gated pattern as `jurisdiction-flag::upgrade` and the
//! `policy-engine::propose_upgrade` / `commit_upgrade` / `cancel_upgrade` flow.
//! Because this contract *is* the admin, the gate is
//! `env.current_contract_address().require_auth()` — the upgrade must be
//! approved by the current M-of-N signer threshold through `__check_auth`,
//! exactly like `add_signer` / `update_threshold`.
//!
//! The WASM swap does not touch storage: the signer set, threshold, pending
//! proposals and the next proposal ID are all preserved, and the contract
//! address is unchanged, so every primitive that uses this contract as its
//! admin keeps working without reconfiguration. An `Upgraded` event carrying
//! the new WASM hash is emitted for auditability. If a future version changes
//! the storage layout it must ship a migration entrypoint, per
//! `STORAGE_VERSIONING.md`.
#![no_std]

use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contracterror, contractevent, contractimpl, contractmeta, contracttype,
    crypto::Hash,
    Address, BytesN, Env, Vec,
};

// Embed crate version and repository URL in the deployed WASM so operators
// can identify which release is live on-chain.
contractmeta!(key = "version", val = env!("CARGO_PKG_VERSION"));
contractmeta!(key = "source", val = env!("CARGO_PKG_REPOSITORY"));

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

/// Emitted when a new signer is added to the set.
///
/// topics : [Symbol("SignerAdded"), Address(signer)]
/// data   : {}
#[contractevent]
pub struct SignerAdded {
    #[topic]
    pub signer: Address,
}

/// Emitted when a signer is removed from the set.
///
/// topics : [Symbol("SignerRemoved"), Address(signer)]
/// data   : {}
#[contractevent]
pub struct SignerRemoved {
    #[topic]
    pub signer: Address,
}

/// Emitted when the signing threshold is updated.
///
/// topics : [Symbol("ThresholdSet")]
/// data   : { threshold: u32 }
#[contractevent]
pub struct ThresholdSet {
    pub threshold: u32,
}

/// Emitted on every successful `__check_auth` call.
///
/// topics : [Symbol("AuthOk")]
/// data   : { valid_count: u32, threshold: u32 }
#[contractevent]
pub struct AuthOk {
    pub valid_count: u32,
    pub threshold: u32,
}

/// Emitted when the contract is paused.
///
/// topics : [Symbol("Paused")]
/// data   : {}
#[contractevent]
pub struct ContractPausedEvent {}

/// Emitted when the contract is unpaused.
///
/// topics : [Symbol("Unpaused")]
/// data   : {}
#[contractevent]
pub struct ContractUnpausedEvent {}

/// Emitted when the contract WASM is upgraded.
///
/// topics : [Symbol("Upgraded")]
/// data   : { new_wasm_hash: BytesN<32> }
#[contractevent]
pub struct Upgraded {
    pub new_wasm_hash: BytesN<32>,
}

/// Emitted when `propose` creates a new proposal, so off-chain signers can
/// discover it without polling storage.
///
/// topics : [Symbol("proposal_created"), u64(id)]
/// data   : { expiry: u32, payload_hash: BytesN<32>, description_hash: Option<BytesN<32>> }
#[contractevent]
pub struct ProposalCreated {
    #[topic]
    pub id: u64,
    pub expiry: u32,
    /// SHA-256 of the proposal payload.
    pub payload_hash: BytesN<32>,
    /// Optional hash of the human-readable proposal document (#803).
    pub description_hash: Option<BytesN<32>>,
}

/// Emitted when `approve` records a signer's approval on a proposal.
///
/// topics : [Symbol("proposal_approved"), u64(id), Address(signer)]
/// data   : { approvals: u32 }
#[contractevent]
pub struct ProposalApproved {
    #[topic]
    pub id: u64,
    #[topic]
    pub signer: Address,
    /// Total number of approvals recorded on the proposal after this one.
    pub approvals: u32,
}

/// Emitted when a signer revokes their approval from a proposal.
///
/// topics : [Symbol("proposal_unapproved"), u64(id), Address(signer)]
/// data   : { approvals: u32 }
#[contractevent]
pub struct ProposalUnapproved {
    #[topic]
    pub id: u64,
    #[topic]
    pub signer: Address,
    pub approvals: u32,
}

/// Emitted when a pending proposal is cancelled by a signer.
///
/// topics : [Symbol("proposal_cancelled"), u64(id), Address(signer)]
/// data   : {}
#[contractevent]
pub struct ProposalCancelled {
    #[topic]
    pub id: u64,
    #[topic]
    pub signer: Address,
}

/// Emitted when a proposal is executed.
///
/// topics : [Symbol("ProposalExecuted")]
/// data   : { proposal_id: u64 }
#[contractevent]
pub struct ProposalExecuted {
    pub proposal_id: u64,
}

/// Emitted when the execution delay timelock is updated.
///
/// topics : [Symbol("ExecutionDelaySet")]
/// data   : { delay: u32 }
#[contractevent]
pub struct ExecutionDelaySet {
    pub delay: u32,
}

/// Emitted when a signer's weight is updated.
///
/// topics : [Symbol("SignerWeightSet"), Address(signer)]
/// data   : { weight: u32 }
#[contractevent]
pub struct SignerWeightSet {
    #[topic]
    pub signer: Address,
    pub weight: u32,
}

/// Emitted when existing equal-weighted signers are migrated to explicit weights.
///
/// topics : [Symbol("MigratedToWeighted")]
/// data   : { total_weight: u32 }
#[contractevent]
pub struct MigratedToWeighted {
    pub total_weight: u32,
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

/// Extend the instance TTL when it drops below this many ledgers
/// (~1 day at ~5s/ledger).
pub const INSTANCE_TTL_THRESHOLD: u32 = 17_280;

/// Target remaining instance TTL after extension (~30 days at ~5s/ledger).
pub const INSTANCE_TTL_EXTEND_TO: u32 = 518_400;

/// Refresh the TTL of the contract instance (and therefore of every
/// instance-storage entry: signers, threshold, proposals, pause flag).
/// Called on every write path so live state survives Soroban archival.
fn extend_instance_ttl(env: &Env) {
    env.storage()
        .instance()
        .extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);
}

#[contracttype]
#[derive(Clone)]
struct Proposal {
    /// The payload to execute (opaque bytes).
    pub payload: soroban_sdk::Bytes,
    /// Optional hash of a human-readable proposal document so signers can
    /// recognise what opaque `payload` bytes actually do (#803).
    pub description_hash: Option<BytesN<32>>,
    /// Ledger sequence at which this proposal expires.
    pub expiry: u32,
    /// Addresses that have approved this proposal.
    pub approvals: Vec<Address>,
    /// Ledger sequence at which execution timelock expires (0 if threshold not reached or no delay).
    pub eta: u32,
}

#[contracttype]
#[derive(Clone)]
enum DataKey {
    /// `Vec<Address>` — the current signer set.
    Signers,
    /// `u32` — minimum weight required to authorize.
    Threshold,
    /// `Proposal` — a pending proposal keyed by its ID.
    Proposal(u64),
    /// `u64` — the next proposal ID to assign.
    NextProposalId,
    /// `Vec<u64>` — IDs of proposals that are still open (#802).
    OpenProposals,
    /// `u32` — delay in ledgers required between reaching threshold and execution.
    ExecutionDelay,
    /// `u32` — weight of a specific signer (keyed by Address).
    SignerWeight(Address),
}

/// IDs of proposals that have not yet been executed, cancelled or expired.
fn open_proposals(env: &Env) -> Vec<u64> {
    env.storage()
        .instance()
        .get(&DataKey::OpenProposals)
        .unwrap_or_else(|| Vec::new(env))
}

fn remove_open_proposal(env: &Env, proposal_id: u64) {
    let ids = open_proposals(env);
    let mut remaining = Vec::new(env);
    let mut changed = false;
    for id in ids.iter() {
        if id == proposal_id {
            changed = true;
        } else {
            remaining.push_back(id);
        }
    }
    if changed {
        if remaining.is_empty() {
            env.storage().instance().remove(&DataKey::OpenProposals);
        } else {
            env.storage()
                .instance()
                .set(&DataKey::OpenProposals, &remaining);
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    /// Contract has not been initialized yet.
    NotInitialized = 1,
    /// `initialize` was called more than once.
    AlreadyInitialized = 2,
    /// The number of valid signatures in the provided set is below threshold.
    ThresholdNotMet = 3,
    /// Threshold value is invalid (zero, or greater than signer count).
    InvalidThreshold = 4,
    /// The address to remove is not currently in the signer set.
    SignerNotFound = 5,
    /// The address to add is already in the signer set.
    AlreadySigner = 6,
    /// The same signer address appears more than once in the provided
    /// signature set for a single `__check_auth` call.
    DuplicateSignature = 7,
    /// The contract is paused; no mutating operations are allowed.
    ContractPaused = 8,
    /// The referenced proposal does not exist.
    ProposalNotFound = 9,
    /// The proposal has passed its expiry ledger sequence.
    ExpiredProposal = 10,
    /// A duplicate signer address was found in the `signers` list passed to
    /// `initialize`. Duplicates are rejected because `__check_auth` counts
    /// distinct signer addresses, so a duplicated entry can make the
    /// threshold impossible to reach.
    DuplicateSigner = 11,
    /// The caller is not in the current signer set.
    NotASigner = 12,
    /// The signer has already approved this proposal.
    AlreadyApproved = 13,
    /// The signer has not approved this proposal.
    NotApproved = 14,
    /// Execution timelock delay has not yet passed.
    TimelockNotMet = 15,
    /// Signer weight is invalid (must be >= 1).
    InvalidWeight = 16,
    /// Number of signers does not match number of weights.
    WeightsMismatch = 17,
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contract]
pub struct MultisigAdmin;

#[contractimpl]
impl MultisigAdmin {
    // -----------------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------------

    /// One-time setup. `signers` is the initial signer set; `threshold` is
    /// the minimum number of valid signatures required (`1 <= threshold <=
    /// signers.len()`).
    pub fn initialize(
        env: Env,
        signers: Vec<Address>,
        threshold: u32,
    ) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Threshold) {
            return Err(Error::AlreadyInitialized);
        }

        // Reject duplicate signer addresses. `__check_auth` counts distinct
        // signer addresses, so a duplicate entry means the effective signer
        // count is smaller than `signers.len()` and a threshold validated
        // against the raw count can be impossible to reach — permanently
        // locking the contract and everything it governs.
        for i in 0..signers.len() {
            let addr_i = signers.get(i).unwrap();
            for j in (i + 1)..signers.len() {
                if signers.get(j).unwrap() == addr_i {
                    return Err(Error::DuplicateSigner);
                }
            }
        }

        if threshold == 0 || threshold as usize > signers.len() as usize {
            return Err(Error::InvalidThreshold);
        }
        env.storage().instance().set(&DataKey::Signers, &signers);
        env.storage()
            .instance()
            .set(&DataKey::Threshold, &threshold);

        // Initialize default weight of 1 for all signers
        for i in 0..signers.len() {
            let signer = signers.get(i).unwrap();
            env.storage()
                .instance()
                .set(&DataKey::SignerWeight(signer), &1u32);
        }

        extend_instance_ttl(&env);
        Ok(())
    }

    /// One-time setup with custom signer weights. `signers` is the initial signer set;
    /// `weights` is the corresponding weight for each signer; `threshold` is the minimum
    /// total weight required to authorize.
    pub fn initialize_with_weights(
        env: Env,
        signers: Vec<Address>,
        weights: Vec<u32>,
        threshold: u32,
    ) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Threshold) {
            return Err(Error::AlreadyInitialized);
        }

        if signers.len() != weights.len() {
            return Err(Error::WeightsMismatch);
        }

        for i in 0..signers.len() {
            let addr_i = signers.get(i).unwrap();
            for j in (i + 1)..signers.len() {
                if signers.get(j).unwrap() == addr_i {
                    return Err(Error::DuplicateSigner);
                }
            }
        }

        let mut total_weight: u32 = 0;
        for i in 0..weights.len() {
            let w = weights.get(i).unwrap();
            if w == 0 {
                return Err(Error::InvalidWeight);
            }
            total_weight = total_weight.saturating_add(w);
        }

        if threshold == 0 || threshold > total_weight {
            return Err(Error::InvalidThreshold);
        }

        env.storage().instance().set(&DataKey::Signers, &signers);
        env.storage()
            .instance()
            .set(&DataKey::Threshold, &threshold);

        for i in 0..signers.len() {
            let signer = signers.get(i).unwrap();
            let weight = weights.get(i).unwrap();
            env.storage()
                .instance()
                .set(&DataKey::SignerWeight(signer), &weight);
        }

        extend_instance_ttl(&env);
        Ok(())
    }

    /// Set an execution delay (in ledgers) between reaching threshold and execution.
    /// Requires current multisig threshold.
    pub fn set_execution_delay(env: Env, delay: u32) -> Result<(), Error> {
        compliance_pausable::require_not_paused_or(&env, Error::ContractPaused)?;
        env.current_contract_address().require_auth();

        env.storage()
            .instance()
            .set(&DataKey::ExecutionDelay, &delay);
        extend_instance_ttl(&env);
        ExecutionDelaySet { delay }.publish(&env);
        Ok(())
    }

    /// Return the execution delay (in ledgers), or 0 if none is configured.
    pub fn get_execution_delay(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::ExecutionDelay)
            .unwrap_or(0)
    }

    /// Set the weight of a specific signer. Requires current multisig threshold.
    pub fn set_signer_weight(env: Env, signer: Address, weight: u32) -> Result<(), Error> {
        compliance_pausable::require_not_paused_or(&env, Error::ContractPaused)?;
        env.current_contract_address().require_auth();

        if weight == 0 {
            return Err(Error::InvalidWeight);
        }

        let signers: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Signers)
            .ok_or(Error::NotInitialized)?;

        let mut is_signer = false;
        for i in 0..signers.len() {
            if signers.get(i).unwrap() == signer {
                is_signer = true;
                break;
            }
        }
        if !is_signer {
            return Err(Error::SignerNotFound);
        }

        env.storage()
            .instance()
            .set(&DataKey::SignerWeight(signer.clone()), &weight);
        extend_instance_ttl(&env);

        let total_weight = Self::get_total_weight(env.clone());
        let threshold = Self::get_threshold(env.clone());
        if total_weight < threshold {
            return Err(Error::InvalidThreshold);
        }

        SignerWeightSet { signer, weight }.publish(&env);
        Ok(())
    }

    /// Returns the weight of a specific signer (defaults to 1 if signer is in set, 0 if not).
    pub fn get_signer_weight(env: Env, signer: Address) -> u32 {
        let signers: Vec<Address> = match env.storage().instance().get(&DataKey::Signers) {
            Some(s) => s,
            None => return 0,
        };

        let mut is_signer = false;
        for i in 0..signers.len() {
            if signers.get(i).unwrap() == signer {
                is_signer = true;
                break;
            }
        }
        if !is_signer {
            return 0;
        }

        env.storage()
            .instance()
            .get(&DataKey::SignerWeight(signer))
            .unwrap_or(1)
    }

    /// Returns the total weight of all signers in the current signer set.
    pub fn get_total_weight(env: Env) -> u32 {
        let signers: Vec<Address> = match env.storage().instance().get(&DataKey::Signers) {
            Some(s) => s,
            None => return 0,
        };

        let mut total: u32 = 0;
        for i in 0..signers.len() {
            let signer = signers.get(i).unwrap();
            let weight = env
                .storage()
                .instance()
                .get(&DataKey::SignerWeight(signer))
                .unwrap_or(1);
            total = total.saturating_add(weight);
        }
        total
    }

    /// Explicitly migrates existing equal-weighted signers by writing weight 1 for each signer.
    /// Requires current multisig threshold.
    pub fn migrate_to_weighted(env: Env) -> Result<(), Error> {
        compliance_pausable::require_not_paused_or(&env, Error::ContractPaused)?;
        env.current_contract_address().require_auth();

        let signers: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Signers)
            .ok_or(Error::NotInitialized)?;

        for i in 0..signers.len() {
            let signer = signers.get(i).unwrap();
            if !env.storage().instance().has(&DataKey::SignerWeight(signer.clone())) {
                env.storage()
                    .instance()
                    .set(&DataKey::SignerWeight(signer), &1u32);
            }
        }

        extend_instance_ttl(&env);
        let total_weight = Self::get_total_weight(env.clone());
        MigratedToWeighted { total_weight }.publish(&env);
        Ok(())
    }

    /// Pause the contract to prevent new proposals/approvals. Requires multisig threshold.
    pub fn pause(env: Env) -> Result<(), Error> {
        env.current_contract_address().require_auth();
        compliance_pausable::pause(&env);
        extend_instance_ttl(&env);
        ContractPausedEvent {}.publish(&env);
        Ok(())
    }

    /// Resume operations after a pause. Requires multisig threshold.
    pub fn unpause(env: Env) -> Result<(), Error> {
        env.current_contract_address().require_auth();
        compliance_pausable::unpause(&env);
        extend_instance_ttl(&env);
        ContractUnpausedEvent {}.publish(&env);
        Ok(())
    }

    /// Check if the contract is currently paused.
    pub fn is_paused(env: Env) -> bool {
        compliance_pausable::is_paused(&env)
    }

    /// Upgrade the contract WASM to `new_wasm_hash`. Requires the current
    /// M-of-N threshold (the call goes through `__check_auth`).
    ///
    /// All storage — signers, threshold and proposals — is preserved across
    /// the upgrade and the contract address does not change. The new WASM
    /// must already be uploaded to the network.
    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) -> Result<(), Error> {
        if !env.storage().instance().has(&DataKey::Threshold) {
            return Err(Error::NotInitialized);
        }
        env.current_contract_address().require_auth();
        env.deployer()
            .update_current_contract_wasm(new_wasm_hash.clone());
        Upgraded { new_wasm_hash }.publish(&env);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Signer-set management (all require the current multisig threshold)
    // -----------------------------------------------------------------------

    /// Add `new_signer` to the signer set. Requires the current M-of-N
    /// threshold to be met (the call goes through `__check_auth`).
    pub fn add_signer(env: Env, new_signer: Address) -> Result<(), Error> {
        compliance_pausable::require_not_paused_or(&env, Error::ContractPaused)?;
        // Require auth from this contract itself — satisfied by __check_auth.
        env.current_contract_address().require_auth();

        let mut signers: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Signers)
            .ok_or(Error::NotInitialized)?;

        // Reject duplicates.
        for i in 0..signers.len() {
            if signers.get(i).unwrap() == new_signer {
                return Err(Error::AlreadySigner);
            }
        }

        signers.push_back(new_signer.clone());
        env.storage().instance().set(&DataKey::Signers, &signers);
        // Default weight is 1 if not previously configured
        if !env.storage().instance().has(&DataKey::SignerWeight(new_signer.clone())) {
            env.storage()
                .instance()
                .set(&DataKey::SignerWeight(new_signer.clone()), &1u32);
        }
        extend_instance_ttl(&env);
        SignerAdded { signer: new_signer }.publish(&env);
        Ok(())
    }

    /// Remove `signer` from the signer set. Requires the current M-of-N
    /// threshold. The resulting signer weight must still be >= threshold.
    pub fn remove_signer(env: Env, signer: Address) -> Result<(), Error> {
        compliance_pausable::require_not_paused_or(&env, Error::ContractPaused)?;
        env.current_contract_address().require_auth();

        let mut signers: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Signers)
            .ok_or(Error::NotInitialized)?;
        let threshold: u32 = env
            .storage()
            .instance()
            .get(&DataKey::Threshold)
            .ok_or(Error::NotInitialized)?;

        // Find the index of the signer to remove.
        let mut found_index: Option<u32> = None;
        for i in 0..signers.len() {
            if signers.get(i).unwrap() == signer {
                found_index = Some(i);
                break;
            }
        }
        let index = found_index.ok_or(Error::SignerNotFound)?;

        signers.remove(index);
        env.storage()
            .instance()
            .remove(&DataKey::SignerWeight(signer.clone()));
        env.storage().instance().set(&DataKey::Signers, &signers);

        // Guard: resulting total weight must still satisfy the threshold.
        let total_weight = Self::get_total_weight(env.clone());
        if total_weight < threshold {
            return Err(Error::InvalidThreshold);
        }

        extend_instance_ttl(&env);
        SignerRemoved { signer }.publish(&env);
        Ok(())
    }

    /// Update the signing threshold. Requires the current M-of-N threshold.
    pub fn update_threshold(env: Env, threshold: u32) -> Result<(), Error> {
        compliance_pausable::require_not_paused_or(&env, Error::ContractPaused)?;
        env.current_contract_address().require_auth();

        let total_weight = Self::get_total_weight(env.clone());
        if threshold == 0 || threshold > total_weight {
            return Err(Error::InvalidThreshold);
        }

        env.storage()
            .instance()
            .set(&DataKey::Threshold, &threshold);
        extend_instance_ttl(&env);
        ThresholdSet { threshold }.publish(&env);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Read-only accessors
    // -----------------------------------------------------------------------

    /// Returns the currently configured signer set together with the
    /// signing threshold, as `(signers, threshold)`. Used by off-chain
    /// tooling (e.g. the indexer) and by other contracts deciding whether to
    /// trust this contract as an admin.
    pub fn get_signers(env: Env) -> (Vec<Address>, u32) {
        let signers: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Signers)
            .unwrap_or_else(|| Vec::new(&env));
        let threshold: u32 = env
            .storage()
            .instance()
            .get(&DataKey::Threshold)
            .unwrap_or(0);
        (signers, threshold)
    }

    pub fn get_threshold(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::Threshold)
            .unwrap_or(0)
    }

    // -----------------------------------------------------------------------
    // Proposal workflow
    // -----------------------------------------------------------------------

    /// Create a new proposal with the given payload. Returns the proposal ID.
    /// The proposal expires at `expiry_ledger`.
    ///
    /// Emits `ProposalCreated { id, expiry, payload_hash }`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // `multisig` is a `MultisigAdminClient`; signers approve until the threshold is met.
    /// let id = multisig.propose(&payload, &expiry_ledger);
    /// multisig.approve(&id, &signer_a);
    /// multisig.approve(&id, &signer_b);
    /// multisig.execute(&id);
    /// ```
    pub fn propose(
        env: Env,
        payload: soroban_sdk::Bytes,
        expiry_ledger: u32,
    ) -> Result<u64, Error> {
        Self::propose_with_description(env, payload, expiry_ledger, None)
    }

    /// Create a proposal carrying an optional hash of a human-readable
    /// description, so signers reviewing opaque payload bytes in a wallet can
    /// tell what they are approving (#803).
    pub fn propose_with_description(
        env: Env,
        payload: soroban_sdk::Bytes,
        expiry_ledger: u32,
        description_hash: Option<BytesN<32>>,
    ) -> Result<u64, Error> {
        compliance_pausable::require_not_paused_or(&env, Error::ContractPaused)?;
        let current_ledger = env.ledger().sequence();
        if expiry_ledger <= current_ledger {
            return Err(Error::ExpiredProposal);
        }

        let proposal_id: u64 = env
            .storage()
            .instance()
            .get(&DataKey::NextProposalId)
            .unwrap_or(0);

        // Guard: contract must be initialized before proposals can be created.
        if !env.storage().instance().has(&DataKey::Signers) {
            return Err(Error::NotInitialized);
        }

        let payload_hash: BytesN<32> = env.crypto().sha256(&payload).to_bytes();
        let proposal = Proposal {
            payload,
            description_hash: description_hash.clone(),
            expiry: expiry_ledger,
            approvals: Vec::new(&env),
            eta: 0,
        };

        env.storage()
            .instance()
            .set(&DataKey::Proposal(proposal_id), &proposal);
        env.storage()
            .instance()
            .set(&DataKey::NextProposalId, &(proposal_id + 1));
        let mut open = open_proposals(&env);
        open.push_back(proposal_id);
        env.storage().instance().set(&DataKey::OpenProposals, &open);
        extend_instance_ttl(&env);

        ProposalCreated {
            id: proposal_id,
            expiry: expiry_ledger,
            payload_hash,
            description_hash,
        }
        .publish(&env);

        Ok(proposal_id)
    }

    /// Approve a proposal. The approver must be a valid signer. A signer can
    /// only approve once. Returns true if the proposal now has enough approvals
    /// to execute.
    ///
    /// Emits `ProposalApproved { id, signer, approvals }`.
    pub fn approve(env: Env, proposal_id: u64, approver: Address) -> Result<bool, Error> {
        compliance_pausable::require_not_paused_or(&env, Error::ContractPaused)?;
        // The approver must prove they authorized this call — prevents any
        // caller from submitting someone else's approval on their behalf.
        approver.require_auth();
        let current_ledger = env.ledger().sequence();

        let mut proposal: Proposal = env
            .storage()
            .instance()
            .get(&DataKey::Proposal(proposal_id))
            .ok_or(Error::ProposalNotFound)?;

        if current_ledger >= proposal.expiry {
            return Err(Error::ExpiredProposal);
        }

        let signers: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Signers)
            .ok_or(Error::NotInitialized)?;

        // Verify approver is in the signer set.
        let mut is_valid_signer = false;
        for i in 0..signers.len() {
            if signers.get(i).unwrap() == approver {
                is_valid_signer = true;
                break;
            }
        }
        if !is_valid_signer {
            return Err(Error::NotASigner);
        }

        // Check if already approved.
        for i in 0..proposal.approvals.len() {
            if proposal.approvals.get(i).unwrap() == approver {
                return Err(Error::AlreadyApproved);
            }
        }

        proposal.approvals.push_back(approver.clone());

        // Count approved weight from active signers.
        let threshold: u32 = env
            .storage()
            .instance()
            .get(&DataKey::Threshold)
            .ok_or(Error::NotInitialized)?;

        let mut approved_weight: u32 = 0;
        for i in 0..proposal.approvals.len() {
            let addr = proposal.approvals.get(i).unwrap();
            for j in 0..signers.len() {
                if signers.get(j).unwrap() == addr {
                    let w = Self::get_signer_weight(env.clone(), addr);
                    approved_weight = approved_weight.saturating_add(w);
                    break;
                }
            }
        }

        // If threshold reached and eta is not set yet, set timelock.
        if approved_weight >= threshold && proposal.eta == 0 {
            let delay = Self::get_execution_delay(env.clone());
            proposal.eta = current_ledger + delay;
        }

        env.storage()
            .instance()
            .set(&DataKey::Proposal(proposal_id), &proposal);
        extend_instance_ttl(&env);

        ProposalApproved {
            id: proposal_id,
            signer: approver,
            approvals: proposal.approvals.len(),
        }
        .publish(&env);

        Ok(approved_weight >= threshold)
    }

    /// Revoke a signer's earlier approval on a pending proposal.
    /// Emits `ProposalUnapproved { id, signer, approvals }`.
    pub fn unapprove(env: Env, signer: Address, proposal_id: u64) -> Result<bool, Error> {
        compliance_pausable::require_not_paused_or(&env, Error::ContractPaused)?;
        signer.require_auth();
        let current_ledger = env.ledger().sequence();

        let mut proposal: Proposal = env
            .storage()
            .instance()
            .get(&DataKey::Proposal(proposal_id))
            .ok_or(Error::ProposalNotFound)?;

        if current_ledger >= proposal.expiry {
            return Err(Error::ExpiredProposal);
        }

        let signers: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Signers)
            .ok_or(Error::NotInitialized)?;

        // Verify signer is in the current signer set.
        let mut is_valid_signer = false;
        for i in 0..signers.len() {
            if signers.get(i).unwrap() == signer {
                is_valid_signer = true;
                break;
            }
        }
        if !is_valid_signer {
            return Err(Error::NotASigner);
        }

        // Find and remove approval.
        let mut found_idx: Option<u32> = None;
        for i in 0..proposal.approvals.len() {
            if proposal.approvals.get(i).unwrap() == signer {
                found_idx = Some(i);
                break;
            }
        }
        let idx = found_idx.ok_or(Error::NotApproved)?;
        proposal.approvals.remove(idx);

        let threshold: u32 = env
            .storage()
            .instance()
            .get(&DataKey::Threshold)
            .ok_or(Error::NotInitialized)?;

        let mut approved_weight: u32 = 0;
        for i in 0..proposal.approvals.len() {
            let addr = proposal.approvals.get(i).unwrap();
            for j in 0..signers.len() {
                if signers.get(j).unwrap() == addr {
                    let w = Self::get_signer_weight(env.clone(), addr);
                    approved_weight = approved_weight.saturating_add(w);
                    break;
                }
            }
        }

        // If approval falls below threshold, reset eta.
        if approved_weight < threshold {
            proposal.eta = 0;
        }

        env.storage()
            .instance()
            .set(&DataKey::Proposal(proposal_id), &proposal);
        extend_instance_ttl(&env);

        ProposalUnapproved {
            id: proposal_id,
            signer,
            approvals: proposal.approvals.len(),
        }
        .publish(&env);

        Ok(approved_weight >= threshold)
    }

    /// Cancel a pending proposal. May be called by any valid signer.
    /// Emits `ProposalCancelled { id, signer }`.
    pub fn cancel(env: Env, signer: Address, proposal_id: u64) -> Result<(), Error> {
        compliance_pausable::require_not_paused_or(&env, Error::ContractPaused)?;
        signer.require_auth();

        let signers: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Signers)
            .ok_or(Error::NotInitialized)?;

        let mut is_valid_signer = false;
        for i in 0..signers.len() {
            if signers.get(i).unwrap() == signer {
                is_valid_signer = true;
                break;
            }
        }
        if !is_valid_signer {
            return Err(Error::NotASigner);
        }

        if !env.storage().instance().has(&DataKey::Proposal(proposal_id)) {
            return Err(Error::ProposalNotFound);
        }

        env.storage()
            .instance()
            .remove(&DataKey::Proposal(proposal_id));
        extend_instance_ttl(&env);

        ProposalCancelled {
            id: proposal_id,
            signer,
        }
        .publish(&env);

        Ok(())
    }

    /// Execute a proposal. Requires that it has at least `threshold` weight,
    /// has not expired, and any configured execution delay has elapsed.
    pub fn execute(env: Env, proposal_id: u64) -> Result<(), Error> {
        let current_ledger = env.ledger().sequence();

        let proposal: Proposal = env
            .storage()
            .instance()
            .get(&DataKey::Proposal(proposal_id))
            .ok_or(Error::ProposalNotFound)?;

        if current_ledger >= proposal.expiry {
            return Err(Error::ExpiredProposal);
        }

        let threshold: u32 = env
            .storage()
            .instance()
            .get(&DataKey::Threshold)
            .ok_or(Error::NotInitialized)?;

        // Count only approvals from addresses still in the current signer set.
        let signers: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Signers)
            .ok_or(Error::NotInitialized)?;

        let mut valid_approval_weight: u32 = 0;
        for i in 0..proposal.approvals.len() {
            let approver = proposal.approvals.get(i).unwrap();
            for j in 0..signers.len() {
                if signers.get(j).unwrap() == approver {
                    let w = Self::get_signer_weight(env.clone(), approver);
                    valid_approval_weight = valid_approval_weight.saturating_add(w);
                    break;
                }
            }
        }

        if valid_approval_weight < threshold {
            return Err(Error::ThresholdNotMet);
        }

        // Verify execution timelock delay has elapsed.
        if proposal.eta > 0 && current_ledger < proposal.eta {
            return Err(Error::TimelockNotMet);
        }

        env.storage()
            .instance()
            .remove(&DataKey::Proposal(proposal_id));
        remove_open_proposal(&env, proposal_id);
        extend_instance_ttl(&env);

        // Emit an on-chain event so off-chain indexers can track which
        // proposals have been executed and when.
        ProposalExecuted { proposal_id }.publish(&env);

        Ok(())
    }

    /// Cancel a pending proposal. Only a current signer may cancel, and the
    /// proposal is removed from both storage and the open-proposal index (#802).
    pub fn cancel_proposal(env: Env, proposal_id: u64, signer: Address) -> Result<(), Error> {
        signer.require_auth();
        let signers: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Signers)
            .ok_or(Error::NotInitialized)?;
        if !signers.contains(signer) {
            return Err(Error::NotASigner);
        }
        if !env.storage().instance().has(&DataKey::Proposal(proposal_id)) {
            return Err(Error::ProposalNotFound);
        }
        env.storage()
            .instance()
            .remove(&DataKey::Proposal(proposal_id));
        remove_open_proposal(&env, proposal_id);
        extend_instance_ttl(&env);
        env.events()
            .publish((soroban_sdk::Symbol::new(&env, "prop_cancel"),), proposal_id);
        Ok(())
    }

    /// List open proposal IDs, skipping expired ones and pruning their state.
    ///
    /// `start` is an index into the open list and `limit` bounds the page so a
    /// caller cannot be forced to decode an unbounded vector (#802).
    pub fn list_proposals(env: Env, start: u32, limit: u32) -> Vec<u64> {
        let current_ledger = env.ledger().sequence();
        let ids = open_proposals(&env);
        let mut kept = Vec::new(&env);
        let mut result = Vec::new(&env);
        let mut position: u32 = 0;

        for id in ids.iter() {
            let proposal: Option<Proposal> = env
                .storage()
                .instance()
                .get(&DataKey::Proposal(id));
            let live = match proposal {
                Some(p) if p.expiry > current_ledger => true,
                _ => {
                    env.storage().instance().remove(&DataKey::Proposal(id));
                    false
                }
            };
            if !live {
                continue;
            }
            kept.push_back(id);
            if position >= start && (limit == 0 || result.len() < limit) {
                result.push_back(id);
            }
            position += 1;
        }

        if kept.len() != ids.len() {
            if kept.is_empty() {
                env.storage().instance().remove(&DataKey::OpenProposals);
            } else {
                env.storage()
                    .instance()
                    .set(&DataKey::OpenProposals, &kept);
            }
        }
        result
    }

    /// Get the details of a proposal (payload, expiry, current approvals).
    pub fn get_proposal(
        env: Env,
        proposal_id: u64,
    ) -> Result<(soroban_sdk::Bytes, u32, Vec<Address>, Option<BytesN<32>>), Error> {
        let proposal: Proposal = env
            .storage()
            .instance()
            .get(&DataKey::Proposal(proposal_id))
            .ok_or(Error::ProposalNotFound)?;
        Ok((
            proposal.payload,
            proposal.expiry,
            proposal.approvals,
            proposal.description_hash,
        ))
    }

    /// Return the execution timelock ETA ledger sequence for a proposal (0 if not locked).
    pub fn get_proposal_eta(env: Env, proposal_id: u64) -> Result<u32, Error> {
        let proposal: Proposal = env
            .storage()
            .instance()
            .get(&DataKey::Proposal(proposal_id))
            .ok_or(Error::ProposalNotFound)?;
        Ok(proposal.eta)
    }
}

// ---------------------------------------------------------------------------
// Custom account interface — the heart of the multisig pattern
// ---------------------------------------------------------------------------

impl CustomAccountInterface for MultisigAdmin {
    /// The signature type is a `Vec<Address>` — the list of approving signer
    /// addresses. The invoker must provide addresses that are all present in
    /// the stored signer set whose total weight meets or exceeds `threshold`.
    type Signature = Vec<Address>;
    type Error = Error;

    #[allow(unused_variables)]
    fn __check_auth(
        env: Env,
        signature_payload: Hash<32>,
        signatures: Vec<Address>,
        auth_context: Vec<Context>,
    ) -> Result<(), Error> {
        let signers: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Signers)
            .ok_or(Error::NotInitialized)?;
        let threshold: u32 = env
            .storage()
            .instance()
            .get(&DataKey::Threshold)
            .ok_or(Error::NotInitialized)?;

        // Reject if the same signer address appears more than once.
        for i in 0..signatures.len() {
            let addr_i = signatures.get(i).unwrap();
            for j in (i + 1)..signatures.len() {
                if signatures.get(j).unwrap() == addr_i {
                    return Err(Error::DuplicateSignature);
                }
            }
        }

        let mut valid_weight: u32 = 0;

        for i in 0..signatures.len() {
            let sig_addr = signatures.get(i).unwrap();
            sig_addr.require_auth();

            for j in 0..signers.len() {
                if signers.get(j).unwrap() == sig_addr {
                    let weight = Self::get_signer_weight(env.clone(), sig_addr.clone());
                    valid_weight = valid_weight.saturating_add(weight);
                    break;
                }
            }
        }

        if valid_weight >= threshold {
            AuthOk {
                valid_count: valid_weight,
                threshold,
            }
            .publish(&env);
            Ok(())
        } else {
            Err(Error::ThresholdNotMet)
        }
    }
}

#[cfg(test)]
mod test;
