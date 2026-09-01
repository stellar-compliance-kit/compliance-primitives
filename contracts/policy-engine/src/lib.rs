//! `policy-engine` is a `#![no_std]` Soroban contract that composes multiple
//! compliance checks into a single policy evaluation call.
//!
//! ## AND / OR design choice
//!
//! Compliance use cases almost always reduce to one of two logical shapes:
//! every check must pass (AND — "this address must be allowlisted **and** in
//! a permitted jurisdiction") or at least one must pass (OR — "this address
//! either cleared KYC with provider A **or** provider B"). A two-variant
//! `CombineOp` enum (`All` / `Any`) covers both without the overhead of an
//! AST, which would be over-engineered for this domain and would add
//! significant complexity to the storage, serialization, and auditing story.
//!
//! ## Check failure surfacing
//!
//! `evaluate` returns `Ok(bool)` rather than panicking or returning an
//! opaque error on a failed policy: a Soroban invocation that returns a
//! contract error rolls back all state changes including emitted events, so
//! any failure audit trail would be silently discarded. By returning
//! `Ok(false)` and emitting a `PolicyResult` event the caller gets a
//! machine-readable result and the chain preserves an auditable record of
//! the decision, consistent with the pattern used in `allowlist-token`.
//!
//! ## Registration design
//!
//! Checks are stored as an admin-managed, mutable `Vec<CheckKind>` in
//! persistent storage. This lets the issuer add, reorder, or remove checks
//! as compliance requirements evolve — without redeploying or upgrading the
//! contract binary. An authorized admin is required for all mutations,
//! keeping the policy immutable to unprivileged callers.
#![no_std]

use soroban_sdk::{
    contract, contractclient, contracterror, contractevent, contractimpl, contracttype,
    Address, Env, String, Symbol, Vec,
};

// ---------------------------------------------------------------------------
// Cross-contract client interfaces
// ---------------------------------------------------------------------------

/// Describes the `denylist-gate` contract interface used for cross-contract
/// calls. The generated `DenylistCheckClient` is used in `evaluate` to call
/// `check()` on a deployed denylist-gate instance. We do not take a direct
/// crate dependency on `denylist-gate` to avoid colliding wasm exports.
#[contractclient(name = "DenylistCheckClient")]
pub trait DenylistCheckInterface {
    fn check(env: Env, address: Address) -> bool;
}

/// Describes the `jurisdiction-flag` contract interface used for
/// cross-contract calls. The generated `JurisdictionCheckClient` is used in
/// `evaluate`. Same reason as above for avoiding a direct crate dep.
#[contractclient(name = "JurisdictionCheckClient")]
pub trait JurisdictionCheckInterface {
    fn is_permitted_jurisdiction(env: Env, address: Address, allowed_codes: Vec<String>) -> bool;
}

// ---------------------------------------------------------------------------
// Storage types
// ---------------------------------------------------------------------------

/// Describes a single compliance check the engine should perform.
///
/// Each variant carries the address of the external contract that implements
/// the check plus any parameters that check needs.
#[contracttype]
#[derive(Clone)]
pub enum CheckKind {
    /// Call `denylist-gate.check(address)`. The address must **not** be on
    /// the denylist for this check to pass.
    Denylist { contract: Address },
    /// Call `jurisdiction-flag.is_permitted_jurisdiction(address,
    /// allowed_codes)`. The address must have a jurisdiction code in
    /// `allowed_codes` for this check to pass.
    Jurisdiction {
        contract: Address,
        allowed_codes: Vec<String>,
    },
}

/// How the engine combines the results of multiple checks.
#[contracttype]
#[derive(Clone, PartialEq)]
pub enum CombineOp {
    /// AND — every check must pass. Used when an address must satisfy all
    /// compliance requirements simultaneously.
    All,
    /// OR — at least one check must pass. Used when multiple equivalent
    /// compliance paths exist (e.g. two KYC providers).
    Any,
}

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Admin,
    Checks,
    CombineOp,
}

// ---------------------------------------------------------------------------
// Errors and events
// ---------------------------------------------------------------------------

/// Maximum number of addresses accepted by `batch_evaluate` in a single call.
///
/// Soroban imposes a per-transaction CPU-instruction and memory budget. Each
/// address in the batch requires one or more cross-contract calls (one per
/// registered check), so an unbounded list would allow a caller to exhaust
/// the budget and brick the transaction. 20 was chosen to mirror the limit
/// used in the `compliance-aggregator` batch family and to keep the worst-case
/// instruction cost within the conservative end of the Soroban default budget.
pub const MAX_BATCH_SIZE: u32 = 20;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    NotInitialized = 1,
    AlreadyInitialized = 2,
    NotAuthorized = 3,
    PolicyViolation = 4,
    /// `batch_evaluate` was called with more than `MAX_BATCH_SIZE` addresses.
    BatchTooLarge = 5,
    ContractPaused = 6,
}

/// Emitted by `evaluate` regardless of the pass/fail outcome so that
/// off-chain compliance tooling can build a full audit trail even when the
/// policy passes (which wouldn't produce an error event).
#[contractevent]
pub struct PolicyResult {
    #[topic]
    pub passed: bool,
    pub from: Address,
    pub to: Address,
}

/// Carries information about which check in the list failed and what kind it
/// was. Serializable on-chain; can be embedded in future error events or
/// returned from an extended evaluate variant.
#[contracttype]
#[derive(Clone)]
#[allow(dead_code)]
pub struct CheckFailure {
    pub check_index: u32,
    pub kind: Symbol,
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contract]
pub struct PolicyEngine;

#[contractimpl]
impl PolicyEngine {
    // -----------------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------------

    /// One-time initializer. Sets `admin` as the authorized manager and
    /// `op` as the combination operator for all future evaluations.
    /// Initializes the check list to empty.
    pub fn initialize(env: Env, admin: Address, op: CombineOp) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::CombineOp, &op);
        let empty: Vec<CheckKind> = Vec::new(&env);
        env.storage().instance().set(&DataKey::Checks, &empty);
        Ok(())
    }

    /// Pause policy mutations (`add_check` / `remove_check`). Admin-only.
    pub fn pause(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        compliance_pausable::pause(&env);
        env.events().publish((), soroban_sdk::symbol_short!("Paused"));
        Ok(())
    }

    /// Resume policy mutations after a pause. Admin-only.
    pub fn unpause(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        compliance_pausable::unpause(&env);
        env.events().publish((), soroban_sdk::symbol_short!("Unpaused"));
        Ok(())
    }

    /// Check if the contract is currently paused.
    pub fn is_paused(env: Env) -> bool {
        compliance_pausable::is_paused(&env)
    }

    // -----------------------------------------------------------------------
    // Admin mutations
    // -----------------------------------------------------------------------

    /// Append a new `check` to the end of the policy list. Admin-only.
    pub fn add_check(env: Env, admin: Address, check: CheckKind) -> Result<(), Error> {
        compliance_pausable::require_not_paused_or(&env, Error::ContractPaused)?;
        Self::require_admin(&env, &admin)?;
        let mut checks: Vec<CheckKind> = env
            .storage()
            .instance()
            .get(&DataKey::Checks)
            .ok_or(Error::NotInitialized)?;
        checks.push_back(check);
        env.storage().instance().set(&DataKey::Checks, &checks);
        Ok(())
    }

    /// Remove the check at position `index` from the policy list.
    /// Admin-only. Indices shift down after removal (Vec::remove semantics).
    pub fn remove_check(env: Env, admin: Address, index: u32) -> Result<(), Error> {
        compliance_pausable::require_not_paused_or(&env, Error::ContractPaused)?;
        Self::require_admin(&env, &admin)?;
        let mut checks: Vec<CheckKind> = env
            .storage()
            .instance()
            .get(&DataKey::Checks)
            .ok_or(Error::NotInitialized)?;
        checks.remove(index);
        env.storage().instance().set(&DataKey::Checks, &checks);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Evaluation
    // -----------------------------------------------------------------------

    /// Evaluate the current policy for a proposed transfer from `from` to
    /// `to`. Runs every registered check against both addresses using the
    /// configured `CombineOp`.
    ///
    /// Returns `Ok(true)` if the policy passes, `Ok(false)` if it fails.
    /// A `PolicyResult` event is always emitted so the outcome is auditable
    /// on-chain regardless of the result. `Err` is returned only for
    /// configuration failures (e.g. the contract was never initialized).
    pub fn evaluate(env: Env, from: Address, to: Address) -> Result<bool, Error> {
        let checks: Vec<CheckKind> = env
            .storage()
            .instance()
            .get(&DataKey::Checks)
            .ok_or(Error::NotInitialized)?;
        let op: CombineOp = env
            .storage()
            .instance()
            .get(&DataKey::CombineOp)
            .ok_or(Error::NotInitialized)?;

        let passed = match op {
            CombineOp::All => {
                // All checks must pass for both from and to.
                let mut all_pass = true;
                for i in 0..checks.len() {
                    let check = checks.get(i).unwrap();
                    if !Self::run_check(&env, &check, &from)
                        || !Self::run_check(&env, &check, &to)
                    {
                        all_pass = false;
                        break;
                    }
                }
                all_pass
            }
            CombineOp::Any => {
                // At least one check must pass for both from and to.
                if checks.is_empty() {
                    false
                } else {
                    let mut any_pass = false;
                    for i in 0..checks.len() {
                        let check = checks.get(i).unwrap();
                        if Self::run_check(&env, &check, &from)
                            && Self::run_check(&env, &check, &to)
                        {
                            any_pass = true;
                            break;
                        }
                    }
                    any_pass
                }
            }
        };

        PolicyResult {
            passed,
            from: from.clone(),
            to: to.clone(),
        }
        .publish(&env);

        Ok(passed)
    }

    /// Evaluate the configured policy for each address in `addresses`
    /// individually and return a `Vec<bool>` of results in the same order.
    ///
    /// Each address is run through every registered check on its own — this
    /// is a per-address (not per-transfer) evaluation. Use `evaluate` when
    /// you need to gate a specific `from → to` transfer; use `batch_evaluate`
    /// when you want to screen a list of addresses in a single call (e.g.
    /// pre-screening a participant registry).
    ///
    /// Returns `Err(Error::BatchTooLarge)` if `addresses.len() >
    /// MAX_BATCH_SIZE` to prevent budget exhaustion. Returns
    /// `Err(Error::NotInitialized)` if the contract has not been set up yet.
    ///
    /// No `PolicyResult` event is emitted per-address to keep the batch
    /// cost predictable; callers that need an audit trail should call
    /// `evaluate` individually for the addresses they intend to act on.
    pub fn batch_evaluate(env: Env, addresses: Vec<Address>) -> Result<Vec<bool>, Error> {
        if addresses.len() > MAX_BATCH_SIZE {
            return Err(Error::BatchTooLarge);
        }

        let checks: Vec<CheckKind> = env
            .storage()
            .instance()
            .get(&DataKey::Checks)
            .ok_or(Error::NotInitialized)?;
        let op: CombineOp = env
            .storage()
            .instance()
            .get(&DataKey::CombineOp)
            .ok_or(Error::NotInitialized)?;

        let mut results: Vec<bool> = Vec::new(&env);

        for address in addresses.iter() {
            let passed = match op {
                CombineOp::All => {
                    let mut all_pass = true;
                    for i in 0..checks.len() {
                        let check = checks.get(i).unwrap();
                        if !Self::run_check(&env, &check, &address) {
                            all_pass = false;
                            break;
                        }
                    }
                    all_pass
                }
                CombineOp::Any => {
                    if checks.is_empty() {
                        false
                    } else {
                        let mut any_pass = false;
                        for i in 0..checks.len() {
                            let check = checks.get(i).unwrap();
                            if Self::run_check(&env, &check, &address) {
                                any_pass = true;
                                break;
                            }
                        }
                        any_pass
                    }
                }
            };
            results.push_back(passed);
        }

        Ok(results)
    }

    // -----------------------------------------------------------------------
    // Read-only accessors
    // -----------------------------------------------------------------------

    /// Returns the current list of registered checks.
    pub fn get_checks(env: Env) -> Vec<CheckKind> {
        env.storage()
            .instance()
            .get(&DataKey::Checks)
            .unwrap_or_else(|| Vec::new(&env))
    }

    /// Returns the current combination operator.
    pub fn get_op(env: Env) -> Result<CombineOp, Error> {
        env.storage()
            .instance()
            .get(&DataKey::CombineOp)
            .ok_or(Error::NotInitialized)
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    fn run_check(env: &Env, check: &CheckKind, address: &Address) -> bool {
        match check {
            CheckKind::Denylist { contract } => {
                let client = DenylistCheckClient::new(env, contract);
                client.check(address)
            }
            CheckKind::Jurisdiction {
                contract,
                allowed_codes,
            } => {
                let client = JurisdictionCheckClient::new(env, contract);
                client.is_permitted_jurisdiction(address, allowed_codes)
            }
        }
    }

    fn require_admin(env: &Env, admin: &Address) -> Result<(), Error> {
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
}

#[cfg(test)]
mod test;
