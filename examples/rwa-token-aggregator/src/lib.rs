//! # RWA Token — Aggregator-Gated Example
//!
//! A reference Real-World Asset (RWA) token whose `transfer` path makes
//! **one kind of compliance call only**: `compliance-aggregator.check_address`.
//! The aggregator is the single top-level gate, and it composes the
//! underlying primitives itself:
//!
//! ```text
//! RwaAggregatorToken.transfer(from, to, amount)
//!   └── compliance-aggregator.check_address(party, allowed_codes)   (× from, to)
//!         ├── circuit-breaker.is_frozen()           — emergency stop, short-circuits
//!         ├── denylist-gate.check(party)
//!         └── jurisdiction-flag.is_permitted_jurisdiction(party, allowed_codes)
//! ```
//!
//! ## How this differs from `/examples/rwa-token`
//!
//! `/examples/rwa-token` stores the address of every primitive and calls each
//! one directly from `transfer`. This crate stores only the aggregator's
//! address. Adding, replacing, or removing a primitive (for example pointing
//! the aggregator at a new `denylist-gate`) is an aggregator admin action and
//! needs no change to, or redeploy of, the token.
//!
//! ## Error mapping
//!
//! `check_address` returns `(all_passed, checks)`. When `all_passed` is
//! `false`, the token inspects the per-check breakdown and returns a
//! dedicated error naming the gate that failed, in the aggregator's evaluation
//! order:
//!
//! | Failed check | Error |
//! |---|---|
//! | `CircuitBreaker` | `Error::CircuitBreakerFrozen` |
//! | `Denylist` | `Error::DeniedByGate` |
//! | `Jurisdiction` | `Error::JurisdictionNotPermitted` |
//!
//! Any failure of the aggregator call itself (for example
//! `NoChecksRegistered`, or a downstream contract trapping) is treated as
//! **fail-closed** and surfaces as `Error::ComplianceUnavailable`, so a
//! misconfigured aggregator can never let a transfer through.
//!
//! ## Implementation details
//!
//! Like the other examples, this crate does **not** link the aggregator's
//! `#[contractimpl]` exports. The client is generated from a
//! `#[contractclient]` trait, and `CheckKind` / `CheckResult` are mirrored
//! here with the same `#[contracttype]` shape so they decode from the
//! aggregator's return value.
//!
//! `mint` is a non-standard demo helper; a real RWA token would mint through
//! an issuer-controlled process.
#![no_std]

use soroban_sdk::{
    contract, contractclient, contracterror, contractimpl, contracttype, symbol_short, Address,
    Env, String, Vec,
};

// ---------------------------------------------------------------------------
// Mirrored aggregator types
// ---------------------------------------------------------------------------

/// Mirror of `compliance_aggregator::CheckKind`. Must keep the same variants
/// and discriminants to decode the aggregator's return value.
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CheckKind {
    Denylist = 0,
    Jurisdiction = 1,
    CircuitBreaker = 2,
    Allowlist = 3,
}

/// Mirror of `compliance_aggregator::CheckResult`.
///
/// The aggregator's `CheckResult` carries a `code` field (the reason code for
/// the check outcome, `0` when the check passed). The field must be mirrored
/// here with the same name and type so the aggregator's return value decodes.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckResult {
    pub check: CheckKind,
    pub passed: bool,
    pub code: u32,
}

/// Subset of the `compliance-aggregator` interface this token uses.
#[contractclient(name = "AggregatorClient")]
pub trait ComplianceAggregatorInterface {
    fn check_address(env: Env, address: Address, allowed_jurisdictions: Vec<String>) -> (bool, Vec<CheckResult>);
}

// ---------------------------------------------------------------------------
// Storage & errors
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Aggregator,
    AllowedCodes,
    Balance(Address),
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    NotInitialized = 1,
    AlreadyInitialized = 2,
    InsufficientBalance = 3,
    InvalidAmount = 4,
    CircuitBreakerFrozen = 5,
    DeniedByGate = 6,
    JurisdictionNotPermitted = 7,
    /// The aggregator call itself failed (misconfiguration or a downstream
    /// trap). Treated as a denial: the token fails closed.
    ComplianceUnavailable = 8,
    NotAllowlisted = 9,
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contract]
pub struct RwaAggregatorToken;

#[contractimpl]
impl RwaAggregatorToken {
    /// Wire this token to a deployed `compliance-aggregator` and the set of
    /// jurisdiction codes that may hold and transfer it.
    pub fn initialize(env: Env, aggregator: Address, allowed_codes: Vec<String>) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Aggregator) {
            return Err(Error::AlreadyInitialized);
        }
        env.storage().instance().set(&DataKey::Aggregator, &aggregator);
        env.storage().instance().set(&DataKey::AllowedCodes, &allowed_codes);
        Ok(())
    }

    /// Returns the configured aggregator address.
    pub fn aggregator(env: Env) -> Result<Address, Error> {
        env.storage().instance().get(&DataKey::Aggregator).ok_or(Error::NotInitialized)
    }

    /// Test/demo helper to fund an address with an initial balance.
    pub fn mint(env: Env, to: Address, amount: i128) {
        let balance = Self::balance(env.clone(), to.clone());
        env.storage().persistent().set(&DataKey::Balance(to), &(balance + amount));
    }

    pub fn balance(env: Env, address: Address) -> i128 {
        env.storage().persistent().get(&DataKey::Balance(address)).unwrap_or(0)
    }

    /// Transfer `amount` from `from` to `to`.
    ///
    /// The only compliance call made is `compliance-aggregator.check_address`,
    /// once for each party. Balances are mutated only after both parties pass.
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) -> Result<(), Error> {
        from.require_auth();
        if amount <= 0 {
            return Err(Error::InvalidAmount);
        }

        let aggregator_addr: Address =
            env.storage().instance().get(&DataKey::Aggregator).ok_or(Error::NotInitialized)?;
        let allowed_codes: Vec<String> =
            env.storage().instance().get(&DataKey::AllowedCodes).ok_or(Error::NotInitialized)?;

        let aggregator = AggregatorClient::new(&env, &aggregator_addr);
        Self::require_compliant(&env, &aggregator, &from, &allowed_codes)?;
        Self::require_compliant(&env, &aggregator, &to, &allowed_codes)?;

        let from_balance = Self::balance(env.clone(), from.clone());
        if from_balance < amount {
            return Err(Error::InsufficientBalance);
        }
        let to_balance = Self::balance(env.clone(), to.clone());

        env.storage().persistent().set(&DataKey::Balance(from), &(from_balance - amount));
        env.storage().persistent().set(&DataKey::Balance(to), &(to_balance + amount));
        Ok(())
    }

    /// Runs the aggregated check for `party` and maps a failure to the error
    /// naming the first failed gate. Any error from the aggregator call itself
    /// fails closed.
    fn require_compliant(
        env: &Env,
        aggregator: &AggregatorClient,
        party: &Address,
        allowed_codes: &Vec<String>,
    ) -> Result<(), Error> {
        let (all_passed, checks) = match aggregator.try_check_address(party, allowed_codes) {
            Ok(Ok(result)) => result,
            _ => return Err(Error::ComplianceUnavailable),
        };
        if all_passed {
            return Ok(());
        }
        for result in checks.iter() {
            if !result.passed {
                // Surface the aggregator's reason code so operators can tell
                // *why* the gate denied, not just which gate it was.
                env.events().publish(
                    (symbol_short!("compliance"), symbol_short!("denied")),
                    (party.clone(), result.check, result.code),
                );
                return Err(match result.check {
                    CheckKind::CircuitBreaker => Error::CircuitBreakerFrozen,
                    CheckKind::Denylist => Error::DeniedByGate,
                    CheckKind::Jurisdiction => Error::JurisdictionNotPermitted,
                    CheckKind::Allowlist => Error::NotAllowlisted,
                });
            }
        }
        // `all_passed == false` with no failed entry should be impossible;
        // fail closed rather than trust an inconsistent result.
        Err(Error::ComplianceUnavailable)
    }
}

#[cfg(test)]
mod test;
