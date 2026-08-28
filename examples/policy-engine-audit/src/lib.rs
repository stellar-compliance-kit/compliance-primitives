//! Reference example: wiring `policy-engine` evaluations to write audit
//! entries to `audit-log`, giving issuers a queryable compliance decision trail.
//!
//! ## Pattern demonstrated
//!
//! This example shows how to compose `policy-engine` and `audit-log` so that
//! every policy evaluation (pass or fail) is recorded on-chain for audit
//! purposes. The pattern is:
//!
//! 1. Deploy both `policy-engine` and `audit-log` instances.
//! 2. After calling `policy-engine.evaluate(from, to)`, immediately call
//!    `audit-log.record(source, kind, subject, detail)` with the evaluation
//!    result.
//! 3. The audit log accumulates an immutable trail of all compliance
//!    decisions that can be queried on-chain via `get_entry(index)` or
//!    `entry_count()`.
//!
//! ## Why audit policy evaluations?
//!
//! The `policy-engine` emits `PolicyResult` events for each evaluation, which
//! off-chain indexers can track. However, another contract cannot read those
//! events at transaction time. By recording the result in `audit-log`, the
//! evaluation outcome becomes queryable on-chain, enabling:
//!
//! - **On-chain proof-of-compliance**: A settlement contract can verify that
//!   a prior compliance check exists in the audit log before proceeding.
//! - **Dispute resolution**: A regulator or auditor can query the log to
//!   reconstruct the full decision history for a given address.
//! - **Immutable trail**: The log is append-only and stored in persistent
//!   ledger storage, providing a tamper-resistant compliance record.
//!
//! ## Cross-contract call flow
//!
//! When a policy evaluation is performed:
//!
//! 1. Call `policy-engine.evaluate(from, to)` to get a pass/fail result.
//! 2. Immediately call `audit-log.record(this_contract_address, kind, from,
//!    detail)` where:
//!    - `kind` is a `Symbol` like `"policy_pass"` or `"policy_fail"`
//!    - `detail` is a `String` with additional context (e.g., which check failed)
//! 3. The `audit-log` contract requires the `source` address to authorize the
//!    call, ensuring entries cannot be forged.
//!
//! ## Trait-based cross-contract calls
//!
//! This crate does not depend directly on `policy-engine` or `audit-log` in
//! its core dependencies to avoid wasm export collisions. Instead,
//! `#[contractclient]` traits define the shape of the calls we need.

#![no_std]

use soroban_sdk::{
    contract, contractclient, contracterror, contractimpl, contracttype, Address, Env, String,
    Symbol,
};

#[contractclient(name = "PolicyEngineClient")]
pub trait PolicyEngineInterface {
    fn evaluate(env: Env, from: Address, to: Address) -> bool;
}

#[contractclient(name = "AuditLogClient")]
pub trait AuditLogInterface {
    fn record(
        env: Env,
        source: Address,
        kind: Symbol,
        subject: Address,
        detail: String,
    );
}

#[contracttype]
#[derive(Clone)]
enum DataKey {
    PolicyEngine,
    AuditLog,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    NotInitialized = 1,
    AlreadyInitialized = 2,
    PolicyViolation = 3,
}

#[contract]
pub struct PolicyEngineAuditDemo;

#[contractimpl]
impl PolicyEngineAuditDemo {
    /// Initialize with addresses of deployed `policy-engine` and `audit-log` instances.
    pub fn initialize(
        env: Env,
        policy_engine: Address,
        audit_log: Address,
    ) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::PolicyEngine) {
            return Err(Error::AlreadyInitialized);
        }
        env.storage()
            .instance()
            .set(&DataKey::PolicyEngine, &policy_engine);
        env.storage()
            .instance()
            .set(&DataKey::AuditLog, &audit_log);
        Ok(())
    }

    /// Evaluate a transfer through the policy engine and log the result to audit-log.
    pub fn evaluate_and_log(env: Env, from: Address, to: Address) -> Result<bool, Error> {
        let policy_engine_addr: Address = env
            .storage()
            .instance()
            .get(&DataKey::PolicyEngine)
            .ok_or(Error::NotInitialized)?;
        let audit_log_addr: Address = env
            .storage()
            .instance()
            .get(&DataKey::AuditLog)
            .ok_or(Error::NotInitialized)?;

        let policy_client = PolicyEngineClient::new(&env, &policy_engine_addr);
        let audit_client = AuditLogClient::new(&env, &audit_log_addr);

        // Evaluate the policy
        let passed = policy_client.evaluate(&from, &to);

        // Log the evaluation result
        let kind = if passed {
            Symbol::new(&env, "policy_pass")
        } else {
            Symbol::new(&env, "policy_fail")
        };
        let detail = String::from_str(
            &env,
            if passed {
                "Transfer approved"
            } else {
                "Transfer denied by policy"
            },
        );

        audit_client.record(&env.current_contract_address(), &kind, &from, &detail);

        Ok(passed)
    }
}

#[cfg(test)]
mod test;
