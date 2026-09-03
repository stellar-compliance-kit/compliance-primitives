//! Reference example: combining `multisig-admin` as the admin of a
//! `compliance-aggregator` contract.
//!
//! ## Pattern demonstrated
//!
//! This example shows how to use `multisig-admin` to govern configuration
//! changes to a `compliance-aggregator` instance. The aggregator's admin
//! entrypoints (`set_denylist_gate`, `set_jurisdiction_flag`) require admin
//! authorization; by setting the aggregator's admin address to a deployed
//! `multisig-admin` instance, those configuration calls must satisfy the
//! multisig threshold (M-of-N signers) rather than relying on a single key.
//!
//! ## Cross-contract auth flow
//!
//! When a configuration change is proposed:
//!
//! 1. The initiating transaction calls `compliance-aggregator.set_denylist_gate(admin, new_gate)`
//!    where `admin` is the address of the `multisig-admin` contract.
//! 2. The aggregator calls `admin.require_auth()`, which triggers Soroban's
//!    `CustomAccountInterface::__check_auth` on the `multisig-admin` contract.
//! 3. The `multisig-admin` contract verifies that the provided `signatures`
//!    (a `Vec<Address>` of approving signers) meets the stored threshold.
//! 4. If the threshold is met, authorization succeeds and the aggregator
//!    proceeds with the configuration change. Otherwise, the transaction fails.
//!
//! This pattern applies to any contract that uses `Address.require_auth()` for
//! admin operations: `allowlist-token`, `denylist-gate`, `jurisdiction-flag`,
//! and `compliance-aggregator` all work identically with `multisig-admin`.
//!
//! ## Trait-based cross-contract calls
//!
//! This crate does not depend directly on `compliance-aggregator` in its core
//! dependencies to avoid wasm export collisions. Instead, `#[contractclient]`
//! traits define the shape of the calls we need. The actual implementations
//! appear in `[dev-dependencies]` for test usage.

#![no_std]

use soroban_sdk::{contract, contractclient, contracterror, contractimpl, Address, Env};

#[contractclient(name = "ComplianceAggregatorAdminClient")]
pub trait ComplianceAggregatorAdminInterface {
    fn set_denylist_gate(env: Env, admin: Address, gate: Address);
    fn set_jurisdiction_flag(env: Env, admin: Address, flag: Address);
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    NotInitialized = 1,
}

#[contract]
pub struct MultisigAggregatorDemo;

#[contractimpl]
impl MultisigAggregatorDemo {
    /// Placeholder contract to satisfy the example pattern. In practice, this
    /// would be your issuer's main contract that needs to reconfigure the
    /// aggregator through multisig governance.
    pub fn placeholder(_env: Env) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(test)]
mod test;
