//! # SEP-41 Token Gated by Denylist
//!
//! A SEP-41-conformant token contract that gates every `transfer` call through
//! a deployed `denylist-gate` instance.
//!
//! ## Purpose and Scope
//!
//! This example bridges two concerns:
//! - **SEP-41 Compliance**: Wallets, DEXes, and ecosystem tooling expect tokens
//!   to implement a standard interface. This contract provides that interface.
//! - **Compliance Composition**: Tokens often need to gate transfers through
//!   compliance checks. This contract integrates a single `denylist-gate` check
//!   into a SEP-41 token.
//!
//! By showing the pattern applied to a real SEP-41 interface, issuers can see
//! how their token contract (which end-users and wallets interact with) can
//! transparently invoke compliance primitives without changing the user-facing API.
//!
//! ## SEP-41 Entry Points
//!
//! This contract implements all entry points required by SEP-41 (see
//! <https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0041.md>):
//! - `initialize(admin, decimal, name, symbol)` — one-time setup
//! - `allowance(from, spender) -> i128` — read allowance
//! - `approve(from, spender, amount, expiration_ledger)` — grant approval
//! - `balance(id) -> i128` — read balance
//! - `transfer(from, to, amount)` — transfer with denylist gate
//! - `transfer_from(spender, from, to, amount)` — transfer with allowance and gate
//! - `burn(from, amount)` — burn tokens
//! - `burn_from(spender, from, amount)` — burn with allowance
//! - `decimals() -> u32` — token decimals
//! - `name() -> String` — token name
//! - `symbol() -> String` — token symbol
//!
//! In addition, an admin-only `mint` function is provided for testing and
//! demonstration (not part of the SEP-41 spec).
//!
//! ## Composition Pattern
//!
//! The denylist gate is wired as a **cross-contract client** using the
//! `#[contractclient]` trait pattern, avoiding linker symbol collisions:
//!
//! 1. No direct dependency on `denylist-gate` crate in `[dependencies]`
//! 2. A `#[contractclient]` trait describes only the call shape
//! 3. `gate_check()` helper verifies both `from` and `to` parties against the gate
//! 4. If either party is denied, `transfer` or `transfer_from` returns `DeniedByGate`
//!
//! The gate check is invisible to API consumers — they call standard `transfer`
//! as normal and receive a standard error if denied. Wallets can treat this as
//! a regular SEP-41 token.
//!
//! ## Differences from other examples
//!
//! - **vs. `/examples/denylist-gate-consumer`**: That is a minimal token showing
//!   the gate-check pattern. This crate shows the pattern applied to the full
//!   SEP-41 interface so issuers can copy the pattern into production.
//! - **vs. `/examples/rwa-token` and `/examples/rwa-compliance-flow`**: Those compose
//!   all three primitives (allowlist, denylist, jurisdiction). This composes
//!   denylist only, keeping the example focused on a single gate.
#![no_std]

use soroban_sdk::{
    contract, contractclient, contractevent, contracterror, contractimpl, contracttype, Address,
    Env, String,
};

// ---------------------------------------------------------------------------
// Cross-contract client for denylist-gate (trait-only, no binary coupling).
// ---------------------------------------------------------------------------

#[contractclient(name = "GateClient")]
pub trait DenylistGateInterface {
    fn check(env: Env, address: Address) -> bool;
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

/// Emitted when a transfer is denied by the denylist gate.
#[contractevent]
pub struct TransferDenied {
    #[topic]
    pub from: Address,
    #[topic]
    pub to: Address,
}

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Admin,
    Gate,
    Decimals,
    Name,
    Symbol,
    Balance(Address),
    Allowance(Address, Address), // (owner, spender)
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
    InsufficientBalance = 4,
    InsufficientAllowance = 5,
    DeniedByGate = 6,
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contract]
pub struct Sep41GatedToken;

#[contractimpl]
impl Sep41GatedToken {
    // -----------------------------------------------------------------------
    // Admin / setup
    // -----------------------------------------------------------------------

    /// One-time setup. `gate` is the address of a deployed `denylist-gate`
    /// contract instance; this token will call `gate.check(address)` before
    /// every transfer.
    pub fn initialize(
        env: Env,
        admin: Address,
        gate: Address,
        decimal: u32,
        name: String,
        symbol: String,
    ) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Gate, &gate);
        env.storage().instance().set(&DataKey::Decimals, &decimal);
        env.storage().instance().set(&DataKey::Name, &name);
        env.storage().instance().set(&DataKey::Symbol, &symbol);
        Ok(())
    }

    /// Mint `amount` tokens to `to`. Admin-only; not part of SEP-41 but
    /// required for bootstrapping in tests/demos.
    pub fn mint(env: Env, admin: Address, to: Address, amount: i128) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        let bal = Self::balance(env.clone(), to.clone());
        env.storage()
            .persistent()
            .set(&DataKey::Balance(to), &(bal + amount));
        Ok(())
    }

    // -----------------------------------------------------------------------
    // SEP-41 read-only
    // -----------------------------------------------------------------------

    pub fn decimals(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::Decimals)
            .unwrap_or(7)
    }

    pub fn name(env: Env) -> String {
        env.storage()
            .instance()
            .get(&DataKey::Name)
            .unwrap_or_else(|| String::from_str(&env, ""))
    }

    pub fn symbol(env: Env) -> String {
        env.storage()
            .instance()
            .get(&DataKey::Symbol)
            .unwrap_or_else(|| String::from_str(&env, ""))
    }

    pub fn balance(env: Env, id: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(id))
            .unwrap_or(0)
    }

    pub fn allowance(env: Env, from: Address, spender: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Allowance(from, spender))
            .unwrap_or(0)
    }

    // -----------------------------------------------------------------------
    // SEP-41 mutating
    // -----------------------------------------------------------------------

    pub fn approve(
        env: Env,
        from: Address,
        spender: Address,
        amount: i128,
        _expiration_ledger: u32,
    ) -> Result<(), Error> {
        from.require_auth();
        env.storage()
            .persistent()
            .set(&DataKey::Allowance(from, spender), &amount);
        Ok(())
    }

    /// Transfer `amount` from `from` to `to`, gated by `denylist-gate`.
    ///
    /// Returns `Err(DeniedByGate)` if either party is on the denylist.
    /// Unlike `allowlist-token`, this uses an error return (not `Ok(false)`)
    /// because denylist blocks should revert all state — a transfer being
    /// silently soft-blocked here is a worse failure mode than a hard abort.
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) -> Result<(), Error> {
        from.require_auth();
        Self::gate_check(&env, &from, &to)?;
        Self::do_transfer(&env, &from, &to, amount)
    }

    pub fn transfer_from(
        env: Env,
        spender: Address,
        from: Address,
        to: Address,
        amount: i128,
    ) -> Result<(), Error> {
        spender.require_auth();
        Self::gate_check(&env, &from, &to)?;

        let key = DataKey::Allowance(from.clone(), spender.clone());
        let allowance: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        if allowance < amount {
            return Err(Error::InsufficientAllowance);
        }
        env.storage()
            .persistent()
            .set(&key, &(allowance - amount));

        Self::do_transfer(&env, &from, &to, amount)
    }

    pub fn burn(env: Env, from: Address, amount: i128) -> Result<(), Error> {
        from.require_auth();
        let bal = Self::balance(env.clone(), from.clone());
        if bal < amount {
            return Err(Error::InsufficientBalance);
        }
        env.storage()
            .persistent()
            .set(&DataKey::Balance(from), &(bal - amount));
        Ok(())
    }

    pub fn burn_from(
        env: Env,
        spender: Address,
        from: Address,
        amount: i128,
    ) -> Result<(), Error> {
        spender.require_auth();
        let key = DataKey::Allowance(from.clone(), spender.clone());
        let allowance: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        if allowance < amount {
            return Err(Error::InsufficientAllowance);
        }
        env.storage()
            .persistent()
            .set(&key, &(allowance - amount));

        let bal = Self::balance(env.clone(), from.clone());
        if bal < amount {
            return Err(Error::InsufficientBalance);
        }
        env.storage()
            .persistent()
            .set(&DataKey::Balance(from), &(bal - amount));
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    fn gate_check(env: &Env, from: &Address, to: &Address) -> Result<(), Error> {
        let gate_address: Address = env
            .storage()
            .instance()
            .get(&DataKey::Gate)
            .ok_or(Error::NotInitialized)?;
        let gate = GateClient::new(env, &gate_address);
        if !gate.check(from) || !gate.check(to) {
            // Emit a small diagnostic event before returning the error.
            // Unlike allowlist-token's Ok(false) pattern, we let the error
            // revert the call — the event is emitted here before returning
            // so the caller can observe it in test output even though the
            // invocation reverts.
            TransferDenied {
                from: from.clone(),
                to: to.clone(),
            }
            .publish(env);
            return Err(Error::DeniedByGate);
        }
        Ok(())
    }

    fn do_transfer(env: &Env, from: &Address, to: &Address, amount: i128) -> Result<(), Error> {
        let from_bal = Self::balance(env.clone(), from.clone());
        if from_bal < amount {
            return Err(Error::InsufficientBalance);
        }
        let to_bal = Self::balance(env.clone(), to.clone());
        env.storage()
            .persistent()
            .set(&DataKey::Balance(from.clone()), &(from_bal - amount));
        env.storage()
            .persistent()
            .set(&DataKey::Balance(to.clone()), &(to_bal + amount));
        Ok(())
    }

    fn require_admin(env: &Env, admin: &Address) -> Result<(), Error> {
        admin.require_auth();
        let stored: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        if stored != *admin {
            return Err(Error::NotAuthorized);
        }
        Ok(())
    }
}

#[cfg(test)]
mod test;
