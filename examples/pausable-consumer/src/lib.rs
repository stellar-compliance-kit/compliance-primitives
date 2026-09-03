// Copyright (c) 2026 Stellar Compliance Kit contributors
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

//! `pausable-consumer` is a minimal `#![no_std]` Soroban contract demonstrating
//! the full five-step wiring pattern for adopting the shared `compliance-pausable` crate.
//!
//! # The Five Wiring Steps
//!
//! 1. **Error variant**: Define `ContractPaused = 4` in your contract's `Error` enum.
//! 2. **Events**: Define local `Paused` and `Unpaused` `#[contractevent]` structs.
//! 3. **Admin-gated pause methods**: Expose `pause`, `unpause`, and `is_paused` in your `#[contractimpl]` block.
//! 4. **Guard placement**: Call `compliance_pausable::require_not_paused(&env, Error::ContractPaused)?`
//!    at the top of every state-mutating method.
//! 5. **Read-only exemption**: Do **not** call `require_not_paused` in read-only query methods.
#![no_std]

use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, Address, Env, String,
};

// ---------------------------------------------------------------------------
// Step 1: Error Variant
// ---------------------------------------------------------------------------
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    NotInitialized = 1,
    AlreadyInitialized = 2,
    NotAuthorized = 3,
    /// Returned whenever a state-mutating method is invoked while the contract is paused.
    ContractPaused = 4,
}

// ---------------------------------------------------------------------------
// Step 2: Local Events
// ---------------------------------------------------------------------------
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
pub struct ValueUpdated {
    #[topic]
    pub updated_by: Address,
    pub new_value: u32,
}

// ---------------------------------------------------------------------------
// Storage Keys
// ---------------------------------------------------------------------------
#[contracttype]
#[derive(Clone)]
enum DataKey {
    Admin,
    StoredValue,
    ConfigText,
}

// ---------------------------------------------------------------------------
// Contract Implementation
// ---------------------------------------------------------------------------
#[contract]
pub struct PausableConsumerContract;

#[contractimpl]
impl PausableConsumerContract {
    /// Initialize the contract with an admin address.
    pub fn initialize(env: Env, admin: Address) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::StoredValue, &0u32);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Step 3: Admin-Gated Pause / Unpause / Is-Paused Methods
    // -----------------------------------------------------------------------

    /// Pause the contract. Admin-only.
    ///
    /// Stores the pause state in instance storage and emits a `Paused` event.
    pub fn pause(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        compliance_pausable::pause(&env);
        Paused { admin }.publish(&env);
        Ok(())
    }

    /// Unpause the contract. Admin-only.
    ///
    /// Clears the pause state from instance storage and emits an `Unpaused` event.
    pub fn unpause(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        compliance_pausable::unpause(&env);
        Unpaused { admin }.publish(&env);
        Ok(())
    }

    /// Returns `true` if the contract is currently paused.
    /// Public query method that can be checked by any caller off-chain or on-chain.
    pub fn is_paused(env: Env) -> bool {
        compliance_pausable::is_paused(&env)
    }

    // -----------------------------------------------------------------------
    // Step 4: Guard Placement on Mutating Methods
    // -----------------------------------------------------------------------

    /// Update the numeric value stored in instance storage. Admin-only.
    ///
    /// Blocked while paused via [`compliance_pausable::require_not_paused`].
    pub fn set_value(env: Env, admin: Address, new_value: u32) -> Result<(), Error> {
        // Step 4 guard check: must be at the very top before state mutations
        compliance_pausable::require_not_paused(&env, Error::ContractPaused)?;
        Self::require_admin(&env, &admin)?;

        env.storage().instance().set(&DataKey::StoredValue, &new_value);
        ValueUpdated {
            updated_by: admin,
            new_value,
        }
        .publish(&env);
        Ok(())
    }

    /// Update arbitrary config text in persistent storage. Admin-only.
    ///
    /// Blocked while paused via [`compliance_pausable::require_not_paused`].
    pub fn set_config_text(env: Env, admin: Address, text: String) -> Result<(), Error> {
        // Step 4 guard check
        compliance_pausable::require_not_paused(&env, Error::ContractPaused)?;
        Self::require_admin(&env, &admin)?;

        env.storage().persistent().set(&DataKey::ConfigText, &text);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Step 5: Read-Only Exemption (No Pause Guard)
    // -----------------------------------------------------------------------

    /// Read the currently stored numeric value.
    ///
    /// Step 5: Read-only methods are deliberately NOT gated by `require_not_paused`,
    /// ensuring state remains queryable even during an emergency freeze.
    pub fn get_value(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::StoredValue)
            .unwrap_or(0)
    }

    /// Read the persistent config text, if set.
    ///
    /// Step 5: Unaffected by pause status.
    pub fn get_config_text(env: Env) -> Option<String> {
        env.storage().persistent().get(&DataKey::ConfigText)
    }

    /// Get the configured admin address.
    ///
    /// Step 5: Unaffected by pause status.
    pub fn get_admin(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::Admin)
    }

    // -----------------------------------------------------------------------
    // Helper: Admin Authorization
    // -----------------------------------------------------------------------
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
