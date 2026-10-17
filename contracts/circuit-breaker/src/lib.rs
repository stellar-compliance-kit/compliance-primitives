#![no_std]

use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, Address, Env, String, Vec,
};

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Admin,
    Frozen,
    PendingAdmin,
    Guardians,
}

/// Version + admin metadata about this contract instance, for tooling that
/// introspects deployed contracts.
#[contracttype]
#[derive(Clone)]
pub struct Metadata {
    pub version: String,
    pub admin: Address,
}

#[contractevent]
pub struct Frozen {
    #[topic]
    pub caller: Address,
}

#[contractevent]
pub struct Unfrozen {
    #[topic]
    pub admin: Address,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    NotInitialized = 1,
    AlreadyInitialized = 2,
    NotAuthorized = 3,
    NoPendingAdmin = 4,
    PendingAdminMismatch = 5,
}

#[contract]
pub struct CircuitBreaker;

#[contractimpl]
impl CircuitBreaker {
    pub fn initialize(env: Env, admin: Address) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Frozen, &false);
        Ok(())
    }

    /// Freeze the breaker. Callable by the admin or any configured guardian,
    /// so an incident can be halted even when the admin key is unavailable.
    pub fn freeze(env: Env, caller: Address) -> Result<(), Error> {
        Self::require_admin_or_guardian(&env, &caller)?;
        env.storage().instance().set(&DataKey::Frozen, &true);
        Frozen {
            caller: caller.clone(),
        }
        .publish(&env);
        Ok(())
    }

    /// Unfreeze is admin-only: resuming flows is deliberately harder than
    /// halting them, so a guardian cannot reopen a frozen system.
    pub fn unfreeze(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::Frozen, &false);
        Unfrozen {
            admin: admin.clone(),
        }
        .publish(&env);
        Ok(())
    }

    pub fn is_frozen(env: Env) -> bool {
        env.storage().instance().get(&DataKey::Frozen).unwrap_or(false)
    }

    /// Add `guardian` to the freeze-only set. Admin-only. Adding an existing
    /// guardian is a no-op.
    pub fn add_guardian(env: Env, admin: Address, guardian: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        let mut guardians = Self::guardians(&env);
        if !Self::contains(&guardians, &guardian) {
            guardians.push_back(guardian);
            env.storage().instance().set(&DataKey::Guardians, &guardians);
        }
        Ok(())
    }

    /// Remove `guardian` from the freeze-only set. Admin-only. Removing a
    /// non-guardian is a no-op.
    pub fn remove_guardian(env: Env, admin: Address, guardian: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        let guardians = Self::guardians(&env);
        if Self::contains(&guardians, &guardian) {
            let mut kept = Vec::new(&env);
            for g in guardians.iter() {
                if g != guardian {
                    kept.push_back(g);
                }
            }
            env.storage().instance().set(&DataKey::Guardians, &kept);
        }
        Ok(())
    }

    pub fn is_guardian(env: Env, address: Address) -> bool {
        Self::contains(&Self::guardians(&env), &address)
    }

    /// Propose a new admin. The current admin remains fully in control
    /// until the proposed admin calls `accept_admin`; this avoids a
    /// single-typo lockout from a direct admin overwrite.
    pub fn propose_admin(env: Env, admin: Address, new_admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::PendingAdmin, &new_admin);
        Ok(())
    }

    /// Accept a pending admin transfer. Must be called by the proposed
    /// admin itself.
    pub fn accept_admin(env: Env, new_admin: Address) -> Result<(), Error> {
        new_admin.require_auth();
        let pending_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::PendingAdmin)
            .ok_or(Error::NoPendingAdmin)?;
        if pending_admin != new_admin {
            return Err(Error::PendingAdminMismatch);
        }
        env.storage().instance().set(&DataKey::Admin, &new_admin);
        env.storage().instance().remove(&DataKey::PendingAdmin);
        Ok(())
    }

    /// Returns metadata about this contract instance, including version and
    /// admin address.
    pub fn metadata(env: Env) -> Result<Metadata, Error> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        Ok(Metadata {
            version: String::from_str(&env, env!("CARGO_PKG_VERSION")),
            admin,
        })
    }

    fn guardians(env: &Env) -> Vec<Address> {
        env.storage()
            .instance()
            .get(&DataKey::Guardians)
            .unwrap_or_else(|| Vec::new(env))
    }

    fn contains(guardians: &Vec<Address>, address: &Address) -> bool {
        guardians.iter().any(|g| g == *address)
    }

    /// Requires `caller`'s authorization and that it is either the admin or a
    /// configured guardian.
    fn require_admin_or_guardian(env: &Env, caller: &Address) -> Result<(), Error> {
        caller.require_auth();
        let stored_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        if stored_admin == *caller || Self::contains(&Self::guardians(env), caller) {
            return Ok(());
        }
        Err(Error::NotAuthorized)
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
