#![no_std]

use soroban_sdk::{contract, contractclient, contracterror, contractimpl, Address, Env};

#[contractclient(name = "CircuitBreakerClient")]
pub trait CircuitBreakerInterface {
    fn is_frozen(env: Env) -> bool;
}

/// Mirrors policy-engine's own `Error` enum discriminants exactly, since the
/// generated client needs a real `#[contracterror]` type (not a bare `u32`)
/// to convert the host-level error code back into a typed Result.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum PolicyEngineError {
    NotInitialized = 1,
    AlreadyInitialized = 2,
    NotAuthorized = 3,
    PolicyViolation = 4,
    BatchTooLarge = 5,
    ContractPaused = 6,
}

#[contractclient(name = "PolicyEngineClient")]
pub trait PolicyEngineInterface {
    fn evaluate(env: Env, from: Address, to: Address) -> Result<bool, PolicyEngineError>;
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    CircuitBreakerFrozen = 1,
    PolicyViolation = 2,
}

#[contract]
pub struct GatedTransferContract;

#[contractimpl]
impl GatedTransferContract {
    pub fn check_transfer(
        env: Env,
        breaker_id: Address,
        policy_id: Address,
        from: Address,
        to: Address,
    ) -> Result<bool, Error> {
        // Check circuit breaker first - fail fast if frozen
        let breaker = CircuitBreakerClient::new(&env, &breaker_id);
        if breaker.is_frozen() {
            return Err(Error::CircuitBreakerFrozen);
        }

        // Then evaluate policy
        let policy = PolicyEngineClient::new(&env, &policy_id);
        let passed = policy
            .try_evaluate(&from, &to)
            .map_err(|_| Error::PolicyViolation)?
            .map_err(|_| Error::PolicyViolation)?;

        if !passed {
            return Err(Error::PolicyViolation);
        }

        Ok(true)
    }
}

#[cfg(test)]
mod test;
