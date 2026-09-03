# `pausable-consumer` Example Contract

This example demonstrates how to integrate the shared `compliance-pausable` crate into a Soroban smart contract using the 5-step wiring pattern.

---

## The 5 Integration Steps

### Step 1: Error Variant
Add `ContractPaused = 4` (or contract-specific discriminant) to your contract's `Error` enum:
```rust
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    NotInitialized = 1,
    AlreadyInitialized = 2,
    NotAuthorized = 3,
    ContractPaused = 4,
}
```

### Step 2: Local Events
Declare contract-local `Paused` and `Unpaused` events using `#[contractevent]`:
```rust
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
```

### Step 3: Admin-Gated Pause Methods
Add `pause`, `unpause`, and `is_paused` to your `#[contractimpl]` block:
```rust
pub fn pause(env: Env, admin: Address) -> Result<(), Error> {
    Self::require_admin(&env, &admin)?;
    compliance_pausable::pause(&env);
    Paused { admin }.publish(&env);
    Ok(())
}

pub fn unpause(env: Env, admin: Address) -> Result<(), Error> {
    Self::require_admin(&env, &admin)?;
    compliance_pausable::unpause(&env);
    Unpaused { admin }.publish(&env);
    Ok(())
}

pub fn is_paused(env: Env) -> bool {
    compliance_pausable::is_paused(&env)
}
```

### Step 4: Guard Placement on State-Mutating Methods
Call `compliance_pausable::require_not_paused` at the top of every mutating entrypoint:
```rust
pub fn set_value(env: Env, admin: Address, new_value: u32) -> Result<(), Error> {
    compliance_pausable::require_not_paused(&env, Error::ContractPaused)?;
    Self::require_admin(&env, &admin)?;
    env.storage().instance().set(&DataKey::StoredValue, &new_value);
    Ok(())
}
```

### Step 5: Read-Only Exemption
Deliberately omit `require_not_paused` from read-only query methods:
```rust
pub fn get_value(env: Env) -> u32 {
    env.storage().instance().get(&DataKey::StoredValue).unwrap_or(0)
}
```

---

## Running Tests

```bash
cargo test --package pausable-consumer
```
