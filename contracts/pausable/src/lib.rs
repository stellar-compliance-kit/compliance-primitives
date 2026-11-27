//! `pausable` is a `#![no_std]` shared crate that provides a minimal pause
//! mechanism for Soroban contracts.
//!
//! **Purpose**: let any Soroban contract add an emergency-stop capability
//! without reimplementing the same storage key and guard logic. A consuming
//! contract stores a single boolean under a well-known key and calls these
//! helpers to manage it.
//!
//! **Usage**: import this crate as a regular dependency and call the free
//! functions directly, passing your contract's `Env`. No contract struct is
//! defined here — these are pure utility functions, not an entry-point
//! contract.
//!
//! ## Pause timestamp and reason (issue #411)
//!
//! In addition to the simple pause flag, this crate optionally tracks **when**
//! a pause happened (via [`env.ledger().timestamp()`]) and an optional
//! **reason string** supplied by the caller.  Both are stored in instance
//! storage under their own [`DataKey`] variants and are readable at any time
//! via [`paused_since`] and [`pause_reason`].
//!
//! Consuming contracts that only need the basic boolean gate do not have to
//! call the new helpers at all — [`pause`] continues to work without a reason,
//! and the old helpers remain unchanged.  Contracts that want the richer
//! audit trail can call [`pause_with_reason`] instead.
//!
//! ### Storage layout
//!
//! | Key             | Type         | Storage  | Lifecycle                              |
//! |-----------------|--------------|----------|----------------------------------------|
//! | `Paused`        | `bool`       | instance | set by [`pause`] / [`unpause`]         |
//! | `PausedSince`   | `u64`        | instance | set by [`pause`] / cleared by [`unpause`] |
//! | `PauseReason`   | `String`     | instance | set by [`pause_with_reason`] / cleared by [`unpause`] |
//!
//! ## Which contracts use this crate vs. a local pause implementation
//!
//! Not every contract in the workspace delegates pause state to this crate.
//! A reader of this file would otherwise need to grep the workspace to find
//! out who depends on it — the table below captures that for each primitive.
//!
//! | Contract | Pause mechanism | Notes |
//! |---|---|---|
//! | `multisig-admin` | **this crate** (`compliance_pausable::*`) | Added when the crate was introduced |
//! | `compliance-aggregator` | **this crate** (`compliance_pausable::*`) | Added when the crate was introduced |
//! | `audit-log` | **this crate** (`compliance_pausable::*`) | Added when the crate was introduced |
//! | `policy-engine` | **this crate** (`compliance_pausable::*`) | Added when the crate was introduced |
//! | `allowlist-token` | **local** `DataKey::Paused` (inline) | Predates the shared crate; not yet migrated |
//! | `denylist-gate` | **local** `DataKey::Paused` (inline) | Predates the shared crate; not yet migrated |
//! | `jurisdiction-flag` | **local** `DataKey::Paused` (inline) | Predates the shared crate; not yet migrated |
//! | `circuit-breaker` | **not applicable** — uses `DataKey::Frozen` | Freeze semantics differ from pause: `Frozen` is a cross-contract gate, not an admin stop |
//!
//! ### Why the three original primitives use local pause state
//!
//! `allowlist-token`, `denylist-gate`, and `jurisdiction-flag` were written
//! before `compliance-pausable` existed. Each inlines its own
//! `env.storage().instance().set(&DataKey::Paused, &true/false)` logic —
//! functionally identical to what this crate does, but not going through it.
//! Migrating them is safe (the storage key and semantics are the same) but
//! requires a coordinated change across three contracts plus their test
//! suites; it has been left for a dedicated refactor rather than mixed into
//! unrelated PRs.
//!
//! ### Why `circuit-breaker` is different
//!
//! `circuit-breaker` uses `DataKey::Frozen` rather than `DataKey::Paused`
//! and exposes `freeze`/`unfreeze`/`is_frozen` rather than
//! `pause`/`unpause`/`is_paused`. This is intentional: freeze is a
//! *cross-contract emergency gate* that other contracts poll before allowing
//! a transfer — it is not the same concept as an admin pause on the
//! circuit-breaker contract itself. The two mechanisms are kept separate to
//! avoid conflating operational pause (admin maintenance window) with
//! emergency freeze (halt-all-transfers signal).
//!
//! ## Pauser role: hot/cold key separation (issue #806)
//!
//! Requiring the admin key to pause slows incident response: the admin key is
//! typically a cold key (hardware wallet, multisig, or offline signer) and
//! bringing it online mid-incident is slow. This crate therefore supports an
//! optional **pauser** role — a hot key that can *only* pause, never unpause.
//!
//! - [`set_pauser`] / [`clear_pauser`] are **admin-only** operations. The
//!   consuming contract must authenticate the admin before calling them; this
//!   crate does not know the admin `Address`.
//! - [`pause_authorized`] lets a caller pause when it is either the admin or
//!   the configured pauser.
//! - [`unpause`] remains **admin-only** — the pauser can never resume the
//!   contract, so a compromised hot key can halt operations but cannot
//!   unilaterally restore them.
//!
//! ### Recommended key setup
//!
//! | Key | Storage | Purpose |
//! |---|---|---|
//! | Admin | cold (multisig / hardware / offline) | Unpause, rotate or clear the pauser, all other privileged ops |
//! | Pauser | hot (server-side signer, on-call automation) | Pause only |
//!
//! Operational guidance:
//!
//! 1. Keep the admin key cold and use it only for unpause, pauser rotation,
//!    and other privileged configuration.
//! 2. Assign the pauser key to on-call automation or a monitoring service so
//!    an incident can be halted within seconds.
//! 3. Rotate the pauser key after any incident, or immediately if it may have
//!    been compromised, via [`set_pauser`] (or [`clear_pauser`] to remove the
//!    role entirely).
//! 4. Because the pauser cannot unpause, a compromised pauser key can only
//!    cause a denial of service that the cold admin key can recover from.
//!
//! A [`PauserChanged`] event is emitted whenever the pauser is set or cleared.
#![no_std]

use soroban_sdk::{contractmeta, contracttype, Env, String};

// Embed crate version and repository URL into the WASM custom section so
// deployed artifacts can be traced back to a release. `contractmeta!` expands
// to a `#[link_section]` static, which is only meaningful (and only accepted)
// when compiling for a wasm target; guard it so the plain rlib build still
// compiles.
#[cfg(target_family = "wasm")]
contractmeta!(key = "version", val = env!("CARGO_PKG_VERSION"));
#[cfg(target_family = "wasm")]
contractmeta!(key = "source", val = env!("CARGO_PKG_REPOSITORY"));

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Paused,
    /// Ledger timestamp (seconds since Unix epoch) recorded when the contract
    /// was last paused.  Absent when the contract is not paused.
    PausedSince,
    /// Optional human-readable reason string recorded when the contract was
    /// last paused via [`pause_with_reason`].  Absent when no reason was
    /// supplied or the contract is not paused.
    PauseReason,
    /// Optional ledger timestamp at which an automatic pause expires.
    /// Absent for pauses created by [`pause`] / [`pause_with_reason`].
    PauseUntil,
    /// Scopes currently paused independently of the global flag (#805).
    PausedScopes,
    /// Optional hot key allowed to pause (but not unpause) the contract.
    Pauser,
}

///Feature-level pause scope (#805). A global pause overrides every scope.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PauseScope {
    /// Minting / issuance operations.
    Mint,
    /// Redemption / withdrawal operations.
    Redeem,
    /// Transfers between accounts.
    Transfer,
    /// Administrative configuration changes.
    Admin,
}

fn active_scopes(env: &Env) -> soroban_sdk::Vec<PauseScope> {
    env.storage()
        .instance()
        .get(&DataKey::PausedScopes)
        .unwrap_or_else(|| soroban_sdk::Vec::new(env))
}

/// Pause a single feature while other features remain operational.
pub fn pause_scope(env: &Env, scope: PauseScope) {
    let mut scopes = active_scopes(env);
    if !scopes.contains(scope.clone()) {
        scopes.push_back(scope);
        env.storage().instance().set(&DataKey::PausedScopes, &scopes);
    }
}

/// Resume a previously paused feature. The global pause is unaffected.
pub fn unpause_scope(env: &Env, scope: PauseScope) {
    let scopes = active_scopes(env);
    let mut remaining = soroban_sdk::Vec::new(env);
    for current in scopes.iter() {
        if current != scope {
            remaining.push_back(current);
        }
    }
    if remaining.is_empty() {
        env.storage().instance().remove(&DataKey::PausedScopes);
    } else {
        env.storage().instance().set(&DataKey::PausedScopes, &remaining);
    }
}

/// Returns `true` when the contract is globally paused or `scope` is paused.
///
/// A global pause overrides every scope, so callers guarding a specific
/// feature with [`require_not_paused_scope`] also stop during a full stop.
pub fn is_paused_scope(env: &Env, scope: PauseScope) -> bool {
    is_paused(env) || active_scopes(env).contains(scope)
}

/// Panic if the contract is globally paused or `scope` is paused.
pub fn require_not_paused_scope(env: &Env, scope: PauseScope) {
    if is_paused_scope(env, scope) {
        panic!("contract is paused");
    }
}

/// Return `Err(err)` if the contract is globally paused or `scope` is paused.
pub fn require_not_paused_scope_or<E>(env: &Env, scope: PauseScope, err: E) -> Result<(), E> {
    if is_paused_scope(env, scope) {
        Err(err)
    } else {
        Ok(())
    }
}

/// Returns `true` if the contract is currently paused.
///
/// Defaults to `false` when no pause flag has been stored yet, so a freshly
/// initialized contract starts in the active (unpaused) state.
pub fn is_paused(env: &Env) -> bool {
    let paused: bool = env
        .storage()
        .instance()
        .get(&DataKey::Paused)
        .unwrap_or(false);
    if !paused {
        return false;
    }
    // An incident pause with an expiry stops being effective once the ledger
    // clock reaches `until` — no explicit unpause required (#804).
    match env.storage().instance().get::<_, u64>(&DataKey::PauseUntil) {
        Some(until) => env.ledger().timestamp() < until,
        None => true,
    }
}

/// Set the paused flag to `true` and record the current ledger timestamp.
///
/// Calling this when already paused is a no-op — the flag and timestamp remain
/// set to their existing values.
///
/// To also record a reason string, call [`pause_with_reason`] instead.
pub fn pause(env: &Env) {
    if !is_paused(env) {
        env.storage().instance().set(&DataKey::Paused, &true);
        env.storage()
            .instance()
            .set(&DataKey::PausedSince, &env.ledger().timestamp());
    }
}

/// Set the paused flag to `true`, record the current ledger timestamp, and
/// store an optional `reason` string for auditability.
///
/// Calling this when already paused is a no-op — the existing pause state,
/// timestamp, and reason are preserved.
///
/// If `reason` is `None`, any previously stored reason is left untouched (or
/// absent).
pub fn pause_with_reason(env: &Env, reason: Option<String>) {
    if !is_paused(env) {
        env.storage().instance().set(&DataKey::Paused, &true);
        env.storage()
            .instance()
            .set(&DataKey::PausedSince, &env.ledger().timestamp());
        if let Some(r) = reason {
            env.storage().instance().set(&DataKey::PauseReason, &r);
        }
    }
}

/// Pause the contract until the given ledger timestamp, then resume
/// automatically (#804).
///
/// The flag, pause timestamp and optional expiry are stored under the same
/// keys as [`pause`]; `is_paused` returns `false` once `now >= until` without
/// requiring an explicit [`unpause`] call. Passing `until` at or before the
/// current ledger timestamp is equivalent to not pausing at all.
pub fn pause_until(env: &Env, until: u64) {
    if env.ledger().timestamp() >= until {
        return;
    }
    env.storage().instance().set(&DataKey::Paused, &true);
    env.storage()
        .instance()
        .set(&DataKey::PausedSince, &env.ledger().timestamp());
    env.storage().instance().set(&DataKey::PauseUntil, &until);
}

/// Returns the ledger timestamp at which an automatic pause expires.
pub fn pause_until_at(env: &Env) -> Option<u64> {
    env.storage().instance().get(&DataKey::PauseUntil)
}

/// Returns the configured pauser address, or `None` if no pauser role is set.
pub fn get_pauser(env: &Env) -> Option<Address> {
    env.storage().instance().get(&DataKey::Pauser)
}

/// Assign `pauser` as the hot key allowed to pause the contract.
///
/// **Admin-only**: the consuming contract must authenticate the admin before
/// calling this helper. This crate does not know the admin `Address`, so it
/// cannot enforce that check itself.
///
/// Emits a [`PauserChanged`] event. Overwrites any previously configured
/// pauser.
pub fn set_pauser(env: &Env, pauser: &Address) {
    env.storage().instance().set(&DataKey::Pauser, pauser);
    env.events().publish(
        (PAUSER_CHANGED,),
        PauserChanged {
            pauser: Some(pauser.clone()),
        },
    );
}

/// Remove the pauser role, leaving only the admin able to pause.
///
/// **Admin-only**: the consuming contract must authenticate the admin before
/// calling this helper.
///
/// Emits a [`PauserChanged`] event with `pauser: None`.
pub fn clear_pauser(env: &Env) {
    env.storage().instance().remove(&DataKey::Pauser);
    env.events()
        .publish((PAUSER_CHANGED,), PauserChanged { pauser: None });
}

/// Pause the contract if `caller` is the admin or the configured pauser.
///
/// The consuming contract must authenticate `caller` (e.g. via
/// `caller.require_auth()`) before calling this helper. Returns `true` when
/// the caller was authorized and the pause was applied, `false` otherwise.
///
/// Unpausing is intentionally **not** covered by this helper — [`unpause`]
/// remains admin-only so a hot pauser key can never resume the contract.
pub fn pause_authorized(env: &Env, caller: &Address, admin: &Address) -> bool {
    let is_admin = caller == admin;
    let is_pauser = match get_pauser(env) {
        Some(pauser) => &pauser == caller,
        None => false,
    };
    if is_admin || is_pauser {
        pause(env);
        true
    } else {
        false
    }
}

/// Clear the paused flag, returning the contract to the active state.
///
/// Also clears the stored pause timestamp and reason so they do not linger
/// after the contract resumes.
///
/// Calling this when not paused is a no-op — the flag remains cleared.
///
/// **Admin-only**: the pauser role cannot unpause.
pub fn unpause(env: &Env) {
    env.storage().instance().set(&DataKey::Paused, &false);
    env.storage().instance().remove(&DataKey::PausedSince);
    env.storage().instance().remove(&DataKey::PauseReason);
    env.storage().instance().remove(&DataKey::PauseUntil);
    env.storage().instance().remove(&DataKey::PausedScopes);
}

/// Returns the ledger timestamp (seconds since Unix epoch) at which the
/// contract was last paused, or `None` if the contract is not currently
/// paused or has never been paused.
///
/// This value is cleared automatically when [`unpause`] is called, so it
/// is only present while the contract is in the paused state.
///
/// # Example
///
/// ```ignore
/// if let Some(since) = pausable::paused_since(&env) {
///     // contract has been paused since ledger timestamp `since`
/// }
/// ```
pub fn paused_since(env: &Env) -> Option<u64> {
    if !is_paused(env) {
        return None;
    }
    env.storage().instance().get(&DataKey::PausedSince)
}

/// Returns the reason string recorded when the contract was last paused via
/// [`pause_with_reason`], or `None` if no reason was provided or the contract
/// is not currently paused.
///
/// This value is cleared automatically when [`unpause`] is called.
pub fn pause_reason(env: &Env) -> Option<String> {
    if !is_paused(env) {
        return None;
    }
    env.storage().instance().get(&DataKey::PauseReason)
}

/// Panic with a descriptive message if the contract is currently paused.
///
/// Consuming contracts should call this at the top of any state-mutating
/// entry point that must be blocked while paused, e.g.:
///
/// ```ignore
/// pub fn transfer(env: Env, ...) -> Result<(), Error> {
///     pausable::require_not_paused(&env);
///     // ...
/// }
/// ```
pub fn require_not_paused(env: &Env) {
    if is_paused(env) {
        panic!("contract is paused");
    }
}

/// Returns `Err(err)` if the contract is currently paused, `Ok(())` otherwise.
///
/// Use this instead of [`require_not_paused`] in entry points that surface
/// pause state as a typed contract error (via `?`) rather than panicking,
/// e.g.:
///
/// ```ignore
/// pub fn transfer(env: Env, ...) -> Result<(), Error> {
///     pausable::require_not_paused_or(&env, Error::ContractPaused)?;
///     // ...
/// }
/// ```
pub fn require_not_paused_or<E>(env: &Env, err: E) -> Result<(), E> {
    if is_paused(env) {
        Err(err)
    } else {
        Ok(())
    }
}

/// Panic with a descriptive message if the contract is **not** currently paused.
///
/// This is the inverse of [`require_not_paused`] and is intended for
/// emergency-only recovery functions that should only be callable *while the
/// contract is paused* — for example, an admin drain or state-reset that must
/// be guarded against accidental invocation during normal operation.
///
/// # Example
///
/// ```ignore
/// /// Emergency drain — only callable while the contract is paused.
/// pub fn emergency_recover(env: Env, admin: Address) -> Result<(), Error> {
///     pausable::require_paused(&env);
///     // ... recovery logic ...
/// }
/// ```
pub fn require_paused(env: &Env) {
    if !is_paused(env) {
        panic!("contract is not paused");
    }
}

/// Returns `Err(err)` if the contract is **not** currently paused, `Ok(())`
/// otherwise.
///
/// Use this in entry points that expose the "not paused" condition as a typed
/// contract error rather than panicking:
///
/// ```ignore
/// pub fn emergency_recover(env: Env) -> Result<(), Error> {
///     pausable::require_paused_or(&env, Error::NotPaused)?;
///     // ...
/// }
/// ```
pub fn require_paused_or<E>(env: &Env, err: E) -> Result<(), E> {
    if !is_paused(env) {
        Err(err)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod test;
