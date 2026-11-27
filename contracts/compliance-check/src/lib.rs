//! # compliance-check
//!
//! A `#![no_std]` crate that defines the shared [`ComplianceCheck`] trait used
//! for **compile-time composition** of Soroban compliance contracts.
//!
//! ## Distinction from `ComplianceCheckInterface` in `rwa-compliance-flow`
//!
//! There are two related but purposefully different abstractions in this workspace:
//!
//! | Abstraction | Where defined | Mechanism | Use case |
//! |---|---|---|---|
//! | [`ComplianceCheck`] (this crate) | `contracts/compliance-check` | Plain Rust trait — no `#[contractclient]` | Compile-time composition: unit tests, generic helpers, same-crate callers |
//! | `ComplianceCheckInterface` | `examples/rwa-compliance-flow` | `#[contractclient]` macro | Real cross-contract XDR calls at runtime |
//!
//! **`ComplianceCheck`** (this trait) is for code that _imports_ the contract
//! crate directly (e.g. integration tests or other contracts in the same build)
//! and calls the method as an ordinary Rust function.  Because it requires no
//! XDR or host-function overhead it is the right choice for unit tests and
//! in-process generic helpers such as `fn check_all(checks: &[impl ComplianceCheck])`.
//!
//! **`ComplianceCheckInterface`** (in `rwa-compliance-flow`) uses the
//! `#[contractclient]` macro to generate an XDR-based client stub suitable for
//! real cross-contract invocations on Soroban — i.e. calling a _deployed_
//! contract from another deployed contract.  It cannot be used for compile-time
//! generics.
//!
//! See `examples/rwa-compliance-flow/src/lib.rs` for the `ComplianceCheckInterface`
//! definition and the detailed rationale for keeping the two separate.
//!
//! ## Usage
//!
//! ```ignore
//! use compliance_check::{ComplianceCheck, CheckResult, INTERFACE_VERSION};
//!
//! // A generic helper that works with ANY compliance contract:
//! fn all_pass<C: ComplianceCheck>(env: &Env, check: &C, address: &Address) -> bool {
//!     // Verify the implementer speaks a compatible interface before calling.
//!     let version = C::interface_version(env);
//!     assert!(version == INTERFACE_VERSION, "incompatible compliance interface");
//!     check.is_compliant(env, address.clone()).allowed
//! }
//! ```
//!
//! ## Migration (interface v1 -> v2)
//!
//! The trait was previously unversioned and `is_compliant` returned a plain
//! `bool`.  Interface version 2 changes the contract of the trait:
//!
//! - `is_compliant` now returns [`CheckResult`] (`{ allowed, code }`) instead of
//!   `bool`.  Callers that only need pass/fail should read `.allowed`.
//! - Implementers must add `fn interface_version(env: &Env) -> u32` returning
//!   [`INTERFACE_VERSION`] (or the version they actually implement).
//! - Callers must verify `interface_version()` is within the range they support
//!   before invoking `is_compliant`, so that deployed implementers built against
//!   an older interface fail loudly instead of silently misbehaving.
#![no_std]

use soroban_sdk::{contractmeta, Address, Env};

contractmeta!(key = "version", val = env!("CARGO_PKG_VERSION"));
contractmeta!(key = "source", val = env!("CARGO_PKG_REPOSITORY"));

/// Current version of the [`ComplianceCheck`] trait interface.
///
/// Bump this whenever the trait's method signatures or semantics change so that
/// callers can detect incompatible deployed implementers.
pub const INTERFACE_VERSION: u32 = 2;

/// Stable reason code: the address passed the check.
pub const CODE_ALLOWED: u32 = 0;
/// Stable reason code: the address is not on the allowlist.
pub const CODE_NOT_ALLOWLISTED: u32 = 1;
/// Stable reason code: the address is on the denylist.
pub const CODE_DENYLISTED: u32 = 2;
/// Stable reason code: the address has no permitted jurisdiction.
pub const CODE_NO_JURISDICTION: u32 = 3;

/// Result of a compliance check.
///
/// `allowed` is the pass/fail outcome; `code` is a stable reason code
/// (see [`CODE_ALLOWED`], [`CODE_NOT_ALLOWLISTED`], [`CODE_DENYLISTED`],
/// [`CODE_NO_JURISDICTION`]) so aggregators and wallets can explain why a
/// check failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckResult {
    /// `true` if the address passed the check.
    pub allowed: bool,
    /// Stable reason code describing the outcome.
    pub code: u32,
}

impl CheckResult {
    /// Construct an allowed result with [`CODE_ALLOWED`].
    pub const fn allowed() -> Self {
        Self { allowed: true, code: CODE_ALLOWED }
    }

    /// Construct a denied result with the given reason `code`.
    pub const fn denied(code: u32) -> Self {
        Self { allowed: false, code }
    }
}

/// Shared compile-time trait for compliance contracts that expose a simple
/// `is_compliant(address) -> CheckResult` check.
///
/// Implementing this trait on a contract struct allows generic callers (tests,
/// other contracts linked at compile time) to use all three compliance
/// primitives interchangeably without cross-contract XDR overhead.
///
/// ## Implementing contracts
///
/// - `allowlist-token` — returns `is_allowed(address)`
/// - `denylist-gate`   — returns `check(address)` (true = not denied)
/// - `jurisdiction-flag` — returns whether `address` has a permitted
///   jurisdiction code (uses the contract's stored default allowed list)
///
/// ## Difference from `ComplianceCheckInterface`
///
/// `ComplianceCheckInterface` in `examples/rwa-compliance-flow` is a
/// `#[contractclient]`-backed interface for _runtime_ cross-contract calls.
/// This trait is the _compile-time_ counterpart for in-process composition.
pub trait ComplianceCheck {
    /// Returns the version of this trait interface implemented by the contract.
    ///
    /// Callers should compare this against [`INTERFACE_VERSION`] (or their
    /// supported range) before calling [`is_compliant`](Self::is_compliant).
    fn interface_version(env: &Env) -> u32;

    /// Returns a [`CheckResult`] describing whether `address` passes this
    /// compliance check and, if not, why.
    fn is_compliant(env: &Env, address: Address) -> CheckResult;
}

#[cfg(test)]
mod tests;
