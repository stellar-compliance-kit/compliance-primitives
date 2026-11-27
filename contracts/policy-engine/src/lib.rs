//! `policy-engine` is a `#![no_std]` Soroban contract that composes multiple
//! compliance checks into a single policy evaluation call.
//!
//! ## Purpose
//!
//! Each compliance primitive in this workspace answers one narrow question
//! about an address ("is it denylisted?", "is it in a permitted
//! jurisdiction?", "is it allowlisted?"). Real issuance policies are rarely
//! that narrow: they combine several of those answers with AND / OR logic
//! and must be changeable as regulation evolves. `policy-engine` holds that
//! composition on-chain, so a token contract makes **one** call —
//! `evaluate(from, to)` — and gets back a single pass/fail decision for the
//! whole policy, instead of hard-coding a sequence of cross-contract calls
//! that would need a redeploy every time the policy changes.
//!
//! ## Who calls it
//!
//! - **Token / transfer contracts** (the primary callers) invoke
//!   `evaluate(from, to)` or `batch_evaluate(pairs)` before moving value and
//!   refuse the transfer when the result is `false`. These calls are
//!   permissionless and require no auth.
//! - **The policy admin** (an issuer key or, preferably, a `multisig-admin`
//!   contract address) calls `initialize`, `add_check`, `remove_check` and
//!   `set_circuit_breaker` to manage the policy. Every mutation requires the
//!   stored admin's auth.
//! - **Off-chain tooling and auditors** call the read-only views
//!   (`get_checks`, `get_op`, `get_policy`, `circuit_breaker`) and consume
//!   the `PolicyResult` event stream to reconstruct every decision.
//!
//! ## How it composes with the other contracts
//!
//! | Contract | Relationship to `policy-engine` |
//! |---|---|
//! | `denylist-gate` | Registered as a [`CheckKind::Denylist`] check; `evaluate` calls its `check(address)`. |
//! | `jurisdiction-flag` | Registered as a [`CheckKind::Jurisdiction`] check; `evaluate` calls `is_permitted_jurisdiction(address, allowed_codes)`. |
//! | `allowlist-token` | Registered as a [`CheckKind::Allowlist`] check; `evaluate` calls its `is_allowed(address)`. |
//! | `circuit-breaker` | Optional emergency stop. When configured and frozen, `evaluate` denies outright without running any check. |
//! | `multisig-admin` | Recommended value for the `admin` address, so policy changes require M-of-N approval via `__check_auth`. |
//! | `pausable` | Shared crate used to guard admin mutations (`add_check`, `remove_check`) while the contract is paused. |
//! | `audit-log` | Complementary: integrators that need an on-chain, contract-readable trail of policy changes record them there; `policy-engine` itself only emits events. |
//! | `compliance-aggregator` | Sibling, not a dependency. The aggregator is a fixed AND-only fan-out optimised for call overhead; `policy-engine` is the configurable AND / OR layer. Pick one per integration. |
//!
//! The primitives are called through locally declared `#[contractclient]`
//! interfaces rather than direct crate dependencies, so any contract that
//! exposes the same function signature can be plugged in as a check.
//!
//! ## AND / OR design choice
//!
//! Compliance use cases almost always reduce to one of two logical shapes:
//! every check must pass (AND — "this address must be allowlisted **and** in
//! a permitted jurisdiction") or at least one must pass (OR — "this address
//! either cleared KYC with provider A **or** provider B"). A two-variant
//! `CombineOp` enum (`All` / `Any`) covers both without the overhead of an
//! AST, which would be over-engineered for this domain and would add
//! significant complexity to the storage, serialization, and auditing story.
//!
//! ## Check failure surfacing
//!
//! `evaluate` returns `Ok(bool)` rather than panicking or returning an
//! opaque error on a failed policy: a Soroban invocation that returns a
//! contract error rolls back all state changes including emitted events, so
//! any failure audit trail would be silently discarded. By returning
//! `Ok(false)` and emitting a `PolicyResult` event the caller gets a
//! machine-readable result and the chain preserves an auditable record of
//! the decision, consistent with the pattern used in `allowlist-token`.
//!
//! ## Registration design
//!
//! Checks are stored as an admin-managed, mutable `Vec<CheckKind>` in
//! persistent storage. This lets the issuer add, reorder, or remove checks
//! as compliance requirements evolve — without redeploying or upgrading the
//! contract binary. An authorized admin is required for all mutations,
//! keeping the policy immutable to unprivileged callers.
//!
//! ## Upgradeability
//!
//! The admin can propose an upgrade with `propose_upgrade(admin, new_wasm,
//! delay_ledgers)`. It can only be installed with `commit_upgrade` after the
//! delay expires, and the admin can call `cancel_upgrade` during that window.
//! The WASM swap preserves contract storage, including the admin, policy, and
//! checks. A successful commit emits `UpgradePerformed`.
//!
//! ## Storage and TTL policy
//!
//! All state (admin, `CombineOp`, the `Checks` vec and the optional
//! circuit-breaker address) lives in **instance** storage, which shares a
//! single TTL with the contract instance itself. Every write path
//! (`initialize`, `set_circuit_breaker`, `add_check`, `remove_check`,
//! `propose_upgrade`, `cancel_upgrade`)
//! finishes by extending that TTL: whenever the remaining TTL has dropped
//! below [`INSTANCE_TTL_THRESHOLD`] (~7 days) it is bumped back up to
//! [`INSTANCE_TTL_EXTEND_TO`] (~90 days). This keeps the policy from being
//! archived by Soroban state expiration — an archived policy would make
//! `evaluate` unreachable until a manual restore.
#![no_std]

use soroban_sdk::{
    contract, contractclient, contracterror, contractevent, contractimpl, contractmeta,
    contracttype, Address, BytesN, Env, String, Symbol, Vec,
};

// ---------------------------------------------------------------------------
// Contract metadata
// ---------------------------------------------------------------------------

// Carries the crate version and repository URL in the deployed WASM so
// operators can tell which release is deployed. Kept in sync with
// `Cargo.toml`; the release workflow verifies both keys are present.
contractmeta!(key = "version", val = env!("CARGO_PKG_VERSION"));
contractmeta!(key = "source", val = "https://github.com/example/stellar-compliance");

// ---------------------------------------------------------------------------
// Cross-contract client interfaces
// ---------------------------------------------------------------------------

/// The interface version this contract expects from every compliance check
/// it calls. Bump this (and the shared trait's version) whenever the check
/// interface changes shape; `evaluate` refuses to call a check whose
/// `interface_version()` does not match.
pub const CHECK_INTERFACE_VERSION: u32 = 1;

/// Result returned by a versioned compliance check.
///
/// `allowed` is the pass/fail decision; `code` is a machine-readable reason
/// code (e.g. `"OK"`, `"DENYLISTED"`, `"BAD_JURISDICTION"`) so aggregators
/// and wallets can surface *why* a policy denied instead of an opaque bool.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckResult {
    pub allowed: bool,
    pub code: Symbol,
}

/// Describes the `denylist-gate` contract interface used for cross-contract
/// calls. The generated `DenylistCheckClient` is used in `evaluate` to call
/// `check()` on a deployed denylist-gate instance. We do not take a direct
/// crate dependency on `denylist-gate` to avoid colliding wasm exports.
///
/// ## Migration note
///
/// The trait is versioned: every implementer must expose
/// `interface_version()` returning [`CHECK_INTERFACE_VERSION`], and `check`
/// now returns a [`CheckResult`] carrying a reason code. `evaluate` verifies
/// the version before calling `check`; implementers that predate the
/// versioned interface will fail the compatibility check rather than being
/// called with an incompatible signature.
#[contractclient(name = "DenylistCheckClient")]
pub trait DenylistCheckInterface {
    fn interface_version(env: Env) -> u32;
    fn check(env: Env, address: Address) -> CheckResult;
}

/// Describes the `jurisdiction-flag` contract interface used for
/// cross-contract calls. The generated `JurisdictionCheckClient` is used in
/// `evaluate`. Same reason as above for avoiding a direct crate dep.
#[contractclient(name = "JurisdictionCheckClient")]
pub trait JurisdictionCheckInterface {
    fn interface_version(env: Env) -> u32;
    fn is_permitted_jurisdiction(
        env: Env,
        address: Address,
        allowed_codes: Vec<String>,
    ) -> CheckResult;
}

/// Describes the `circuit-breaker` contract interface used for cross-contract
/// calls. Same reason as above for avoiding a direct crate dep.
#[contractclient(name = "CircuitBreakerClient")]
pub trait CircuitBreakerInterface {
    fn interface_version(env: Env) -> u32;
    fn is_frozen(env: Env) -> bool;
}

/// Describes the `allowlist-token` contract interface used for the policy
/// engine's allowlist check.
#[contractclient(name = "AllowlistCheckClient")]
pub trait AllowlistCheckInterface {
    fn interface_version(env: Env) -> u32;
    fn is_allowed(env: Env, address: Address) -> CheckResult;
}

/// Amount-aware compliance check interface.
///
/// Checks that need the transfer amount (e.g. travel-rule thresholds) can be
/// plugged in by implementing `check_with_amount(address, amount)`. The
/// engine calls this method from `evaluate_with_amount`; when no amount is
/// supplied the engine falls back to the address-only `check` method.
#[contractclient(name = "AmountAwareCheckClient")]
pub trait AmountAwareCheckInterface {
    fn check_with_amount(env: Env, address: Address, amount: i128) -> bool;
}

// ---------------------------------------------------------------------------
// Storage types
// ---------------------------------------------------------------------------

/// Parameters for a denylist-gate check.
#[contracttype]
#[derive(Clone)]
pub struct DenylistCheck {
    /// Address of the deployed `denylist-gate` contract to call.
    pub contract: Address,
}

/// Parameters for a jurisdiction-flag check.
#[contracttype]
#[derive(Clone)]
pub struct JurisdictionCheck {
    /// Address of the deployed `jurisdiction-flag` contract to call.
    pub contract: Address,
    /// The set of jurisdiction codes that are permitted.
    pub allowed_codes: Vec<String>,
}

/// Parameters for an allowlist-token check.
#[contracttype]
#[derive(Clone)]
pub struct AllowlistCheck {
    /// Address of the deployed `allowlist-token` contract to call.
    pub contract: Address,
}

/// Parameters for a circuit-breaker check.
///
/// When this check is evaluated, the engine calls `is_frozen()` on the
/// configured circuit-breaker contract. The check **passes** only when the
/// circuit-breaker is **not** frozen (i.e. the emergency stop has not been
/// triggered). This lets an issuer compose an explicit "is the system
/// live?" gate alongside denylist and jurisdiction rules inside a single
/// policy tree, rather than relying solely on the top-level circuit-breaker
/// short-circuit in `evaluate`.
#[contracttype]
#[derive(Clone)]
pub struct CircuitBreakerCheck {
    /// Address of the deployed `circuit-breaker` contract to call.
    pub contract: Address,
}

/// Describes a single compliance check the engine should perform.
///
/// Each variant carries the address of the external contract that implements
/// the check plus any parameters that check needs.
///
/// ## `#[contracttype]` enum variant shape restriction
///
/// The Soroban SDK's `#[contracttype]` macro (pinned in this workspace) only
/// supports **unit** or **single-tuple** enum variants. Named-field variants
/// such as:
///
/// ```ignore
/// // ❌ Does NOT compile with #[contracttype]
/// pub enum CheckKind {
///     Jurisdiction { contract: Address, allowed_codes: Vec<String> },
/// }
/// ```
///
/// are rejected by the macro with a compile error. This is a known limitation
/// of the XDR-based storage encoding used by Soroban: each variant is stored
/// as a tagged union, and named fields would require an extra layer of
/// encoding that the macro does not generate.
///
/// **The correct pattern** is to wrap multi-field parameters in a dedicated
/// `#[contracttype]` struct and use a single-tuple variant:
///
/// ```ignore
/// // ✅ Correct: wrap multi-field params in a struct
/// #[contracttype]
/// pub struct JurisdictionCheck {
///     pub contract: Address,
///     pub allowed_codes: Vec<String>,
/// }
///
/// #[contracttype]
/// pub enum CheckKind {
///     Jurisdiction(JurisdictionCheck),  // single-tuple variant — compiles
/// }
/// ```
///
/// If you add a new `CheckKind` variant that needs multiple parameters, follow
/// this same pattern: define a `#[contracttype]` struct for the parameters,
/// then add a single-tuple variant wrapping that struct. **Do not** attempt to
/// use named-field variants, even if a future contributor believes the SDK now
/// supports them — verify against the pinned SDK version in `Cargo.toml`
/// before changing this shape.
#[contracttype]
#[derive(Clone)]
pub enum CheckKind {
    /// Call `denylist-gate.check(address)`. The address must **not** be on
    /// the denylist for this check to pass.
    Denylist(DenylistCheck),
    /// Call `jurisdiction-flag.is_permitted_jurisdiction(address,
    /// allowed_codes)`. The address must have a jurisdiction code in
    /// `allowed_codes` for this check to pass.
    Jurisdiction(JurisdictionCheck),
    /// Call `allowlist-token.is_allowed(address)`. The address must be
    /// present on the allowlist for this check to pass.
    Allowlist(AllowlistCheck),
    /// Call `circuit-breaker.is_frozen()`. The check passes only when the
    /// circuit-breaker is **not** frozen. Use this to embed an emergency-stop
    /// gate directly in the policy tree so a single call to `evaluate`
    /// covers the full compliance stack including the freeze check.
    CircuitBreaker(CircuitBreakerCheck),
}

/// How the engine combines the results of multiple checks.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum CombineOp {
    /// AND — every check must pass. Used when an address must satisfy all
    /// compliance requirements simultaneously.
    All,
    /// OR — at least one check must pass. Used when multiple equivalent
    /// compliance paths exist (e.g. two KYC providers).
    Any,
}

/// Describes a pair of addresses (e.g. sender and recipient) for evaluating
/// compliance policies on transfers in batches.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddressPair {
    pub from: Address,
    pub to: Address,
}

/// A single named policy: its admin, combination operator, checks, the
/// configurable check limit and a monotonically increasing version.
#[contracttype]
#[derive(Clone)]
pub struct Policy {
    /// Address authorized to mutate this policy.
    pub admin: Address,
    /// How check results are combined (`All` = AND, `Any` = OR).
    pub op: CombineOp,
    /// The ordered list of checks that evaluation will run.
    pub checks: Vec<CheckKind>,
    /// Maximum number of checks this policy may hold (<= hard limit).
    pub max_checks: u32,
    /// Monotonic version, bumped on every mutation.
    pub policy_version: u32,
}

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Admin,
    /// Default policy name used by the legacy `evaluate(from, to)` entry point.
    DefaultPolicy,
    /// Map of policy name -> [`Policy`].
    Policies,
    /// Address of the `circuit-breaker` contract to consult, if any. When
    /// set and frozen, evaluation short-circuits to deny.
    CircuitBreaker,
    PendingUpgrade,
}

/// Delayed upgrade proposal state.
#[contracttype]
#[derive(Clone)]
pub struct UpgradeState {
    pub new_wasm: BytesN<32>,
    pub activated_at: u64,
}

// ---------------------------------------------------------------------------
// Errors and events
// ---------------------------------------------------------------------------

/// Maximum number of addresses accepted by `batch_evaluate` in a single call.
///
/// Soroban imposes a per-transaction CPU-instruction and memory budget. Each
/// address in the batch requires one or more cross-contract calls (one per
/// registered check), so an unbounded list would allow a caller to exhaust
/// the budget and brick the transaction. 20 was chosen to mirror the limit
/// used in the `compliance-aggregator` batch family and to keep the worst-case
/// instruction cost within the conservative end of the Soroban default budget.
pub const MAX_BATCH_SIZE: u32 = 20;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    NotInitialized = 1,
    AlreadyInitialized = 2,
    NotAuthorized = 3,
    PolicyViolation = 4,
    /// Returned by `add_check` when the number of registered checks would
    /// exceed `MAX_CHECKS`. Keeps per-evaluation resource cost bounded and
    /// prevents unbounded storage growth.
    MaxDepthExceeded = 5,
    /// Returned by `swap_checks` when either index `i` or `j` is out of
    /// range for the current check list.
    IndexOutOfBounds = 6,
    /// Returned by state-changing entry points while the contract is paused.
    ContractPaused = 7,
    /// Returned by `get_check` when the requested index is out of range.
    CheckIndexOutOfRange = 8,
    /// Returned by `commit_upgrade` when no upgrade is pending or its delay
    /// has not elapsed.
    UpgradeNotReady = 9,
    /// Returned when a configured check contract reports an
    /// `interface_version()` that does not match [`CHECK_INTERFACE_VERSION`].
    IncompatibleCheckInterface = 10,
}

/// Default maximum number of checks that can be registered in a single
/// policy. Chosen to keep per-evaluation cross-contract call overhead well
/// within Soroban's instruction limits while still supporting all realistic
/// compliance stack sizes.
pub const MAX_CHECKS: u32 = 16;

/// Hard upper bound on the configurable per-policy `max_checks`. An admin may
/// lower a policy's limit below this but never raise it above.
pub const MAX_CHECKS_HARD_LIMIT: u32 = 32;

/// Extend the contract's instance storage when its remaining TTL drops below
/// this many ledgers (~7 days at ~5s/ledger).
pub const INSTANCE_TTL_THRESHOLD: u32 = compliance_ttl::TTL_THRESHOLD;

/// Target remaining TTL, in ledgers, after an extension (~90 days at
/// ~5s/ledger).
pub const INSTANCE_TTL_EXTEND_TO: u32 = compliance_ttl::TTL_EXTEND_TO;

/// Outcome of one configured check for a `(from, to)` pair, as reported by
/// [`PolicyEngine::evaluate_dry_run`].
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct CheckOutcome {
    /// Zero-based position of the check in the registered policy list.
    pub check_index: u32,
    /// Short name of the check variant, e.g. `"Denylist"`.
    pub kind: Symbol,
    /// Whether the check passed for the `from` address.
    pub from_passed: bool,
    /// Whether the check passed for the `to` address.
    pub to_passed: bool,
}

/// Result of [`PolicyEngine::evaluate_dry_run`].
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct DryRunResult {
    /// Overall policy outcome, identical to what `evaluate` would return for
    /// the same pair at the same ledger.
    pub passed: bool,
    /// Whether the configured circuit-breaker is currently frozen. When `true`,
    /// `passed` is `false` regardless of the individual checks.
    pub circuit_breaker_frozen: bool,
    /// Per-check outcomes, in registration order. Every check is evaluated.
    pub checks: Vec<CheckOutcome>,
}

/// Emitted by `evaluate` regardless of the pass/fail outcome so that
/// off-chain compliance tooling can build a full audit trail even when the
/// policy passes (which wouldn't produce an error event).
#[contractevent]
pub struct PolicyResult {
    #[topic]
    pub passed: bool,
    pub from: Address,
    pub to: Address,
    /// Machine-readable reason code for the decision (e.g. `"OK"`,
    /// `"DENYLISTED"`, `"FROZEN"`, `"AllFailed"`). Lets off-chain tooling
    /// surface *why* a policy denied without a second call.
    pub code: Symbol,
}

/// Emitted whenever the contract is upgraded to a new WASM implementation,
/// for on-chain auditability of the upgrade path.
#[contractevent]
pub struct UpgradePerformed {
    #[topic]
    pub admin: Address,
}

/// Carries information about a failed check. Serializable on-chain, so it can
/// be embedded in contract events or returned from view calls.
///
/// ## Intended use
///
/// `CheckFailure` is the payload surfaced by [`PolicyEngine::evaluate_verbose`],
/// an extended variant of `evaluate` that returns details about a failed
/// policy, in addition to the overall pass/fail result.
///
/// ### Design sketch
///
/// ```text
/// evaluate_verbose(env, from, to)
///   -> Result<(bool, Option<CheckFailure>), Error>
/// ```
///
/// - When the policy **passes**, the second element is `None`.
/// - When an `All` policy **fails**, the second element is `Some(CheckFailure)`
///   with the zero-based index and kind of the first failing check.
/// - When an `Any` policy **fails**, the second element is
///   `Some(CheckFailure { check_index: u32::MAX, kind: "AllFailed" })` because
///   every check failed; no individual check is singled out.
///
/// Off-chain tooling (block explorers, compliance dashboards) can call
/// `evaluate_verbose` once and immediately know both the outcome and, on
/// failure, which rule first failed under `All`, or that every rule failed
/// under `Any`, without needing a second evaluation call.
///
/// ### Why `Option<CheckFailure>` instead of embedding in the error
///
/// `evaluate` deliberately returns `Ok(false)` on a policy failure rather than
/// `Err(...)` so that the emitted `PolicyResult` event is not rolled back (see
/// the module-level doc comment for the full rationale). `evaluate_verbose`
/// preserves this invariant: the `CheckFailure` detail rides in the `Ok(…)`
/// payload alongside the bool, keeping events auditable while surfacing richer
/// diagnostic data to callers.
///
/// ### Tracking
///
/// `evaluate_verbose` is implemented in this contract. See the
/// `evaluate_verbose` function below. Future work could extend `CheckFailure`
/// with additional fields (e.g. the address that failed, or the full
/// `CheckKind` payload) if callers need more context.
#[contracttype]
#[derive(Clone)]
pub struct CheckFailure {
    /// Zero-based index into the `Vec<CheckKind>` of the first failing check
    /// under `All`. Under `Any`, `u32::MAX` means every check failed and there
    /// is no single failing check to identify.
    pub check_index: u32,
    /// Short `Symbol` name of the failed `CheckKind` variant under `All`, e.g.
    /// `"Denylist"` or `"Jurisdiction"`. Under `Any`, this is `"AllFailed"`
    /// when every check fails.
    pub kind: Symbol,
}

/// A snapshot of the full policy configuration: the combination operator and
/// the ordered list of registered checks.
///
/// Returned by [`PolicyEngine::get_policy`] so off-chain tooling and auditors
/// can read back the complete policy in a single view call.
#[contracttype]
#[derive(Clone)]
pub struct PolicyNode {
    /// How check results are combined (`All` = AND, `Any` = OR).
    pub op: CombineOp,
    /// The ordered list of checks that evaluation will run.
    pub checks: Vec<CheckKind>,
    /// The configured maximum number of checks for this policy.
    pub max_checks: u32,
    /// Monotonic version of this policy.
    pub policy_version: u32,
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contract]
pub struct PolicyEngine;

#[contractimpl]
impl PolicyEngine {
    // -----------------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------------

    /// One-time initializer. Sets `admin` as the authorized manager and
    /// `op` as the combination operator for all future evaluations.
    /// Initializes the check list to empty.
    pub fn initialize(
        env: Env,
        admin: Address,
        op: CombineOp,
        circuit_breaker: Option<Address>,
    ) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        let default_name = Symbol::new(&env, "default");
        env.storage()
            .instance()
            .set(&DataKey::DefaultPolicy, &default_name);
        let empty: Vec<CheckKind> = Vec::new(&env);
        let policy = Policy {
            admin: admin.clone(),
            op,
            checks: empty,
            max_checks: MAX_CHECKS,
            policy_version: 1,
        };
        let mut policies: Map<Symbol, Policy> = Map::new(&env);
        policies.set(default_name, policy);
        env.storage().instance().set(&DataKey::Policies, &policies);
        if let Some(breaker) = circuit_breaker {
            env.storage()
                .instance()
                .set(&DataKey::CircuitBreaker, &breaker);
        }
        Self::extend_instance_ttl(&env);
        Ok(())
    }

    /// Create a new named policy managed by `admin`. Admin-only (the
    /// contract-level admin). Fails if a policy with `name` already exists.
    pub fn create_policy(
        env: Env,
        admin: Address,
        name: Symbol,
        op: CombineOp,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        let mut policies: Map<Symbol, Policy> = env
            .storage()
            .instance()
            .get(&DataKey::Policies)
            .ok_or(Error::NotInitialized)?;
        if policies.contains_key(name.clone()) {
            return Err(Error::PolicyAlreadyExists);
        }
        let empty: Vec<CheckKind> = Vec::new(&env);
        policies.set(
            name,
            Policy {
                admin,
                op,
                checks: empty,
                max_checks: MAX_CHECKS,
                policy_version: 1,
            },
        );
        env.storage().instance().set(&DataKey::Policies, &policies);
        Self::extend_instance_ttl(&env);
        Ok(())
    }

    /// Reassign the admin of a named policy. Only the current policy admin
    /// (or the contract admin) may call this.
    pub fn set_policy_admin(
        env: Env,
        admin: Address,
        name: Symbol,
        new_admin: Address,
    ) -> Result<(), Error> {
        Self::require_policy_admin(&env, &name, &admin)?;
        let mut policies: Map<Symbol, Policy> = env
            .storage()
            .instance()
            .get(&DataKey::Policies)
            .ok_or(Error::NotInitialized)?;
        let mut policy = policies.get(name.clone()).ok_or(Error::PolicyNotFound)?;
        policy.admin = new_admin;
        policy.policy_version = policy.policy_version.saturating_add(1);
        policies.set(name, policy);
        env.storage().instance().set(&DataKey::Policies, &policies);
        Self::extend_instance_ttl(&env);
        Ok(())
    }

    /// Remove a named policy. Admin-only. The default policy cannot be
    /// removed.
    pub fn remove_policy(env: Env, admin: Address, name: Symbol) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        let default_name: Symbol = env
            .storage()
            .instance()
            .get(&DataKey::DefaultPolicy)
            .ok_or(Error::NotInitialized)?;
        if name == default_name {
            return Err(Error::NotAuthorized);
        }
        let mut policies: Map<Symbol, Policy> = env
            .storage()
            .instance()
            .get(&DataKey::Policies)
            .ok_or(Error::NotInitialized)?;
        if !policies.contains_key(name.clone()) {
            return Err(Error::PolicyNotFound);
        }
        policies.remove(name);
        env.storage().instance().set(&DataKey::Policies, &policies);
        Self::extend_instance_ttl(&env);
        Ok(())
    }

    /// Set the maximum number of checks allowed for a named policy.
    /// Admin-only for that policy. Rejects values above
    /// [`MAX_CHECKS_HARD_LIMIT`].
    pub fn set_max_checks(
        env: Env,
        admin: Address,
        name: Symbol,
        max_checks: u32,
    ) -> Result<(), Error> {
        Self::require_policy_admin(&env, &name, &admin)?;
        if max_checks > MAX_CHECKS_HARD_LIMIT {
            return Err(Error::MaxChecksTooHigh);
        }
        let mut policies: Map<Symbol, Policy> = env
            .storage()
            .instance()
            .get(&DataKey::Policies)
            .ok_or(Error::NotInitialized)?;
        let mut policy = policies.get(name.clone()).ok_or(Error::PolicyNotFound)?;
        policy.max_checks = max_checks;
        policy.policy_version = policy.policy_version.saturating_add(1);
        policies.set(name, policy);
        env.storage().instance().set(&DataKey::Policies, &policies);
        Self::extend_instance_ttl(&env);
        Ok(())
    }

    /// Register or replace the `circuit-breaker` contract address.
    /// Admin-only. Pass this to enable emergency-freeze short-circuiting.
    pub fn set_circuit_breaker(env: Env, admin: Address, breaker: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage()
            .instance()
            .set(&DataKey::CircuitBreaker, &breaker);
        Self::extend_instance_ttl(&env);
        Ok(())
    }

    /// Returns the currently registered `circuit-breaker` address, if any.
    pub fn circuit_breaker(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::CircuitBreaker)
    }

    /// Propose an upgrade to an uploaded Wasm hash. The admin may cancel it
    /// before `delay_ledgers` have elapsed.
    pub fn propose_upgrade(
        env: Env,
        admin: Address,
        new_wasm: BytesN<32>,
        delay_ledgers: u32,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        let state = UpgradeState {
            new_wasm,
            activated_at: u64::from(env.ledger().sequence())
                .saturating_add(delay_ledgers as u64),
        };
        env.storage().instance().set(&DataKey::PendingUpgrade, &state);
        Self::extend_instance_ttl(&env);
        env.events()
            .publish((soroban_sdk::symbol_short!("upgprop"),), (admin, delay_ledgers));
        Ok(())
    }

    /// Commit a pending upgrade after its delay has elapsed.
    pub fn commit_upgrade(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        let state: UpgradeState = env
            .storage()
            .instance()
            .get(&DataKey::PendingUpgrade)
            .ok_or(Error::UpgradeNotReady)?;
        if u64::from(env.ledger().sequence()) < state.activated_at {
            return Err(Error::UpgradeNotReady);
        }
        env.deployer().update_current_contract_wasm(state.new_wasm);
        env.storage().instance().remove(&DataKey::PendingUpgrade);
        UpgradePerformed { admin }.publish(&env);
        Ok(())
    }

    /// Cancel a pending upgrade. Admin-only.
    pub fn cancel_upgrade(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().remove(&DataKey::PendingUpgrade);
        Self::extend_instance_ttl(&env);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Admin mutations
    // -----------------------------------------------------------------------

    /// Append a new `check` to the end of the policy list. Admin-only.
    ///
    /// Returns `Err(Error::MaxDepthExceeded)` if the list already contains
    /// `MAX_CHECKS` entries. This keeps the number of cross-contract calls
    /// issued by `evaluate` bounded and prevents storage bloat.
    pub fn add_check(env: Env, admin: Address, check: CheckKind) -> Result<(), Error> {
        let name = Self::default_policy_name(&env)?;
        Self::add_check_to_policy(env, admin, name, check)
    }

    /// Append a new `check` to a named policy. Admin-only for that policy.
    pub fn add_check_to_policy(
        env: Env,
        admin: Address,
        name: Symbol,
        check: CheckKind,
    ) -> Result<(), Error> {
        compliance_pausable::require_not_paused_or(&env, Error::ContractPaused)?;
        Self::require_policy_admin(&env, &name, &admin)?;
        let mut policies: Map<Symbol, Policy> = env
            .storage()
            .instance()
            .get(&DataKey::Policies)
            .ok_or(Error::NotInitialized)?;
        let mut policy = policies.get(name.clone()).ok_or(Error::PolicyNotFound)?;
        if policy.checks.len() >= policy.max_checks {
            return Err(Error::MaxDepthExceeded);
        }
        policy.checks.push_back(check);
        policy.policy_version = policy.policy_version.saturating_add(1);
        policies.set(name, policy);
        env.storage().instance().set(&DataKey::Policies, &policies);
        Self::extend_instance_ttl(&env);
        Ok(())
    }

    /// Remove the check at position `index` from the policy list.
    /// Admin-only. Indices shift down after removal (Vec::remove semantics).
    pub fn remove_check(env: Env, admin: Address, index: u32) -> Result<(), Error> {
        let name = Self::default_policy_name(&env)?;
        Self::remove_check_from_policy(env, admin, name, index)
    }

    /// Remove the check at position `index` from a named policy.
    /// Admin-only for that policy.
    pub fn remove_check_from_policy(
        env: Env,
        admin: Address,
        name: Symbol,
        index: u32,
    ) -> Result<(), Error> {
        compliance_pausable::require_not_paused_or(&env, Error::ContractPaused)?;
        Self::require_policy_admin(&env, &name, &admin)?;
        let mut policies: Map<Symbol, Policy> = env
            .storage()
            .instance()
            .get(&DataKey::Policies)
            .ok_or(Error::NotInitialized)?;
        let mut policy = policies.get(name.clone()).ok_or(Error::PolicyNotFound)?;
        if index >= policy.checks.len() {
            return Err(Error::IndexOutOfBounds);
        }
        policy.checks.remove(index);
        policy.policy_version = policy.policy_version.saturating_add(1);
        policies.set(name, policy);
        env.storage().instance().set(&DataKey::Policies, &policies);
        Self::extend_instance_ttl(&env);
        Ok(())
    }

    /// Swap the checks at positions `i` and `j` in the policy list.
    /// Admin-only.
    ///
    /// Issuers can use this to reorder checks without having to remove and
    /// re-add them (which would also change their indices). A common use case
    /// is placing the cheapest check first so it short-circuits early under
    /// `CombineOp::All`, avoiding unnecessary cross-contract calls.
    ///
    /// Returns `Err(Error::IndexOutOfBounds)` if either index is out of range.
    /// No-ops if `i == j`.
    pub fn swap_checks(env: Env, admin: Address, i: u32, j: u32) -> Result<(), Error> {
        let name = Self::default_policy_name(&env)?;
        Self::swap_checks_in_policy(env, admin, name, i, j)
    }

    /// Swap the checks at positions `i` and `j` in a named policy.
    /// Admin-only for that policy.
    pub fn swap_checks_in_policy(
        env: Env,
        admin: Address,
        name: Symbol,
        i: u32,
        j: u32,
    ) -> Result<(), Error> {
        Self::require_policy_admin(&env, &name, &admin)?;
        if i == j {
            return Ok(());
        }
        let mut policies: Map<Symbol, Policy> = env
            .storage()
            .instance()
            .get(&DataKey::Policies)
            .ok_or(Error::NotInitialized)?;
        let mut policy = policies.get(name.clone()).ok_or(Error::PolicyNotFound)?;
        let len = policy.checks.len();
        if i >= len || j >= len {
            return Err(Error::IndexOutOfBounds);
        }
        let check_i = policy.checks.get(i).unwrap();
        let check_j = policy.checks.get(j).unwrap();
        policy.checks.set(i, check_j);
        policy.checks.set(j, check_i);
        policy.policy_version = policy.policy_version.saturating_add(1);
        policies.set(name, policy);
        env.storage().instance().set(&DataKey::Policies, &policies);
        Ok(())
    }

    /// Remove every configured check in one call. Admin-only.
    pub fn clear_checks(env: Env, admin: Address) -> Result<(), Error> {
        let name = Self::default_policy_name(&env)?;
        Self::clear_checks_in_policy(env, admin, name)
    }

    /// Remove every configured check from a named policy. Admin-only for
    /// that policy.
    pub fn clear_checks_in_policy(
        env: Env,
        admin: Address,
        name: Symbol,
    ) -> Result<(), Error> {
        compliance_pausable::require_not_paused_or(&env, Error::ContractPaused)?;
        Self::require_policy_admin(&env, &name, &admin)?;
        let mut policies: Map<Symbol, Policy> = env
            .storage()
            .instance()
            .get(&DataKey::Policies)
            .ok_or(Error::NotInitialized)?;
        let mut policy = policies.get(name.clone()).ok_or(Error::PolicyNotFound)?;
        policy.checks = Vec::new(&env);
        policy.policy_version = policy.policy_version.saturating_add(1);
        policies.set(name, policy);
        env.storage().instance().set(&DataKey::Policies, &policies);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Evaluation
    // -----------------------------------------------------------------------

    /// Evaluate the current policy for a proposed transfer from `from` to
    /// `to`. Runs every registered check against both addresses using the
    /// configured `CombineOp`.
    ///
    /// Returns `Ok(true)` if the policy passes, `Ok(false)` if it fails.
    /// A `PolicyResult` event is always emitted so the outcome is auditable
    /// on-chain regardless of the result. `Err` is returned only for
    /// configuration failures (e.g. the contract was never initialized).
    ///
    /// # Example
    ///
    /// ```ignore
    /// // `engine` is a `PolicyEngineClient`; block the transfer if the policy fails.
    /// if !engine.evaluate(&from, &to) {
    ///     panic!("transfer blocked by policy");
    /// }
    /// ```
    pub fn evaluate(env: Env, from: Address, to: Address) -> Result<bool, Error> {
        let checks: Vec<CheckKind> = env
            .storage()
            .instance()
            .get(&DataKey::Checks)
            .ok_or(Error::NotInitialized)?;
        let op: CombineOp = env
            .storage()
            .instance()
            .get(&DataKey::CombineOp)
            .ok_or(Error::NotInitialized)?;
        let (passed, _, _) = Self::evaluate_inner(&env, &checks, &op, &from, &to)?;
        Ok(passed)
    }

    /// Evaluate the current policy for multiple address pairs (transfers) in a single call.
    ///
    /// Returns a `Vec<bool>` containing the pass/fail status for each pair in the same order.
    pub fn batch_evaluate(env: Env, pairs: Vec<AddressPair>) -> Result<Vec<bool>, Error> {
        let name = Self::default_policy_name(&env)?;
        let policy = Self::load_policy(&env, &name)?;
        let mut results = Vec::new(&env);
        for pair in pairs.iter() {
            let (passed, _, _) =
                Self::evaluate_inner(&env, &checks, &op, &pair.from, &pair.to)?;
            results.push_back(passed);
        }
        Ok(results)
    }

    /// Like `evaluate`, but on failure also returns a [`CheckFailure`] with
    /// details appropriate to the configured combine operation.
    ///
    /// Returns `Ok((true, None))` when the policy passes.
    ///
    /// On failure the reported [`CheckFailure`] depends on the operator:
    ///
    /// - **`CombineOp::All`** — the first failing check is reported: its
    ///   zero-based `check_index` and its `kind` (e.g. `"Denylist"`).
    /// - **`CombineOp::Any`** — every check failed, so no individual check is
    ///   blamed. The sentinel `check_index == u32::MAX` with
    ///   `kind == "AllFailed"` is returned instead.
    ///
    /// A `PolicyResult` event is emitted just as in `evaluate`, keeping the
    /// audit trail intact regardless of the outcome. The circuit-breaker
    /// short-circuit (if configured) is still respected and produces
    /// `Ok((false, None))` — no index is surfaced in that case because the
    /// freeze is a system-wide condition rather than a per-check failure.
    pub fn evaluate_verbose(
        env: Env,
        from: Address,
        to: Address,
    ) -> Result<(bool, Option<CheckFailure>), Error> {
        let name = Self::default_policy_name(&env)?;
        let policy = Self::load_policy(&env, &name)?;
        let result = Self::evaluate_inner(&env, &name, &policy, &from, &to, None);
        Ok(result)
    }

    /// Preview the policy decision for `(from, to)` without recording it.
    ///
    /// Read-only: emits no `PolicyResult` event and writes nothing to this
    /// contract's storage. Every check is evaluated, so `checks` reports the
    /// outcome of each one, which `evaluate` does not do under `CombineOp::All`
    /// (it stops at the first failure). `passed` follows the same combine rules
    /// as `evaluate`, including the circuit-breaker short-circuit.
    ///
    /// Each check still makes its usual cross-contract call to the contract it
    /// targets. The read-only guarantee covers this contract only.
    pub fn evaluate_dry_run(env: Env, from: Address, to: Address) -> Result<DryRunResult, Error> {
        let checks: Vec<CheckKind> = env
            .storage()
            .instance()
            .get(&DataKey::Checks)
            .ok_or(Error::NotInitialized)?;
        let op: CombineOp = env
            .storage()
            .instance()
            .get(&DataKey::CombineOp)
            .ok_or(Error::NotInitialized)?;
        let result = Self::evaluate_inner(&env, &checks, &op, &from, &to)?;
        Ok((result.0, result.1))
    }

    /// Core evaluation. Returns `(passed, failure_detail, reason_code)`.
    ///
    /// Before any check is called, each configured check contract's
    /// `interface_version()` is verified against
    /// [`CHECK_INTERFACE_VERSION`]; a mismatch aborts with
    /// `Err(Error::IncompatibleCheckInterface)` rather than silently calling
    /// an incompatible implementer. The reason code from the shared
    /// [`CheckResult`] is propagated into the emitted `PolicyResult` event.
    fn evaluate_inner(
        env: &Env,
        name: &Symbol,
        policy: &Policy,
        from: &Address,
        to: &Address,
    ) -> Result<(bool, Option<CheckFailure>, Symbol), Error> {
        // Verify every configured check speaks the expected interface
        // version before we call any of them.
        for i in 0..checks.len() {
            let check = checks.get(i).unwrap();
            Self::verify_check_interface(env, &check)?;
        }

        let breaker_addr: Option<Address> = env
            .storage()
            .instance()
            .get::<DataKey, Address>(&DataKey::CircuitBreaker);
        if let Some(addr) = breaker_addr {
            if CircuitBreakerClient::new(env, &addr).is_frozen() {
                let code = Symbol::new(env, "FROZEN");
                PolicyResult {
                    passed: false,
                    from: from.clone(),
                    to: to.clone(),
                    code: code.clone(),
                }
                .publish(env);
                return Ok((false, None, code));
            }
        }

        let checks = &policy.checks;
        let result = match policy.op {
            CombineOp::All => {
                let mut result = (true, None, Symbol::new(env, "OK"));
                for i in 0..checks.len() {
                    let check = checks.get(i).unwrap();
                    let from_res = Self::run_check(env, &check, from);
                    let to_res = Self::run_check(env, &check, to);
                    if !from_res.allowed || !to_res.allowed {
                        // Prefer the failing side's reason code so callers
                        // see why the check denied.
                        let code = if !from_res.allowed {
                            from_res.code
                        } else {
                            to_res.code
                        };
                        result = (
                            false,
                            Some(CheckFailure {
                                check_index: i,
                                kind: Self::check_kind_symbol(env, &check),
                            }),
                            code,
                        );
                        break;
                    }
                }
                result
            }
            CombineOp::Any => {
                if checks.is_empty() {
                    (false, None, Symbol::new(env, "NoChecks"))
                } else {
                    let mut any_pass = false;
                    let mut last_code = Symbol::new(env, "AllFailed");
                    for i in 0..checks.len() {
                        let check = checks.get(i).unwrap();
                        let from_res = Self::run_check(env, &check, from);
                        let to_res = Self::run_check(env, &check, to);
                        if from_res.allowed && to_res.allowed {
                            any_pass = true;
                            break;
                        }
                        last_code = if !from_res.allowed {
                            from_res.code
                        } else {
                            to_res.code
                        };
                    }
                    if any_pass {
                        (true, None, Symbol::new(env, "OK"))
                    } else {
                        // Every check failed under `Any`, so no individual
                        // check is representative. Surface the dedicated
                        // sentinel rather than blaming an arbitrary index.
                        (
                            false,
                            Some(CheckFailure {
                                check_index: u32::MAX,
                                kind: Symbol::new(env, "AllFailed"),
                            }),
                            last_code,
                        )
                    }
                }
            }
        };

        PolicyResult {
            passed: result.0,
            from: from.clone(),
            to: to.clone(),
            code: result.2.clone(),
        }
        .publish(env);
        Ok(result)
    }

    // -----------------------------------------------------------------------
    // Read-only accessors
    // -----------------------------------------------------------------------

    /// Returns the check at position `index` in the registered policy list,
    /// or `Err(Error::CheckIndexOutOfRange)` if `index` is out of range.
    ///
    /// This is more efficient than `get_checks()` when a caller only needs a
    /// single entry (e.g. to inspect or display the config of one rule in a
    /// UI), because it avoids deserializing and returning the entire
    /// `Vec<CheckKind>` — especially important as the list grows toward
    /// `MAX_CHECKS`.
    pub fn get_check(env: Env, index: u32) -> Result<CheckKind, Error> {
        let name = Self::default_policy_name(&env)?;
        let policy = Self::load_policy(&env, &name)?;
        policy.checks.get(index).ok_or(Error::CheckIndexOutOfRange)
    }

    /// Returns the current admin address, or `Err(Error::NotInitialized)` if
    /// the contract has not yet been initialized.
    ///
    /// Useful for off-chain tooling, UIs, and other contracts that need to
    /// verify who controls this policy-engine instance without having to
    /// replay the initialization transaction.
    pub fn get_admin(env: Env) -> Result<Address, Error> {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)
    }

    /// Returns the current list of registered checks.
    pub fn get_checks(env: Env) -> Vec<CheckKind> {
        match Self::default_policy_name(&env) {
            Ok(name) => match Self::load_policy(&env, &name) {
                Ok(policy) => policy.checks,
                Err(_) => Vec::new(&env),
            },
            Err(_) => Vec::new(&env),
        }
    }

    /// Returns the current combination operator of the default policy.
    pub fn get_op(env: Env) -> Result<CombineOp, Error> {
        let name = Self::default_policy_name(&env)?;
        let policy = Self::load_policy(&env, &name)?;
        Ok(policy.op)
    }

    /// Returns whether the policy engine is currently paused.
    pub fn is_paused(env: Env) -> bool {
        compliance_pausable::is_paused(&env)
    }

    /// Returns the full configured policy tree as a [`PolicyNode`].
    ///
    /// Off-chain tooling and auditors can call this single view to read back
    /// everything needed to understand and reproduce the policy that a
    /// deployed instance will evaluate, without having to reconstruct it from
    /// deployment transaction history.
    ///
    /// Returns `Err(Error::NotInitialized)` if the contract has not yet been
    /// initialized.
    pub fn get_policy(env: Env, name: Symbol) -> Result<PolicyNode, Error> {
        let policy = Self::load_policy(&env, &name)?;
        Ok(PolicyNode {
            op: policy.op,
            checks: policy.checks,
            max_checks: policy.max_checks,
            policy_version: policy.policy_version,
        })
    }

    /// Returns the current version of a named policy.
    pub fn get_policy_version(env: Env, name: Symbol) -> Result<u32, Error> {
        let policy = Self::load_policy(&env, &name)?;
        Ok(policy.policy_version)
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Verifies that the contract backing `check` reports a compatible
    /// `interface_version()`. Returns
    /// `Err(Error::IncompatibleCheckInterface)` on mismatch.
    fn verify_check_interface(env: &Env, check: &CheckKind) -> Result<(), Error> {
        let version = match check {
            CheckKind::Denylist(params) => {
                DenylistCheckClient::new(env, &params.contract).interface_version()
            }
            CheckKind::Jurisdiction(params) => {
                JurisdictionCheckClient::new(env, &params.contract).interface_version()
            }
            CheckKind::Allowlist(params) => {
                AllowlistCheckClient::new(env, &params.contract).interface_version()
            }
            CheckKind::CircuitBreaker(params) => {
                CircuitBreakerClient::new(env, &params.contract).interface_version()
            }
        };
        if version != CHECK_INTERFACE_VERSION {
            return Err(Error::IncompatibleCheckInterface);
        }
        Ok(())
    }

    fn run_check(env: &Env, check: &CheckKind, address: &Address) -> CheckResult {
        match check {
            CheckKind::Denylist(params) => {
                let client = DenylistCheckClient::new(env, &params.contract);
                client.check(address)
            }
            CheckKind::Jurisdiction(params) => {
                let client = JurisdictionCheckClient::new(env, &params.contract);
                // A callee error (e.g. `EmptyAllowedCodes`) fails the check.
                match client.try_is_permitted_jurisdiction(address, &params.allowed_codes) {
                    Ok(Ok(result)) => result,
                    _ => CheckResult {
                        allowed: false,
                        code: Symbol::new(env, "CheckError"),
                    },
                }
            }
            CheckKind::Allowlist(params) => {
                let client = AllowlistCheckClient::new(env, &params.contract);
                client.is_allowed(address)
            }
            CheckKind::CircuitBreaker(params) => {
                // The circuit-breaker check is address-independent: it reflects
                // the global freeze state of the system. The check passes only
                // when the breaker is NOT frozen.
                let _ = address; // address not used for this check kind
                let client = CircuitBreakerClient::new(env, &params.contract);
                if client.is_frozen() {
                    CheckResult {
                        allowed: false,
                        code: Symbol::new(env, "FROZEN"),
                    }
                } else {
                    CheckResult {
                        allowed: true,
                        code: Symbol::new(env, "OK"),
                    }
                }
            }
        }
    }

    /// Returns a short `Symbol` naming the `CheckKind` variant for use in
    /// `CheckFailure`. Kept in sync with the enum variants.
    fn check_kind_symbol(env: &Env, check: &CheckKind) -> Symbol {
        match check {
            CheckKind::Denylist(_) => Symbol::new(env, "Denylist"),
            CheckKind::Jurisdiction(_) => Symbol::new(env, "Jurisdiction"),
            CheckKind::Allowlist(_) => Symbol::new(env, "Allowlist"),
            CheckKind::CircuitBreaker(_) => Symbol::new(env, "CircuitBreaker"),
        }
    }

    /// Refresh the TTL of the contract instance (and therefore of every
    /// instance-storage entry). See the "Storage and TTL policy" section of
    /// the module docs.
    fn extend_instance_ttl(env: &Env) {
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);
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
mod test_utils;

#[cfg(test)]
mod test;

#[cfg(test)]
mod dry_run_test;

#[cfg(test)]
mod fuzz;

#[cfg(test)]
mod bench;

