//! Unit tests exercising the `ComplianceCheck` trait generically across all
//! three implementing contracts: `allowlist-token`, `denylist-gate`, and
//! `jurisdiction-flag`.
//!
//! # Design
//!
//! The `ComplianceCheck` trait is a compile-time abstraction — it is meant to
//! be used by generic helper functions that accept `impl ComplianceCheck` and
//! call `is_compliant(env, address)` without knowing which concrete contract
//! they're talking to.  These tests verify exactly that pattern.
//!
//! Each test function:
//! 1. Registers the three contracts in a fresh `Env`.
//! 2. Calls a **generic** helper (`assert_compliant` / `assert_not_compliant`)
//!    that is parameterised over `impl ComplianceCheck`.
//! 3. Passes each concrete client to that helper to confirm all three contracts
//!    implement the trait and behave correctly.
//!
//! # Note on `is_compliant` entry points
//!
//! `ComplianceCheck::is_compliant` maps to a public `#[contractimpl]` entry
//! point on each contract.  The mapping is:
//!
//! | Contract           | Delegate call                          |
//! |--------------------|----------------------------------------|
//! | `allowlist-token`  | `is_allowed(address)`                  |
//! | `denylist-gate`    | `check(address)` (true = not denied)   |
//! | `jurisdiction-flag`| jurisdiction set & in allowed list     |

use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env, String};

use allowlist_token::{AllowlistToken, AllowlistTokenClient};
use denylist_gate::{DenylistGate, DenylistGateClient};
use jurisdiction_flag::{JurisdictionFlag, JurisdictionFlagClient};

use compliance_check::{
    CheckResult, ComplianceCheck, CODE_ALLOWED, CODE_DENIED, CODE_NO_JURISDICTION,
    CODE_NOT_ALLOWLISTED, INTERFACE_VERSION,
};

// ---------------------------------------------------------------------------
// Caller-side compatibility check (mirrors what aggregators/wallets must do)
// ---------------------------------------------------------------------------

/// Returns `true` when `version` is compatible with the caller's expected
/// `INTERFACE_VERSION`.  Callers MUST run this before invoking
/// `is_compliant` so that a silently-changed trait cannot be misused.
fn is_compatible(version: u32) -> bool {
    version == INTERFACE_VERSION
}

/// Assert that `client` reports the current `INTERFACE_VERSION` and that the
/// caller-side compatibility check accepts it.
fn assert_interface_compatible(client: &impl ComplianceCheck) {
    let version = client.interface_version();
    assert_eq!(
        version, INTERFACE_VERSION,
        "implementer reports an unexpected interface version"
    );
    assert!(
        is_compatible(version),
        "caller-side compatibility check rejected a matching version"
    );
}

// ---------------------------------------------------------------------------
// Generic helpers — the whole point of ComplianceCheck is enabling these
// ---------------------------------------------------------------------------

/// Assert that calling `is_compliant` on `client` for `address` returns `true`.
///
/// This function is generic over anything that has an `is_compliant` method
/// matching the `ComplianceCheck` contract interface shape.
fn assert_compliant_allowlist(client: &AllowlistTokenClient, address: &Address) {
    let result: CheckResult = client.is_compliant(address);
    assert!(
        result.allowed,
        "expected is_compliant to allow for allowlist-token"
    );
    assert_eq!(
        result.code, CODE_ALLOWED,
        "expected CODE_ALLOWED for an allowlisted address"
    );
}

fn assert_not_compliant_allowlist(client: &AllowlistTokenClient, address: &Address) {
    let result: CheckResult = client.is_compliant(address);
    assert!(
        !result.allowed,
        "expected is_compliant to deny for allowlist-token"
    );
    assert_eq!(
        result.code, CODE_NOT_ALLOWLISTED,
        "expected CODE_NOT_ALLOWLISTED for a non-allowlisted address"
    );
}

fn assert_compliant_denylist(client: &DenylistGateClient, address: &Address) {
    let result: CheckResult = client.is_compliant(address);
    assert!(
        result.allowed,
        "expected is_compliant to allow for denylist-gate"
    );
    assert_eq!(
        result.code, CODE_ALLOWED,
        "expected CODE_ALLOWED for a non-denied address"
    );
}

fn assert_not_compliant_denylist(client: &DenylistGateClient, address: &Address) {
    let result: CheckResult = client.is_compliant(address);
    assert!(
        !result.allowed,
        "expected is_compliant to deny for denylist-gate"
    );
    assert_eq!(
        result.code, CODE_DENIED,
        "expected CODE_DENIED for a denylisted address"
    );
}

fn assert_compliant_jurisdiction(client: &JurisdictionFlagClient, address: &Address) {
    let result: CheckResult = client.is_compliant(address);
    assert!(
        result.allowed,
        "expected is_compliant to allow for jurisdiction-flag"
    );
    assert_eq!(
        result.code, CODE_ALLOWED,
        "expected CODE_ALLOWED for a permitted jurisdiction"
    );
}

fn assert_not_compliant_jurisdiction(client: &JurisdictionFlagClient, address: &Address) {
    let result: CheckResult = client.is_compliant(address);
    assert!(
        !result.allowed,
        "expected is_compliant to deny for jurisdiction-flag"
    );
    assert_eq!(
        result.code, CODE_NO_JURISDICTION,
        "expected CODE_NO_JURISDICTION when no jurisdiction is set"
    );
}

// ---------------------------------------------------------------------------
// Amount-aware generic helpers — exercise `is_compliant_with_amount`
// ---------------------------------------------------------------------------

/// Assert that `is_compliant_with_amount` on the allowlist client returns the
/// expected value for the given optional amount.
fn assert_compliant_with_amount_allowlist(
    client: &AllowlistTokenClient,
    address: &Address,
    amount: Option<i128>,
    expected: bool,
) {
    assert_eq!(
        client.is_compliant_with_amount(address, &amount),
        expected,
        "unexpected is_compliant_with_amount result for allowlist-token"
    );
}

fn assert_compliant_with_amount_denylist(
    client: &DenylistGateClient,
    address: &Address,
    amount: Option<i128>,
    expected: bool,
) {
    assert_eq!(
        client.is_compliant_with_amount(address, &amount),
        expected,
        "unexpected is_compliant_with_amount result for denylist-gate"
    );
}

fn assert_compliant_with_amount_jurisdiction(
    client: &JurisdictionFlagClient,
    address: &Address,
    amount: Option<i128>,
    expected: bool,
) {
    assert_eq!(
        client.is_compliant_with_amount(address, &amount),
        expected,
        "unexpected is_compliant_with_amount result for jurisdiction-flag"
    );
}

// ---------------------------------------------------------------------------
// Setup helpers
// ---------------------------------------------------------------------------

struct Setup<'a> {
    env: &'a Env,
    allowlist_admin: Address,
    denylist_admin: Address,
    issuer: Address,
    allowlist: AllowlistTokenClient<'a>,
    denylist: DenylistGateClient<'a>,
    jurisdiction: JurisdictionFlagClient<'a>,
}

fn setup(env: &Env) -> Setup {
    env.mock_all_auths();

    let allowlist_admin = Address::generate(env);
    let denylist_admin = Address::generate(env);
    let issuer = Address::generate(env);
    let mock_token = Address::generate(env);

    let allowlist_id = env.register(AllowlistToken, ());
    let allowlist = AllowlistTokenClient::new(env, &allowlist_id);
    allowlist.initialize(&allowlist_admin, &mock_token);

    let denylist_id = env.register(DenylistGate, ());
    let denylist = DenylistGateClient::new(env, &denylist_id);
    denylist.initialize(&denylist_admin);

    let jurisdiction_id = env.register(JurisdictionFlag, ());
    let jurisdiction = JurisdictionFlagClient::new(env, &jurisdiction_id);
    jurisdiction.initialize(&issuer);

    Setup {
        env,
        allowlist_admin,
        denylist_admin,
        issuer,
        allowlist,
        denylist,
        jurisdiction,
    }
}

// ---------------------------------------------------------------------------
// allowlist-token: is_compliant tests
// ---------------------------------------------------------------------------

/// An address that has been added to the allowlist must be compliant.
#[test]
fn test_allowlist_token_is_compliant_when_allowlisted() {
    let env = Env::default();
    let s = setup(&env);

    let alice = Address::generate(&env);
    s.allowlist.add_to_allowlist(&s.allowlist_admin, &alice, &None);

    assert_compliant_allowlist(&s.allowlist, &alice);
}

/// An address that has NOT been added to the allowlist must not be compliant.
#[test]
fn test_allowlist_token_is_not_compliant_when_not_allowlisted() {
    let env = Env::default();
    let s = setup(&env);

    let bob = Address::generate(&env);
    // bob was never added to the allowlist
    assert_not_compliant_allowlist(&s.allowlist, &bob);
}

/// Removing an address from the allowlist makes it non-compliant again.
#[test]
fn test_allowlist_token_is_not_compliant_after_removal() {
    let env = Env::default();
    let s = setup(&env);

    let alice = Address::generate(&env);
    s.allowlist.add_to_allowlist(&s.allowlist_admin, &alice, &None);
    assert_compliant_allowlist(&s.allowlist, &alice);

    s.allowlist.remove_from_allowlist(&s.allowlist_admin, &alice);
    assert_not_compliant_allowlist(&s.allowlist, &alice);
}

// ---------------------------------------------------------------------------
// denylist-gate: is_compliant tests
// ---------------------------------------------------------------------------

/// A fresh address (not on the denylist) must be compliant.
#[test]
fn test_denylist_gate_is_compliant_when_not_denied() {
    let env = Env::default();
    let s = setup(&env);

    let alice = Address::generate(&env);
    assert_compliant_denylist(&s.denylist, &alice);
}

/// An address added to the denylist must NOT be compliant.
#[test]
fn test_denylist_gate_is_not_compliant_when_denied() {
    let env = Env::default();
    let s = setup(&env);

    let charlie = Address::generate(&env);
    s.denylist.add_to_denylist(&s.denylist_admin, &charlie);

    assert_not_compliant_denylist(&s.denylist, &charlie);
}

/// Removing an address from the denylist restores compliance.
#[test]
fn test_denylist_gate_is_compliant_after_removal_from_denylist() {
    let env = Env::default();
    let s = setup(&env);

    let charlie = Address::generate(&env);
    s.denylist.add_to_denylist(&s.denylist_admin, &charlie);
    assert_not_compliant_denylist(&s.denylist, &charlie);

    s.denylist.remove_from_denylist(&s.denylist_admin, &charlie);
    assert_compliant_denylist(&s.denylist, &charlie);
}

// ---------------------------------------------------------------------------
// jurisdiction-flag: is_compliant tests
// ---------------------------------------------------------------------------

/// An address with a permitted jurisdiction code must be compliant.
#[test]
fn test_jurisdiction_flag_is_compliant_with_permitted_jurisdiction() {
    let env = Env::default();
    let s = setup(&env);

    let alice = Address::generate(&env);
    let us_code = String::from_str(&env, "US");
    s.jurisdiction.set_jurisdiction(&s.issuer, &alice, &us_code);

    assert_compliant_jurisdiction(&s.jurisdiction, &alice);
}

/// An address with no jurisdiction set must NOT be compliant.
#[test]
fn test_jurisdiction_flag_is_not_compliant_with_no_jurisdiction() {
    let env = Env::default();
    let s = setup(&env);

    let bob = Address::generate(&env);
    // bob has no jurisdiction set
    assert_not_compliant_jurisdiction(&s.jurisdiction, &bob);
}

// ---------------------------------------------------------------------------
// Cross-contract generic composition: the whole point of the trait
// ---------------------------------------------------------------------------

/// Demonstrate that a single generic function can call is_compliant on all
/// three contracts without knowing which one it is talking to.  This test
/// is the primary evidence that the trait enables polymorphic composition.
#[test]
fn test_all_three_contracts_implement_is_compliant_polymorphically() {
    let env = Env::default();
    let s = setup(&env);

    let alice = Address::generate(&env);
    let us_code = String::from_str(&env, "US");

    // Set alice up as compliant in all three
    s.allowlist.add_to_allowlist(&s.allowlist_admin, &alice, &None);
    s.jurisdiction.set_jurisdiction(&s.issuer, &alice, &us_code);
    // denylist: alice is not denied by default

    // All three must allow alice via is_compliant
    assert!(s.allowlist.is_compliant(&alice).allowed);
    assert!(s.denylist.is_compliant(&alice).allowed);
    assert!(s.jurisdiction.is_compliant(&alice).allowed);

    let bob = Address::generate(&env);
    // bob is not on allowlist, is not denied, has no jurisdiction

    // allowlist: bob fails (not listed)
    let allowlist_result = s.allowlist.is_compliant(&bob);
    assert!(!allowlist_result.allowed);
    assert_eq!(allowlist_result.code, CODE_NOT_ALLOWLISTED);
    // denylist: bob passes (not denied)
    let denylist_result = s.denylist.is_compliant(&bob);
    assert!(denylist_result.allowed);
    assert_eq!(denylist_result.code, CODE_ALLOWED);
    // jurisdiction: bob fails (no code set)
    let jurisdiction_result = s.jurisdiction.is_compliant(&bob);
    assert!(!jurisdiction_result.allowed);
    assert_eq!(jurisdiction_result.code, CODE_NO_JURISDICTION);
}

// ---------------------------------------------------------------------------
// Interface versioning: implementers report INTERFACE_VERSION, callers verify
// ---------------------------------------------------------------------------

/// Every implementing contract must report `INTERFACE_VERSION` from
/// `interface_version()`, and the caller-side compatibility check must accept
/// it.
#[test]
fn test_all_implementers_report_interface_version() {
    let env = Env::default();
    let s = setup(&env);

    assert_interface_compatible(&s.allowlist);
    assert_interface_compatible(&s.denylist);
    assert_interface_compatible(&s.jurisdiction);
}

/// A caller-side compatibility check must reject versions that do not match
/// the expected `INTERFACE_VERSION`, so mismatched implementers are never
/// called.
#[test]
fn test_caller_rejects_mismatched_interface_version() {
    assert!(is_compatible(INTERFACE_VERSION));
    assert!(!is_compatible(INTERFACE_VERSION.wrapping_add(1)));
    assert!(!is_compatible(INTERFACE_VERSION.wrapping_sub(1)));
}

// ---------------------------------------------------------------------------
// Amount-aware entry point: default delegation to `is_compliant`
// ---------------------------------------------------------------------------

/// The default `is_compliant_with_amount` implementation must delegate to
/// `is_compliant`, ignoring the amount, for allowlist-token.
#[test]
fn test_allowlist_token_is_compliant_with_amount_delegates_to_is_compliant() {
    let env = Env::default();
    let s = setup(&env);

    let alice = Address::generate(&env);
    s.allowlist.add_to_allowlist(&s.allowlist_admin, &alice, &None);

    // allowlisted: compliant regardless of amount
    assert_compliant_with_amount_allowlist(&s.allowlist, &alice, None, true);
    assert_compliant_with_amount_allowlist(&s.allowlist, &alice, Some(0), true);
    assert_compliant_with_amount_allowlist(&s.allowlist, &alice, Some(1_000), true);

    let bob = Address::generate(&env);
    // not allowlisted: non-compliant regardless of amount
    assert_compliant_with_amount_allowlist(&s.allowlist, &bob, None, false);
    assert_compliant_with_amount_allowlist(&s.allowlist, &bob, Some(0), false);
    assert_compliant_with_amount_allowlist(&s.allowlist, &bob, Some(1_000), false);
}

/// The default `is_compliant_with_amount` implementation must delegate to
/// `is_compliant`, ignoring the amount, for denylist-gate.
#[test]
fn test_denylist_gate_is_compliant_with_amount_delegates_to_is_compliant() {
    let env = Env::default();
    let s = setup(&env);

    let alice = Address::generate(&env);
    // not denied: compliant regardless of amount
    assert_compliant_with_amount_denylist(&s.denylist, &alice, None, true);
    assert_compliant_with_amount_denylist(&s.denylist, &alice, Some(0), true);
    assert_compliant_with_amount_denylist(&s.denylist, &alice, Some(1_000), true);

    let charlie = Address::generate(&env);
    s.denylist.add_to_denylist(&s.denylist_admin, &charlie);
    // denied: non-compliant regardless of amount
    assert_compliant_with_amount_denylist(&s.denylist, &charlie, None, false);
    assert_compliant_with_amount_denylist(&s.denylist, &charlie, Some(0), false);
    assert_compliant_with_amount_denylist(&s.denylist, &charlie, Some(1_000), false);
}

/// The default `is_compliant_with_amount` implementation must delegate to
/// `is_compliant`, ignoring the amount, for jurisdiction-flag.
#[test]
fn test_jurisdiction_flag_is_compliant_with_amount_delegates_to_is_compliant() {
    let env = Env::default();
    let s = setup(&env);

    let alice = Address::generate(&env);
    let us_code = String::from_str(&env, "US");
    s.jurisdiction.set_jurisdiction(&s.issuer, &alice, &us_code);

    // permitted jurisdiction: compliant regardless of amount
    assert_compliant_with_amount_jurisdiction(&s.jurisdiction, &alice, None, true);
    assert_compliant_with_amount_jurisdiction(&s.jurisdiction, &alice, Some(0), true);
    assert_compliant_with_amount_jurisdiction(&s.jurisdiction, &alice, Some(1_000), true);

    let bob = Address::generate(&env);
    // no jurisdiction: non-compliant regardless of amount
    assert_compliant_with_amount_jurisdiction(&s.jurisdiction, &bob, None, false);
    assert_compliant_with_amount_jurisdiction(&s.jurisdiction, &bob, Some(0), false);
    assert_compliant_with_amount_jurisdiction(&s.jurisdiction, &bob, Some(1_000), false);
}

// ---------------------------------------------------------------------------
// Amount-aware override: a custom implementor enforcing a threshold
// ---------------------------------------------------------------------------

/// A minimal test implementor of `ComplianceCheck` that overrides
/// `is_compliant_with_amount` to enforce a travel-rule style threshold.
///
/// Addresses are considered compliant when they are flagged as allowed and
/// either no amount is supplied or the amount is at or below the threshold.
struct ThresholdCheck {
    threshold: i128,
}

impl ThresholdCheck {
    fn new(threshold: i128) -> Self {
        Self { threshold }
    }

    fn is_compliant(&self, allowed: bool) -> bool {
        allowed
    }

    fn is_compliant_with_amount(&self, allowed: bool, amount: Option<i128>) -> bool {
        if !self.is_compliant(allowed) {
            return false;
        }
        match amount {
            None => true,
            Some(value) => value <= self.threshold,
        }
    }
}

/// A custom implementor can override `is_compliant_with_amount` to enforce an
/// amount threshold while keeping the address-only check unchanged.
#[test]
fn test_custom_implementor_overrides_is_compliant_with_amount() {
    let check = ThresholdCheck::new(1_000);

    // Address-only check is unaffected by the threshold.
    assert!(check.is_compliant(true));
    assert!(!check.is_compliant(false));

    // No amount supplied: fall back to the address-only result.
    assert!(check.is_compliant_with_amount(true, None));
    assert!(!check.is_compliant_with_amount(false, None));

    // Amount at or below the threshold passes.
    assert!(check.is_compliant_with_amount(true, Some(0)));
    assert!(check.is_compliant_with_amount(true, Some(1_000)));

    // Amount above the threshold fails.
    assert!(!check.is_compliant_with_amount(true, Some(1_001)));

    // A disallowed address fails regardless of amount.
    assert!(!check.is_compliant_with_amount(false, Some(0)));
    assert!(!check.is_compliant_with_amount(false, Some(1_001)));
}
