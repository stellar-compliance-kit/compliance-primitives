//! Tests for `compliance-aggregator`.
//!
//! ## Coverage
//! - Initialization and admin management
//! - `check_address` with denylist-only, jurisdiction-only, and both checks
//! - Pass/fail combinations across both checks
//! - `check_all` batch variant for multiple addresses
//! - Error cases: no checks registered, empty address list, non-admin callers
//!
//! ## Benchmark section
//! The "benchmark" tests at the bottom compare the Soroban simulated resource
//! costs (via `cost_estimate().budget()`) of:
//! 1. Calling each primitive directly from the test harness — simulating what
//!    a consumer would pay if they called them individually.
//! 2. Calling `check_address` on this aggregator for the same address.
//!
//! The numbers are printed to stdout (visible with `cargo test -- --nocapture`)
//! and an assertion ensures the aggregated path never exceeds the sum of the
//! individual paths by more than a small constant factor (verifying we're not
//! adding gratuitous overhead).

// In #![no_std] crate test builds, the test runner links std but does not
// bring it into scope automatically. Declare it here so we can use println!
// in the benchmark output below.
extern crate std;

use super::*;
use circuit_breaker::{CircuitBreaker, CircuitBreakerClient as CbClient};
use denylist_gate::{DenylistGate, DenylistGateClient};
use jurisdiction_flag::{JurisdictionFlag, JurisdictionFlagClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{contract, contractimpl, contracttype, vec, Env, String};

#[contracttype]
#[derive(Clone)]
enum MockAllowlistKey {
    Allowed(Address),
}

#[contract]
pub struct MockAllowlist;

#[contractimpl]
impl MockAllowlist {
    pub fn set_allowed(env: Env, address: Address, allowed: bool) {
        env.storage().instance().set(&MockAllowlistKey::Allowed(address), &allowed);
    }

    pub fn is_allowed(env: Env, address: Address) -> bool {
        env.storage().instance().get(&MockAllowlistKey::Allowed(address)).unwrap_or(false)
    }
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

#[contract]
pub struct MockAllowlist;

#[contracttype]
#[derive(Clone)]
enum MockAllowlistKey {
    Allowed(Address),
}

#[contractimpl]
impl MockAllowlist {
    pub fn set_allowed(env: Env, address: Address, allowed: bool) {
        env.storage()
            .instance()
            .set(&MockAllowlistKey::Allowed(address), &allowed);
    }

    pub fn is_allowed(env: Env, address: Address) -> bool {
        env.storage()
            .instance()
            .get(&MockAllowlistKey::Allowed(address))
            .unwrap_or(false)
    }
}

/// Registers and initialises both underlying primitives plus the aggregator.
/// Returns `(gate_admin, gate_id, flag_issuer, flag_id, agg_admin, agg_id, agg_client)`.
#[allow(clippy::type_complexity)]
fn setup_all(env: &Env) -> (Address, Address, Address, Address, Address, Address, ComplianceAggregatorClient<'_>) {
    env.mock_all_auths();

    // denylist-gate
    let gate_admin = Address::generate(env);
    let gate_id = env.register(DenylistGate, ());
    DenylistGateClient::new(env, &gate_id).initialize(&gate_admin);

    // jurisdiction-flag
    let flag_issuer = Address::generate(env);
    let flag_id = env.register(JurisdictionFlag, ());
    JurisdictionFlagClient::new(env, &flag_id).initialize(&flag_issuer);

    // aggregator
    let agg_admin = Address::generate(env);
    let agg_id = env.register(ComplianceAggregator, ());
    let agg_client = ComplianceAggregatorClient::new(env, &agg_id);
    agg_client.initialize(&agg_admin, &Some(gate_id.clone()), &Some(flag_id.clone()), &None);

    (gate_admin, gate_id, flag_issuer, flag_id, agg_admin, agg_id, agg_client)
}

/// Helper: sets `address` jurisdiction to `code` via the flag contract.
fn set_jurisdiction(env: &Env, flag_id: &Address, issuer: &Address, address: &Address, code: &str) {
    JurisdictionFlagClient::new(env, flag_id).set_jurisdiction(issuer, address, &String::from_str(env, code));
}

/// Helper: adds `address` to the denylist.
fn deny(env: &Env, gate_id: &Address, admin: &Address, address: &Address) {
    DenylistGateClient::new(env, gate_id).add_to_denylist(admin, address);
}

fn us_vec(env: &Env) -> soroban_sdk::Vec<soroban_sdk::String> {
    vec![env, String::from_str(env, "US")]
}

// ---------------------------------------------------------------------------
// Initialization & admin
// ---------------------------------------------------------------------------

#[test]
fn test_initialize_stores_gate_and_flag() {
    let env = Env::default();
    let (_, gate_id, _, flag_id, _, _, client) = setup_all(&env);
    assert_eq!(client.denylist_gate(), Some(gate_id));
    assert_eq!(client.jurisdiction_flag(), Some(flag_id));
    assert_eq!(client.get_checks_summary(), (true, true, false, false));
}

#[test]
fn test_initialize_without_checks() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let id = env.register(ComplianceAggregator, ());
    let client = ComplianceAggregatorClient::new(&env, &id);
    client.initialize(&admin, &None, &None, &None);
    assert_eq!(client.denylist_gate(), None);
    assert_eq!(client.jurisdiction_flag(), None);
}

#[test]
fn test_get_checks_summary_reports_configured_checks() {
    let env = Env::default();
    env.mock_all_auths();

    let gate_admin = Address::generate(&env);
    let gate_id = env.register(DenylistGate, ());
    DenylistGateClient::new(&env, &gate_id).initialize(&gate_admin);

    let flag_issuer = Address::generate(&env);
    let flag_id = env.register(JurisdictionFlag, ());
    JurisdictionFlagClient::new(&env, &flag_id).initialize(&flag_issuer);

    let agg_admin = Address::generate(&env);
    let agg_id = env.register(ComplianceAggregator, ());
    let client = ComplianceAggregatorClient::new(&env, &agg_id);
    client.initialize(&agg_admin, &Some(gate_id.clone()), &Some(flag_id.clone()), &None);

    assert_eq!(client.get_checks_summary(), (true, true, false, false));

    let client_without_flag = ComplianceAggregatorClient::new(&env, &agg_id);
    // Re-initialize is not permitted; verify the summary is still a view over storage.
    assert_eq!(client_without_flag.get_checks_summary(), (true, true, false, false));
}

#[test]
fn test_double_initialize_fails() {
    let env = Env::default();
    let (_, _, _, _, admin, _, client) = setup_all(&env);
    let result = client.try_initialize(&admin, &None, &None, &None);
    assert_eq!(result, Err(Ok(Error::AlreadyInitialized)));
}

#[test]
fn test_get_admin_returns_initialized_admin() {
    let env = Env::default();
    let (_, _, _, _, admin, _, client) = setup_all(&env);
    assert_eq!(client.get_admin(), admin);
}

#[test]
fn test_get_admin_before_initialize_fails() {
    let env = Env::default();
    let id = env.register(ComplianceAggregator, ());
    let client = ComplianceAggregatorClient::new(&env, &id);
    assert_eq!(client.try_get_admin(), Err(Ok(Error::NotInitialized)));
}

#[test]
fn test_get_admin_reflects_set_admin() {
    let env = Env::default();
    let (_, _, _, _, admin, _, client) = setup_all(&env);
    let new_admin = Address::generate(&env);
    client.set_admin(&admin, &new_admin);
    assert_eq!(client.get_admin(), new_admin);
}

#[test]
fn test_set_admin_succeeds() {
    let env = Env::default();
    let (_, _, _, _, admin, _, client) = setup_all(&env);
    let new_admin = Address::generate(&env);
    client.set_admin(&admin, &new_admin);
    // new_admin should now be able to update the gate
    let gate2_id = env.register(DenylistGate, ());
    client.set_denylist_gate(&new_admin, &gate2_id);
    assert_eq!(client.denylist_gate(), Some(gate2_id));
}

#[test]
fn test_set_admin_rejects_non_admin() {
    let env = Env::default();
    let (_, _, _, _, _, _, client) = setup_all(&env);
    let impostor = Address::generate(&env);
    let new_admin = Address::generate(&env);
    let result = client.try_set_admin(&impostor, &new_admin);
    assert_eq!(result, Err(Ok(Error::NotAuthorized)));
}

#[test]
fn test_set_circuit_breaker_rejects_changes_while_paused() {
    let env = Env::default();
    let (_, _, _, _, admin, _, client) = setup_all(&env);
    let breaker = Address::generate(&env);
    client.pause(&admin);

    let result = client.try_set_circuit_breaker(&admin, &breaker);
    assert_eq!(result, Err(Ok(Error::ContractPaused)));
}

#[test]
fn test_set_denylist_gate_rejects_non_admin() {
    let env = Env::default();
    let (_, _, _, _, _, _, client) = setup_all(&env);
    let impostor = Address::generate(&env);
    let gate2_id = env.register(DenylistGate, ());
    let result = client.try_set_denylist_gate(&impostor, &gate2_id);
    assert_eq!(result, Err(Ok(Error::NotAuthorized)));
}

#[test]
fn test_set_jurisdiction_flag_rejects_non_admin() {
    let env = Env::default();
    let (_, _, _, _, _, _, client) = setup_all(&env);
    let impostor = Address::generate(&env);
    let flag2_id = env.register(JurisdictionFlag, ());
    let result = client.try_set_jurisdiction_flag(&impostor, &flag2_id);
    assert_eq!(result, Err(Ok(Error::NotAuthorized)));
}

#[test]
fn test_set_allowlist_rejects_non_admin() {
    let env = Env::default();
    let (_, _, _, _, _, _, client) = setup_all(&env);
    let impostor = Address::generate(&env);
    let allowlist = Address::generate(&env);
    let result = client.try_set_allowlist(&impostor, &allowlist);
    assert_eq!(result, Err(Ok(Error::NotAuthorized)));
}

// ---------------------------------------------------------------------------
// check_address — denylist only
// ---------------------------------------------------------------------------

#[test]
fn test_check_address_denylist_only_pass() {
    let env = Env::default();
    env.mock_all_auths();

    let gate_admin = Address::generate(&env);
    let gate_id = env.register(DenylistGate, ());
    DenylistGateClient::new(&env, &gate_id).initialize(&gate_admin);

    let agg_admin = Address::generate(&env);
    let agg_id = env.register(ComplianceAggregator, ());
    let client = ComplianceAggregatorClient::new(&env, &agg_id);
    client.initialize(&agg_admin, &Some(gate_id.clone()), &None, &None);

    let alice = Address::generate(&env);
    let (all_passed, checks) = client.check_address(&alice, &vec![&env]);
    assert!(all_passed);
    assert_eq!(checks.len(), 1);
    assert_eq!(
        checks.get(0),
        Some(CheckResult {
            check: CheckKind::Denylist,
            passed: true,
            code: CODE_OK,
        })
    );
}

#[test]
fn test_check_address_denylist_only_fail() {
    let env = Env::default();
    env.mock_all_auths();

    let gate_admin = Address::generate(&env);
    let gate_id = env.register(DenylistGate, ());
    let gate_client = DenylistGateClient::new(&env, &gate_id);
    gate_client.initialize(&gate_admin);

    let agg_admin = Address::generate(&env);
    let agg_id = env.register(ComplianceAggregator, ());
    let client = ComplianceAggregatorClient::new(&env, &agg_id);
    client.initialize(&agg_admin, &Some(gate_id.clone()), &None, &None);

    let alice = Address::generate(&env);
    gate_client.add_to_denylist(&gate_admin, &alice);

    let (all_passed, checks) = client.check_address(&alice, &vec![&env]);
    assert!(!all_passed);
    let result = checks.get(0).unwrap();
    assert_eq!(result.check, CheckKind::Denylist);
    assert!(!result.passed);
    assert_eq!(result.code, CODE_DENIED);
    assert_ne!(result.code, CODE_OK);
}

// ---------------------------------------------------------------------------
// check_address — jurisdiction only
// ---------------------------------------------------------------------------

#[test]
fn test_check_address_jurisdiction_only_pass() {
    let env = Env::default();
    env.mock_all_auths();

    let flag_issuer = Address::generate(&env);
    let flag_id = env.register(JurisdictionFlag, ());
    let flag_client = JurisdictionFlagClient::new(&env, &flag_id);
    flag_client.initialize(&flag_issuer);

    let agg_admin = Address::generate(&env);
    let agg_id = env.register(ComplianceAggregator, ());
    let client = ComplianceAggregatorClient::new(&env, &agg_id);
    client.initialize(&agg_admin, &None, &Some(flag_id.clone()), &None);

    let alice = Address::generate(&env);
    flag_client.set_jurisdiction(&flag_issuer, &alice, &String::from_str(&env, "US"));

    let (all_passed, checks) = client.check_address(&alice, &us_vec(&env));
    assert!(all_passed);
    assert_eq!(
        checks.get(0),
        Some(CheckResult {
            check: CheckKind::Jurisdiction,
            passed: true,
            code: CODE_OK,
        })
    );
}

#[test]
fn test_check_address_jurisdiction_only_fail_wrong_code() {
    let env = Env::default();
    env.mock_all_auths();

    let flag_issuer = Address::generate(&env);
    let flag_id = env.register(JurisdictionFlag, ());
    let flag_client = JurisdictionFlagClient::new(&env, &flag_id);
    flag_client.initialize(&flag_issuer);

    let agg_admin = Address::generate(&env);
    let agg_id = env.register(ComplianceAggregator, ());
    let client = ComplianceAggregatorClient::new(&env, &agg_id);
    client.initialize(&agg_admin, &None, &Some(flag_id.clone()), &None);

    let alice = Address::generate(&env);
    // Alice is in RU, but only US is permitted
    flag_client.set_jurisdiction(&flag_issuer, &alice, &String::from_str(&env, "RU"));

    let (all_passed, checks) = client.check_address(&alice, &us_vec(&env));
    assert!(!all_passed);
    let result = checks.get(0).unwrap();
    assert_eq!(result.check, CheckKind::Jurisdiction);
    assert!(!result.passed);
    assert_eq!(result.code, CODE_JURISDICTION);
    assert_ne!(result.code, CODE_OK);
}

// ---------------------------------------------------------------------------
// check_address — both checks, all combinations
// ---------------------------------------------------------------------------

#[test]
fn test_both_checks_pass() {
    let env = Env::default();
    let (_, gate_id, flag_issuer, flag_id, _, _, client) = setup_all(&env);
    let _ = gate_id;

    let alice = Address::generate(&env);
    set_jurisdiction(&env, &flag_id, &flag_issuer, &alice, "US");

    let (all_passed, checks) = client.check_address(&alice, &us_vec(&env));
    assert!(all_passed);
    assert_eq!(checks.len(), 2);
    assert!(checks.get(0).unwrap().passed); // denylist
    assert_eq!(checks.get(0).unwrap().code, CODE_OK);
    assert!(checks.get(1).unwrap().passed); // jurisdiction
    assert_eq!(checks.get(1).unwrap().code, CODE_OK);
}

#[test]
fn test_denylist_fail_jurisdiction_pass() {
    let env = Env::default();
    let (gate_admin, gate_id, flag_issuer, flag_id, _, _, client) = setup_all(&env);

    let alice = Address::generate(&env);
    set_jurisdiction(&env, &flag_id, &flag_issuer, &alice, "US");
    deny(&env, &gate_id, &gate_admin, &alice);

    let (all_passed, checks) = client.check_address(&alice, &us_vec(&env));
    assert!(!all_passed);
    assert_eq!(checks.get(0).unwrap().check, CheckKind::Denylist);
    assert!(!checks.get(0).unwrap().passed);
    assert_eq!(checks.get(0).unwrap().code, CODE_DENIED);
    assert_eq!(checks.get(1).unwrap().check, CheckKind::Jurisdiction);
    assert!(checks.get(1).unwrap().passed);
    assert_eq!(checks.get(1).unwrap().code, CODE_OK);
}

#[test]
fn test_denylist_pass_jurisdiction_fail() {
    let env = Env::default();
    let (_, _, _, _, _, _, client) = setup_all(&env);

    let alice = Address::generate(&env);
    // Alice has no jurisdiction set → is_permitted_jurisdiction returns false

    let (all_passed, checks) = client.check_address(&alice, &us_vec(&env));
    assert!(!all_passed);
    assert!(checks.get(0).unwrap().passed); // denylist passes (not denied)
    assert_eq!(checks.get(0).unwrap().code, CODE_OK);
    assert!(!checks.get(1).unwrap().passed); // jurisdiction fails (no code)
    assert_eq!(checks.get(1).unwrap().code, CODE_JURISDICTION);
}

#[test]
fn test_both_checks_fail() {
    let env = Env::default();
    let (gate_admin, gate_id, _, _, _, _, client) = setup_all(&env);

    let alice = Address::generate(&env);
    // No jurisdiction set, and also denied
    deny(&env, &gate_id, &gate_admin, &alice);

    let (all_passed, checks) = client.check_address(&alice, &us_vec(&env));
    assert!(!all_passed);
    assert!(!checks.get(0).unwrap().passed); // denylist fails
    assert_eq!(checks.get(0).unwrap().code, CODE_DENIED);
    assert!(!checks.get(1).unwrap().passed); // jurisdiction fails
    assert_eq!(checks.get(1).unwrap().code, CODE_JURISDICTION);
}

// ---------------------------------------------------------------------------
// check_address — error cases
// ---------------------------------------------------------------------------

#[test]
fn test_check_address_no_checks_registered() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let id = env.register(ComplianceAggregator, ());
    let client = ComplianceAggregatorClient::new(&env, &id);
    client.initialize(&admin, &None, &None, &None);

    let alice = Address::generate(&env);
    let result = client.try_check_address(&alice, &vec![&env]);
    assert_eq!(result, Err(Ok(Error::NoChecksRegistered)));
}

// ---------------------------------------------------------------------------
// Edge cases (#215): zero checks, single check parity, AND-composition
// ---------------------------------------------------------------------------

/// Single-check aggregator must behave identically to calling that
/// underlying check directly: same pass/fail outcome, and the aggregator's
/// `checks` vector must carry exactly that one result.
#[test]
fn test_single_check_matches_direct_call() {
    let env = Env::default();
    env.mock_all_auths();

    let gate_admin = Address::generate(&env);
    let gate_id = env.register(DenylistGate, ());
    let gate_client = DenylistGateClient::new(&env, &gate_id);
    gate_client.initialize(&gate_admin);

    let agg_admin = Address::generate(&env);
    let agg_id = env.register(ComplianceAggregator, ());
    let agg_client = ComplianceAggregatorClient::new(&env, &agg_id);
    agg_client.initialize(&agg_admin, &Some(gate_id.clone()), &None, &None);

    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    gate_client.add_to_denylist(&gate_admin, &bob);

    // Direct call results.
    let alice_direct = gate_client.check(&alice);
    let bob_direct = gate_client.check(&bob);

    // Aggregator results, single check registered.
    let (alice_all, alice_checks) = agg_client.check_address(&alice, &vec![&env]);
    let (bob_all, bob_checks) = agg_client.check_address(&bob, &vec![&env]);

    assert_eq!(alice_all, alice_direct);
    assert_eq!(bob_all, bob_direct);
    assert_eq!(alice_checks.len(), 1);
    assert_eq!(bob_checks.len(), 1);
    assert_eq!(alice_checks.get(0).unwrap().passed, alice_direct);
    assert_eq!(bob_checks.get(0).unwrap().passed, bob_direct);
    assert_eq!(alice_checks.get(0).unwrap().code, CODE_OK);
    assert_eq!(bob_checks.get(0).unwrap().code, CODE_DENIED);
}

/// Zero configured checks must produce the documented `NoChecksRegistered`
/// error rather than panicking or silently reporting a pass. This is a
/// second, explicit assertion of that documented contract behavior
/// (complementing `test_check_address_no_checks_registered` above) that
/// also checks the same for a freshly-registered (never-initialized-with-
/// any-check) aggregator instance to rule out any state leakage.
#[test]
fn test_zero_checks_is_documented_error_not_panic() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let id = env.register(ComplianceAggregator, ());
    let client = ComplianceAggregatorClient::new(&env, &id);
    client.initialize(&admin, &None, &None, &None);

    let addr = Address::generate(&env);
    // Must not panic: try_* surfaces the error as a Result.
    let result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| client.try_check_address(&addr, &vec![&env])));
    assert!(result.is_ok(), "check_address must not panic on zero checks");
    assert_eq!(result.unwrap(), Err(Ok(Error::NoChecksRegistered)));
}

/// This contract only supports AND-composition of registered checks (see
/// module docs: "all checks here are AND-composed"); there is no OR/nesting
/// operator, so a literal AND-of-ORs configuration is out of scope for this
/// contract (that belongs to `policy-engine`, issue #109). This test instead
/// verifies the AND-composition semantics hold exhaustively across all four
/// pass/fail combinations of the two registered checks, which is the closest
/// meaningful analogue available here: `all_passed` must equal the boolean
/// AND of the individual check results in every case.
#[test]
fn test_and_composition_exhaustive_truth_table() {
    let env = Env::default();

    for (deny_alice, right_jurisdiction) in [(false, true), (false, false), (true, true), (true, false)] {
        let (gate_admin, gate_id, flag_issuer, flag_id, _, _, client) = setup_all(&env);
        let alice = Address::generate(&env);

        if deny_alice {
            deny(&env, &gate_id, &gate_admin, &alice);
        }
        if right_jurisdiction {
            set_jurisdiction(&env, &flag_id, &flag_issuer, &alice, "US");
        }

        let (all_passed, checks) = client.check_address(&alice, &us_vec(&env));
        let expected = !deny_alice && right_jurisdiction;
        assert_eq!(all_passed, expected);
        assert_eq!(checks.get(0).unwrap().passed, !deny_alice);
        assert_eq!(checks.get(1).unwrap().passed, right_jurisdiction);
        // Reason codes must reflect the individual outcome.
        assert_eq!(
            checks.get(0).unwrap().code,
            if deny_alice { CODE_DENIED } else { CODE_OK }
        );
        assert_eq!(
            checks.get(1).unwrap().code,
            if right_jurisdiction {
                CODE_OK
            } else {
                CODE_JURISDICTION
            }
        );
    }
}

// ---------------------------------------------------------------------------
// check_all — batch tests
// ---------------------------------------------------------------------------

#[test]
fn test_check_all_all_pass() {
    let env = Env::default();
    let (_, _, flag_issuer, flag_id, _, _, client) = setup_all(&env);

    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    set_jurisdiction(&env, &flag_id, &flag_issuer, &alice, "US");
    set_jurisdiction(&env, &flag_id, &flag_issuer, &bob, "US");

    let addresses = vec![&env, alice.clone(), bob.clone()];
    let results = client.check_all(&addresses, &us_vec(&env));
    assert_eq!(results.len(), 2);
    assert!(results.get(0).unwrap().all_passed);
    assert!(results.get(1).unwrap().all_passed);
    for r in results.iter() {
        for c in r.checks.iter() {
            assert_eq!(c.code, CODE_OK);
        }
    }
}

#[test]
fn test_check_all_mixed_results() {
    let env = Env::default();
    let (gate_admin, gate_id, flag_issuer, flag_id, _, _, client) = setup_all(&env);

    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    let carol = Address::generate(&env);

    // alice: both pass
    set_jurisdiction(&env, &flag_id, &flag_issuer, &alice, "US");
    // bob: denylist fail, jurisdiction pass
    set_jurisdiction(&env, &flag_id, &flag_issuer, &bob, "US");
    deny(&env, &gate_id, &gate_admin, &bob);
    // carol: denylist pass, no jurisdiction → jurisdiction fail

    let addresses = vec![&env, alice.clone(), bob.clone(), carol.clone()];
    let results = client.check_all(&addresses, &us_vec(&env));

    assert_eq!(results.len(), 3);

    let alice_r = results.get(0).unwrap();
    assert_eq!(alice_r.address, alice);
    assert!(alice_r.all_passed);
    assert_eq!(alice_r.checks.get(0).unwrap().code, CODE_OK);
    assert_eq!(alice_r.checks.get(1).unwrap().code, CODE_OK);

    let bob_r = results.get(1).unwrap();
    assert_eq!(bob_r.address, bob);
    assert!(!bob_r.all_passed);
    assert!(!bob_r.checks.get(0).unwrap().passed); // denylist
    assert_eq!(bob_r.checks.get(0).unwrap().code, CODE_DENIED);
    assert!(bob_r.checks.get(1).unwrap().passed); // jurisdiction
    assert_eq!(bob_r.checks.get(1).unwrap().code, CODE_OK);

    let carol_r = results.get(2).unwrap();
    assert_eq!(carol_r.address, carol);
    assert!(!carol_r.all_passed);
    assert!(carol_r.checks.get(0).unwrap().passed); // denylist
    assert_eq!(carol_r.checks.get(0).unwrap().code, CODE_OK);
    assert!(!carol_r.checks.get(1).unwrap().passed); // jurisdiction
    assert_eq!(carol_r.checks.get(1).unwrap().code, CODE_JURISDICTION);
}

#[test]
fn test_check_all_empty_list_error() {
    let env = Env::default();
    let (_, _, _, _, _, _, client) = setup_all(&env);
    let result = client.try_check_all(&vec![&env], &us_vec(&env));
    assert_eq!(result, Err(Ok(Error::EmptyAddressList)));
}

#[test]
fn test_check_all_no_checks_registered() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let id = env.register(ComplianceAggregator, ());
    let client = ComplianceAggregatorClient::new(&env, &id);
    client.initialize(&admin, &None, &None, &None);

    let alice = Address::generate(&env);
    let result = client.try_check_all(&vec![&env, alice], &vec![&env]);
    assert_eq!(result, Err(Ok(Error::NoChecksRegistered)));
}

#[test]
fn test_allowlist_check_address_batch_and_summary() {
    let env = Env::default();
    env.mock_all_auths();

    let allowlist_id = env.register(MockAllowlist, ());
    let allowlist = MockAllowlistClient::new(&env, &allowlist_id);

    let admin = Address::generate(&env);
    let aggregator_id = env.register(ComplianceAggregator, ());
    let client = ComplianceAggregatorClient::new(&env, &aggregator_id);
    client.initialize(&admin, &None, &None, &None);
    client.set_allowlist(&admin, &allowlist_id);

    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    allowlist.set_allowed(&alice, &true);

    assert_eq!(client.allowlist_token(), Some(allowlist_id.clone()));
    assert_eq!(client.get_checks_summary(), (false, false, false, true));

    let (alice_passed, alice_checks) = client.check_address(&alice, &vec![&env]);
    assert!(alice_passed);
    assert!(alice_checks.get(0).unwrap().passed);

    let (bob_passed, _bob_checks) = client.check_address(&bob, &vec![&env]);
    assert!(!bob_passed);
    let (_, bob_failures) = client.check_address_with_failures(&bob, &vec![&env]);
    assert_eq!(
        bob_failures,
        vec![&env, CheckFailure { source: CheckKind::Allowlist, code: CheckFailureCode::NotAllowlisted },]
    );

    let batch = client.check_all(&vec![&env, alice.clone(), bob.clone()], &vec![&env]);
    assert!(batch.get(0).unwrap().all_passed);
    let detailed_batch = client.check_all_with_failures(&vec![&env, alice.clone(), bob.clone()], &vec![&env]);
    assert_eq!(
        detailed_batch.get(1).unwrap().failures,
        vec![&env, CheckFailure { source: CheckKind::Allowlist, code: CheckFailureCode::NotAllowlisted },]
    );

    assert_eq!(client.batch_check(&vec![&env, alice, bob], &vec![&env]), vec![&env, true, false]);

    client.clear_allowlist(&admin);
    assert_eq!(client.allowlist_token(), None);
    assert_eq!(client.get_checks_summary(), (false, false, false, false));
}

// ---------------------------------------------------------------------------
// batch_check (#216)
// ---------------------------------------------------------------------------

#[test]
fn test_batch_check_matches_individual_check_address() {
    let env = Env::default();
    let (gate_admin, gate_id, flag_issuer, flag_id, _, _, client) = setup_all(&env);

    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    let carol = Address::generate(&env);

    // alice: both pass
    set_jurisdiction(&env, &flag_id, &flag_issuer, &alice, "US");
    // bob: denylist fail, jurisdiction pass
    set_jurisdiction(&env, &flag_id, &flag_issuer, &bob, "US");
    deny(&env, &gate_id, &gate_admin, &bob);
    // carol: denylist pass, no jurisdiction set -> jurisdiction fail

    let addresses = vec![&env, alice.clone(), bob.clone(), carol.clone()];
    let batch_results = client.batch_check(&addresses, &us_vec(&env));

    assert_eq!(batch_results.len(), 3);
    for (i, addr) in [&alice, &bob, &carol].into_iter().enumerate() {
        let (expected, _) = client.check_address(addr, &us_vec(&env));
        assert_eq!(batch_results.get(i as u32).unwrap(), expected);
    }
}

#[test]
fn test_batch_check_empty_list_error() {
    let env = Env::default();
    let (_, _, _, _, _, _, client) = setup_all(&env);
    let result = client.try_batch_check(&vec![&env], &us_vec(&env));
    assert_eq!(result, Err(Ok(Error::EmptyAddressList)));
}

#[test]
fn test_batch_check_no_checks_registered() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let id = env.register(ComplianceAggregator, ());
    let client = ComplianceAggregatorClient::new(&env, &id);
    client.initialize(&admin, &None, &None, &None);

    let alice = Address::generate(&env);
    let result = client.try_batch_check(&vec![&env, alice], &vec![&env]);
    assert_eq!(result, Err(Ok(Error::NoChecksRegistered)));
}

#[test]
fn test_batch_check_rejects_oversized_batch() {
    let env = Env::default();
    let (_, _, _, _, _, _, client) = setup_all(&env);

    let mut addresses: Vec<Address> = Vec::new(&env);
    for _ in 0..(ComplianceAggregator::MAX_BATCH_SIZE + 1) {
        addresses.push_back(Address::generate(&env));
    }

    let result = client.try_batch_check(&addresses, &us_vec(&env));
    assert_eq!(result, Err(Ok(Error::BatchTooLarge)));
}

// ---------------------------------------------------------------------------
// Interface versioning (#808)
// ---------------------------------------------------------------------------

#[test]
fn test_aggregator_reports_interface_version() {
    let env = Env::default();
    let (_, _, _, _, _, _, client) = setup_all(&env);
    assert_eq!(client.interface_version(), ComplianceAggregator::INTERFACE_VERSION);
}

/// A primitive that reports an incompatible `interface_version()` must cause
/// the aggregator to fail closed with the documented error rather than
/// silently trusting an unknown result shape.
#[test]
fn test_incompatible_primitive_interface_version_fails_closed() {
    let env = Env::default();
    env.mock_all_auths();

    // Register a stub that claims an incompatible interface version.
    let stub_id = env.register(IncompatibleStub, ());
    IncompatibleStubClient::new(&env, &stub_id).initialize();

    let agg_admin = Address::generate(&env);
    let agg_id = env.register(ComplianceAggregator, ());
    let client = ComplianceAggregatorClient::new(&env, &agg_id);
    client.initialize(&agg_admin, &Some(stub_id.clone()), &None, &None);

    let alice = Address::generate(&env);
    let result = client.try_check_address(&alice, &vec![&env]);
    assert_eq!(result, Err(Ok(Error::IncompatibleInterfaceVersion)));
}

// ---------------------------------------------------------------------------
// Benchmark: individual calls vs. aggregated call
//
// Soroban's `cost_estimate().budget()` gives CPU-instruction and memory-byte
// counters that model host-level execution cost. We compare:
//   A) Consumer calls denylist-gate.check() + jurisdiction-flag.is_permitted_jurisdiction()
//      directly, each as a separate cross-contract call — two invocations.
//   B) Consumer calls compliance-aggregator.check_address(), which makes both
//      downstream calls internally — one invocation from the consumer.
//
// **What this measures**: the consumer's observable call overhead.
// Path A: the consumer makes 2 separate cross-contract calls.
// Path B: the consumer makes 1 cross-contract call; the aggregator makes 2
//         downstream calls internally, so the total host work is greater than
//         path A (the aggregator adds one extra call frame). This is expected:
//         the aggregator trades total-host-instruction-count for a simpler
//         consumer API and a single network round-trip per transfer.
//
// The assertion below verifies that the aggregated path does not add more
// than 4× the raw primitive cost — confirming no gratuitous overhead beyond
// the one additional call frame.
//
// Note: in the Soroban test environment all contracts run in a single Env so
// "cross-contract" boundaries are simulated rather than real. The relative
// instruction counts still correctly model call-dispatch overhead.
// ---------------------------------------------------------------------------

#[test]
fn bench_individual_vs_aggregated() {
    // ---- Setup shared state ----
    let env = Env::default();
    env.mock_all_auths();

    let gate_admin = Address::generate(&env);
    let gate_id = env.register(DenylistGate, ());
    let gate_client = DenylistGateClient::new(&env, &gate_id);
    gate_client.initialize(&gate_admin);

    let flag_issuer = Address::generate(&env);
    let flag_id = env.register(JurisdictionFlag, ());
    let flag_client = JurisdictionFlagClient::new(&env, &flag_id);
    flag_client.initialize(&flag_issuer);

    let agg_admin = Address::generate(&env);
    let agg_id = env.register(ComplianceAggregator, ());
    let agg_client = ComplianceAggregatorClient::new(&env, &agg_id);
    agg_client.initialize(&agg_admin, &Some(gate_id.clone()), &Some(flag_id.clone()), &None);

    let alice = Address::generate(&env);
    flag_client.set_jurisdiction(&flag_issuer, &alice, &String::from_str(&env, "US"));

    let allowed = us_vec(&env);

    // ---- Path A: two direct calls (2 invocations from consumer) ----
    env.cost_estimate().budget().reset_default();
    let deny_ok = gate_client.check(&alice);
    let juris_ok = flag_client.is_permitted_jurisdiction(&alice, &allowed);
    let individual_cpu = env.cost_estimate().budget().cpu_instruction_cost();
    let individual_mem = env.cost_estimate().budget().memory_bytes_cost();
