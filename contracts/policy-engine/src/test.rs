use super::*;
use crate::test_utils::{
    MockCircuitBreaker, MockCircuitBreakerClient, MockDenylist, MockDenylistClient,
    MockJurisdiction, MockJurisdictionClient,
};
use compliance_check::{CheckResult, ComplianceCheckClient, COMPLIANCE_CHECK_INTERFACE_VERSION};
use circuit_breaker::{CircuitBreaker, CircuitBreakerClient as CbClient};
use denylist_gate::{DenylistGate, DenylistGateClient};
use jurisdiction_flag::{JurisdictionFlag, JurisdictionFlagClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{vec, BytesN, Env, String};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Registers a mock denylist contract, returns its address.
fn setup_denylist(env: &Env) -> Address {
    env.register(MockDenylist, ())
}

/// Registers a mock jurisdiction contract, returns its address.
fn setup_jurisdiction(env: &Env) -> Address {
    env.register(MockJurisdiction, ())
}

/// The default policy name used by the single-policy helpers below.
fn default_policy(env: &Env) -> String {
    String::from_str(env, "default")
}

/// Registers and initialises a policy-engine contract with a single named
/// policy using `All` semantics, returns `(admin, contract_id, client)`.
fn setup_engine_all(env: &Env) -> (Address, Address, PolicyEngineClient<'_>) {
    let admin = Address::generate(env);
    let id = env.register(PolicyEngine, ());
    let client = PolicyEngineClient::new(env, &id);
    client.initialize(&admin);
    client.create_policy(&admin, &default_policy(env), &CombineOp::All, &None);
    (admin, id, client)
}

/// Same as above but with `Any` semantics.
fn setup_engine_any(env: &Env) -> (Address, Address, PolicyEngineClient<'_>) {
    let admin = Address::generate(env);
    let id = env.register(PolicyEngine, ());
    let client = PolicyEngineClient::new(env, &id);
    client.initialize(&admin);
    client.create_policy(&admin, &default_policy(env), &CombineOp::Any, &None);
    (admin, id, client)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// With All semantics: a denylist check (addresses clear) and a jurisdiction
/// check (addresses in permitted list) both pass → evaluate returns true.
#[test]
fn test_all_checks_pass() {
    let env = Env::default();
    env.mock_all_auths();

    let deny_id = setup_denylist(&env);
    let juri_id = setup_jurisdiction(&env);

    let from = Address::generate(&env);
    let to = Address::generate(&env);

    // Set permitted jurisdictions for both addresses.
    let code_us = String::from_str(&env, "US");
    MockJurisdictionClient::new(&env, &juri_id).set_jurisdiction(&from, &code_us);
    MockJurisdictionClient::new(&env, &juri_id).set_jurisdiction(&to, &code_us);

    let (admin, _engine_id, client) = setup_engine_all(&env);

    client.add_check(
        &admin,
        &CheckKind::Denylist(DenylistCheck {
            contract: deny_id.clone(),
        }),
    );
    client.add_check(
        &admin,
        &CheckKind::Jurisdiction(JurisdictionCheck {
            contract: juri_id.clone(),
            allowed_codes: vec![&env, String::from_str(&env, "US")],
        }),
    );

    let result = client.evaluate_policy(&default_policy(&env), &from, &to);
    assert!(result);
}

/// With All semantics: one of two checks fails (sender is on the denylist)
/// → evaluate returns false.
#[test]
fn test_one_check_fails_and_semantics() {
    let env = Env::default();
    env.mock_all_auths();

    let deny_id = setup_denylist(&env);
    let juri_id = setup_jurisdiction(&env);

    let from = Address::generate(&env);
    let to = Address::generate(&env);

    // Both addresses have valid jurisdiction codes.
    let code_us = String::from_str(&env, "US");
    MockJurisdictionClient::new(&env, &juri_id).set_jurisdiction(&from, &code_us);
    MockJurisdictionClient::new(&env, &juri_id).set_jurisdiction(&to, &code_us);

    // But `from` is denied.
    MockDenylistClient::new(&env, &deny_id).add_to_denylist(&from);

    let (admin, _engine_id, client) = setup_engine_all(&env);

    client.add_check(
        &admin,
        &CheckKind::Denylist(DenylistCheck {
            contract: deny_id.clone(),
        }),
    );
    client.add_check(
        &admin,
        &CheckKind::Jurisdiction(JurisdictionCheck {
            contract: juri_id.clone(),
            allowed_codes: vec![&env, String::from_str(&env, "US")],
        }),
    );

    let result = client.evaluate_policy(&default_policy(&env), &from, &to);
    assert!(!result);
}

/// With Any semantics: the denylist check fails (both addresses denied) but
/// the jurisdiction check passes → evaluate returns true because at least
/// one check passes for both parties.
#[test]
fn test_one_check_passes_or_semantics() {
    let env = Env::default();
    env.mock_all_auths();

    let deny_id = setup_denylist(&env);
    let juri_id = setup_jurisdiction(&env);

    let from = Address::generate(&env);
    let to = Address::generate(&env);

    // Both addresses are on the denylist (denylist check will fail).
    MockDenylistClient::new(&env, &deny_id).add_to_denylist(&from);
    MockDenylistClient::new(&env, &deny_id).add_to_denylist(&to);

    // But both have valid jurisdiction codes (jurisdiction check will pass).
    let code_us = String::from_str(&env, "US");
    MockJurisdictionClient::new(&env, &juri_id).set_jurisdiction(&from, &code_us);
    MockJurisdictionClient::new(&env, &juri_id).set_jurisdiction(&to, &code_us);

    let (admin, _engine_id, client) = setup_engine_any(&env);

    client.add_check(
        &admin,
        &CheckKind::Denylist(DenylistCheck {
            contract: deny_id.clone(),
        }),
    );
    client.add_check(
        &admin,
        &CheckKind::Jurisdiction(JurisdictionCheck {
            contract: juri_id.clone(),
            allowed_codes: vec![&env, String::from_str(&env, "US")],
        }),
    );

    // With Any: the jurisdiction check passes for both → result is true.
    let result = client.evaluate_policy(&default_policy(&env), &from, &to);
    assert!(result);
}

/// Verify that add_check and remove_check correctly mutate the checks list.
#[test]
fn test_add_and_remove_check() {
    let env = Env::default();
    env.mock_all_auths();

    let deny_id = setup_denylist(&env);

    let (admin, _engine_id, client) = setup_engine_all(&env);

    let name = default_policy(&env);

    // Initially empty.
    assert_eq!(client.get_checks(&name).len(), 0);

    // Add one check.
    client.add_check(
        &admin,
        &name,
        &CheckKind::Denylist(DenylistCheck {
            contract: deny_id.clone(),
        }),
    );
    assert_eq!(client.get_checks(&name).len(), 1);

    // Add a second check.
    let juri_id = setup_jurisdiction(&env);
    client.add_check(
        &admin,
        &name,
        &CheckKind::Jurisdiction(JurisdictionCheck {
            contract: juri_id.clone(),
            allowed_codes: vec![&env, String::from_str(&env, "US")],
        }),
    );
    assert_eq!(client.get_checks(&name).len(), 2);

    // Remove the first check (index 0); list should shrink to 1.
    client.remove_check(&admin, &name, &0);
    assert_eq!(client.get_checks(&name).len(), 1);
}

#[test]
fn test_remove_check_out_of_bounds_returns_contract_error() {
    let env = Env::default();
    env.mock_all_auths();
    let (admin, _engine_id, client) = setup_engine_all(&env);

    let name = default_policy(&env);
    let result = client.try_remove_check(&admin, &name, &0u32);
    assert_eq!(result, Err(Ok(Error::IndexOutOfBounds)));
}

#[test]
fn test_clear_checks_resets_policy_to_empty() {
    let env = Env::default();
    env.mock_all_auths();

    let deny_id = setup_denylist(&env);
    let juri_id = setup_jurisdiction(&env);

    let (admin, _engine_id, client) = setup_engine_all(&env);
    let name = default_policy(&env);
    client.add_check(
        &admin,
        &name,
        &CheckKind::Denylist(DenylistCheck {
            contract: deny_id.clone(),
        }),
    );
    client.add_check(
        &admin,
        &name,
        &CheckKind::Jurisdiction(JurisdictionCheck {
            contract: juri_id.clone(),
            allowed_codes: vec![&env, String::from_str(&env, "US")],
        }),
    );

    assert_eq!(client.get_checks(&name).len(), 2);
    client.clear_checks(&admin, &name);
    assert_eq!(client.get_checks(&name).len(), 0);
}

/// `swap_checks` exchanges the positions of two checks so that `evaluate`
/// follows the new order, including short-circuit behaviour under `CombineOp::All`.
#[test]
fn test_swap_checks_reorders_and_short_circuits() {
    let env = Env::default();
    env.mock_all_auths();

    let deny_id = setup_denylist(&env);
    let juri_id = setup_jurisdiction(&env);

    let from = Address::generate(&env);
    let to = Address::generate(&env);

    // `from` is on the denylist — under CombineOp::All this check will fail.
    MockDenylistClient::new(&env, &deny_id).add_to_denylist(&from);

    // Both addresses have valid jurisdiction codes so the jurisdiction check passes.
    let code_us = String::from_str(&env, "US");
    MockJurisdictionClient::new(&env, &juri_id).set_jurisdiction(&from, &code_us);
    MockJurisdictionClient::new(&env, &juri_id).set_jurisdiction(&to, &code_us);

    let (admin, _engine_id, client) = setup_engine_all(&env);
    let name = default_policy(&env);

    // Add jurisdiction check first (index 0), then denylist check (index 1).
    client.add_check(
        &admin,
        &name,
        &CheckKind::Jurisdiction(JurisdictionCheck {
            contract: juri_id.clone(),
            allowed_codes: vec![&env, String::from_str(&env, "US")],
        }),
    );
    client.add_check(
        &admin,
        &name,
        &CheckKind::Denylist(DenylistCheck {
            contract: deny_id.clone(),
        }),
    );

    // Before swap: jurisdiction (passes) then denylist (fails) → false.
    assert!(!client.evaluate_policy(&name, &from, &to));

    // Swap positions 0 and 1: denylist is now index 0, jurisdiction is index 1.
    client.swap_checks(&admin, &name, &0, &1);
    let checks = client.get_checks(&name);
    assert_eq!(checks.len(), 2);
    // The first check must now be the denylist check.
    match checks.get(0).unwrap() {
        CheckKind::Denylist(_) => {}
        _ => panic!("expected Denylist at index 0 after swap"),
    }
    match checks.get(1).unwrap() {
        CheckKind::Jurisdiction(_) => {}
        _ => panic!("expected Jurisdiction at index 1 after swap"),
    }

    // After swap the denylist short-circuits first — result is still false,
    // but the cheaper check now fires before the jurisdiction check.
    assert!(!client.evaluate_policy(&name, &from, &to));
}

/// `swap_checks` with equal indices is a no-op — the list is unchanged.
#[test]
fn test_swap_checks_same_index_is_noop() {
    let env = Env::default();
    env.mock_all_auths();

    let deny_id = setup_denylist(&env);
    let (admin, _engine_id, client) = setup_engine_all(&env);
    let name = default_policy(&env);

    client.add_check(
        &admin,
        &name,
        &CheckKind::Denylist(DenylistCheck {
            contract: deny_id.clone(),
        }),
    );
    assert_eq!(client.get_checks(&name).len(), 1);

    // Swapping index 0 with itself must not panic and must leave the list intact.
    client.swap_checks(&admin, &name, &0, &0);
    assert_eq!(client.get_checks(&name).len(), 1);
}

/// `swap_checks` with an out-of-range index panics (the generated client
/// surfaces the contract error as a panic in test environments).
#[test]
#[should_panic]
fn test_swap_checks_out_of_bounds() {
    let env = Env::default();
    env.mock_all_auths();

    let deny_id = setup_denylist(&env);
    let (admin, _engine_id, client) = setup_engine_all(&env);
    let name = default_policy(&env);

    client.add_check(
        &admin,
        &name,
        &CheckKind::Denylist(DenylistCheck {
            contract: deny_id.clone(),
        }),
    );

    // Only one check at index 0; index 1 is out of range.
    client.swap_checks(&admin, &name, &0, &1);
}

/// `get_policy` returns a `PolicyNode` whose `op` and `checks` fields exactly
/// match what was configured via `initialize` / `add_check`.
#[test]
fn test_get_policy_matches_configuration() {
    let env = Env::default();
    env.mock_all_auths();

    // Set up two external contracts to use as checks.
    let deny_admin = Address::generate(&env);
    let juri_issuer = Address::generate(&env);
    let deny_id = setup_denylist(&env);
    let juri_id = setup_jurisdiction(&env);

    // Initialise with `Any` semantics and add two checks.
    let (admin, _engine_id, client) = setup_engine_any(&env);
    let name = default_policy(&env);

    let allowed_codes = vec![&env, String::from_str(&env, "US"), String::from_str(&env, "GB")];

    client.add_check(
        &admin,
        &name,
        &CheckKind::Denylist(DenylistCheck {
            contract: deny_id.clone(),
        }),
    );
    client.add_check(
        &admin,
        &name,
        &CheckKind::Jurisdiction(JurisdictionCheck {
            contract: juri_id.clone(),
            allowed_codes: allowed_codes.clone(),
        }),
    );

    // Fetch the full policy tree.
    let policy = client.get_policy(&name);

    // The combine operator must match what was passed to `initialize`.
    assert_eq!(policy.op, CombineOp::Any);

    // There must be exactly two checks, in insertion order.
    assert_eq!(policy.checks.len(), 2);

    // First check must be the denylist check with the correct contract address.
    match policy.checks.get(0).unwrap() {
        CheckKind::Denylist(inner) => assert_eq!(inner.contract, deny_id),
        _ => panic!("expected Denylist check at index 0"),
    }

    // Second check must be the jurisdiction check with correct contract and codes.
    match policy.checks.get(1).unwrap() {
        CheckKind::Jurisdiction(inner) => {
            assert_eq!(inner.contract, juri_id);
            assert_eq!(inner.allowed_codes, allowed_codes);
        }
        _ => panic!("expected Jurisdiction check at index 1"),
    }
}

// ---------------------------------------------------------------------------
// TTL extension
// ---------------------------------------------------------------------------

fn instance_ttl(env: &Env, contract_id: &Address) -> u32 {
    use soroban_sdk::testutils::storage::Instance as _;
    env.as_contract(contract_id, || env.storage().instance().get_ttl())
}

/// A write refreshes the instance TTL, so the policy stays readable after the
/// ledger advances past the TTL the entries were originally given.
#[test]
fn test_write_extends_instance_ttl_past_original_expiry() {
    use soroban_sdk::testutils::Ledger as _;

    let env = Env::default();
    env.mock_all_auths();
    let (admin, contract_id, client) = setup_engine_all(&env);
    let deny_id = setup_denylist(&env);

    // `initialize` is a write path and must extend the TTL.
    assert_eq!(instance_ttl(&env, &contract_id), INSTANCE_TTL_EXTEND_TO);

    // Advance until the remaining TTL drops below the extension threshold.
    env.ledger().with_mut(|li| {
        li.sequence_number += INSTANCE_TTL_EXTEND_TO - INSTANCE_TTL_THRESHOLD + 1;
    });
    assert!(instance_ttl(&env, &contract_id) < INSTANCE_TTL_THRESHOLD);

    // A write refreshes the TTL back to the target.
    let name = default_policy(&env);
    client.add_check(
        &admin,
        &name,
        &CheckKind::Denylist(DenylistCheck {
            contract: deny_id.clone(),
        }),
    );
    assert_eq!(instance_ttl(&env, &contract_id), INSTANCE_TTL_EXTEND_TO);

    // Advance past the ledger at which the original TTL would have expired.
    env.ledger().with_mut(|li| {
        li.sequence_number += INSTANCE_TTL_THRESHOLD + 1;
    });

    // State written before and after the refresh is still readable.
    assert_eq!(client.get_checks(&name).len(), 1);
    assert!(client.get_op(&name) == CombineOp::All);

    // Remaining write paths also refresh the TTL. Remaining TTL is currently
    // EXTEND_TO - THRESHOLD - 1; drop it just below the threshold.
    env.ledger().with_mut(|li| {
        li.sequence_number += INSTANCE_TTL_EXTEND_TO - 2 * INSTANCE_TTL_THRESHOLD;
    });
    assert!(instance_ttl(&env, &contract_id) < INSTANCE_TTL_THRESHOLD);
    client.remove_check(&admin, &name, &0);
    assert_eq!(instance_ttl(&env, &contract_id), INSTANCE_TTL_EXTEND_TO);

    env.ledger().with_mut(|li| {
        li.sequence_number += INSTANCE_TTL_EXTEND_TO - INSTANCE_TTL_THRESHOLD + 1;
    });
    let breaker = Address::generate(&env);
    client.set_circuit_breaker(&admin, &breaker);
    assert_eq!(instance_ttl(&env, &contract_id), INSTANCE_TTL_EXTEND_TO);
    assert_eq!(client.circuit_breaker(), Some(breaker));
}

// ---------------------------------------------------------------------------
// Tests for issue #403: CircuitBreaker check kind
// ---------------------------------------------------------------------------

/// Registers a mock circuit-breaker contract, returns its address.
fn setup_circuit_breaker(env: &Env) -> Address {
    env.register(MockCircuitBreaker, ())
}

/// Policy with all three check kinds under `CombineOp::All`: denylist passes,
/// jurisdiction passes, circuit-breaker is not frozen → `evaluate` returns true.
#[test]
fn test_all_three_check_kinds_all_pass() {
    let env = Env::default();
    env.mock_all_auths();

    let deny_id = setup_denylist(&env);
    let juri_id = setup_jurisdiction(&env);
    let cb_id = setup_circuit_breaker(&env);

    let from = Address::generate(&env);
    let to = Address::generate(&env);

    // Both addresses have valid jurisdiction codes; circuit-breaker is not frozen.
    let code_us = String::from_str(&env, "US");
    MockJurisdictionClient::new(&env, &juri_id).set_jurisdiction(&from, &code_us);
    MockJurisdictionClient::new(&env, &juri_id).set_jurisdiction(&to, &code_us);
    // MockCircuitBreaker starts unfrozen by default.

    let (admin, _engine_id, client) = setup_engine_all(&env);
    let name = default_policy(&env);

    client.add_check(
        &admin,
        &name,
        &CheckKind::Denylist(DenylistCheck {
            contract: deny_id.clone(),
        }),
    );
    client.add_check(
        &admin,
        &name,
        &CheckKind::Jurisdiction(JurisdictionCheck {
            contract: juri_id.clone(),
            allowed_codes: vec![&env, String::from_str(&env, "US")],
        }),
    );
    client.add_check(
        &admin,
        &name,
        &CheckKind::CircuitBreaker(CircuitBreakerCheck {
            contract: cb_id.clone(),
        }),
    );

    let result = client.evaluate_policy(&name, &from, &to);
    assert!(result, "expected all-pass with three check kinds (All)");
}

/// Policy with all three check kinds under `CombineOp::All`: circuit-breaker
/// is frozen → the circuit-breaker check fails → `evaluate` returns false.
#[test]
fn test_circuit_breaker_check_kind_frozen_fails_all() {
    let env = Env::default();
    env.mock_all_auths();

    let deny_id = setup_denylist(&env);
    let juri_id = setup_jurisdiction(&env);
    let cb_id = setup_circuit_breaker(&env);

    let from = Address::generate(&env);
    let to = Address::generate(&env);

    // Both addresses clear denylist and jurisdiction.
    let code_us = String::from_str(&env, "US");
    MockJurisdictionClient::new(&env, &juri_id).set_jurisdiction(&from, &code_us);
    MockJurisdictionClient::new(&env, &juri_id).set_jurisdiction(&to, &code_us);

    // Freeze the circuit-breaker — this check should fail.
    MockCircuitBreakerClient::new(&env, &cb_id).freeze();

    let (admin, _engine_id, client) = setup_engine_all(&env);
    let name = default_policy(&env);

    client.add_check(
        &admin,
        &name,
        &CheckKind::Denylist(DenylistCheck {
            contract: deny_id.clone(),
        }),
    );
    client.add_check(
        &admin,
        &name,
        &CheckKind::Jurisdiction(JurisdictionCheck {
            contract: juri_id.clone(),
            allowed_codes: vec![&env, String::from_str(&env, "US")],
        }),
    );
    client.add_check(
        &admin,
        &name,
        &CheckKind::CircuitBreaker(CircuitBreakerCheck {
            contract: cb_id.clone(),
        }),
    );

    let result = client.evaluate_policy(&name, &from, &to);
    assert!(!result, "expected false when circuit-breaker is frozen (All)");
}

/// Policy with all three check kinds under `CombineOp::Any`: denylist and
/// jurisdiction both fail but circuit-breaker is not frozen → circuit-breaker
/// check passes for both parties → `evaluate` returns true.
#[test]
fn test_circuit_breaker_check_kind_passes_any_semantics() {
    let env = Env::default();
    env.mock_all_auths();

    let deny_id = setup_denylist(&env);
    let juri_id = setup_jurisdiction(&env);
    let cb_id = setup_circuit_breaker(&env);

    let from = Address::generate(&env);
    let to = Address::generate(&env);

    // Both addresses are denied (denylist check fails).
    MockDenylistClient::new(&env, &deny_id).add_to_denylist(&from);
    MockDenylistClient::new(&env, &deny_id).add_to_denylist(&to);
    // No jurisdiction codes set (jurisdiction check fails).
    // Circuit-breaker is not frozen (circuit-breaker check passes).

    let (admin, _engine_id, client) = setup_engine_any(&env);
    let name = default_policy(&env);

    client.add_check(
        &admin,
        &name,
        &CheckKind::Denylist(DenylistCheck {
            contract: deny_id.clone(),
        }),
    );
    client.add_check(
        &admin,
        &name,
        &CheckKind::Jurisdiction(JurisdictionCheck {
            contract: juri_id.clone(),
            allowed_codes: vec![&env, String::from_str(&env, "US")],
        }),
    );
    client.add_check(
        &admin,
        &name,
        &CheckKind::CircuitBreaker(CircuitBreakerCheck {
            contract: cb_id.clone(),
        }),
    );

    // With Any: circuit-breaker passes for both → result is true.
    let result = client.evaluate_policy(&name, &from, &to);
    assert!(result, "expected true: circuit-breaker passes under Any semantics");
}

/// Policy with all three check kinds under `CombineOp::Any`: all three checks
/// fail → `evaluate` returns false.
#[test]
fn test_all_three_check_kinds_all_fail_any() {
    let env = Env::default();
    env.mock_all_auths();

    let deny_id = setup_denylist(&env);
    let juri_id = setup_jurisdiction(&env);
    let cb_id = setup_circuit_breaker(&env);

    let from = Address::generate(&env);
    let to = Address::generate(&env);

    // Denylist check fails: both denied.
    MockDenylistClient::new(&env, &deny_id).add_to_denylist(&from);
    MockDenylistClient::new(&env, &deny_id).add_to_denylist(&to);
    // Jurisdiction check fails: no codes set.
    // Circuit-breaker check fails: frozen.
    MockCircuitBreakerClient::new(&env, &cb_id).freeze();

    let (admin, _engine_id, client) = setup_engine_any(&env);
    let name = default_policy(&env);

    client.add_check(
        &admin,
        &name,
        &CheckKind::Denylist(DenylistCheck {
            contract: deny_id.clone(),
        }),
    );
    client.add_check(
        &admin,
        &name,
        &CheckKind::Jurisdiction(JurisdictionCheck {
            contract: juri_id.clone(),
            allowed_codes: vec![&env, String::from_str(&env, "US")],
        }),
    );
    client.add_check(
        &admin,
        &name,
        &CheckKind::CircuitBreaker(CircuitBreakerCheck {
            contract: cb_id.clone(),
        }),
    );

    let result = client.evaluate_policy(&name, &from, &to);
    assert!(!result, "expected false when all three checks fail under Any");
}

// ---------------------------------------------------------------------------
// Tests for issue #404: get_admin view function
// ---------------------------------------------------------------------------

/// `get_admin` returns the address that was passed to `initialize`.
#[test]
fn test_get_admin_returns_initialized_admin() {
    let env = Env::default();
    env.mock_all_auths();

    let (admin, _engine_id, client) = setup_engine_all(&env);

    let returned_admin = client.get_admin();
    assert_eq!(returned_admin, admin, "get_admin should return the initialized admin address");
}

/// `get_admin` returns `Err(NotInitialized)` when called before `initialize`.
#[test]
fn test_get_admin_not_initialized_returns_error() {
    let env = Env::default();
    env.mock_all_auths();

    // Register the contract but do NOT call initialize.
    let id = env.register(PolicyEngine, ());
    let client = PolicyEngineClient::new(&env, &id);

    let result = client.try_get_admin();
    assert!(
        result.is_err(),
        "get_admin should return an error before initialization"
    );
}

/// `is_paused` reflects the shared pausable state.
#[test]
fn test_is_paused_returns_current_state() {
    let env = Env::default();
    env.mock_all_auths();
    let (_admin, engine_id, client) = setup_engine_all(&env);

    assert!(!client.is_paused());

    env.as_contract(&engine_id, || compliance_pausable::pause(&env));
    assert!(client.is_paused());
}

// ---------------------------------------------------------------------------
// Tests for issues #807 / #808: CheckResult reason codes and interface version
// ---------------------------------------------------------------------------

/// The mock implementers advertise the current interface version, and the
/// engine accepts them.
#[test]
fn test_mocks_report_current_interface_version() {
    let env = Env::default();
    env.mock_all_auths();

    let deny_id = setup_denylist(&env);
    let juri_id = setup_jurisdiction(&env);
    let cb_id = setup_circuit_breaker(&env);

    assert_eq!(
        ComplianceCheckClient::new(&env, &deny_id).interface_version(),
        COMPLIANCE_CHECK_INTERFACE_VERSION
    );
    assert_eq!(
        ComplianceCheckClient::new(&env, &juri_id).interface_version(),
        COMPLIANCE_CHECK_INTERFACE_VERSION
    );
    assert_eq!(
        ComplianceCheckClient::new(&env, &cb_id).interface_version(),
        COMPLIANCE_CHECK_INTERFACE_VERSION
    );
}

/// Mocks return a `CheckResult` carrying both the verdict and a reason code.
#[test]
fn test_mock_returns_check_result_with_reason_code() {
    let env = Env::default();
    env.mock_all_auths();

    let deny_id = setup_denylist(&env);
    let from = Address::generate(&env);
    let to = Address::generate(&env);

    let deny_client = MockDenylistClient::new(&env, &deny_id);

    // Clear addresses: allowed with the OK reason code.
    let ok = deny_client.check(&from, &to);
    assert!(ok.allowed);
    assert_eq!(ok.code, REASON_OK);

    // Denied address: not allowed with the DENYLISTED reason code.
    deny_client.add_to_denylist(&from);
    let denied = deny_client.check(&from, &to);
    assert!(!denied.allowed);
    assert_eq!(denied.code, REASON_DENYLISTED);
}

/// The engine rejects an implementer whose interface version is incompatible
/// instead of silently calling into it.
#[test]
fn test_engine_rejects_incompatible_interface_version() {
    let env = Env::default();
    env.mock_all_auths();

    let deny_id = setup_denylist(&env);
    let from = Address::generate(&env);
    let to = Address::generate(&env);

    // Force the mock to report an incompatible version.
    MockDenylistClient::new(&env, &deny_id)
        .set_interface_version(&(COMPLIANCE_CHECK_INTERFACE_VERSION + 1));

    let (admin, _engine_id, client) = setup_engine_all(&env);
    client.add_check(
        &admin,
        &CheckKind::Denylist(DenylistCheck {
            contract: deny_id.clone(),
        }),
    );

    let result = client.try_evaluate(&from, &to);
    assert_eq!(result, Err(Ok(Error::IncompatibleInterfaceVersion)));
}

/// A denial surfaces the implementer's reason code through `evaluate_verbose`.
#[test]
fn test_evaluate_verbose_surfaces_reason_code() {
    let env = Env::default();
    env.mock_all_auths();

    let deny_id = setup_denylist(&env);
    let from = Address::generate(&env);
    let to = Address::generate(&env);

    MockDenylistClient::new(&env, &deny_id).add_to_denylist(&from);

    let (admin, _engine_id, client) = setup_engine_all(&env);
    client.add_check(
        &admin,
        &CheckKind::Denylist(DenylistCheck {
            contract: deny_id.clone(),
        }),
    );

    let (passed, failure) = client.evaluate_verbose(&from, &to);
    assert!(!passed, "expected policy to fail");
    let f = failure.expect("expected Some(CheckFailure) when policy fails");
    assert_eq!(f.check_index, 0);
    assert_eq!(f.kind, soroban_sdk::Symbol::new(&env, "Denylist"));
    assert_eq!(f.code, REASON_DENYLISTED);
}

/// A passing policy reports the OK reason code.
#[test]
fn test_evaluate_verbose_pass_reports_ok_reason_code() {
    let env = Env::default();
    env.mock_all_auths();

    let deny_id = setup_denylist(&env);
    let from = Address::generate(&env);
    let to = Address::generate(&env);

    let (admin, _engine_id, client) = setup_engine_all(&env);
    client.add_check(
        &admin,
        &CheckKind::Denylist(DenylistCheck {
            contract: deny_id.clone(),
        }),
    );

    let (passed, failure) = client.evaluate_verbose(&from, &to);
    assert!(passed, "expected policy to pass");
    assert!(failure.is_none(), "expected no CheckFailure when policy passes");
}

// ---------------------------------------------------------------------------
// Tests for issue #405: evaluate_verbose surfaces CheckFailure
// ---------------------------------------------------------------------------

/// `evaluate_verbose` returns `(true, None)` when all checks pass (All op).
#[test]
fn test_evaluate_verbose_passes_returns_none_failure() {
    let env = Env::default();
    env.mock_all_auths();

    let deny_id = setup_denylist(&env);
    let juri_id = setup_jurisdiction(&env);

    let from = Address::generate(&env);
    let to = Address::generate(&env);

    let code_us = String::from_str(&env, "US");
    MockJurisdictionClient::new(&env, &juri_id).set_jurisdiction(&from, &code_us);
    MockJurisdictionClient::new(&env, &juri_id).set_jurisdiction(&to, &code_us);

    let (admin, _engine_id, client) = setup_engine_all(&env);
    let name = default_policy(&env);

    client.add_check(
        &admin,
        &name,
        &CheckKind::Denylist(DenylistCheck {
            contract: deny_id.clone(),
        }),
    );
    client.add_check(
        &admin,
        &name,
        &CheckKind::Jurisdiction(JurisdictionCheck {
            contract: juri_id.clone(),
            allowed_codes: vec![&env, String::from_str(&env, "US")],
        }),
    );

    let (passed, failure) = client.evaluate_verbose(&name, &from, &to);
    assert!(passed, "expected policy to pass");
    assert!(failure.is_none(), "expected no CheckFailure when policy passes");
}

/// `evaluate_verbose` returns `(false, Some(CheckFailure))` with the correct
/// index and kind when the denylist check fails under All semantics.
#[test]
fn test_evaluate_verbose_fails_surfaces_check_failure() {
    let env = Env::default();
    env.mock_all_auths();

    let deny_id = setup_denylist(&env);
    let juri_id = setup_jurisdiction(&env);

    let from = Address::generate(&env);
    let to = Address::generate(&env);

    // Both addresses have valid jurisdiction codes but `from` is denied.
    let code_us = String::from_str(&env, "US");
    MockJurisdictionClient::new(&env, &juri_id).set_jurisdiction(&from, &code_us);
    MockJurisdictionClient::new(&env, &juri_id).set_jurisdiction(&to, &code_us);
    MockDenylistClient::new(&env, &deny_id).add_to_denylist(&from);

    let (admin, _engine_id, client) = setup_engine_all(&env);
    let name = default_policy(&env);

    // Register Denylist at index 0, Jurisdiction at index 1.
    client.add_check(
        &admin,
        &name,
        &CheckKind::Denylist(DenylistCheck {
            contract: deny_id.clone(),
        }),
    );
    client.add_check(
        &admin,
        &name,
        &CheckKind::Jurisdiction(JurisdictionCheck {
            contract: juri_id.clone(),
            allowed_codes: vec![&env, String::from_str(&env, "US")],
        }),
    );

    let (passed, failure) = client.evaluate_verbose(&name, &from, &to);
    assert!(!passed, "expected policy to fail");

    let f = failure.expect("expected Some(CheckFailure) when policy fails");
    assert_eq!(f.check_index, 0, "denylist is at index 0");
    assert_eq!(
        f.kind,
        soroban_sdk::Symbol::new(&env, "Denylist"),
        "kind should be 'Denylist'"
    );
}

/// Under `CombineOp::All`, when the *second* check fails, `evaluate_verbose`
/// must report that check's index (1) and kind — not index 0.
#[test]
fn test_evaluate_verbose_all_failure_blames_failing_check() {
    let env = Env::default();
    env.mock_all_auths();

    let deny_id = setup_denylist(&env);
    let juri_id = setup_jurisdiction(&env);

    let from = Address::generate(&env);
    let to = Address::generate(&env);

    // Denylist check passes: neither address is denied.
    // Jurisdiction check fails: no codes set for either address.
    let (admin, _engine_id, client) = setup_engine_all(&env);
    let name = default_policy(&env);

    // Register Denylist at index 0, Jurisdiction at index 1.
    client.add_check(
        &admin,
        &name,
        &CheckKind::Denylist(DenylistCheck {
            contract: deny_id.clone(),
        }),
    );
    client.add_check(
        &admin,
        &name,
        &CheckKind::Jurisdiction(JurisdictionCheck {
            contract: juri_id.clone(),
            allowed_codes: vec![&env, String::from_str(&env, "US")],
        }),
    );

    let (passed, failure) = client.evaluate_verbose(&name, &from, &to);
    assert!(!passed, "expected policy to fail");

    let f = failure.expect("expected Some(CheckFailure) when policy fails");
    assert_eq!(f.check_index, 1, "the failing jurisdiction check is at index 1");
    assert_eq!(
        f.kind,
        soroban_sdk::Symbol::new(&env, "Jurisdiction"),
        "kind should be 'Jurisdiction'"
    );
}

/// A failed `Any` policy reports that all checks failed, not an arbitrary
/// check at index zero.
#[test]
fn test_evaluate_verbose_any_failure_does_not_blame_first_check() {
    let env = Env::default();
    env.mock_all_auths();

    let deny_id = setup_denylist(&env);
    let juri_id = setup_jurisdiction(&env);
    let from = Address::generate(&env);
    let to = Address::generate(&env);
    MockDenylistClient::new(&env, &deny_id).add_to_denylist(&from);

    let (admin, _engine_id, client) = setup_engine_any(&env);
    let name = default_policy(&env);
    client.add_check(
        &admin,
        &name,
        &CheckKind::Denylist(DenylistCheck {
            contract: deny_id,
        }),
    );
    client.add_check(
        &admin,
        &name,
        &CheckKind::Jurisdiction(JurisdictionCheck {
            contract: juri_id,
            allowed_codes: vec![&env, String::from_str(&env, "US")],
        }),
    );

    let (passed, failure) = client.evaluate_verbose(&name, &from, &to);
    assert!(!passed, "expected policy to fail");

    let failure = failure.expect("expected failure details for failed Any policy");
    assert_eq!(failure.check_index, u32::MAX);
    assert_eq!(failure.kind, soroban_sdk::Symbol::new(&env, "AllFailed"));
}

/// Under `CombineOp::Any`, when both checks fail, `evaluate_verbose` must not
/// blame an arbitrary check: it reports the sentinel `check_index == u32::MAX`
/// and the `AllFailed` kind.
#[test]
fn test_evaluate_verbose_any_all_checks_fail_reports_all_failed() {
    let env = Env::default();
    env.mock_all_auths();

    let deny_id = setup_denylist(&env);
    let juri_id = setup_jurisdiction(&env);

    let from = Address::generate(&env);
    let to = Address::generate(&env);

    // Denylist check fails: `from` is denied.
    MockDenylistClient::new(&env, &deny_id).add_to_denylist(&from);
    // Jurisdiction check fails: no codes set for either address.

    let (admin, _engine_id, client) = setup_engine_any(&env);
    let name = default_policy(&env);

    client.add_check(
        &admin,
        &name,
        &CheckKind::Denylist(DenylistCheck {
            contract: deny_id.clone(),
        }),
    );
    client.add_check(
        &admin,
        &name,
        &CheckKind::Jurisdiction(JurisdictionCheck {
            contract: juri_id.clone(),
            allowed_codes: vec![&env, String::from_str(&env, "US")],
        }),
    );

    let (passed, failure) = client.evaluate_verbose(&name, &from, &to);
    assert!(!passed, "expected policy to fail");

    let f = failure.expect("expected Some(CheckFailure) when policy fails");
    assert_eq!(
        f.check_index,
        u32::MAX,
        "Any failure must not blame an arbitrary check index"
    );
    assert_eq!(
        f.kind,
        soroban_sdk::Symbol::new(&env, "AllFailed"),
        "kind should be 'AllFailed'"
    );
}

/// A passing policy under `Any` semantics returns `None` for the failure payload.
#[test]
fn test_evaluate_verbose_any_pass_returns_none_failure() {
    let env = Env::default();
    env.mock_all_auths();

    let deny_id = setup_denylist(&env);
    let juri_id = setup_j