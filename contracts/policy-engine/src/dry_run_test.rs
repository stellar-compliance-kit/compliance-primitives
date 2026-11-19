//! Tests for `PolicyEngine::evaluate_dry_run`.

use super::*;
use crate::test_utils::{
    MockCircuitBreaker, MockCircuitBreakerClient, MockDenylist, MockDenylistClient,
    MockJurisdiction, MockJurisdictionClient,
};
use soroban_sdk::testutils::{Address as _, Events as _};
use soroban_sdk::{vec, Env, String};

fn setup_engine(env: &Env, op: CombineOp) -> (Address, PolicyEngineClient<'_>) {
    let admin = Address::generate(env);
    let id = env.register(PolicyEngine, ());
    let client = PolicyEngineClient::new(env, &id);
    client.initialize(&admin, &op, &None);
    (admin, client)
}

#[test]
fn test_dry_run_reports_every_check_and_matches_evaluate() {
    let env = Env::default();
    env.mock_all_auths();

    let deny_id = env.register(MockDenylist, ());
    let juri_id = env.register(MockJurisdiction, ());
    let from = Address::generate(&env);
    let to = Address::generate(&env);
    let code_us = String::from_str(&env, "US");
    MockDenylistClient::new(&env, &deny_id).add_to_denylist(&from);
    MockJurisdictionClient::new(&env, &juri_id).set_jurisdiction(&from, &code_us);
    MockJurisdictionClient::new(&env, &juri_id).set_jurisdiction(&to, &code_us);

    let (admin, client) = setup_engine(&env, CombineOp::All);
    client.add_check(&admin, &CheckKind::Denylist(DenylistCheck { contract: deny_id.clone() }));
    client.add_check(
        &admin,
        &CheckKind::Jurisdiction(JurisdictionCheck {
            contract: juri_id.clone(),
            allowed_codes: vec![&env, String::from_str(&env, "US")],
        }),
    );

    let dry = client.evaluate_dry_run(&from, &to);
    assert!(!dry.passed);
    assert!(!dry.circuit_breaker_frozen);
    // Every check is reported, even though `All` would stop at the first failure.
    assert_eq!(dry.checks.len(), 2);
    let denylist = dry.checks.get(0).unwrap();
    assert_eq!(denylist.check_index, 0);
    assert_eq!(denylist.kind, Symbol::new(&env, "Denylist"));
    assert!(!denylist.from_passed);
    assert!(denylist.to_passed);
    let jurisdiction = dry.checks.get(1).unwrap();
    assert_eq!(jurisdiction.kind, Symbol::new(&env, "Jurisdiction"));
    assert!(jurisdiction.from_passed);
    assert!(jurisdiction.to_passed);

    assert_eq!(client.evaluate(&from, &to), dry.passed);
}

#[test]
fn test_dry_run_any_passes_when_one_check_clears() {
    let env = Env::default();
    env.mock_all_auths();

    let deny_id = env.register(MockDenylist, ());
    let juri_id = env.register(MockJurisdiction, ());
    let from = Address::generate(&env);
    let to = Address::generate(&env);
    let code_us = String::from_str(&env, "US");
    MockDenylistClient::new(&env, &deny_id).add_to_denylist(&from);
    MockJurisdictionClient::new(&env, &juri_id).set_jurisdiction(&from, &code_us);
    MockJurisdictionClient::new(&env, &juri_id).set_jurisdiction(&to, &code_us);

    let (admin, client) = setup_engine(&env, CombineOp::Any);
    client.add_check(&admin, &CheckKind::Denylist(DenylistCheck { contract: deny_id.clone() }));
    client.add_check(
        &admin,
        &CheckKind::Jurisdiction(JurisdictionCheck {
            contract: juri_id.clone(),
            allowed_codes: vec![&env, String::from_str(&env, "US")],
        }),
    );

    let dry = client.evaluate_dry_run(&from, &to);
    assert!(dry.passed);
    assert_eq!(dry.passed, client.evaluate(&from, &to));
}

#[test]
fn test_dry_run_emits_no_events() {
    let env = Env::default();
    env.mock_all_auths();

    let deny_id = env.register(MockDenylist, ());
    let from = Address::generate(&env);
    let to = Address::generate(&env);
    let (admin, client) = setup_engine(&env, CombineOp::All);
    client.add_check(&admin, &CheckKind::Denylist(DenylistCheck { contract: deny_id.clone() }));

    let before = env.events().all().len();
    client.evaluate_dry_run(&from, &to);
    assert_eq!(env.events().all().len(), before, "dry run must not emit PolicyResult");

    // The same pair through `evaluate` does emit, which proves the check above is meaningful.
    client.evaluate(&from, &to);
    assert!(env.events().all().len() > before);
}

#[test]
fn test_dry_run_frozen_circuit_breaker_fails_overall() {
    let env = Env::default();
    env.mock_all_auths();

    let deny_id = env.register(MockDenylist, ());
    let cb_id = env.register(MockCircuitBreaker, ());
    MockCircuitBreakerClient::new(&env, &cb_id).freeze();
    let from = Address::generate(&env);
    let to = Address::generate(&env);

    let (admin, client) = setup_engine(&env, CombineOp::All);
    client.set_circuit_breaker(&admin, &cb_id);
    client.add_check(&admin, &CheckKind::Denylist(DenylistCheck { contract: deny_id.clone() }));

    let dry = client.evaluate_dry_run(&from, &to);
    assert!(!dry.passed);
    assert!(dry.circuit_breaker_frozen);
    assert_eq!(dry.checks.len(), 1);
    assert!(dry.checks.get(0).unwrap().from_passed);
    assert!(!client.evaluate(&from, &to));
}

#[test]
fn test_dry_run_fails_before_initialize() {
    let env = Env::default();
    let id = env.register(PolicyEngine, ());
    let client = PolicyEngineClient::new(&env, &id);
    let from = Address::generate(&env);
    let to = Address::generate(&env);

    assert_eq!(
        client.try_evaluate_dry_run(&from, &to),
        Err(Ok(Error::NotInitialized))
    );
}
