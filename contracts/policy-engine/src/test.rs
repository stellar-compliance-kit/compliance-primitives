use super::*;
use denylist_gate::{DenylistGate, DenylistGateClient};
use jurisdiction_flag::{JurisdictionFlag, JurisdictionFlagClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{vec, Env, String};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Registers and initialises a denylist-gate contract, returns its address.
fn setup_denylist(env: &Env, admin: &Address) -> Address {
    let id = env.register(DenylistGate, ());
    DenylistGateClient::new(env, &id).initialize(admin);
    id
}

/// Registers and initialises a jurisdiction-flag contract, returns its address.
fn setup_jurisdiction(env: &Env, issuer: &Address) -> Address {
    let id = env.register(JurisdictionFlag, ());
    JurisdictionFlagClient::new(env, &id).initialize(issuer);
    id
}

/// Registers and initialises a policy-engine contract with `All` semantics,
/// returns `(admin, contract_id, client)`.
fn setup_engine_all(env: &Env) -> (Address, Address, PolicyEngineClient<'_>) {
    let admin = Address::generate(env);
    let id = env.register(PolicyEngine, ());
    let client = PolicyEngineClient::new(env, &id);
    client.initialize(&admin, &CombineOp::All);
    (admin, id, client)
}

/// Same as above but with `Any` semantics.
fn setup_engine_any(env: &Env) -> (Address, Address, PolicyEngineClient<'_>) {
    let admin = Address::generate(env);
    let id = env.register(PolicyEngine, ());
    let client = PolicyEngineClient::new(env, &id);
    client.initialize(&admin, &CombineOp::Any);
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

    let deny_admin = Address::generate(&env);
    let juri_issuer = Address::generate(&env);
    let deny_id = setup_denylist(&env, &deny_admin);
    let juri_id = setup_jurisdiction(&env, &juri_issuer);

    let from = Address::generate(&env);
    let to = Address::generate(&env);

    // Set permitted jurisdictions for both addresses.
    let code_us = String::from_str(&env, "US");
    JurisdictionFlagClient::new(&env, &juri_id)
        .set_jurisdiction(&juri_issuer, &from, &code_us);
    JurisdictionFlagClient::new(&env, &juri_id)
        .set_jurisdiction(&juri_issuer, &to, &code_us);

    let (admin, _engine_id, client) = setup_engine_all(&env);

    client.add_check(
        &admin,
        &CheckKind::Denylist {
            contract: deny_id.clone(),
        },
    );
    client.add_check(
        &admin,
        &CheckKind::Jurisdiction {
            contract: juri_id.clone(),
            allowed_codes: vec![&env, String::from_str(&env, "US")],
        },
    );

    let result = client.evaluate(&from, &to);
    assert!(result);
}

/// With All semantics: one of two checks fails (sender is on the denylist)
/// → evaluate returns false.
#[test]
fn test_one_check_fails_and_semantics() {
    let env = Env::default();
    env.mock_all_auths();

    let deny_admin = Address::generate(&env);
    let juri_issuer = Address::generate(&env);
    let deny_id = setup_denylist(&env, &deny_admin);
    let juri_id = setup_jurisdiction(&env, &juri_issuer);

    let from = Address::generate(&env);
    let to = Address::generate(&env);

    // Both addresses have valid jurisdiction codes.
    let code_us = String::from_str(&env, "US");
    JurisdictionFlagClient::new(&env, &juri_id)
        .set_jurisdiction(&juri_issuer, &from, &code_us);
    JurisdictionFlagClient::new(&env, &juri_id)
        .set_jurisdiction(&juri_issuer, &to, &code_us);

    // But `from` is denied.
    DenylistGateClient::new(&env, &deny_id).add_to_denylist(&deny_admin, &from);

    let (admin, _engine_id, client) = setup_engine_all(&env);

    client.add_check(
        &admin,
        &CheckKind::Denylist {
            contract: deny_id.clone(),
        },
    );
    client.add_check(
        &admin,
        &CheckKind::Jurisdiction {
            contract: juri_id.clone(),
            allowed_codes: vec![&env, String::from_str(&env, "US")],
        },
    );

    let result = client.evaluate(&from, &to);
    assert!(!result);
}

/// With Any semantics: the denylist check fails (both addresses denied) but
/// the jurisdiction check passes → evaluate returns true because at least
/// one check passes for both parties.
#[test]
fn test_one_check_passes_or_semantics() {
    let env = Env::default();
    env.mock_all_auths();

    let deny_admin = Address::generate(&env);
    let juri_issuer = Address::generate(&env);
    let deny_id = setup_denylist(&env, &deny_admin);
    let juri_id = setup_jurisdiction(&env, &juri_issuer);

    let from = Address::generate(&env);
    let to = Address::generate(&env);

    // Both addresses are on the denylist (denylist check will fail).
    DenylistGateClient::new(&env, &deny_id).add_to_denylist(&deny_admin, &from);
    DenylistGateClient::new(&env, &deny_id).add_to_denylist(&deny_admin, &to);

    // But both have valid jurisdiction codes (jurisdiction check will pass).
    let code_us = String::from_str(&env, "US");
    JurisdictionFlagClient::new(&env, &juri_id)
        .set_jurisdiction(&juri_issuer, &from, &code_us);
    JurisdictionFlagClient::new(&env, &juri_id)
        .set_jurisdiction(&juri_issuer, &to, &code_us);

    let (admin, _engine_id, client) = setup_engine_any(&env);

    client.add_check(
        &admin,
        &CheckKind::Denylist {
            contract: deny_id.clone(),
        },
    );
    client.add_check(
        &admin,
        &CheckKind::Jurisdiction {
            contract: juri_id.clone(),
            allowed_codes: vec![&env, String::from_str(&env, "US")],
        },
    );

    // With Any: the jurisdiction check passes for both → result is true.
    let result = client.evaluate(&from, &to);
    assert!(result);
}

/// Verify that add_check and remove_check correctly mutate the checks list.
#[test]
fn test_add_and_remove_check() {
    let env = Env::default();
    env.mock_all_auths();

    let deny_admin = Address::generate(&env);
    let deny_id = setup_denylist(&env, &deny_admin);

    let (admin, _engine_id, client) = setup_engine_all(&env);

    // Initially empty.
    assert_eq!(client.get_checks().len(), 0);

    // Add one check.
    client.add_check(
        &admin,
        &CheckKind::Denylist {
            contract: deny_id.clone(),
        },
    );
    assert_eq!(client.get_checks().len(), 1);

    // Add a second check.
    let juri_issuer = Address::generate(&env);
    let juri_id = setup_jurisdiction(&env, &juri_issuer);
    client.add_check(
        &admin,
        &CheckKind::Jurisdiction {
            contract: juri_id.clone(),
            allowed_codes: vec![&env, String::from_str(&env, "US")],
        },
    );
    assert_eq!(client.get_checks().len(), 2);

    // Remove the first check (index 0); list should shrink to 1.
    client.remove_check(&admin, &0);
    assert_eq!(client.get_checks().len(), 1);
}

// ---------------------------------------------------------------------------
// batch_evaluate tests
// ---------------------------------------------------------------------------

/// batch_evaluate with All semantics: results must match individual evaluate()
/// calls for the same addresses (each address evaluated against itself as both
/// from and to, which is how run_check is applied per address in the batch).
#[test]
fn test_batch_evaluate_matches_individual_evaluate() {
    let env = Env::default();
    env.mock_all_auths();

    let deny_admin = Address::generate(&env);
    let juri_issuer = Address::generate(&env);
    let deny_id = setup_denylist(&env, &deny_admin);
    let juri_id = setup_jurisdiction(&env, &juri_issuer);

    // alice: clear denylist, has US jurisdiction → should pass
    // bob: on denylist, has US jurisdiction → should fail (All semantics)
    // carol: clear denylist, no jurisdiction → should fail
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    let carol = Address::generate(&env);

    let code_us = String::from_str(&env, "US");
    JurisdictionFlagClient::new(&env, &juri_id)
        .set_jurisdiction(&juri_issuer, &alice, &code_us);
    JurisdictionFlagClient::new(&env, &juri_id)
        .set_jurisdiction(&juri_issuer, &bob, &code_us);
    DenylistGateClient::new(&env, &deny_id).add_to_denylist(&deny_admin, &bob);

    let (admin, _engine_id, client) = setup_engine_all(&env);
    client.add_check(
        &admin,
        &CheckKind::Denylist {
            contract: deny_id.clone(),
        },
    );
    client.add_check(
        &admin,
        &CheckKind::Jurisdiction {
            contract: juri_id.clone(),
            allowed_codes: vec![&env, String::from_str(&env, "US")],
        },
    );

    // Run batch_evaluate.
    let addresses = vec![&env, alice.clone(), bob.clone(), carol.clone()];
    let batch_results = client.batch_evaluate(&addresses);
    assert_eq!(batch_results.len(), 3);

    // Compare each batch result against the equivalent individual evaluate()
    // call (each address evaluated as both from and to).
    let individual_alice = client.evaluate(&alice, &alice);
    let individual_bob = client.evaluate(&bob, &bob);
    let individual_carol = client.evaluate(&carol, &carol);

    assert_eq!(batch_results.get(0).unwrap(), individual_alice);
    assert_eq!(batch_results.get(1).unwrap(), individual_bob);
    assert_eq!(batch_results.get(2).unwrap(), individual_carol);

    // Sanity-check the expected values explicitly.
    assert!(batch_results.get(0).unwrap()); // alice passes
    assert!(!batch_results.get(1).unwrap()); // bob fails (denied)
    assert!(!batch_results.get(2).unwrap()); // carol fails (no jurisdiction)
}

/// batch_evaluate with Any semantics: each address only needs to satisfy one
/// check. Results must again match calling evaluate() individually.
#[test]
fn test_batch_evaluate_any_semantics_matches_individual() {
    let env = Env::default();
    env.mock_all_auths();

    let deny_admin = Address::generate(&env);
    let juri_issuer = Address::generate(&env);
    let deny_id = setup_denylist(&env, &deny_admin);
    let juri_id = setup_jurisdiction(&env, &juri_issuer);

    // dave: on denylist, but has US jurisdiction → passes (Any: jurisdiction check wins)
    // eve: on denylist, no jurisdiction → fails (Any: neither check passes)
    let dave = Address::generate(&env);
    let eve = Address::generate(&env);

    let code_us = String::from_str(&env, "US");
    DenylistGateClient::new(&env, &deny_id).add_to_denylist(&deny_admin, &dave);
    JurisdictionFlagClient::new(&env, &juri_id)
        .set_jurisdiction(&juri_issuer, &dave, &code_us);
    DenylistGateClient::new(&env, &deny_id).add_to_denylist(&deny_admin, &eve);

    let (admin, _engine_id, client) = setup_engine_any(&env);
    client.add_check(
        &admin,
        &CheckKind::Denylist {
            contract: deny_id.clone(),
        },
    );
    client.add_check(
        &admin,
        &CheckKind::Jurisdiction {
            contract: juri_id.clone(),
            allowed_codes: vec![&env, String::from_str(&env, "US")],
        },
    );

    let addresses = vec![&env, dave.clone(), eve.clone()];
    let batch_results = client.batch_evaluate(&addresses);
    assert_eq!(batch_results.len(), 2);

    let individual_dave = client.evaluate(&dave, &dave);
    let individual_eve = client.evaluate(&eve, &eve);

    assert_eq!(batch_results.get(0).unwrap(), individual_dave);
    assert_eq!(batch_results.get(1).unwrap(), individual_eve);

    assert!(batch_results.get(0).unwrap()); // dave passes via jurisdiction
    assert!(!batch_results.get(1).unwrap()); // eve fails both checks
}

/// batch_evaluate must return BatchTooLarge when the list exceeds MAX_BATCH_SIZE.
#[test]
fn test_batch_evaluate_too_large() {
    let env = Env::default();
    env.mock_all_auths();

    let (_, _, client) = setup_engine_all(&env);

    // Build a list with MAX_BATCH_SIZE + 1 addresses.
    let mut addresses: Vec<Address> = Vec::new(&env);
    for _ in 0..=MAX_BATCH_SIZE {
        addresses.push_back(Address::generate(&env));
    }

    let result = client.try_batch_evaluate(&addresses);
    assert_eq!(result, Err(Ok(Error::BatchTooLarge)));
}

/// batch_evaluate with exactly MAX_BATCH_SIZE addresses must succeed.
#[test]
fn test_batch_evaluate_at_limit_succeeds() {
    let env = Env::default();
    env.mock_all_auths();

    let (_, _, client) = setup_engine_all(&env);

    let mut addresses: Vec<Address> = Vec::new(&env);
    for _ in 0..MAX_BATCH_SIZE {
        addresses.push_back(Address::generate(&env));
    }

    // No checks registered — All semantics with zero checks returns true for every address.
    let results = client.batch_evaluate(&addresses);
    assert_eq!(results.len(), MAX_BATCH_SIZE);
}
