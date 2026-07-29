use super::*;
use soroban_sdk::testutils::{Address as _, Events as _};
use soroban_sdk::{vec, BytesN, Env, IntoVal, Map, Symbol, Val};

/// Compiled WASM of the denylist-gate contract, used as an upgrade target
/// in tests. The upgrade replaces the running code with the same contract
/// code, which is sufficient to verify that storage (admin, denylist entries)
/// survives the upgrade and that the auth gate works.
const DENYLIST_GATE_WASM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../target/wasm32v1-none/release/denylist_gate.wasm"
));

fn setup(env: &Env) -> (Address, Address, DenylistGateClient<'_>) {
    env.mock_all_auths();
    let admin = Address::generate(env);
    let contract_id = env.register(DenylistGate, ());
    let client = DenylistGateClient::new(env, &contract_id);
    client.initialize(&admin);
    (admin, contract_id, client)
}

#[test]
fn test_check_defaults_to_clear() {
    let env = Env::default();
    let (_admin, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    assert!(client.check(&alice));
}

#[test]
fn test_add_and_remove_from_denylist() {
    let env = Env::default();
    let (admin, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);

    client.add_to_denylist(&admin, &alice);
    assert!(!client.check(&alice));

    client.remove_from_denylist(&admin, &alice);
    assert!(client.check(&alice));
}

#[test]
fn test_add_to_denylist_rejects_non_admin() {
    let env = Env::default();
    let (_admin, _contract_id, client) = setup(&env);
    let impostor = Address::generate(&env);
    let alice = Address::generate(&env);

    let result = client.try_add_to_denylist(&impostor, &alice);
    assert_eq!(result, Err(Ok(Error::NotAuthorized)));
    assert!(client.check(&alice));
}

#[test]
fn test_empty_address_key_is_well_defined() {
    // An address that has never been touched must read as "clear" (true),
    // not panic or default to denied. This guards the `unwrap_or(false)`
    // fallback in `check`.
    let env = Env::default();
    let (_admin, _contract_id, client) = setup(&env);
    let never_seen = Address::generate(&env);
    assert!(client.check(&never_seen));
}

#[test]
fn test_remove_from_denylist_never_added_is_noop() {
    let env = Env::default();
    let (admin, contract_id, client) = setup(&env);
    let never_added = Address::generate(&env);

    assert!(client.check(&never_added));

    client.remove_from_denylist(&admin, &never_added);

    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                contract_id.clone(),
                (Symbol::new(&env, "deny_remove"), never_added.clone()).into_val(&env),
                Map::<Symbol, Val>::new(&env).into_val(&env),
            ),
        ]
    );
    assert!(client.check(&never_added));
}

#[test]
fn test_double_initialize_fails() {
    let env = Env::default();
    let (admin, _contract_id, client) = setup(&env);
    let result = client.try_initialize(&admin);
    assert_eq!(result, Err(Ok(Error::AlreadyInitialized)));
}

#[test]
fn test_upgrade_by_admin_preserves_storage() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let contract_id = env.register(DenylistGate, ());
    let client = DenylistGateClient::new(&env, &contract_id);
    client.initialize(&admin);

    // Set up some state
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    client.add_to_denylist(&admin, &alice);
    assert!(!client.check(&alice));
    assert!(client.check(&bob));

    // Upload the same contract's wasm and use it as upgrade target
    let wasm_hash: BytesN<32> = env.deployer().upload_contract_wasm(DENYLIST_GATE_WASM);

    // Upgrade
    client.upgrade(&admin, &wasm_hash);

    // Storage survives the upgrade — denylist entries and admin are
    // preserved because the upgrade only replaces the code, not the
    // contract ID or its storage.
    assert!(!client.check(&alice));
    assert!(client.check(&bob));

    // The contract still functions after the upgrade
    let charlie = Address::generate(&env);
    client.add_to_denylist(&admin, &charlie);
    assert!(!client.check(&charlie));
}

#[test]
fn test_upgrade_rejects_non_admin() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let contract_id = env.register(DenylistGate, ());
    let client = DenylistGateClient::new(&env, &contract_id);
    client.initialize(&admin);

    let wasm_hash: BytesN<32> = env.deployer().upload_contract_wasm(DENYLIST_GATE_WASM);

    let impostor = Address::generate(&env);
    let result = client.try_upgrade(&impostor, &wasm_hash);
    assert_eq!(result, Err(Ok(Error::NotAuthorized)));
}
