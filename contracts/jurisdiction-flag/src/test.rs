use super::*;
use soroban_sdk::testutils::{Address as _, Events as _};
use soroban_sdk::{vec, BytesN, Env};

/// Compiled WASM of the jurisdiction-flag contract, used as an upgrade target
/// in tests. The upgrade replaces the running code with the same contract
/// code, which is sufficient to verify that storage (issuer, jurisdiction
/// flags) survives the upgrade and that the auth gate works.
const JURISDICTION_FLAG_WASM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../target/wasm32v1-none/release/jurisdiction_flag.wasm"
));

fn setup(env: &Env) -> (Address, Address, JurisdictionFlagClient<'_>) {
    env.mock_all_auths();
    let issuer = Address::generate(env);
    let contract_id = env.register(JurisdictionFlag, ());
    let client = JurisdictionFlagClient::new(env, &contract_id);
    client.initialize(&issuer);
    (issuer, contract_id, client)
}

#[test]
fn test_set_and_get_jurisdiction() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);

    assert_eq!(client.get_jurisdiction(&alice), None);

    let code = String::from_str(&env, "US");
    client.set_jurisdiction(&issuer, &alice, &code);
    assert_eq!(client.get_jurisdiction(&alice), Some(code));
}

#[test]
fn test_set_jurisdiction_rejects_non_issuer() {
    let env = Env::default();
    let (_issuer, _contract_id, client) = setup(&env);
    let impostor = Address::generate(&env);
    let alice = Address::generate(&env);
    let code = String::from_str(&env, "US");

    let result = client.try_set_jurisdiction(&impostor, &alice, &code);
    assert_eq!(result, Err(Ok(Error::NotAuthorized)));
    assert_eq!(client.get_jurisdiction(&alice), None);
}

#[test]
fn test_is_permitted_jurisdiction_true_when_code_in_list() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let code = String::from_str(&env, "US");
    client.set_jurisdiction(&issuer, &alice, &code);

    let allowed = vec![
        &env,
        String::from_str(&env, "CA"),
        String::from_str(&env, "US"),
    ];
    assert!(client.is_permitted_jurisdiction(&alice, &allowed));
}

#[test]
fn test_is_permitted_jurisdiction_false_when_no_jurisdiction_set() {
    let env = Env::default();
    let (_issuer, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let allowed = vec![&env, String::from_str(&env, "US")];
    assert!(!client.is_permitted_jurisdiction(&alice, &allowed));
}

#[test]
fn test_is_permitted_jurisdiction_false_with_empty_allowed_list() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let code = String::from_str(&env, "US");
    client.set_jurisdiction(&issuer, &alice, &code);

    let allowed: Vec<String> = vec![&env];
    assert!(!client.is_permitted_jurisdiction(&alice, &allowed));
}

#[test]
fn test_is_permitted_jurisdiction_false_when_no_jurisdiction_and_empty_allowed_list() {
    let env = Env::default();
    let (_issuer, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);

    let allowed: Vec<String> = vec![&env];
    assert!(!client.is_permitted_jurisdiction(&alice, &allowed));
}

#[test]
fn test_set_jurisdiction_fails_before_initialize() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(JurisdictionFlag, ());
    let client = JurisdictionFlagClient::new(&env, &contract_id);
    let issuer = Address::generate(&env);
    let alice = Address::generate(&env);
    let code = String::from_str(&env, "US");

    let result = client.try_set_jurisdiction(&issuer, &alice, &code);
    assert_eq!(result, Err(Ok(Error::NotInitialized)));
    assert_eq!(env.events().all(), vec![&env]);
}

#[test]
fn test_double_initialize_fails() {
    let env = Env::default();
    let (issuer, _contract_id, client) = setup(&env);
    let result = client.try_initialize(&issuer);
    assert_eq!(result, Err(Ok(Error::AlreadyInitialized)));
}

#[test]
fn test_upgrade_by_issuer_preserves_storage() {
    let env = Env::default();
    env.mock_all_auths();
    let issuer = Address::generate(&env);
    let contract_id = env.register(JurisdictionFlag, ());
    let client = JurisdictionFlagClient::new(&env, &contract_id);
    client.initialize(&issuer);

    // Set up some state
    let alice = Address::generate(&env);
    let code = String::from_str(&env, "US");
    client.set_jurisdiction(&issuer, &alice, &code);
    assert_eq!(
        client.get_jurisdiction(&alice),
        Some(String::from_str(&env, "US"))
    );

    // Upload the same contract's wasm and use it as upgrade target
    let wasm_hash: BytesN<32> = env.deployer().upload_contract_wasm(JURISDICTION_FLAG_WASM);

    // Upgrade
    client.upgrade(&issuer, &wasm_hash);

    // Storage survives the upgrade — issuer and jurisdiction flags are
    // preserved because the upgrade only replaces the code, not the
    // contract ID or its storage.
    assert_eq!(
        client.get_jurisdiction(&alice),
        Some(String::from_str(&env, "US"))
    );

    // The contract still functions after the upgrade
    let bob = Address::generate(&env);
    let code2 = String::from_str(&env, "CA");
    client.set_jurisdiction(&issuer, &bob, &code2);
    assert_eq!(client.get_jurisdiction(&bob), Some(String::from_str(&env, "CA")));
}

#[test]
fn test_upgrade_rejects_non_issuer() {
    let env = Env::default();
    env.mock_all_auths();
    let issuer = Address::generate(&env);
    let contract_id = env.register(JurisdictionFlag, ());
    let client = JurisdictionFlagClient::new(&env, &contract_id);
    client.initialize(&issuer);

    let wasm_hash: BytesN<32> = env.deployer().upload_contract_wasm(JURISDICTION_FLAG_WASM);

    let impostor = Address::generate(&env);
    let result = client.try_upgrade(&impostor, &wasm_hash);
    assert_eq!(result, Err(Ok(Error::NotAuthorized)));
}
