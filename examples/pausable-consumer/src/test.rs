use super::*;
use soroban_sdk::testutils::{Address as _, Events as _};
use soroban_sdk::{vec, Env, IntoVal, Map, Symbol, Val};

fn setup(env: &Env) -> (Address, Address, PausableConsumerContractClient<'_>) {
    env.mock_all_auths();
    let admin = Address::generate(env);
    let contract_id = env.register(PausableConsumerContract, ());
    let client = PausableConsumerContractClient::new(env, &contract_id);
    client.initialize(&admin);
    (admin, contract_id, client)
}

#[test]
fn test_not_paused_by_default() {
    let env = Env::default();
    let (_admin, _contract_id, client) = setup(&env);
    assert!(!client.is_paused());
}

#[test]
fn test_pause_and_unpause_by_admin() {
    let env = Env::default();
    let (admin, _contract_id, client) = setup(&env);

    client.pause(&admin);
    assert!(client.is_paused());

    client.unpause(&admin);
    assert!(!client.is_paused());
}

#[test]
fn test_mutating_methods_blocked_while_paused() {
    let env = Env::default();
    let (admin, _contract_id, client) = setup(&env);

    // Baseline mutation works while unpaused
    client.set_value(&admin, &42);
    assert_eq!(client.get_value(), 42);

    // Pause contract
    client.pause(&admin);
    assert!(client.is_paused());

    // State-mutating calls must return Error::ContractPaused
    let set_val_res = client.try_set_value(&admin, &100);
    assert_eq!(set_val_res, Err(Ok(Error::ContractPaused)));

    let text = String::from_str(&env, "updated config");
    let set_cfg_res = client.try_set_config_text(&admin, &text);
    assert_eq!(set_cfg_res, Err(Ok(Error::ContractPaused)));

    // Verify state was not modified
    assert_eq!(client.get_value(), 42);
    assert_eq!(client.get_config_text(), None);
}

#[test]
fn test_read_only_methods_succeed_while_paused() {
    let env = Env::default();
    let (admin, _contract_id, client) = setup(&env);

    let text = String::from_str(&env, "initial config");
    client.set_value(&admin, &99);
    client.set_config_text(&admin, &text);

    // Pause the contract
    client.pause(&admin);
    assert!(client.is_paused());

    // Step 5 verification: Read-only methods execute without error
    assert_eq!(client.get_value(), 99);
    assert_eq!(client.get_config_text(), Some(text));
    assert_eq!(client.get_admin(), Some(admin));
}

#[test]
fn test_mutations_resume_after_unpause() {
    let env = Env::default();
    let (admin, _contract_id, client) = setup(&env);

    client.pause(&admin);
    assert_eq!(
        client.try_set_value(&admin, &500),
        Err(Ok(Error::ContractPaused))
    );

    // Unpause
    client.unpause(&admin);
    assert!(!client.is_paused());

    // Mutation succeeds now
    client.set_value(&admin, &500);
    assert_eq!(client.get_value(), 500);
}

#[test]
fn test_non_admin_cannot_pause_or_unpause() {
    let env = Env::default();
    let (admin, _contract_id, client) = setup(&env);
    let impostor = Address::generate(&env);

    let pause_res = client.try_pause(&impostor);
    assert_eq!(pause_res, Err(Ok(Error::NotAuthorized)));
    assert!(!client.is_paused());

    // Pause with legit admin
    client.pause(&admin);
    assert!(client.is_paused());

    // Impostor cannot unpause
    let unpause_res = client.try_unpause(&impostor);
    assert_eq!(unpause_res, Err(Ok(Error::NotAuthorized)));
    assert!(client.is_paused());
}

#[test]
fn test_events_emitted_on_pause_and_unpause() {
    let env = Env::default();
    let (admin, contract_id, client) = setup(&env);

    client.pause(&admin);
    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                contract_id.clone(),
                (Symbol::new(&env, "paused"), admin.clone()).into_val(&env),
                Map::<Symbol, Val>::new(&env).into_val(&env),
            ),
        ]
    );

    // Clear events
    let _ = env.events().all();

    client.unpause(&admin);
    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                contract_id.clone(),
                (Symbol::new(&env, "unpaused"), admin.clone()).into_val(&env),
                Map::<Symbol, Val>::new(&env).into_val(&env),
            ),
        ]
    );
}
