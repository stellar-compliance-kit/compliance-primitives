extern crate std;

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Env, IntoVal};

fn setup(env: &Env) -> (Address, CircuitBreakerClient<'_>) {
    env.mock_all_auths();
    let admin = Address::generate(env);
    let contract_id = env.register(CircuitBreaker, ());
    let client = CircuitBreakerClient::new(env, &contract_id);
    client.initialize(&admin);
    (admin, client)
}

#[test]
fn test_is_frozen_defaults_to_false() {
    let env = Env::default();
    let (_admin, client) = setup(&env);
    assert!(!client.is_frozen());
}

#[test]
fn test_admin_can_freeze_and_unfreeze() {
    let env = Env::default();
    let (admin, client) = setup(&env);

    client.freeze(&admin);
    assert!(client.is_frozen());

    client.unfreeze(&admin);
    assert!(!client.is_frozen());
}

#[test]
fn test_freeze_and_unfreeze_emit_events_with_admin() {
    let env = Env::default();
    let (admin, client) = setup(&env);

    client.freeze(&admin);
    let freeze_events = env.events().all();
    let (_contract_id, topics, _data) = freeze_events.last().unwrap();
    assert_eq!(
        topics.get_unchecked(0),
        soroban_sdk::Symbol::new(&env, "frozen").into_val(&env)
    );
    assert_eq!(topics.get_unchecked(1), admin.clone().into_val(&env));

    client.unfreeze(&admin);
    let unfreeze_events = env.events().all();
    let (_contract_id, topics, _data) = unfreeze_events.last().unwrap();
    assert_eq!(
        topics.get_unchecked(0),
        soroban_sdk::Symbol::new(&env, "unfrozen").into_val(&env)
    );
    assert_eq!(topics.get_unchecked(1), admin.clone().into_val(&env));
}

#[test]
fn test_non_admin_cannot_freeze_or_unfreeze() {
    let env = Env::default();
    let (admin, client) = setup(&env);
    let impostor = Address::generate(&env);

    let freeze_result = client.try_freeze(&impostor);
    assert_eq!(freeze_result, Err(Ok(Error::NotAuthorized)));
    assert!(!client.is_frozen());

    let unfreeze_result = client.try_unfreeze(&impostor);
    assert_eq!(unfreeze_result, Err(Ok(Error::NotAuthorized)));
    assert!(!client.is_frozen());

    client.freeze(&admin);
    assert!(client.is_frozen());

    let unfreeze_result = client.try_unfreeze(&impostor);
    assert_eq!(unfreeze_result, Err(Ok(Error::NotAuthorized)));
    assert!(client.is_frozen());
}

/// Lightweight sequence fuzzer for circuit-breaker freeze/unfreeze invariants.
///
/// Feeds randomized sequences of freeze/unfreeze/is_frozen calls from varying
/// callers and asserts the contract never panics and is_frozen always reflects
/// the last successful admin-authorized call.
fn next_u32(state: &mut u32) -> u32 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = if x == 0 { 0x9E37_79B9 } else { x };
    *state
}

fn next_usize(state: &mut u32, upper: usize) -> usize {
    (next_u32(state) as usize) % upper
}

#[test]
fn fuzz_circuit_breaker_freeze_unfreeze_sequences() {
    let iterations: u32 = std::env::var("FUZZ_ITERATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(128);
    let ops_per_iter: u32 = std::env::var("FUZZ_OPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(24);

    for seed in 1..=iterations {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let contract_id = env.register(CircuitBreaker, ());
        let client = CircuitBreakerClient::new(&env, &contract_id);
        client.initialize(&admin);

        let addresses: [Address; 5] = [
            Address::generate(&env),
            Address::generate(&env),
            Address::generate(&env),
            Address::generate(&env),
            Address::generate(&env),
        ];

        let mut model: Option<bool> = None;
        let mut rng = seed;

        for _ in 0..ops_per_iter {
            let addr_i = next_usize(&mut rng, addresses.len());
            let op = next_usize(&mut rng, 3);
            let caller = &addresses[addr_i];

            match op {
                0 => {
                    let result = client.try_freeze(caller);
                    if result.is_ok() {
                        model = Some(true);
                    }
                }
                1 => {
                    let result = client.try_unfreeze(caller);
                    if result.is_ok() {
                        model = Some(false);
                    }
                }
                _ => {
                    let is_frozen = client.is_frozen();
                    if let Some(expected) = model {
                        assert_eq!(
                            is_frozen, expected,
                            "seed={seed}: is_frozen mismatch after successful operation"
                        );
                    }
                }
            }
        }

        let final_state = client.is_frozen();
        if let Some(expected) = model {
            assert_eq!(
                final_state, expected,
                "seed={seed}: final state mismatch with model"
            );
        }
    }
}
