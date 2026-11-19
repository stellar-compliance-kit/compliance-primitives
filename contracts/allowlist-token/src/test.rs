use super::*;
use ed25519_dalek::SigningKey;
use soroban_sdk::testutils::{Address as _, Events as _, Ledger as _};
use soroban_sdk::testutils::ed25519::Sign;
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, vec, Bytes, BytesN, Env, IntoVal, Map, Symbol, Val, Vec};
use std::path::{Path, PathBuf};

// ─── MockToken ───────────────────────────────────────────────────────────────

/// A minimal token double used only by these tests, so `allowlist-token`'s
/// unit tests don't depend on any particular real SEP-41 implementation.
#[contract]
struct MockToken;

#[contracttype]
enum MockKey {
    Balance(Address),
}

#[contractimpl]
impl MockToken {
    /// Test-only: credits `amount` to `to` without any auth check.
    pub fn mint(env: Env, to: Address, amount: i128) {
        let current = Self::balance(env.clone(), to.clone());
        env.storage()
            .instance()
            .set(&MockKey::Balance(to), &(current + amount));
    }

    pub fn balance(env: Env, id: Address) -> i128 {
        env.storage()
            .instance()
            .get(&MockKey::Balance(id))
            .unwrap_or(0)
    }

    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        let from_balance = Self::balance(env.clone(), from.clone());
        let to_balance = Self::balance(env.clone(), to.clone());
        env.storage()
            .instance()
            .set(&MockKey::Balance(from.clone()), &(from_balance - amount));
        env.storage()
            .instance()
            .set(&MockKey::Balance(to.clone()), &(to_balance + amount));
        env.storage().instance().set(&Symbol::new(&env, "last"), &(from, to, amount));
    }

    pub fn last_transfer(env: Env) -> Option<(Address, Address, i128)> {
        env.storage().instance().get(&Symbol::new(&env, "last"))
    }

    pub fn clawback(env: Env, from: Address, amount: i128) {
        env.storage()
            .instance()
            .set(&Symbol::new(&env, "clawback"), &(from, amount));
    }

    pub fn last_clawback(env: Env) -> Option<(Address, i128)> {
        env.storage().instance().get(&Symbol::new(&env, "clawback"))
    }
}

// ─── Setup helper ────────────────────────────────────────────────────────────

fn setup(env: &Env) -> (Address, Address, Address, AllowlistTokenClient<'_>) {
    env.mock_all_auths();
    let admin = Address::generate(env);
    let token_id = env.register(MockToken, ());
    let contract_id = env.register(AllowlistToken, ());
    let client = AllowlistTokenClient::new(env, &contract_id);
    client.initialize(&admin, &token_id);
    (admin, token_id, contract_id, client)
}

// ─── Budget baseline helpers ─────────────────────────────────────────────────

fn read_baseline(path: &Path, section: &str) -> (u64, u64) {
    let contents = std::fs::read_to_string(path).unwrap();
    let section_header = format!("[{section}]");
    let mut in_section = false;
    let mut cpu = None;
    let mut memory = None;

    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_section = trimmed == section_header;
            continue;
        }
        if !in_section {
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("cpu = ") {
            cpu = Some(value.parse::<u64>().unwrap());
        } else if let Some(value) = trimmed.strip_prefix("memory = ") {
            memory = Some(value.parse::<u64>().unwrap());
        }
    }

    let cpu = cpu.expect("missing cpu baseline");
    let memory = memory.expect("missing memory baseline");
    (cpu, memory)
}

fn baseline_path_for_manifest_dir(manifest_dir: PathBuf) -> PathBuf {
    manifest_dir.join("..").join("..").join("budget-baselines.toml")
}

fn assert_budget_within_threshold(measured: (u64, u64), baseline: (u64, u64), label: &str) {
    let (measured_cpu, measured_memory) = measured;
    let (baseline_cpu, baseline_memory) = baseline;
    let cpu_limit = (baseline_cpu as f64 * 1.10).ceil() as u64;
    let memory_limit = (baseline_memory as f64 * 1.10).ceil() as u64;

    assert!(
        measured_cpu <= cpu_limit,
        "{label} CPU regression: measured {measured_cpu}, baseline {baseline_cpu}, limit {cpu_limit}"
    );
    assert!(
        measured_memory <= memory_limit,
        "{label} memory regression: measured {measured_memory}, baseline {baseline_memory}, limit {memory_limit}"
    );
}

// ─── Delegated-signature helpers ─────────────────────────────────────────────

/// Ledger bound used by tests that don't exercise `valid_until_ledger`.
fn default_valid_until(env: &Env) -> u32 {
    env.ledger().sequence() + 1_000
}

fn delegated_message_bytes(
    env: &Env,
    target: &Address,
    nonce: u64,
    expiry: u64,
    valid_until_ledger: u32,
) -> Bytes {
    let mut message = Bytes::new(env);
    message.append(&Bytes::from_slice(env, b"allowlist-delegated-v2:"));
    let target_str = target.to_string().to_string();
    message.append(&Bytes::from_slice(env, target_str.as_bytes()));
    message.push_back(b':');
    message.append(&Bytes::from_slice(env, b"add_to_allowlist"));
    message.push_back(b':');
    let nonce_str = nonce.to_string();
    message.append(&Bytes::from_slice(env, nonce_str.as_bytes()));
    message.push_back(b':');
    let expiry_str = expiry.to_string();
    message.append(&Bytes::from_slice(env, expiry_str.as_bytes()));
    message.push_back(b':');
    let valid_until_str = valid_until_ledger.to_string();
    message.append(&Bytes::from_slice(env, valid_until_str.as_bytes()));
    message
}

/// Sign with the default ledger bound (`default_valid_until`).
fn sign_delegated_action(
    env: &Env,
    signing_key: &SigningKey,
    target: &Address,
    nonce: u64,
    expiry: u64,
) -> BytesN<64> {
    sign_delegated_action_until(env, signing_key, target, nonce, expiry, default_valid_until(env))
}

fn sign_delegated_action_until(
    env: &Env,
    signing_key: &SigningKey,
    target: &Address,
    nonce: u64,
    expiry: u64,
    valid_until_ledger: u32,
) -> BytesN<64> {
    let message = delegated_message_bytes(env, target, nonce, expiry, valid_until_ledger);
    let sig = signing_key.sign(&message).unwrap();
    BytesN::from_array(env, &sig)
}

fn delegated_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[
        0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
        23, 24, 25, 26, 27, 28, 29, 30, 31,
    ])
}

// ─── Existing unit tests ──────────────────────────────────────────────────────

#[test]
fn test_initialize_and_allowlist_roundtrip() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);

    assert!(!client.is_allowed(&alice));
    client.add_to_allowlist(&admin, &alice, &None);
    assert!(client.is_allowed(&alice));
    client.remove_from_allowlist(&admin, &alice);
    assert!(!client.is_allowed(&alice));
}

#[test]
fn test_multiple_allowlist_operations() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    let addresses = vec![&env, alice.clone(), bob.clone()];

    client.add_multiple_to_allowlist(&admin, &addresses, &None);
    assert!(client.is_allowed(&alice));
    assert!(client.is_allowed(&bob));

    client.remove_multiple_from_allowlist(&admin, &addresses);
    assert!(!client.is_allowed(&alice));
    assert!(!client.is_allowed(&bob));
}

#[test]
fn test_multiple_allowlist_operations_reject_batches_over_limit() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let mut addresses = Vec::new(&env);
    for _ in 0..=MAX_BATCH_SIZE {
        addresses.push_back(Address::generate(&env));
    }

    assert_eq!(
        client.try_add_multiple_to_allowlist(&admin, &addresses, &None),
        Err(Ok(Error::BatchTooLarge))
    );
    assert_eq!(
        client.try_remove_multiple_from_allowlist(&admin, &addresses),
        Err(Ok(Error::BatchTooLarge))
    );
}

#[test]
fn test_multiple_allowlist_operations_reject_non_admin() {
    let env = Env::default();
    let (_admin, _token_id, _contract_id, client) = setup(&env);
    let impostor = Address::generate(&env);
    let addresses = vec![&env, Address::generate(&env)];

    assert_eq!(
        client.try_add_multiple_to_allowlist(&impostor, &addresses, &None),
        Err(Ok(Error::NotAuthorized))
    );
    assert_eq!(
        client.try_remove_multiple_from_allowlist(&impostor, &addresses),
        Err(Ok(Error::NotAuthorized))
    );
}

#[test]
fn test_transfer_forwards_to_underlying_token_when_both_allowlisted() {
    let env = Env::default();
    let (admin, token_id, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);

    client.add_to_allowlist(&admin, &alice, &None);
    client.add_to_allowlist(&admin, &bob, &None);

    let ok = client.transfer(&alice, &bob, &500);
    assert!(ok);

    let token_client = MockTokenClient::new(&env, &token_id);
    let last = token_client.last_transfer().unwrap();
    assert_eq!(last, (alice, bob, 500));
}

#[test]
fn test_budget_regression_allowlist_transfer() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);

    client.add_to_allowlist(&admin, &alice, &None);
    client.add_to_allowlist(&admin, &bob, &None);

    let mut budget = env.cost_estimate().budget();
    budget.reset_default();
    let ok = client.transfer(&alice, &bob, &500);
    assert!(ok);

    let measured = (budget.cpu_instruction_cost(), budget.memory_bytes_cost());
    let baseline_path = baseline_path_for_manifest_dir(PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()));
    let baseline = read_baseline(&baseline_path, "allowlist-token.transfer");
    assert_budget_within_threshold(measured, baseline, "allowlist-token transfer");
}

#[test]
fn test_budget_regression_allowlist_add_to_allowlist() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);

    let mut budget = env.cost_estimate().budget();
    budget.reset_default();
    client.add_to_allowlist(&admin, &alice, &None);

    let measured = (budget.cpu_instruction_cost(), budget.memory_bytes_cost());
    let baseline_path = baseline_path_for_manifest_dir(PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()));
    let baseline = read_baseline(&baseline_path, "allowlist-token.add_to_allowlist");
    assert_budget_within_threshold(measured, baseline, "allowlist-token add_to_allowlist");
}

#[test]
fn test_budget_regression_allowlist_add_to_allowlist_delegated() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let signing_key = delegated_signing_key();
    let pubkey = BytesN::from_array(&env, &signing_key.verifying_key().to_bytes());
    client.set_delegated_admin_key(&admin, &pubkey);

    let expiry = env.ledger().timestamp() + 60;
    let signature = sign_delegated_action(&env, &signing_key, &alice, 1, expiry);

    let mut budget = env.cost_estimate().budget();
    budget.reset_default();
    client.add_to_allowlist_delegated(&admin, &alice, &1u64, &expiry, &default_valid_until(&env), &signature);

    let measured = (budget.cpu_instruction_cost(), budget.memory_bytes_cost());
    let baseline_path = baseline_path_for_manifest_dir(PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()));
    let baseline = read_baseline(&baseline_path, "allowlist-token.add_to_allowlist_delegated");
    assert_budget_within_threshold(measured, baseline, "allowlist-token add_to_allowlist_delegated");
}

/// The delegated path (ed25519 verification plus nonce/pubkey storage access)
/// must cost more CPU than the direct-auth baseline it is compared against.
#[test]
fn test_delegated_add_costs_more_cpu_than_direct_add() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    let signing_key = delegated_signing_key();
    let pubkey = BytesN::from_array(&env, &signing_key.verifying_key().to_bytes());
    client.set_delegated_admin_key(&admin, &pubkey);

    let expiry = env.ledger().timestamp() + 60;
    let signature = sign_delegated_action(&env, &signing_key, &bob, 1, expiry);

    let mut budget = env.cost_estimate().budget();
    budget.reset_default();
    client.add_to_allowlist(&admin, &alice, &None);
    let direct_cpu = budget.cpu_instruction_cost();

    budget.reset_default();
    client.add_to_allowlist_delegated(&admin, &bob, &1u64, &expiry, &default_valid_until(&env), &signature);
    let delegated_cpu = budget.cpu_instruction_cost();

    assert!(
        delegated_cpu > direct_cpu,
        "delegated add ({delegated_cpu} cpu) should cost more than direct add ({direct_cpu} cpu)"
    );
}

#[test]
fn test_transfer_blocked_when_recipient_not_allowlisted() {
    let env = Env::default();
    let (admin, _token_id, contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);

    client.add_to_allowlist(&admin, &alice, &None);

    let ok = client.transfer(&alice, &bob, &500);
    assert!(!ok);

    // `assert_events_eq` pretty-prints both the actual and expected events on
    // mismatch instead of a single-line raw XDR dump.
    compliance_test_trace::assert_events_eq(
        &env,
        &env.events().all(),
        &vec![
            &env,
            (
                contract_id.clone(),
                (Symbol::new(&env, "allow_add"), alice.clone()).into_val(&env),
                Map::<Symbol, Val>::new(&env).into_val(&env),
            ),
            (
                contract_id.clone(),
                (symbol_short!("blocked"), alice.clone(), bob.clone()).into_val(&env),
                Map::<Symbol, Val>::from_array(&env, [(symbol_short!("amount"), 500i128.into_val(&env))])
                    .into_val(&env),
            ),
        ],
    );
}

#[test]
fn test_add_to_allowlist_rejects_non_admin() {
    let env = Env::default();
    let (_admin, _token_id, _contract_id, client) = setup(&env);
    let impostor = Address::generate(&env);
    let alice = Address::generate(&env);

    let result = client.try_add_to_allowlist(&impostor, &alice, &None);
    assert_eq!(result, Err(Ok(Error::NotAuthorized)));
    assert!(!client.is_allowed(&alice));
}

#[test]
fn test_non_admin_allowlist_mutations_rejected_end_to_end() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let impostor = Address::generate(&env);
    let alice = Address::generate(&env);

    let add_result = client.try_add_to_allowlist(&impostor, &alice, &None);
    assert_eq!(add_result, Err(Ok(Error::NotAuthorized)));
    assert!(!client.is_allowed(&alice));

    client.add_to_allowlist(&admin, &alice, &None);
    assert!(client.is_allowed(&alice));

    let remove_result = client.try_remove_from_allowlist(&impostor, &alice);
    assert_eq!(remove_result, Err(Ok(Error::NotAuthorized)));
    assert!(client.is_allowed(&alice));
}

#[test]
fn test_pause_blocks_allowlist_mutations_but_allows_admin_rotation() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let next_admin = Address::generate(&env);

    client.add_to_allowlist(&admin, &alice);
    client.pause(&admin);

    assert_eq!(
        client.try_add_to_allowlist(&admin, &Address::generate(&env)),
        Err(Ok(Error::ContractPaused))
    );
    assert_eq!(
        client.try_remove_from_allowlist(&admin, &alice),
        Err(Ok(Error::ContractPaused))
    );
    assert!(client.is_allowed(&alice));

    client.propose_admin(&admin, &next_admin);
    client.accept_admin(&next_admin);
    assert_eq!(client.get_admin(), next_admin);
}

#[test]
fn test_delegated_add_to_allowlist_succeeds() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let signing_key = SigningKey::from_bytes(&[
        0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
        23, 24, 25, 26, 27, 28, 29, 30, 31,
    ]);
    let pubkey = BytesN::from_array(&env, &signing_key.verifying_key().to_bytes());

    client.set_delegated_admin_key(&admin, &pubkey);

    let expiry = env.ledger().timestamp() + 60;
    let signature = sign_delegated_action(&env, &signing_key, &alice, 1, expiry);

    client.add_to_allowlist_delegated(&admin, &alice, &1u64, &expiry, &default_valid_until(&env), &signature);
    assert!(client.is_allowed(&alice));
}

#[test]
fn test_delegated_add_to_allowlist_rejects_replay() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let signing_key = SigningKey::from_bytes(&[
        0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
        23, 24, 25, 26, 27, 28, 29, 30, 31,
    ]);
    let pubkey = BytesN::from_array(&env, &signing_key.verifying_key().to_bytes());

    client.set_delegated_admin_key(&admin, &pubkey);

    let expiry = env.ledger().timestamp() + 60;
    let signature = sign_delegated_action(&env, &signing_key, &alice, 1, expiry);

    client.add_to_allowlist_delegated(&admin, &alice, &1u64, &expiry, &default_valid_until(&env), &signature);
    let replay = client.try_add_to_allowlist_delegated(&admin, &alice, &1u64, &expiry, &default_valid_until(&env), &signature);
    assert_eq!(replay, Err(Ok(Error::InvalidNonce)));
    assert!(client.is_allowed(&alice));
}

#[test]
fn test_delegated_add_to_allowlist_rejects_expired_signature() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let signing_key = SigningKey::from_bytes(&[
        0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
        23, 24, 25, 26, 27, 28, 29, 30, 31,
    ]);
    let pubkey = BytesN::from_array(&env, &signing_key.verifying_key().to_bytes());

    client.set_delegated_admin_key(&admin, &pubkey);

    env.ledger().set_timestamp(100);
    let expiry = 99u64;
    let signature = sign_delegated_action(&env, &signing_key, &alice, 1, expiry);

    let result = client.try_add_to_allowlist_delegated(&admin, &alice, &1u64, &expiry, &default_valid_until(&env), &signature);
    assert_eq!(result, Err(Ok(Error::ExpiredSignature)));
    assert!(!client.is_allowed(&alice));
}

#[test]
fn test_delegated_add_to_allowlist_rejects_non_admin_key() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let signing_key = SigningKey::from_bytes(&[
        0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
        23, 24, 25, 26, 27, 28, 29, 30, 31,
    ]);
    let attacker_key = SigningKey::from_bytes(&[
        32u8, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53,
        54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
    ]);
    let pubkey = BytesN::from_array(&env, &signing_key.verifying_key().to_bytes());

    client.set_delegated_admin_key(&admin, &pubkey);

    let expiry = env.ledger().timestamp() + 60;
    let signature = sign_delegated_action(&env, &attacker_key, &alice, 1, expiry);

    let result = client.try_add_to_allowlist_delegated(&admin, &alice, &1u64, &expiry, &default_valid_until(&env), &signature);
    assert_eq!(result, Err(Ok(Error::NotAuthorized)));
    assert!(!client.is_allowed(&alice));
}

#[test]
fn test_remove_from_allowlist_never_added_is_noop() {
    let env = Env::default();
    let (admin, _token_id, contract_id, client) = setup(&env);
    let never_added = Address::generate(&env);

    assert!(!client.is_allowed(&never_added));

    client.remove_from_allowlist(&admin, &never_added);

    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                contract_id.clone(),
                (Symbol::new(&env, "allow_remove"), never_added.clone()).into_val(&env),
                Map::<Symbol, Val>::new(&env).into_val(&env),
            ),
        ]
    );
    assert!(!client.is_allowed(&never_added));
}

#[test]
fn test_is_allowed_false_before_initialize() {
    let env = Env::default();
    let contract_id = env.register(AllowlistToken, ());
    let client = AllowlistTokenClient::new(&env, &contract_id);
    let alice = Address::generate(&env);

    assert!(!client.is_allowed(&alice));
}

#[test]
fn test_get_admin_returns_initialized_admin() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);

    assert_eq!(client.get_admin(), admin);
}

#[test]
fn test_get_admin_tracks_admin_transfer() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let new_admin = Address::generate(&env);

    assert_eq!(client.get_admin(), admin);
    client.transfer_admin(&admin, &new_admin);
    assert_eq!(client.get_admin(), new_admin);
}

#[test]
fn test_get_admin_fails_before_initialize() {
    let env = Env::default();
    let contract_id = env.register(AllowlistToken, ());
    let client = AllowlistTokenClient::new(&env, &contract_id);

    let result = client.try_get_admin();
    assert_eq!(result, Err(Ok(Error::NotInitialized)));
}

#[test]
fn test_double_initialize_fails() {
    let env = Env::default();
    let (admin, token_id, _contract_id, client) = setup(&env);
    let result = client.try_initialize(&admin, &token_id);
    assert_eq!(result, Err(Ok(Error::AlreadyInitialized)));
}

#[test]
fn test_add_to_allowlist_emits_allow_add_event() {
    let env = Env::default();
    let (admin, _token_id, contract_id, client) = setup(&env);
    let alice = Address::generate(&env);

    client.add_to_allowlist(&admin, &alice, &None);

    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                contract_id.clone(),
                (Symbol::new(&env, "allow_add"), alice.clone()).into_val(&env),
                Map::<Symbol, Val>::new(&env).into_val(&env),
            ),
        ]
    );
}

#[test]
fn test_remove_from_allowlist_emits_allow_remove_event() {
    let env = Env::default();
    let (admin, _token_id, contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    client.add_to_allowlist(&admin, &alice, &None);

    client.remove_from_allowlist(&admin, &alice);

    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                contract_id.clone(),
                (Symbol::new(&env, "allow_add"), alice.clone()).into_val(&env),
                Map::<Symbol, Val>::new(&env).into_val(&env),
            ),
            (
                contract_id.clone(),
                (Symbol::new(&env, "allow_remove"), alice.clone()).into_val(&env),
                Map::<Symbol, Val>::new(&env).into_val(&env),
            ),
        ]
    );
}

#[test]
fn test_add_to_allowlist_extends_persistent_ttl() {
    use soroban_sdk::testutils::storage::Persistent as _;
    use soroban_sdk::testutils::Ledger;

    let env = Env::default();
    env.ledger().with_mut(|li| {
        li.sequence_number = 100_000;
        li.min_persistent_entry_ttl = 500;
        li.max_entry_ttl = 6_311_520;
    });

    let (admin, _token_id, contract_id, client) = setup(&env);
    let alice = Address::generate(&env);

    client.add_to_allowlist(&admin, &alice, &None);

    env.as_contract(&contract_id, || {
        let ttl = env
            .storage()
            .persistent()
            .get_ttl(&DataKey::Allowed(alice.clone()));
        assert_eq!(
            ttl, ALLOWED_TTL_EXTEND_TO,
            "fresh allowlist write should bump TTL to ALLOWED_TTL_EXTEND_TO"
        );
    });

    // Advance far enough that remaining TTL falls below the threshold, then
    // re-add and confirm extension runs again.
    env.ledger().with_mut(|li| {
        li.sequence_number += ALLOWED_TTL_EXTEND_TO - ALLOWED_TTL_THRESHOLD + 1;
    });
    env.as_contract(&contract_id, || {
        let ttl = env
            .storage()
            .persistent()
            .get_ttl(&DataKey::Allowed(alice.clone()));
        assert!(
            ttl < ALLOWED_TTL_THRESHOLD,
            "TTL should be below threshold after ledger bump, got {ttl}"
        );
    });

    client.add_to_allowlist(&admin, &alice, &None);
    env.as_contract(&contract_id, || {
        let ttl = env
            .storage()
            .persistent()
            .get_ttl(&DataKey::Allowed(alice.clone()));
        assert_eq!(ttl, ALLOWED_TTL_EXTEND_TO);
    });
}

#[test]
fn test_transfers_keep_allowlist_entries_live_past_original_ttl() {
    use soroban_sdk::testutils::storage::Persistent as _;

    let env = Env::default();
    env.ledger().with_mut(|li| {
        li.sequence_number = 100_000;
        li.min_persistent_entry_ttl = 500;
        li.max_entry_ttl = 6_311_520;
    });

    let (admin, _token_id, contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    client.add_to_allowlist(&admin, &alice);
    client.add_to_allowlist(&admin, &bob);

    let transfer_interval = ALLOWED_TTL_EXTEND_TO - ALLOWED_TTL_THRESHOLD + 1;
    for _ in 0..3 {
        env.ledger().with_mut(|li| li.sequence_number += transfer_interval);
        assert!(client.transfer(&alice, &bob, &1));
        env.as_contract(&contract_id, || {
            for address in [&alice, &bob] {
                let ttl = env
                    .storage()
                    .persistent()
                    .get_ttl(&DataKey::Allowed(address.clone()));
                assert_eq!(ttl, ALLOWED_TTL_EXTEND_TO);
            }
        });
    }

    assert!(client.is_allowed(&alice));
    assert!(client.is_allowed(&bob));
}

/// Property: after any sequence of add/remove on a fixed address pool,
/// `is_allowed(addr)` matches whether the last op touching `addr` was an add.
#[test]
fn prop_allowlist_add_remove_last_write_wins() {
    use proptest::prelude::*;
    use proptest::test_runner::{Config, TestRunner};

    #[derive(Clone, Debug)]
    enum Op {
        Add(usize),
        Remove(usize),
    }

    let mut runner = TestRunner::new(Config {
        cases: 64,
        max_shrink_iters: 100,
        ..Config::default()
    });

    runner
        .run(
            &(1usize..32).prop_flat_map(|len| {
                proptest::collection::vec(
                    (0usize..4).prop_flat_map(|addr_i| {
                        proptest::bool::ANY.prop_map(move |is_add| {
                            if is_add {
                                Op::Add(addr_i)
                            } else {
                                Op::Remove(addr_i)
                            }
                        })
                    }),
                    len,
                )
            }),
            |ops| {
                let env = Env::default();
                let (admin, _token_id, _contract_id, client) = setup(&env);
                let addresses: [Address; 4] = [
                    Address::generate(&env),
                    Address::generate(&env),
                    Address::generate(&env),
                    Address::generate(&env),
                ];
                let mut model = [false; 4];

                for op in &ops {
                    match *op {
                        Op::Add(i) => {
                            client.add_to_allowlist(&admin, &addresses[i], &None);
                            model[i] = true;
                        }
                        Op::Remove(i) => {
                            client.remove_from_allowlist(&admin, &addresses[i]);
                            model[i] = false;
                        }
                    }
                }

                for (i, address) in addresses.iter().enumerate() {
                    prop_assert_eq!(
                        client.is_allowed(address),
                        model[i],
                        "addr {} mismatch after {:?}",
                        i,
                        ops
                    );
                }
                Ok(())
            },
        )
        .unwrap();
}

// ─── Compliance officer (#357) ───────────────────────────────────────────────

#[test]
fn test_officer_can_remove_from_allowlist_after_assignment() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let officer = Address::generate(&env);
    let alice = Address::generate(&env);

    client.add_to_allowlist(&admin, &alice, &None);
    client.set_compliance_officer(&admin, &officer);

    client.remove_from_allowlist(&officer, &alice);
    assert!(!client.is_allowed(&alice));
}

#[test]
fn test_officer_cannot_assign_or_revoke_officer_role() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let officer = Address::generate(&env);
    let other = Address::generate(&env);

    client.set_compliance_officer(&admin, &officer);

    assert_eq!(
        client.try_set_compliance_officer(&officer, &other),
        Err(Ok(Error::NotAuthorized))
    );
    assert_eq!(
        client.try_revoke_compliance_officer(&officer),
        Err(Ok(Error::NotAuthorized))
    );
}

#[test]
fn test_officer_cannot_add_to_allowlist() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let officer = Address::generate(&env);
    let alice = Address::generate(&env);

    client.set_compliance_officer(&admin, &officer);

    assert_eq!(
        client.try_add_to_allowlist(&officer, &alice, &None),
        Err(Ok(Error::NotAuthorized))
    );
    assert!(!client.is_allowed(&alice));
}

#[test]
fn test_revoked_officer_can_no_longer_remove_from_allowlist() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let officer = Address::generate(&env);
    let alice = Address::generate(&env);

    client.add_to_allowlist(&admin, &alice, &None);
    client.set_compliance_officer(&admin, &officer);
    client.revoke_compliance_officer(&admin);

    assert_eq!(
        client.try_remove_from_allowlist(&officer, &alice),
        Err(Ok(Error::NotAuthorized))
    );
    assert!(client.is_allowed(&alice));
}

// ─── Role / key change events (#750) ─────────────────────────────────────────

#[test]
fn test_set_compliance_officer_emits_event_with_previous() {
    let env = Env::default();
    let (admin, _token_id, contract_id, client) = setup(&env);
    let first = Address::generate(&env);
    let second = Address::generate(&env);

    client.set_compliance_officer(&admin, &first);
    let events = env.events().all();
    let (id, topics, data) = events.last().unwrap();
    assert_eq!(id, contract_id);
    assert_eq!(
        topics,
        (
            Symbol::new(&env, "compliance_officer_set"),
            admin.clone(),
            first.clone(),
        )
            .into_val(&env)
    );
    assert_eq!(
        data,
        Map::<Symbol, Val>::from_array(
            &env,
            [(
                Symbol::new(&env, "previous"),
                Option::<Address>::None.into_val(&env),
            )],
        )
        .into_val(&env)
    );

    client.set_compliance_officer(&admin, &second);
    let events = env.events().all();
    let (id, topics, data) = events.last().unwrap();
    assert_eq!(id, contract_id);
    assert_eq!(
        topics,
        (
            Symbol::new(&env, "compliance_officer_set"),
            admin.clone(),
            second.clone(),
        )
            .into_val(&env)
    );
    assert_eq!(
        data,
        Map::<Symbol, Val>::from_array(
            &env,
            [(Symbol::new(&env, "previous"), Some(first).into_val(&env))],
        )
        .into_val(&env)
    );
}

#[test]
fn test_revoke_compliance_officer_emits_event_with_previous() {
    let env = Env::default();
    let (admin, _token_id, contract_id, client) = setup(&env);
    let officer = Address::generate(&env);
    client.set_compliance_officer(&admin, &officer);

    client.revoke_compliance_officer(&admin);

    let events = env.events().all();
    let (id, topics, data) = events.last().unwrap();
    assert_eq!(id, contract_id);
    assert_eq!(
        topics,
        (Symbol::new(&env, "compliance_officer_revoked"), admin.clone()).into_val(&env)
    );
    assert_eq!(
        data,
        Map::<Symbol, Val>::from_array(
            &env,
            [(Symbol::new(&env, "previous"), Some(officer).into_val(&env))],
        )
        .into_val(&env)
    );
}

#[test]
fn test_revoke_compliance_officer_without_officer_emits_none_previous() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);

    client.revoke_compliance_officer(&admin);

    let events = env.events().all();
    let (_, topics, data) = events.last().unwrap();
    assert_eq!(
        topics,
        (Symbol::new(&env, "compliance_officer_revoked"), admin).into_val(&env)
    );
    assert_eq!(
        data,
        Map::<Symbol, Val>::from_array(
            &env,
            [(
                Symbol::new(&env, "previous"),
                Option::<Address>::None.into_val(&env),
            )],
        )
        .into_val(&env)
    );
}

#[test]
fn test_set_delegated_admin_key_emits_event_with_old_and_new_key() {
    let env = Env::default();
    let (admin, _token_id, contract_id, client) = setup(&env);
    let first = BytesN::from_array(&env, &[1; 32]);
    let second = BytesN::from_array(&env, &[2; 32]);

    client.set_delegated_admin_key(&admin, &first);
    let events = env.events().all();
    let (id, topics, data) = events.last().unwrap();
    assert_eq!(id, contract_id);
    assert_eq!(
        topics,
        (Symbol::new(&env, "delegated_admin_key_set"), admin.clone()).into_val(&env)
    );
    assert_eq!(
        data,
        Map::<Symbol, Val>::from_array(
            &env,
            [
                (
                    Symbol::new(&env, "previous"),
                    Option::<BytesN<32>>::None.into_val(&env),
                ),
                (Symbol::new(&env, "pubkey"), first.clone().into_val(&env)),
            ],
        )
        .into_val(&env)
    );

    client.set_delegated_admin_key(&admin, &second);
    let events = env.events().all();
    let (_, topics, data) = events.last().unwrap();
    assert_eq!(
        topics,
        (Symbol::new(&env, "delegated_admin_key_set"), admin).into_val(&env)
    );
    assert_eq!(
        data,
        Map::<Symbol, Val>::from_array(
            &env,
            [
                (Symbol::new(&env, "previous"), Some(first).into_val(&env)),
                (Symbol::new(&env, "pubkey"), second.into_val(&env)),
            ],
        )
        .into_val(&env)
    );
}

// ─── Pause / unpause / is_paused (#358) ──────────────────────────────────────

#[test]
fn test_transfer_blocked_while_paused_and_succeeds_after_unpause() {
    let env = Env::default();
    let (admin, token_id, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    client.add_to_allowlist(&admin, &alice, &None);
    client.add_to_allowlist(&admin, &bob, &None);

    assert!(!client.is_paused());
    client.pause(&admin);
    assert!(client.is_paused());
    assert_eq!(
        client.try_transfer(&alice, &bob, &10),
        Err(Ok(Error::ContractPaused))
    );

    client.unpause(&admin);
    assert!(!client.is_paused());
    assert!(client.transfer(&alice, &bob, &10));
    let token = MockTokenClient::new(&env, &token_id);
    assert_eq!(token.last_transfer(), Some((alice, bob, 10)));
}

/// Pause blocks add/remove so a paused contract's allowlist stays frozen.
/// Admin rotation and unpause remain available (regression test for #583).
#[test]
fn test_pause_blocks_add_to_allowlist() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let bob = Address::generate(&env);

    client.pause(&admin);

    assert_eq!(
        client.try_add_to_allowlist(&admin, &bob, &None),
        Err(Ok(Error::ContractPaused))
    );
    assert!(!client.is_allowed(&bob));
}

#[test]
fn test_pause_blocks_remove_from_allowlist() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    client.add_to_allowlist(&admin, &alice, &None);

    client.pause(&admin);

    assert_eq!(
        client.try_remove_from_allowlist(&admin, &alice),
        Err(Ok(Error::ContractPaused))
    );
    // Entry must still be there — the allowlist must stay frozen.
    assert!(client.is_allowed(&alice));
}

#[test]
fn test_pause_blocks_remove_multiple_from_allowlist() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    client.add_multiple_to_allowlist(&admin, &vec![&env, alice.clone(), bob.clone()], &None);

    client.pause(&admin);

    assert_eq!(
        client.try_remove_multiple_from_allowlist(&admin, &vec![&env, alice.clone(), bob.clone()]),
        Err(Ok(Error::ContractPaused))
    );
    // Entries must still be there — the allowlist must stay frozen.
    assert!(client.is_allowed(&alice));
    assert!(client.is_allowed(&bob));
}

#[test]
fn test_unpause_restores_allowlist_mutations() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let bob = Address::generate(&env);

    client.pause(&admin);
    client.unpause(&admin);

    // After unpause, mutations work again.
    client.add_to_allowlist(&admin, &bob, &None);
    assert!(client.is_allowed(&bob));
}

#[test]
fn test_admin_rotation_works_while_paused() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let new_admin = Address::generate(&env);

    client.pause(&admin);
    // propose_admin / accept_admin must succeed while paused so a compromised
    // key can always be rotated out.
    client.propose_admin(&admin, &new_admin);
    client.accept_admin(&new_admin);
    assert_eq!(client.get_admin(), new_admin);
}

#[test]
fn test_pause_and_unpause_reject_non_admin() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let impostor = Address::generate(&env);

    assert_eq!(client.try_pause(&impostor), Err(Ok(Error::NotAuthorized)));
    assert!(!client.is_paused());

    client.pause(&admin);
    assert_eq!(client.try_unpause(&impostor), Err(Ok(Error::NotAuthorized)));
    assert!(client.is_paused());
}

// ─── get_delegated_nonce (#359) ──────────────────────────────────────────────

#[test]
fn test_get_delegated_nonce_is_zero_before_any_delegated_call() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);

    assert_eq!(client.get_delegated_nonce(&admin), 0);
}

#[test]
fn test_get_delegated_nonce_returns_last_used_nonce() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    let signing_key = delegated_signing_key();
    let pubkey = BytesN::from_array(&env, &signing_key.verifying_key().to_bytes());
    client.set_delegated_admin_key(&admin, &pubkey);

    let expiry = env.ledger().timestamp() + 60;
    let signature = sign_delegated_action(&env, &signing_key, &alice, 7, expiry);
    client.add_to_allowlist_delegated(&admin, &alice, &7u64, &expiry, &default_valid_until(&env), &signature);

    assert_eq!(client.get_delegated_nonce(&admin), 7);
}

#[test]
fn test_proposal_lifecycle_events_include_payloads() {
    let env = Env::default();
    let (admin, _token_id, contract_id, client) = setup(&env);
    let proposed_admin = Address::generate(&env);
    let new_wasm = BytesN::from_array(&env, &[7; 32]);
    let activated_at = u64::from(env.ledger().sequence()) + 10;

    client.propose_admin(&admin, &proposed_admin);
    client.propose_upgrade(&admin, &new_wasm, &10);

    compliance_test_trace::assert_events_eq(
        &env,
        &env.events().all(),
        &vec![
            &env,
            (
                contract_id.clone(),
                (
                    Symbol::new(&env, "admin_proposed"),
                    admin.clone(),
                    proposed_admin.clone(),
                )
                    .into_val(&env),
                Map::<Symbol, Val>::new(&env).into_val(&env),
            ),
            (
                contract_id,
                (Symbol::new(&env, "upgrade_proposed"), admin.clone()).into_val(&env),
                Map::<Symbol, Val>::from_array(
                    &env,
                    [
                        (Symbol::new(&env, "activated_at"), activated_at.into_val(&env)),
                        (Symbol::new(&env, "new_wasm"), new_wasm.into_val(&env)),
                    ],
                )
                .into_val(&env),
            ),
        ],
    );
}

#[test]
fn test_upgrade_cancel_event_includes_admin() {
    let env = Env::default();
    let (admin, _token_id, contract_id, client) = setup(&env);
    let new_wasm = BytesN::from_array(&env, &[9; 32]);
    client.propose_upgrade(&admin, &new_wasm, &10);

    client.cancel_upgrade(&admin);

    let events = env.events().all();
    let (_, topics, data) = events.last().unwrap();
    assert_eq!(
        topics,
        (Symbol::new(&env, "upgrade_cancelled"), admin).into_val(&env)
    );
    assert_eq!(data, Map::<Symbol, Val>::new(&env).into_val(&env));
    assert_eq!(events.last().unwrap().0, contract_id);
}

// ─── Address freeze (#762) ───────────────────────────────────────────────────

fn setup_allowlisted_pair(
    env: &Env,
) -> (Address, Address, Address, Address, AllowlistTokenClient<'_>) {
    let (admin, token_id, _contract_id, client) = setup(env);
    let alice = Address::generate(env);
    let bob = Address::generate(env);
    client.add_to_allowlist(&admin, &alice, &None);
    client.add_to_allowlist(&admin, &bob, &None);
    (admin, token_id, alice, bob, client)
}

#[test]
fn test_freeze_keeps_allowlist_status() {
    let env = Env::default();
    let (admin, _token_id, alice, _bob, client) = setup_allowlisted_pair(&env);

    assert!(!client.is_frozen(&alice));
    client.freeze(&admin, &alice);
    assert!(client.is_frozen(&alice));
    assert!(client.is_allowed(&alice));

    client.unfreeze(&admin, &alice);
    assert!(!client.is_frozen(&alice));
    assert!(client.is_allowed(&alice));
}

#[test]
fn test_frozen_sender_cannot_transfer() {
    let env = Env::default();
    let (admin, token_id, alice, bob, client) = setup_allowlisted_pair(&env);

    client.freeze(&admin, &alice);
    assert_eq!(
        client.try_transfer(&alice, &bob, &10),
        Err(Ok(Error::AddressFrozen))
    );
    assert_eq!(MockTokenClient::new(&env, &token_id).last_transfer(), None);
}

#[test]
fn test_frozen_recipient_cannot_receive() {
    let env = Env::default();
    let (admin, token_id, alice, bob, client) = setup_allowlisted_pair(&env);

    client.freeze(&admin, &bob);
    assert_eq!(
        client.try_transfer(&alice, &bob, &10),
        Err(Ok(Error::AddressFrozen))
    );
    assert_eq!(MockTokenClient::new(&env, &token_id).last_transfer(), None);
}

#[test]
fn test_unfreeze_restores_transfers() {
    let env = Env::default();
    let (admin, token_id, alice, bob, client) = setup_allowlisted_pair(&env);

    client.freeze(&admin, &alice);
    client.unfreeze(&admin, &alice);

    assert!(client.transfer(&alice, &bob, &10));
    assert_eq!(
        MockTokenClient::new(&env, &token_id).last_transfer(),
        Some((alice, bob, 10))
    );
}

#[test]
fn test_officer_can_freeze_and_unfreeze() {
    let env = Env::default();
    let (admin, _token_id, alice, _bob, client) = setup_allowlisted_pair(&env);
    let officer = Address::generate(&env);
    client.set_compliance_officer(&admin, &officer);

    client.freeze(&officer, &alice);
    assert!(client.is_frozen(&alice));
    client.unfreeze(&officer, &alice);
    assert!(!client.is_frozen(&alice));
}

#[test]
fn test_freeze_rejects_unauthorized_caller() {
    let env = Env::default();
    let (_admin, _token_id, alice, _bob, client) = setup_allowlisted_pair(&env);
    let stranger = Address::generate(&env);

    assert_eq!(
        client.try_freeze(&stranger, &alice),
        Err(Ok(Error::NotAuthorized))
    );
    assert_eq!(
        client.try_unfreeze(&stranger, &alice),
        Err(Ok(Error::NotAuthorized))
    );
    assert!(!client.is_frozen(&alice));
}

#[test]
fn test_revoked_officer_cannot_freeze() {
    let env = Env::default();
    let (admin, _token_id, alice, _bob, client) = setup_allowlisted_pair(&env);
    let officer = Address::generate(&env);
    client.set_compliance_officer(&admin, &officer);
    client.revoke_compliance_officer(&admin);

    assert_eq!(
        client.try_freeze(&officer, &alice),
        Err(Ok(Error::NotAuthorized))
    );
}

#[test]
fn test_freeze_blocked_while_paused() {
    let env = Env::default();
    let (admin, _token_id, alice, _bob, client) = setup_allowlisted_pair(&env);
    client.pause(&admin);

    assert_eq!(
        client.try_freeze(&admin, &alice),
        Err(Ok(Error::ContractPaused))
    );
    assert_eq!(
        client.try_unfreeze(&admin, &alice),
        Err(Ok(Error::ContractPaused))
    );
}

#[test]
fn test_freeze_and_unfreeze_emit_events() {
    let env = Env::default();
    let (admin, _token_id, contract_id, client) = setup(&env);
    let alice = Address::generate(&env);

    client.freeze(&admin, &alice);
    let events = env.events().all();
    let (id, topics, data) = events.last().unwrap();
    assert_eq!(id, contract_id);
    assert_eq!(
        topics,
        (Symbol::new(&env, "address_frozen"), admin.clone(), alice.clone()).into_val(&env)
    );
    assert_eq!(data, Map::<Symbol, Val>::new(&env).into_val(&env));

    client.unfreeze(&admin, &alice);
    let events = env.events().all();
    let (id, topics, data) = events.last().unwrap();
    assert_eq!(id, contract_id);
    assert_eq!(
        topics,
        (Symbol::new(&env, "address_unfrozen"), admin, alice).into_val(&env)
    );
    assert_eq!(data, Map::<Symbol, Val>::new(&env).into_val(&env));
}

// ─── Clawback (#763) ─────────────────────────────────────────────────────────

#[test]
fn test_admin_clawback_forwards_to_underlying_token() {
    let env = Env::default();
    let (admin, token_id, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);

    client.clawback(&admin, &alice, &25);
    assert_eq!(
        MockTokenClient::new(&env, &token_id).last_clawback(),
        Some((alice, 25))
    );
}

#[test]
fn test_clawback_emits_event() {
    let env = Env::default();
    let (admin, _token_id, contract_id, client) = setup(&env);
    let alice = Address::generate(&env);

    client.clawback(&admin, &alice, &25);

    let events = env.events().all();
    let (id, topics, data) = events.last().unwrap();
    assert_eq!(id, contract_id);
    assert_eq!(
        topics,
        (Symbol::new(&env, "clawback"), admin, alice).into_val(&env)
    );
    assert_eq!(
        data,
        Map::<Symbol, Val>::from_array(
            &env,
            [(Symbol::new(&env, "amount"), 25i128.into_val(&env))],
        )
        .into_val(&env)
    );
}

#[test]
fn test_clawback_rejects_non_admin() {
    let env = Env::default();
    let (admin, token_id, _contract_id, client) = setup(&env);
    let officer = Address::generate(&env);
    let alice = Address::generate(&env);
    client.set_compliance_officer(&admin, &officer);

    assert_eq!(
        client.try_clawback(&officer, &alice, &25),
        Err(Ok(Error::NotAuthorized))
    );
    assert_eq!(MockTokenClient::new(&env, &token_id).last_clawback(), None);
}

#[test]
fn test_clawback_rejects_non_positive_amount() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);

    assert_eq!(
        client.try_clawback(&admin, &alice, &0),
        Err(Ok(Error::InvalidInput))
    );
    assert_eq!(
        client.try_clawback(&admin, &alice, &-1),
        Err(Ok(Error::InvalidInput))
    );
}

#[test]
fn test_clawback_requires_freeze_when_enabled() {
    let env = Env::default();
    let (admin, token_id, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);

    assert!(!client.get_clawback_requires_freeze());
    client.set_clawback_requires_freeze(&admin, &true);
    assert!(client.get_clawback_requires_freeze());

    assert_eq!(
        client.try_clawback(&admin, &alice, &25),
        Err(Ok(Error::ClawbackRequiresFreeze))
    );
    assert_eq!(MockTokenClient::new(&env, &token_id).last_clawback(), None);

    client.freeze(&admin, &alice);
    client.clawback(&admin, &alice, &25);
    assert_eq!(
        MockTokenClient::new(&env, &token_id).last_clawback(),
        Some((alice, 25))
    );
}

#[test]
fn test_set_clawback_requires_freeze_rejects_non_admin() {
    let env = Env::default();
    let (_admin, _token_id, _contract_id, client) = setup(&env);
    let stranger = Address::generate(&env);

    assert_eq!(
        client.try_set_clawback_requires_freeze(&stranger, &true),
        Err(Ok(Error::NotAuthorized))
    );
    assert!(!client.get_clawback_requires_freeze());
}

#[test]
fn test_clawback_allowed_while_paused() {
    let env = Env::default();
    let (admin, token_id, _contract_id, client) = setup(&env);
    let alice = Address::generate(&env);
    client.pause(&admin);

    client.clawback(&admin, &alice, &5);
    assert_eq!(
        MockTokenClient::new(&env, &token_id).last_clawback(),
        Some((alice, 5))
    );
}

// ─── get_delegated_admin_key (#764) ──────────────────────────────────────────

#[test]
fn test_get_delegated_admin_key_returns_none_before_configuration() {
    let env = Env::default();
    let (_admin, _token_id, _contract_id, client) = setup(&env);
    assert_eq!(client.get_delegated_admin_key(), None);
}

#[test]
fn test_get_delegated_admin_key_returns_active_key() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);

    let first = BytesN::from_array(&env, &delegated_signing_key().verifying_key().to_bytes());
    client.set_delegated_admin_key(&admin, &first);
    assert_eq!(client.get_delegated_admin_key(), Some(first));

    let rotated = BytesN::from_array(&env, &[7u8; 32]);
    client.set_delegated_admin_key(&admin, &rotated);
    assert_eq!(client.get_delegated_admin_key(), Some(rotated));
}

// ─── Delegated signature ledger expiry (#765) ────────────────────────────────

fn setup_delegation(env: &Env) -> (Address, SigningKey, AllowlistTokenClient<'_>) {
    let (admin, _token_id, _contract_id, client) = setup(env);
    let signing_key = delegated_signing_key();
    let pubkey = BytesN::from_array(env, &signing_key.verifying_key().to_bytes());
    client.set_delegated_admin_key(&admin, &pubkey);
    (admin, signing_key, client)
}

#[test]
fn test_delegated_signature_accepted_up_to_valid_until_ledger() {
    let env = Env::default();
    let (admin, signing_key, client) = setup_delegation(&env);
    let alice = Address::generate(&env);
    env.ledger().set_sequence_number(500);
    let expiry = env.ledger().timestamp() + 60;
    let valid_until = 500u32;
    let signature = sign_delegated_action_until(&env, &signing_key, &alice, 1, expiry, valid_until);

    client.add_to_allowlist_delegated(&admin, &alice, &1u64, &expiry, &valid_until, &signature);
    assert!(client.is_allowed(&alice));
}

#[test]
fn test_delegated_signature_rejected_after_valid_until_ledger() {
    let env = Env::default();
    let (admin, signing_key, client) = setup_delegation(&env);
    let alice = Address::generate(&env);
    env.ledger().set_sequence_number(100);
    let expiry = env.ledger().timestamp() + 1_000_000;
    let valid_until = 200u32;
    let signature = sign_delegated_action_until(&env, &signing_key, &alice, 1, expiry, valid_until);

    // The leaked signature is submitted after its ledger window closed.
    env.ledger().set_sequence_number(201);
    let result = client.try_add_to_allowlist_delegated(
        &admin, &alice, &1u64, &expiry, &valid_until, &signature,
    );
    assert_eq!(result, Err(Ok(Error::ExpiredSignature)));
    assert!(!client.is_allowed(&alice));
}

#[test]
fn test_delegated_valid_until_ledger_is_bound_by_signature() {
    let env = Env::default();
    let (admin, signing_key, client) = setup_delegation(&env);
    let alice = Address::generate(&env);
    env.ledger().set_sequence_number(100);
    let expiry = env.ledger().timestamp() + 60;
    let signature = sign_delegated_action_until(&env, &signing_key, &alice, 1, expiry, 150);

    // A relayer cannot stretch the window by submitting a larger bound.
    let result = client.try_add_to_allowlist_delegated(
        &admin, &alice, &1u64, &expiry, &10_000u32, &signature,
    );
    assert_eq!(result, Err(Ok(Error::NotAuthorized)));
    assert!(!client.is_allowed(&alice));
}

#[test]
fn test_allowlist_count_tracks_only_real_state_changes() {
    let env = Env::default();
    let (admin, _token, _id, client) = setup(&env);
    let a = Address::generate(&env);
    let b = Address::generate(&env);

    assert_eq!(client.allowlist_count(), 0);

    client.add_to_allowlist(&admin, &a, &None);
    assert_eq!(client.allowlist_count(), 1);

    // Re-adding an existing address only changes its expiration.
    client.add_to_allowlist(&admin, &a, &Some(env.ledger().sequence() + 100));
    assert_eq!(client.allowlist_count(), 1);

    client.add_multiple_to_allowlist(&admin, &vec![&env, a.clone(), b.clone()], &None);
    assert_eq!(client.allowlist_count(), 2);

    client.remove_from_allowlist(&admin, &b);
    assert_eq!(client.allowlist_count(), 1);

    // Removing an address that is not listed is a no-op.
    client.remove_from_allowlist(&admin, &b);
    assert_eq!(client.allowlist_count(), 1);

    client.remove_multiple_from_allowlist(&admin, &vec![&env, a.clone(), b.clone()]);
    assert_eq!(client.allowlist_count(), 0);
}

#[test]
fn test_is_allowed_batch_returns_results_in_input_order() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let listed = Address::generate(&env);
    let unlisted = Address::generate(&env);
    client.add_to_allowlist(&admin, &listed, &None);

    let addresses = vec![&env, unlisted.clone(), listed.clone(), unlisted.clone()];
    assert_eq!(
        client.is_allowed_batch(&addresses),
        vec![&env, false, true, false]
    );
    assert_eq!(client.is_allowed_batch(&Vec::new(&env)), Vec::new(&env));
}

#[test]
fn test_is_allowed_batch_rejects_batches_over_limit() {
    let env = Env::default();
    let (_admin, _token_id, _contract_id, client) = setup(&env);
    let mut addresses = Vec::new(&env);
    for _ in 0..=MAX_BATCH_SIZE {
        addresses.push_back(Address::generate(&env));
    }

    assert_eq!(
        client.try_is_allowed_batch(&addresses),
        Err(Ok(Error::BatchTooLarge))
    );
}

// ─── Merkle allowlist helpers ────────────────────────────────────────────────

/// Mirrors the leaf encoding documented in `docs/allowlist-merkle-root.md`.
fn merkle_leaf(env: &Env, address: &Address) -> BytesN<32> {
    let address_str = address.to_string().to_string();
    let mut preimage = Bytes::from_slice(env, &[0x00]);
    preimage.append(&Bytes::from_slice(env, address_str.as_bytes()));
    env.crypto().sha256(&preimage).to_bytes()
}

/// Mirrors the sorted-pair node encoding documented in `docs/allowlist-merkle-root.md`.
fn merkle_node(env: &Env, a: &BytesN<32>, b: &BytesN<32>) -> BytesN<32> {
    let (lo, hi) = if a.to_array() <= b.to_array() {
        (a, b)
    } else {
        (b, a)
    };
    let mut preimage = Bytes::from_slice(env, &[0x01]);
    preimage.append(&Bytes::from_slice(env, &lo.to_array()));
    preimage.append(&Bytes::from_slice(env, &hi.to_array()));
    env.crypto().sha256(&preimage).to_bytes()
}

/// Builds a four-holder tree and returns its root, the holders, and each
/// holder's two-level proof.
fn build_four_leaf_tree(
    env: &Env,
) -> (BytesN<32>, [Address; 4], [Vec<BytesN<32>>; 4]) {
    let holders = [
        Address::generate(env),
        Address::generate(env),
        Address::generate(env),
        Address::generate(env),
    ];
    let l0 = merkle_leaf(env, &holders[0]);
    let l1 = merkle_leaf(env, &holders[1]);
    let l2 = merkle_leaf(env, &holders[2]);
    let l3 = merkle_leaf(env, &holders[3]);
    let n01 = merkle_node(env, &l0, &l1);
    let n23 = merkle_node(env, &l2, &l3);
    let root = merkle_node(env, &n01, &n23);
    let proofs = [
        vec![env, l1.clone(), n23.clone()],
        vec![env, l0.clone(), n23.clone()],
        vec![env, l3.clone(), n01.clone()],
        vec![env, l2.clone(), n01.clone()],
    ];
    (root, holders, proofs)
}

#[test]
fn test_max_balance_limits_recipient_balance() {
    let env = Env::default();
    let (admin, token_id, _contract_id, client) = setup(&env);
    let token = MockTokenClient::new(&env, &token_id);
    let sender = Address::generate(&env);
    let receiver = Address::generate(&env);
    client.add_multiple_to_allowlist(&admin, &vec![&env, sender.clone(), receiver.clone()], &None);
    token.mint(&sender, &500);
    token.mint(&receiver, &80);

    client.set_global_max_balance(&admin, &Some(100));
    assert_eq!(client.get_global_max_balance(), Some(100));

    // 80 + 20 = 100 is at the limit, so it is allowed.
    assert!(client.transfer(&sender, &receiver, &20));

    // 100 + 1 exceeds the limit.
    assert_eq!(
        client.try_transfer(&sender, &receiver, &1),
        Err(Ok(Error::MaxBalanceExceeded))
    );
    assert_eq!(token.balance(&receiver), 100);
}

#[test]
fn test_per_address_max_balance_is_stricter_when_both_apply() {
    let env = Env::default();
    let (admin, token_id, _contract_id, client) = setup(&env);
    let token = MockTokenClient::new(&env, &token_id);
    let sender = Address::generate(&env);
    let receiver = Address::generate(&env);
    client.add_multiple_to_allowlist(&admin, &vec![&env, sender.clone(), receiver.clone()], &None);
    token.mint(&sender, &500);

    client.set_global_max_balance(&admin, &Some(100));
    client.set_address_max_balance(&admin, &receiver, &Some(50));
    assert_eq!(client.get_address_max_balance(&receiver), Some(50));

    // The per-address limit (50) is stricter than the global one (100).
    assert_eq!(
        client.try_transfer(&sender, &receiver, &51),
        Err(Ok(Error::MaxBalanceExceeded))
    );
    assert!(client.transfer(&sender, &receiver, &50));

    // Clearing the per-address limit leaves only the global limit.
    client.set_address_max_balance(&admin, &receiver, &None);
    assert_eq!(client.get_address_max_balance(&receiver), None);
    assert!(client.transfer(&sender, &receiver, &50));
    assert_eq!(token.balance(&receiver), 100);
}

#[test]
fn test_max_balance_setters_are_admin_only_and_reject_negative_limits() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let attacker = Address::generate(&env);
    let holder = Address::generate(&env);

    assert_eq!(
        client.try_set_global_max_balance(&attacker, &Some(10)),
        Err(Ok(Error::NotAuthorized))
    );
    assert_eq!(
        client.try_set_address_max_balance(&attacker, &holder, &Some(10)),
        Err(Ok(Error::NotAuthorized))
    );
    assert_eq!(
        client.try_set_global_max_balance(&admin, &Some(-1)),
        Err(Ok(Error::InvalidInput))
    );
    assert_eq!(
        client.try_set_address_max_balance(&admin, &holder, &Some(-1)),
        Err(Ok(Error::InvalidInput))
    );
}

#[test]
fn test_merkle_proof_rejected_before_root_is_set() {
    let env = Env::default();
    let (_admin, _token_id, _contract_id, client) = setup(&env);
    let (_root, holders, proofs) = build_four_leaf_tree(&env);

    assert_eq!(client.get_allowlist_root(), None);
    assert!(!client.is_allowed_with_proof(&holders[0], &proofs[0]));
}

#[test]
fn test_merkle_proof_accepts_members_and_rejects_others() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let (root, holders, proofs) = build_four_leaf_tree(&env);
    client.set_allowlist_root(&admin, &root);
    assert_eq!(client.get_allowlist_root(), Some(root.clone()));

    for i in 0..4 {
        assert!(client.is_allowed_with_proof(&holders[i], &proofs[i]));
    }

    // A valid proof for one holder does not verify another holder.
    assert!(!client.is_allowed_with_proof(&holders[0], &proofs[1]));

    // An outsider cannot reuse a member's proof.
    let outsider = Address::generate(&env);
    assert!(!client.is_allowed_with_proof(&outsider, &proofs[0]));

    // Proofs longer than the cap are rejected without hashing.
    let mut too_long = Vec::new(&env);
    for _ in 0..=MAX_MERKLE_PROOF_LEN {
        too_long.push_back(BytesN::from_array(&env, &[0u8; 32]));
    }
    assert!(!client.is_allowed_with_proof(&holders[0], &too_long));
}

#[test]
fn test_set_allowlist_root_is_admin_only_and_blocked_while_paused() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let (root, _holders, _proofs) = build_four_leaf_tree(&env);
    let attacker = Address::generate(&env);

    assert_eq!(
        client.try_set_allowlist_root(&attacker, &root),
        Err(Ok(Error::NotAuthorized))
    );

    client.pause(&admin);
    assert_eq!(
        client.try_set_allowlist_root(&admin, &root),
        Err(Ok(Error::ContractPaused))
    );
}

#[test]
fn test_transfer_with_proof_forwards_only_when_both_proofs_verify() {
    let env = Env::default();
    let (admin, token_id, _contract_id, client) = setup(&env);
    let (root, holders, proofs) = build_four_leaf_tree(&env);
    client.set_allowlist_root(&admin, &root);
    let token = MockTokenClient::new(&env, &token_id);

    // Both parties prove membership: the transfer is forwarded.
    assert!(client.transfer_with_proof(
        &holders[0],
        &holders[2],
        &50,
        &proofs[0],
        &proofs[2],
    ));
    assert_eq!(
        token.last_transfer(),
        Some((holders[0].clone(), holders[2].clone(), 50))
    );

    // Recipient proof is missing: the transfer is blocked and nothing is forwarded.
    let outsider = Address::generate(&env);
    assert!(!client.transfer_with_proof(
        &holders[0],
        &outsider,
        &60,
        &proofs[0],
        &proofs[0],
    ));
    assert_eq!(
        token.last_transfer(),
        Some((holders[0].clone(), holders[2].clone(), 50))
    );
}

#[test]
fn test_transfer_with_proof_respects_freeze_and_pause() {
    let env = Env::default();
    let (admin, _token_id, _contract_id, client) = setup(&env);
    let (root, holders, proofs) = build_four_leaf_tree(&env);
    client.set_allowlist_root(&admin, &root);

    client.freeze(&admin, &holders[1]);
    assert_eq!(
        client.try_transfer_with_proof(
            &holders[0],
            &holders[1],
            &10,
            &proofs[0],
            &proofs[1],
        ),
        Err(Ok(Error::AddressFrozen))
    );
    client.unfreeze(&admin, &holders[1]);

    client.pause(&admin);
    assert_eq!(
        client.try_transfer_with_proof(
            &holders[0],
            &holders[1],
            &10,
            &proofs[0],
            &proofs[1],
        ),
        Err(Ok(Error::ContractPaused))
    );
}
