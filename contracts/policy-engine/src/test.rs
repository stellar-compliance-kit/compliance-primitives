use super::*;
use denylist_gate::{DenylistGate, DenylistGateClient};
use jurisdiction_flag::{JurisdictionFlag, JurisdictionFlagClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{vec, Env, String};
use std::path::{Path, PathBuf};

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
// Upgradeability
// ---------------------------------------------------------------------------

/// Self-referencing WASM import used to exercise the upgrade path: the
/// contract "upgrades" to its own currently-built WASM binary. This mirrors
/// the migration test pattern used elsewhere in the Soroban ecosystem for
/// verifying that `update_current_contract_wasm` preserves storage without
/// requiring a second, distinct contract version to exist.
mod self_wasm {
    soroban_sdk::contractimport!(
        file = "../../target/wasm32-unknown-unknown/release/policy_engine.wasm"
    );
}

/// Deploys policy-engine, writes state (admin, combine op, a registered
/// check), performs an admin-gated upgrade to a new WASM hash, and confirms
/// all previously written state is intact and the contract remains callable
/// afterward.
#[test]
fn test_upgrade_preserves_state_and_remains_callable() {
    let env = Env::default();
    env.mock_all_auths();

    let (admin, _id, client) = setup_engine_all(&env);

    let deny_admin = Address::generate(&env);
    let deny_id = setup_denylist(&env, &deny_admin);
    client.add_check(&admin, &CheckKind::Denylist { contract: deny_id });
    assert_eq!(client.get_checks().len(), 1);

    let new_wasm_hash = env.deployer().upload_contract_wasm(self_wasm::WASM);
    client.upgrade(&admin, &new_wasm_hash);

    // State written before the upgrade survives.
    assert_eq!(client.get_checks().len(), 1);
    assert_eq!(client.get_op(), CombineOp::All);

    // The contract is still callable and admin-gating still works after the
    // upgrade: a non-admin caller trying to mutate should fail, admin succeeds.
    let juri_issuer = Address::generate(&env);
    let juri_id = setup_jurisdiction(&env, &juri_issuer);
    client.add_check(
        &admin,
        &CheckKind::Jurisdiction {
            contract: juri_id,
            allowed_codes: vec![&env, String::from_str(&env, "US")],
        },
    );
    assert_eq!(client.get_checks().len(), 2);
}

/// A non-admin address may not trigger an upgrade.
#[test]
fn test_upgrade_requires_admin() {
    let env = Env::default();
    env.mock_all_auths();

    let (_admin, id, _client) = setup_engine_all(&env);
    let client = PolicyEngineClient::new(&env, &id);

    let attacker = Address::generate(&env);
    let new_wasm_hash = env.deployer().upload_contract_wasm(self_wasm::WASM);
    let result = client.try_upgrade(&attacker, &new_wasm_hash);
    assert_eq!(result, Err(Ok(Error::NotAuthorized)));
}

// ---------------------------------------------------------------------------
// Resource-fee (budget) regression check
// ---------------------------------------------------------------------------

fn baseline_path_for_manifest_dir(manifest_dir: PathBuf) -> PathBuf {
    manifest_dir.join("..").join("..").join("budget-baselines.toml")
}

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

/// Benchmarks policy-engine's hottest entrypoint, `evaluate`, against the
/// recorded baseline in `budget-baselines.toml`. Fails (and so fails CI via
/// the `budget-regression` job, which runs `cargo test ... budget_regression`)
/// if measured CPU or memory cost regresses more than 10% past baseline.
#[test]
fn test_budget_regression_policy_engine_evaluate() {
    let env = Env::default();
    env.mock_all_auths();

    let (admin, _id, client) = setup_engine_all(&env);
    let deny_admin = Address::generate(&env);
    let deny_id = setup_denylist(&env, &deny_admin);
    client.add_check(&admin, &CheckKind::Denylist { contract: deny_id });

    let from = Address::generate(&env);
    let to = Address::generate(&env);

    let mut budget = env.cost_estimate().budget();
    budget.reset_default();
    let passed = client.evaluate(&from, &to);
    assert!(passed);

    let measured = (budget.cpu_instruction_cost(), budget.memory_bytes_cost());
    let baseline_path = baseline_path_for_manifest_dir(PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
    ));
    let baseline = read_baseline(&baseline_path, "policy-engine.evaluate");
    assert_budget_within_threshold(measured, baseline, "policy-engine evaluate");
}
