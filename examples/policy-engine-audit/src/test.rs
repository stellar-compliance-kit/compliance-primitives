use super::*;
use audit_log::{AuditLog, AuditLogClient};
use denylist_gate::{DenylistGate, DenylistGateClient};
use jurisdiction_flag::{JurisdictionFlag, JurisdictionFlagClient};
use policy_engine::{CheckKind, CombineOp, PolicyEngine, PolicyEngineClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{symbol_short, vec, Env, String};

fn setup(
    env: &Env,
) -> (
    Address,
    Address,
    Address,
    Address,
    PolicyEngineAuditDemoClient<'_>,
) {
    env.mock_all_auths();

    // Deploy denylist-gate
    let gate_admin = Address::generate(env);
    let gate_id = env.register(DenylistGate, ());
    DenylistGateClient::new(env, &gate_id).initialize(&gate_admin);

    // Deploy jurisdiction-flag
    let flag_issuer = Address::generate(env);
    let flag_id = env.register(JurisdictionFlag, ());
    JurisdictionFlagClient::new(env, &flag_id).initialize(&flag_issuer);

    // Deploy policy-engine with AND logic
    let policy_admin = Address::generate(env);
    let policy_id = env.register(PolicyEngine, ());
    let policy_client = PolicyEngineClient::new(env, &policy_id);
    policy_client.initialize(&policy_admin, &CombineOp::All);

    // Add checks to policy-engine
    let denylist_check = CheckKind::Denylist {
        contract: gate_id.clone(),
    };
    policy_client.add_check(&policy_admin, &denylist_check);

    let jurisdiction_check = CheckKind::Jurisdiction {
        contract: flag_id.clone(),
        allowed_codes: vec![env, String::from_str(env, "US"), String::from_str(env, "CA")],
    };
    policy_client.add_check(&policy_admin, &jurisdiction_check);

    // Deploy audit-log
    let log_admin = Address::generate(env);
    let log_id = env.register(AuditLog, ());
    AuditLogClient::new(env, &log_id).initialize(&log_admin);

    // Deploy the demo contract
    let demo_id = env.register(PolicyEngineAuditDemo, ());
    let demo_client = PolicyEngineAuditDemoClient::new(env, &demo_id);
    demo_client.initialize(&policy_id, &log_id);

    (gate_id, gate_admin, flag_id, flag_issuer, demo_client)
}

#[test]
fn test_passing_evaluation_is_logged() {
    let env = Env::default();
    let (_gate_id, _gate_admin, flag_id, flag_issuer, demo_client) = setup(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);

    // Set alice to permitted jurisdiction
    let flag_client = JurisdictionFlagClient::new(&env, &flag_id);
    flag_client.set_jurisdiction(&flag_issuer, &alice, &String::from_str(&env, "US"));
    flag_client.set_jurisdiction(&flag_issuer, &bob, &String::from_str(&env, "CA"));

    // Evaluate (should pass)
    let result = demo_client.evaluate_and_log(&alice, &bob);
    assert_eq!(result, true);

    // Verify audit log entry
    let log_addr: Address = env
        .as_contract(&demo_client.address, || {
            env.storage()
                .instance()
                .get(&DataKey::AuditLog)
                .unwrap()
        });
    let log_client = AuditLogClient::new(&env, &log_addr);
    assert_eq!(log_client.entry_count(), 1);

    let entry = log_client.get_entry(&0).unwrap();
    assert_eq!(entry.source, demo_client.address);
    assert_eq!(entry.kind, symbol_short!("policy_pass"));
    assert_eq!(entry.subject, alice);
}

#[test]
fn test_failing_evaluation_is_logged() {
    let env = Env::default();
    let (gate_id, gate_admin, flag_id, flag_issuer, demo_client) = setup(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);

    // Set alice to permitted jurisdiction but add to denylist
    let flag_client = JurisdictionFlagClient::new(&env, &flag_id);
    flag_client.set_jurisdiction(&flag_issuer, &alice, &String::from_str(&env, "US"));
    flag_client.set_jurisdiction(&flag_issuer, &bob, &String::from_str(&env, "CA"));

    let gate_client = DenylistGateClient::new(&env, &gate_id);
    gate_client.add_to_denylist(&gate_admin, &alice);

    // Evaluate (should fail due to denylist)
    let result = demo_client.evaluate_and_log(&alice, &bob);
    assert_eq!(result, false);

    // Verify audit log entry
    let log_addr: Address = env
        .as_contract(&demo_client.address, || {
            env.storage()
                .instance()
                .get(&DataKey::AuditLog)
                .unwrap()
        });
    let log_client = AuditLogClient::new(&env, &log_addr);
    assert_eq!(log_client.entry_count(), 1);

    let entry = log_client.get_entry(&0).unwrap();
    assert_eq!(entry.source, demo_client.address);
    assert_eq!(entry.kind, symbol_short!("policy_fail"));
    assert_eq!(entry.subject, alice);
}

#[test]
fn test_multiple_evaluations_create_sequential_log_entries() {
    let env = Env::default();
    let (_gate_id, _gate_admin, flag_id, flag_issuer, demo_client) = setup(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    let charlie = Address::generate(&env);

    let flag_client = JurisdictionFlagClient::new(&env, &flag_id);
    flag_client.set_jurisdiction(&flag_issuer, &alice, &String::from_str(&env, "US"));
    flag_client.set_jurisdiction(&flag_issuer, &bob, &String::from_str(&env, "CA"));
    flag_client.set_jurisdiction(&flag_issuer, &charlie, &String::from_str(&env, "GB"));

    // Three evaluations: pass, pass, fail
    let result1 = demo_client.evaluate_and_log(&alice, &bob);
    assert_eq!(result1, true);

    let result2 = demo_client.evaluate_and_log(&bob, &alice);
    assert_eq!(result2, true);

    let result3 = demo_client.evaluate_and_log(&charlie, &alice);
    assert_eq!(result3, false); // charlie has non-permitted jurisdiction

    // Verify log has 3 entries with correct outcomes
    let log_addr: Address = env
        .as_contract(&demo_client.address, || {
            env.storage()
                .instance()
                .get(&DataKey::AuditLog)
                .unwrap()
        });
    let log_client = AuditLogClient::new(&env, &log_addr);
    assert_eq!(log_client.entry_count(), 3);

    let entry0 = log_client.get_entry(&0).unwrap();
    assert_eq!(entry0.kind, symbol_short!("policy_pass"));
    assert_eq!(entry0.subject, alice);

    let entry1 = log_client.get_entry(&1).unwrap();
    assert_eq!(entry1.kind, symbol_short!("policy_pass"));
    assert_eq!(entry1.subject, bob);

    let entry2 = log_client.get_entry(&2).unwrap();
    assert_eq!(entry2.kind, symbol_short!("policy_fail"));
    assert_eq!(entry2.subject, charlie);
}
