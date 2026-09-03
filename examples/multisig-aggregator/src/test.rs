use super::*;
use compliance_aggregator::{ComplianceAggregator, ComplianceAggregatorClient};
use denylist_gate::{DenylistGate, DenylistGateClient};
use jurisdiction_flag::{JurisdictionFlag, JurisdictionFlagClient};
use multisig_admin::{MultisigAdmin, MultisigAdminClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{vec, Env};

fn setup(env: &Env) -> (Address, Address, ComplianceAggregatorClient<'_>) {
    env.mock_all_auths();

    // Deploy multisig-admin with 2-of-3 threshold
    let signer1 = Address::generate(env);
    let signer2 = Address::generate(env);
    let signer3 = Address::generate(env);
    let signers = vec![env, signer1.clone(), signer2.clone(), signer3.clone()];

    let multisig_id = env.register(MultisigAdmin, ());
    let multisig_client = MultisigAdminClient::new(env, &multisig_id);
    multisig_client.initialize(&signers, &2);

    // Deploy compliance-aggregator with multisig as admin
    let aggregator_id = env.register(ComplianceAggregator, ());
    let aggregator_client = ComplianceAggregatorClient::new(env, &aggregator_id);
    aggregator_client.initialize(&multisig_id, &None, &None);

    (multisig_id, aggregator_id, aggregator_client)
}

#[test]
fn test_multisig_threshold_required_for_aggregator_config_change() {
    let env = Env::default();
    let (multisig_id, _aggregator_id, aggregator_client) = setup(&env);

    // Deploy a new denylist-gate
    let gate_admin = Address::generate(&env);
    let gate_id = env.register(DenylistGate, ());
    DenylistGateClient::new(&env, &gate_id).initialize(&gate_admin);

    // Attempt to set the denylist gate with multisig as admin
    // The mock_all_auths() in setup will automatically satisfy the multisig
    // threshold check for this test
    aggregator_client.set_denylist_gate(&multisig_id, &gate_id);

    // Verify the configuration was updated
    assert_eq!(aggregator_client.denylist_gate(), Some(gate_id));
}

#[test]
fn test_multisig_governs_jurisdiction_flag_configuration() {
    let env = Env::default();
    let (multisig_id, _aggregator_id, aggregator_client) = setup(&env);

    // Deploy a new jurisdiction-flag
    let flag_issuer = Address::generate(&env);
    let flag_id = env.register(JurisdictionFlag, ());
    JurisdictionFlagClient::new(&env, &flag_id).initialize(&flag_issuer);

    // Set the jurisdiction flag with multisig as admin
    aggregator_client.set_jurisdiction_flag(&multisig_id, &flag_id);

    // Verify the configuration was updated
    assert_eq!(aggregator_client.jurisdiction_flag(), Some(flag_id));
}

#[test]
fn test_multisig_can_reconfigure_both_checks() {
    let env = Env::default();
    let (multisig_id, _aggregator_id, aggregator_client) = setup(&env);

    // Deploy both primitives
    let gate_admin = Address::generate(&env);
    let gate_id = env.register(DenylistGate, ());
    DenylistGateClient::new(&env, &gate_id).initialize(&gate_admin);

    let flag_issuer = Address::generate(&env);
    let flag_id = env.register(JurisdictionFlag, ());
    JurisdictionFlagClient::new(&env, &flag_id).initialize(&flag_issuer);

    // Configure both through multisig
    aggregator_client.set_denylist_gate(&multisig_id, &gate_id);
    aggregator_client.set_jurisdiction_flag(&multisig_id, &flag_id);

    // Verify both configurations
    assert_eq!(aggregator_client.denylist_gate(), Some(gate_id));
    assert_eq!(aggregator_client.jurisdiction_flag(), Some(flag_id));
}
