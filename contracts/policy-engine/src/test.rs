use super::*;
use soroban_sdk::{vec, Env};

#[test]
fn test_not_wrapped_check_inverts_underlying_result() {
    let env = Env::default();
    let contract_id = env.register(PolicyEngine, ());
    let client = PolicyEngineClient::new(&env, &contract_id);

    let not_true = PolicyNode::Not(vec![&env, PolicyNode::Check(true)]);
    let not_false = PolicyNode::Not(vec![&env, PolicyNode::Check(false)]);

    assert!(!client.evaluate(&not_true));
    assert!(client.evaluate(&not_false));
}

#[test]
fn test_nested_combinator_tree_evaluates_in_correct_order() {
    let env = Env::default();
    let contract_id = env.register(PolicyEngine, ());
    let client = PolicyEngineClient::new(&env, &contract_id);

    let tree = PolicyNode::And(vec![
        &env,
        PolicyNode::Or(vec![
            &env,
            PolicyNode::Check(false),
            PolicyNode::Not(vec![&env, PolicyNode::Check(false)]),
        ]),
        PolicyNode::And(vec![
            &env,
            PolicyNode::Check(true),
            PolicyNode::Or(vec![
                &env,
                PolicyNode::Check(false),
                PolicyNode::Check(true),
            ]),
        ]),
    ]);

    assert!(client.evaluate(&tree));
}
