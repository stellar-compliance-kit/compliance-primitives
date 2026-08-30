#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, Env, Vec};

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyNode {
    /// Leaf predicate.
    Check(bool),
    /// Unary negation of a single child node.
    Not(Vec<PolicyNode>),
    /// All child nodes must evaluate to true.
    And(Vec<PolicyNode>),
    /// Any child node may evaluate to true.
    Or(Vec<PolicyNode>),
}

#[contract]
pub struct PolicyEngine;

#[contractimpl]
impl PolicyEngine {
    pub fn evaluate(_env: Env, node: PolicyNode) -> bool {
        Self::eval_node(&node)
    }

    fn eval_node(node: &PolicyNode) -> bool {
        match node {
            PolicyNode::Check(value) => *value,
            PolicyNode::Not(children) => match children.iter().next() {
                Some(child) => !Self::eval_node(&child),
                None => false,
            },
            PolicyNode::And(children) => {
                for child in children.iter() {
                    if !Self::eval_node(&child) {
                        return false;
                    }
                }
                true
            }
            PolicyNode::Or(children) => {
                for child in children.iter() {
                    if Self::eval_node(&child) {
                        return true;
                    }
                }
                false
            }
        }
    }
}

#[cfg(test)]
mod test;
