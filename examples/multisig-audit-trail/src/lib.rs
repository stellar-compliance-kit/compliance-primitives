//! `multisig-audit-trail` demonstrates how to use `multisig-admin` proposals
//! in conjunction with `audit-log` to create a complete governance audit trail.
//!
//! ## Governance Flow
//!
//! 1. An authorized signer **proposes** a governance action (e.g., adding a
//!    new signer, updating a denylist). The proposal is created with an
//!    expiry ledger sequence.
//! 2. Other signers **approve** the proposal. Each approval is logged to the
//!    audit-log as a "proposal_approved" event.
//! 3. Once the threshold is met, the proposal is **executed**. This logs an
//!    "proposal_executed" event.
//! 4. If a proposal expires before execution, any attempt to approve or execute
//!    it returns an error. The audit-log maintains the complete approval
//!    history up to that point.
//!
//! ## Why audit-log?
//!
//! Off-chain governance dashboards can query the audit-log to show:
//! - Who proposed what and when
//! - Who approved (or rejected) it
//! - When it was executed
//! - Which proposals expired without execution
//!
//! This creates an immutable, on-chain proof of governance decisions — critical
//! for regulatory compliance and post-incident forensics.
//!
//! ## Integration Pattern
//!
//! This example is not a contract itself; rather, it shows the pattern for
//! wrapping calls to `multisig-admin` with calls to `audit-log.record()`. A
//! real governance contract would follow this pattern, forwarding governance
//! events to a known audit-log instance.

#![no_std]

use soroban_sdk::{contract, contractimpl, Address, Bytes, Env, String, Symbol};

// Trait definition for cross-contract calls to multisig-admin
mod multisig_trait {
    use soroban_sdk::{contractclient, Address, Bytes, Env, Vec};

    #[contractclient(name = "MultisigAdminClient")]
    pub trait MultisigAdmin {
        fn propose(env: Env, payload: Bytes, expiry_ledger: u32) -> u64;
        fn approve(env: Env, proposal_id: u64, approver: Address) -> bool;
        fn execute(env: Env, proposal_id: u64) -> ();
        fn get_proposal(
            env: Env,
            proposal_id: u64,
        ) -> (Bytes, u32, Vec<Address>);
    }
}

// Trait definition for cross-contract calls to audit-log
mod audit_log_trait {
    use soroban_sdk::{contractclient, Address, Env, String, Symbol};

    #[contractclient(name = "AuditLogClient")]
    pub trait AuditLog {
        fn record(
            env: Env,
            source: Address,
            kind: Symbol,
            subject: Address,
            detail: String,
        ) -> ();
    }
}

// Dummy contract serving as the example entry point (non-functional)
#[contract]
pub struct MultisigAuditTrail;

#[contractimpl]
impl MultisigAuditTrail {
    /// This is a documentation example, not a working implementation.
    /// In a real scenario, a governance wrapper would:
    ///
    /// 1. Call `multisig_admin.propose(...)` and get a proposal ID
    /// 2. Forward each approval to the audit-log:
    ///    ```text
    ///    audit_log.record(
    ///        source: governance_contract,
    ///        kind: "proposal_approved",
    ///        subject: approver,
    ///        detail: format!("proposal {}", proposal_id)
    ///    )
    ///    ```
    /// 3. Log execution:
    ///    ```text
    ///    audit_log.record(
    ///        source: governance_contract,
    ///        kind: "proposal_executed",
    ///        subject: Address::try_from_val(&env, &proposal_id).unwrap(),
    ///        detail: "governance action completed"
    ///    )
    ///    ```
    pub fn noop(_env: Env) {}
}

#[cfg(test)]
mod test {
    use super::*;
    use audit_log_trait::AuditLogClient;
    use multisig_trait::MultisigAdminClient;
    use soroban_sdk::{
        testutils::{Address as _, Ledger as _},
        vec, Address, Env,
    };

    fn setup_multisig(env: &Env, n: usize, threshold: u32) -> (Vec<Address>, Address) {
        env.mock_all_auths();
        let mut signers = vec![env];
        for _ in 0..n {
            signers.push_back(Address::generate(env));
        }
        let contract_id = env.register(
            soroban_sdk::contractimpl!(super::multisig_trait::MultisigAdminClient),
            (),
        );
        // Note: This would normally call multisig_admin.initialize(), but
        // the actual implementation is in the multisig-admin crate.
        (signers, contract_id)
    }

    fn setup_audit_log(env: &Env, admin: Address) -> Address {
        env.mock_all_auths();
        let contract_id = env.register(
            soroban_sdk::contractimpl!(super::audit_log_trait::AuditLogClient),
            (),
        );
        // Note: This would normally call audit_log.initialize(admin), but
        // the actual implementation is in the audit-log crate.
        contract_id
    }

    #[test]
    fn test_proposal_and_approval_flow() {
        let env = Env::default();
        let (signers, multisig_id) = setup_multisig(&env, 3, 2);
        let audit_log_id = setup_audit_log(&env, Address::generate(&env));

        // In a real scenario:
        // 1. Create a proposal
        let payload = Bytes::new(&env);
        let expiry = env.ledger().sequence() + 100;
        let _proposal_id = 0u64; // multisig.propose(&payload, expiry)

        // 2. First signer approves
        let approver1 = signers.get(0).unwrap();
        let _ready = false; // multisig.approve(_proposal_id, &approver1)

        // 3. Log the approval to audit-log
        let audit_log = AuditLogClient::new(&env, &audit_log_id);
        audit_log.record(
            &multisig_id,
            &Symbol::new(&env, "proposal_approved"),
            &approver1,
            &String::from_slice(&env, "proposal 0 approved"),
        );

        // 4. Second signer approves
        let approver2 = signers.get(1).unwrap();
        let _ready = true; // multisig.approve(_proposal_id, &approver2)

        audit_log.record(
            &multisig_id,
            &Symbol::new(&env, "proposal_approved"),
            &approver2,
            &String::from_slice(&env, "proposal 0 approved"),
        );

        // 5. Execute the proposal
        let _executed = (); // multisig.execute(_proposal_id)

        audit_log.record(
            &multisig_id,
            &Symbol::new(&env, "proposal_executed"),
            &Address::generate(&env),
            &String::from_slice(&env, "proposal 0 executed"),
        );
    }

    #[test]
    fn test_expired_proposal_flow() {
        let env = Env::default();
        let (signers, multisig_id) = setup_multisig(&env, 2, 1);
        let audit_log_id = setup_audit_log(&env, Address::generate(&env));

        // Create a proposal that will expire
        let payload = Bytes::new(&env);
        let expiry = env.ledger().sequence() + 10;
        let _proposal_id = 0u64; // multisig.propose(&payload, expiry)

        // First signer approves
        let approver = signers.get(0).unwrap();
        let audit_log = AuditLogClient::new(&env, &audit_log_id);

        audit_log.record(
            &multisig_id,
            &Symbol::new(&env, "proposal_approved"),
            &approver,
            &String::from_slice(&env, "proposal 0 approved"),
        );

        // Advance ledger past expiry
        env.ledger().set_sequence_number(expiry);

        // Any attempt to approve or execute now returns ExpiredProposal.
        // Log a rejection event for governance clarity.
        audit_log.record(
            &multisig_id,
            &Symbol::new(&env, "proposal_expired"),
            &Address::generate(&env),
            &String::from_slice(&env, "proposal 0 expired at ledger 10"),
        );
    }

    #[test]
    fn test_proposal_approval_history() {
        let env = Env::default();
        let (signers, multisig_id) = setup_multisig(&env, 3, 2);
        let audit_log_id = setup_audit_log(&env, Address::generate(&env));

        let payload = Bytes::new(&env);
        let expiry = env.ledger().sequence() + 100;
        let _proposal_id = 0u64; // multisig.propose(&payload, expiry)

        let audit_log = AuditLogClient::new(&env, &audit_log_id);

        // Record approvals from all signers to show full governance history
        for i in 0..signers.len() as u32 {
            let signer = signers.get(i).unwrap();
            audit_log.record(
                &multisig_id,
                &Symbol::new(&env, "proposal_approved"),
                &signer,
                &String::from_slice(&env, "proposal 0 approved"),
            );
        }

        // Then log execution
        audit_log.record(
            &multisig_id,
            &Symbol::new(&env, "proposal_executed"),
            &Address::generate(&env),
            &String::from_slice(&env, "proposal 0 executed"),
        );
    }
}
