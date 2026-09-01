# Multisig Audit Trail Example

Demonstrates how to integrate `multisig-admin` proposals with `audit-log` to create a complete on-chain governance audit trail.

## Overview

This example shows the pattern for recording governance events (proposals, approvals, executions) to an on-chain audit log. The workflow is:

1. **Propose** — A signer creates a governance proposal with an expiry ledger sequence.
2. **Approve** — Other signers approve the proposal. Each approval is logged to the audit-log.
3. **Execute** — Once the threshold is met, the proposal is executed and logged.
4. **Expire** — If a proposal reaches its expiry ledger without execution, any further approval or execution attempts fail; the audit-log records the expiry for governance clarity.

## Key Concepts

### Why Audit-Log?

Off-chain dashboards and regulatory compliance tools need to answer:
- "Who proposed this governance action?"
- "Who approved it and when?"
- "Was it executed or did it expire?"
- "What's the complete history of governance decisions?"

The on-chain audit-log provides an immutable, queryable trail that answers all of these without depending on off-chain indexers.

### Why Proposal Expiry?

Stale proposals are a governance risk: a proposal created months ago with one approval could suddenly gain a second approval and execute when the original context is no longer relevant. The `expiry` ledger sequence ensures proposals self-destruct if not completed in a timely manner.

## Example Flow

### Success Case

```
Ledger 100: Signer A proposes action X (expires at ledger 110)
Ledger 101: Signer B approves → audit-log records "proposal_approved" (1/2 approvals)
Ledger 102: Signer C approves → threshold met → execute → audit-log records "proposal_executed"
```

### Expiry Case

```
Ledger 100: Signer A proposes action Y (expires at ledger 110)
Ledger 105: Signer B approves → audit-log records "proposal_approved"
Ledger 111: Signer C attempts to approve → Error: ExpiredProposal
           → audit-log records "proposal_expired" for clarity
```

## Running the Tests

```sh
cargo test --example multisig-audit-trail
```

The tests demonstrate:
1. **test_proposal_and_approval_flow** — A complete lifecycle: propose → approve → approve → execute.
2. **test_expired_proposal_flow** — A proposal that expires before execution.
3. **test_proposal_approval_history** — Recording every approval to build a governance trail.

## Integration Pattern

In a real governance contract, wrap calls to `multisig-admin` with calls to `audit-log.record()`:

```rust
// Propose a governance action
let proposal_id = multisig_admin.propose(&payload, expiry_ledger)?;

// Log the proposal creation
audit_log.record(
    governance_contract_id,
    Symbol::new(&env, "proposal_created"),
    Address::generate(&env), // or subject address
    String::from_slice(&env, &format!("proposal {}", proposal_id))
)?;

// ... later, when an approver signs:
let ready = multisig_admin.approve(proposal_id, approver)?;
audit_log.record(
    governance_contract_id,
    Symbol::new(&env, "proposal_approved"),
    approver,
    String::from_slice(&env, &format!("proposal {}", proposal_id))
)?;

// When threshold is reached, execute and log:
multisig_admin.execute(proposal_id)?;
audit_log.record(
    governance_contract_id,
    Symbol::new(&env, "proposal_executed"),
    Address::generate(&env),
    String::from_slice(&env, &format!("proposal {}", proposal_id))
)?;
```

## See Also

- [`multisig-admin`](../../contracts/multisig-admin) — M-of-N proposal and approval system
- [`audit-log`](../../contracts/audit-log) — On-chain compliance audit trail
