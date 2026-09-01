# multisig-admin

M-of-N administrative governance for protected contract actions.

| Method | Purpose |
| --- | --- |
| `initialize(signers, threshold)` | Configure signers and the approval threshold. |
| `propose(action)` | Create a pending administrative proposal. |
| `approve(signer, proposal_id)` | Approve a proposal as an authorized signer. |
| `execute(proposal_id)` | Execute a proposal after the threshold is met. |
