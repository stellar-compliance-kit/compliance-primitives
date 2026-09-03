# multisig-aggregator

Reference example demonstrating how to use `multisig-admin` as the admin of a `compliance-aggregator` contract.

## Pattern

This example shows multisig governance of compliance configuration:

- `multisig-admin` is set as the admin of a `compliance-aggregator` instance
- Configuration changes (`set_denylist_gate`, `set_jurisdiction_flag`) require M-of-N signer approval
- Same pattern works for `allowlist-token`, `denylist-gate`, and `jurisdiction-flag`

## Key tests

| Test | Description |
|------|-------------|
| `test_multisig_threshold_required_for_aggregator_config_change` | Configuration change requires multisig approval |
| `test_multisig_governs_jurisdiction_flag_configuration` | Jurisdiction flag can be set through multisig |
| `test_multisig_can_reconfigure_both_checks` | Both denylist and jurisdiction checks can be reconfigured |

## Cross-contract auth flow

1. Transaction calls `compliance-aggregator.set_denylist_gate(multisig_addr, new_gate)`
2. Aggregator calls `multisig_addr.require_auth()`
3. Soroban invokes `MultisigAdmin::__check_auth`
4. Multisig verifies threshold is met
5. Configuration change proceeds if authorized
