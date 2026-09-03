# policy-engine-audit

Reference example demonstrating how to wire `policy-engine` evaluations to `audit-log` for queryable compliance decision trails.

## Pattern

This example shows audit logging of policy evaluations:

- Every `policy-engine.evaluate()` call is followed by `audit-log.record()`
- Both pass and fail outcomes are logged
- Creates an on-chain, queryable compliance trail

## Why audit policy evaluations?

- **On-chain proof-of-compliance**: Other contracts can verify prior checks exist
- **Dispute resolution**: Reconstruct full decision history for any address
- **Immutable trail**: Append-only persistent storage provides tamper-resistant records

## Key tests

| Test | Description |
|------|-------------|
| `test_passing_evaluation_is_logged` | Successful evaluations create audit entries |
| `test_failing_evaluation_is_logged` | Failed evaluations are logged with failure kind |
| `test_multiple_evaluations_create_sequential_log_entries` | Multiple evaluations create ordered log trail |

## Integration flow

1. Deploy `policy-engine` with compliance checks configured
2. Deploy `audit-log` instance
3. After each `policy-engine.evaluate(from, to)`, call `audit-log.record()`
4. Query results with `get_entry(index)` or `entry_count()`
