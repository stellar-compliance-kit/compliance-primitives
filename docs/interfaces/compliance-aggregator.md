# compliance-aggregator

A composition point for evaluating multiple compliance primitives as one decision.

| Method | Purpose |
| --- | --- |
| `initialize(admin, checks)` | Configure the checks and administrator. |
| `evaluate(from, to) -> bool` | Evaluate the configured policy for a transfer. |
| `get_checks() -> checks` | Inspect configured compliance checks. |

Use the deployed contract’s generated interface for exact enum and address encoding.
