# Architecture

The compliance primitives are nine independently deployable Soroban contracts that compose through explicit calls. The `allowlist-token` wrapper delegates cleared transfers to an underlying SEP-41 token. The `compliance-aggregator` combines checks from the `denylist-gate`, `jurisdiction-flag`, and `policy-engine`. A token or RWA wrapper can call the aggregator before transfers. `pausable` and `circuit-breaker` can stop operations during emergencies. `audit-log` records compliance decisions, while `multisig-admin` protects administrative actions.

```text
allowlist-token -> compliance-aggregator
compliance-aggregator -> denylist-gate
compliance-aggregator -> jurisdiction-flag
compliance-aggregator -> policy-engine
compliance-aggregator -> audit-log
multisig-admin -> allowlist-token
multisig-admin -> denylist-gate
multisig-admin -> jurisdiction-flag
multisig-admin -> policy-engine
pausable -> allowlist-token
circuit-breaker -> compliance-aggregator
```

The graph is intentionally modular: applications choose the controls they need and call them before permitting a transfer or administrative operation.
