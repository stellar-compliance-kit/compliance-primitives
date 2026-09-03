# circuit-breaker-policy-engine

Demonstrates wiring `circuit-breaker` as a pre-check before `policy-engine` evaluation, implementing the emergency-freeze pattern from `docs/emergency-freeze-design.md`.

## Pattern

The example contract calls `circuit-breaker.is_frozen()` first. If frozen, the check fails immediately with `Error::CircuitBreakerFrozen` without evaluating the policy. If unfrozen, it proceeds to `policy-engine.evaluate()`.

This ensures a single admin-controlled breaker can halt all compliance checks system-wide during an incident, regardless of how complex the policy configuration is.

## Primitives composed

- `circuit-breaker` — emergency freeze switch
- `policy-engine` — composable compliance policy evaluator
- `denylist-gate` — used as an example check within the policy

## Build & test

```sh
cargo test -p circuit-breaker-policy-engine
cargo build -p circuit-breaker-policy-engine --target wasm32v1-none --release
```

## Test coverage

- Transfer passes when breaker unfrozen and policy passes
- Transfer fails when breaker is frozen
- Transfer recovers after unfreeze
- Policy violations are still detected when breaker is unfrozen
- Breaker check takes precedence over policy evaluation (fail-fast)
