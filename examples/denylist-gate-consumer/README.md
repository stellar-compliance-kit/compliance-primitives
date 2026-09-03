# denylist-gate-consumer

Minimal example token that calls `denylist-gate.check()` and `circuit-breaker.is_frozen()` before every transfer.

## Pattern

This example demonstrates the simplest compliance integration: check the circuit breaker first (fail-fast if frozen), then check the denylist gate. If either check fails, the transfer is blocked.

The contract uses `#[contractclient]` traits to call the primitives via cross-contract calls, avoiding linking their implementations into the same wasm binary.

## Primitives composed

- `circuit-breaker` — emergency freeze switch
- `denylist-gate` — address denylist enforcement

## Build & test

```sh
cargo test -p denylist-gate-consumer
cargo build -p denylist-gate-consumer --target wasm32v1-none --release
```
