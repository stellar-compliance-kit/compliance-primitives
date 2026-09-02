# jurisdiction-flag-consumer

Example token that enforces jurisdiction-based transfer restrictions using `jurisdiction-flag`.

## Pattern

This example demonstrates how to integrate `jurisdiction-flag` into a token's transfer logic. Before allowing a transfer, the contract verifies that both sender and receiver have jurisdiction codes in the permitted list.

The contract uses `#[contractclient]` to call `jurisdiction-flag.is_permitted_jurisdiction()` via cross-contract invocation.

## Primitives composed

- `jurisdiction-flag` — jurisdiction-based access control

## Build & test

```sh
cargo test -p jurisdiction-flag-consumer
cargo build -p jurisdiction-flag-consumer --target wasm32v1-none --release
```
