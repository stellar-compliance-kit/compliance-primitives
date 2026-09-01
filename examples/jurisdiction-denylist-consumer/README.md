# jurisdiction-denylist-consumer

Demonstrates combining `jurisdiction-flag` and `denylist-gate` in a single transfer check.

## Pattern

This example shows how to compose two compliance primitives in sequence:

1. Check jurisdiction: both addresses must have permitted jurisdiction codes
2. Check denylist: neither address can be on the denylist

Both checks must pass for the transfer to succeed. This demonstrates a common compliance pattern where multiple independent checks are required.

## Primitives composed

- `jurisdiction-flag` — jurisdiction-based access control
- `denylist-gate` — address denylist enforcement

## Build & test

```sh
cargo test -p jurisdiction-denylist-consumer
cargo build -p jurisdiction-denylist-consumer --target wasm32v1-none --release
```
