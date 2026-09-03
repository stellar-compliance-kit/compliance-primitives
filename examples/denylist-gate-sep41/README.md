# denylist-gate-sep41

Demonstrates `denylist-gate` integration in a SEP-41 compliant anchor service pattern.

## Pattern

This example shows how to wire `denylist-gate` into the approval flow for SEP-41 (cross-border payments). The contract checks whether sender or receiver addresses are on the denylist before approving a payment operation.

SEP-41 requires anchors to perform compliance checks before approving transfers. This example provides a minimal implementation of that compliance layer using `denylist-gate`.

## Primitives composed

- `denylist-gate` — address denylist enforcement

## Build & test

```sh
cargo test -p denylist-gate-sep41
cargo build -p denylist-gate-sep41 --target wasm32v1-none --release
```
