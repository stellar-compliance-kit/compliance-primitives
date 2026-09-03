# rwa-compliance-flow

Integration example demonstrating a complete RWA token compliance flow using all three core primitives together.

## Pattern

This example demonstrates a comprehensive compliance stack for Real-World Asset (RWA) tokenization. The transfer flow enforces three compliance checks in sequence:

1. **Allowlist check** — both parties must be on the allowlist
2. **Denylist check** — neither party can be on the denylist  
3. **Jurisdiction check** — both parties must have permitted jurisdiction codes

All three checks must pass for a transfer to succeed. This represents a realistic compliance configuration for regulated digital assets.

## Primitives composed

- `allowlist-token` — allowlist-based access control
- `denylist-gate` — address denylist enforcement
- `jurisdiction-flag` — jurisdiction-based access control

## Build & test

```sh
cargo test -p rwa-compliance-flow
cargo build -p rwa-compliance-flow --target wasm32v1-none --release
```
