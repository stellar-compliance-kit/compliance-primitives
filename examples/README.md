# Examples

Runnable examples showing how the compliance primitives are composed in
practice. Each directory is a self-contained crate (or script) that you can
build with the workspace — a few are only meant to be read as a reference for
the calling pattern, and say so in their own README.

## Quick reference

Which example demonstrates which primitive, and the composition pattern it
shows:

| Example | Primitives demonstrated | Pattern shown |
|---------|------------------------|---------------|
| [`allowlist-token-usage`](./allowlist-token-usage) | `allowlist-token` | CLI walkthrough (shell script): deploy, `add_to_allowlist`, then watch a transfer be blocked and later succeed |
| [`circuit-breaker-policy-engine`](./circuit-breaker-policy-engine) | `circuit-breaker`, `policy-engine`, `denylist-gate` | Circuit breaker as a fail-fast pre-check before the policy engine evaluates a check |
| [`compliance-integration-flow`](./compliance-integration-flow) | `jurisdiction-flag`, `policy-engine`, `compliance-aggregator`, `multisig-admin`, `circuit-breaker`, `audit-log` (+ `pausable` used internally by `jurisdiction-flag`) | Wide integration: one transfer flow that touches seven contracts, with multisig-controlled admin and an audited decision trail |
| [`denylist-gate-consumer`](./denylist-gate-consumer) | `denylist-gate`, `circuit-breaker` | Minimal token: check the breaker, then the gate, for both parties before mutating balances |
| [`denylist-gate-sep41`](./denylist-gate-sep41) | `denylist-gate` | SEP-41-conformant token whose `transfer` is gated, with the standard interface unchanged for wallets and DEXes |
| [`jurisdiction-denylist-consumer`](./jurisdiction-denylist-consumer) | `denylist-gate`, `jurisdiction-flag` | Ordered AND composition: gate check for `from` and `to` first, then the sender's jurisdiction, each failing with its own error |
| [`jurisdiction-flag-consumer`](./jurisdiction-flag-consumer) | `jurisdiction-flag` | Single check on the sender's jurisdiction only (the recipient is left to its own policy) |
| [`multisig-aggregator`](./multisig-aggregator) | `multisig-admin`, `compliance-aggregator` | M-of-N authorization: the aggregator's admin is set to a multisig instance, so config changes must clear the threshold |
| [`multisig-audit-trail`](./multisig-audit-trail) | `multisig-admin`, `audit-log` | Governance trail: propose → approve → execute, with every approval and execution recorded in the audit log |
| [`pausable-consumer`](./pausable-consumer) | `pausable` (`compliance-pausable` crate) | The five wiring steps for adopting the shared pause crate: error variant, events, admin-gated methods, guard placement, read-only exemption |
| [`policy-engine-audit`](./policy-engine-audit) | `policy-engine`, `audit-log` | Evaluate-then-record: every policy evaluation, pass or fail, is written to the audit log |
| [`rwa-compliance-flow`](./rwa-compliance-flow) | `allowlist-token`, `denylist-gate`, `jurisdiction-flag` | Composition layer without a token implementation: three checks in series (AND), each returning its own error type |
| [`rwa-token`](./rwa-token) | `allowlist-token`, `denylist-gate`, `jurisdiction-flag` | Full reference token: all three gates in a fail-fast serial composition before balances move |

Two entries need a caveat: `compliance-integration-flow` is scoped to the seven
contracts that currently build cleanly (its own module docs explain why
`allowlist-token` and `denylist-gate` are excluded), and `allowlist-token-usage`
is a shell script rather than a crate.

## How these map to the contracts

Every primitive named above is a crate under [`/contracts`](../contracts):

| Primitive | Crate |
|-----------|-------|
| Allowlist | [`contracts/allowlist-token`](../contracts/allowlist-token) |
| Denylist | [`contracts/denylist-gate`](../contracts/denylist-gate) |
| Jurisdiction | [`contracts/jurisdiction-flag`](../contracts/jurisdiction-flag) |
| Policy engine | [`contracts/policy-engine`](../contracts/policy-engine) |
| Aggregator | [`contracts/compliance-aggregator`](../contracts/compliance-aggregator) |
| Multisig admin | [`contracts/multisig-admin`](../contracts/multisig-admin) |
| Circuit breaker | [`contracts/circuit-breaker`](../contracts/circuit-breaker) |
| Audit log | [`contracts/audit-log`](../contracts/audit-log) |
| Pausable | [`contracts/pausable`](../contracts/pausable) |

## Running an example

Build and test a single example crate from the repository root:

```sh
cargo test -p denylist-gate-consumer
```

`allowlist-token-usage` is different: it is a shell walkthrough that needs the
Stellar CLI and a local Soroban network — see its
[README](./allowlist-token-usage/README.md) for prerequisites. `rwa-token` also
has a runtime deployment path documented in its own README and `TESTNET.md`.
