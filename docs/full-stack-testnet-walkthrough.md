# Full-stack testnet walkthrough

[`scripts/deploy-full-stack-testnet.sh`](../scripts/deploy-full-stack-testnet.sh)
builds and deploys all eight deployable contracts in this workspace to
Stellar testnet in one step, wires the composable ones together, and prints
a summary of contract IDs plus a couple of sample transactions. This doc
walks through what it does and how to poke at the result afterward.

For a smaller deployment — just the three original primitives plus the
`rwa-token` example — see
[`scripts/deploy-rwa-testnet.sh`](../scripts/deploy-rwa-testnet.sh) and
[`examples/rwa-token/TESTNET.md`](../examples/rwa-token/TESTNET.md) instead.

## Prerequisites

- `stellar-cli` compatible with `soroban-sdk` 27 (cli ≥ 23, ideally 27.x).
- A funded testnet identity: `stellar keys generate <name> --network testnet
  --fund`, then `export STELLAR_SOURCE=<name>`.

## Running it

```sh
STELLAR_SOURCE=<your-testnet-identity> ./scripts/deploy-full-stack-testnet.sh
```

Optional environment variables:

- `STELLAR_NETWORK` — defaults to `testnet`.
- `ALLOWED_CODES` — JSON array of jurisdiction codes, defaults to
  `["US","CA"]`. Used when wiring `jurisdiction-flag` into
  `policy-engine`'s check list.

## What gets deployed, and in what order

**Step 1 — no-dependency primitives** (deployed and initialized in any
order, since none of them reference another contract's address):

| Contract | Initialized as |
| --- | --- |
| `allowlist-token` | `admin` = issuer, `token` = a placeholder address (this script doesn't deploy a real SEP-41 token) |
| `denylist-gate` | `admin` = issuer |
| `jurisdiction-flag` | `issuer` = issuer |
| `audit-log` | `admin` = issuer |
| `circuit-breaker` | `admin` = issuer |
| `multisig-admin` | `signers` = `[issuer]`, `threshold` = 1 |

**Step 2 — composers**, deployed after step 1 because their `initialize`
(or setup) calls need the step-1 contract IDs:

| Contract | Wired to |
| --- | --- |
| `compliance-aggregator` | `denylist_gate` and `jurisdiction_flag` set to the step-1 contract IDs |
| `policy-engine` | initialized with `op = All`, then `add_check`-ed with a `Denylist` check against `denylist-gate` and a `Jurisdiction` check against `jurisdiction-flag` |

`pausable` is the ninth crate in the workspace but is a compile-time-only
helper library — it has no `#[contract]` macro and produces no wasm
exports of its own (see `contracts/pausable/src/lib.rs`), so there's
nothing to deploy for it.

`allowlist-token` is deployed and initialized but **not** wired into
`compliance-aggregator` or `policy-engine`: both of those only support
composing `denylist-gate` and `jurisdiction-flag` today (see
`CheckKind` in `contracts/policy-engine/src/lib.rs` and the
`Option<Address>` fields on `compliance-aggregator`'s `initialize`) — there
is no generic "allowlist" check kind yet.

## The `multisig-admin` demo

`multisig-admin` is deployed and initialized standalone, with the deploying
issuer as its sole signer (`threshold = 1`). This is deliberately kept
simple so the rest of the script's single-signer testnet flow still works
end to end. It does **not** replace the `admin` of any other contract in
this deployment.

To see the pattern it's designed for — an M-of-N multisig governing one of
the other primitives — re-initialize a primitive with
`--admin "$MULTISIG_ID"` in place of the issuer address. No changes to the
primitive are needed: Soroban's auth framework satisfies a contract
address's `require_auth()` by invoking that contract's `__check_auth`, and
`multisig-admin` implements exactly that. See the module doc at the top of
`contracts/multisig-admin/src/lib.rs` for the full explanation.

## Sample transactions to try after deploying

The script prints these with your actual contract IDs substituted in;
they're repeated here with placeholders for reference.

**Aggregated compliance check** (denylist-gate passes by default; the
jurisdiction check fails until you set a jurisdiction — see below):

```sh
stellar contract invoke \
  --id "$AGGREGATOR_ID" --source "$STELLAR_SOURCE" --network testnet \
  -- check_address --address "$ISSUER" --allowed_jurisdictions '["US","CA"]'
```

**Set a jurisdiction**, then re-run the check above to see it pass both
registered checks:

```sh
stellar contract invoke \
  --id "$JURISDICTION_ID" --source "$STELLAR_SOURCE" --network testnet \
  -- set_jurisdiction --issuer "$ISSUER" --address "$ISSUER" --code US
```

**Same check via `policy-engine`** (its `evaluate` takes a `from`/`to`
pair, since it's modeled on gating a transfer rather than a single
address):

```sh
stellar contract invoke \
  --id "$POLICY_ENGINE_ID" --source "$STELLAR_SOURCE" --network testnet \
  -- evaluate --from "$ISSUER" --to "$ISSUER"
```

**Record an audit entry.** Note that `audit-log.record`'s own `source`
parameter (the address that must authorize the call) happens to share a
name with the CLI's own `--source` identity flag — they're unrelated:
everything before the standalone `--` configures the CLI invocation itself,
everything after it is the contract call's named arguments.

```sh
stellar contract invoke \
  --id "$AUDIT_LOG_ID" --source "$STELLAR_SOURCE" --network testnet \
  -- record --source "$ISSUER" --kind manual_check --subject "$ISSUER" \
  --detail "walkthrough smoke test"
```

**Check the circuit breaker** (should read `false` — nothing freezes it in
this deployment):

```sh
stellar contract invoke \
  --id "$CIRCUIT_BREAKER_ID" --source "$STELLAR_SOURCE" --network testnet \
  -- is_frozen
```

## Redeploying after a testnet reset

Testnet resets periodically. Re-run
`scripts/deploy-full-stack-testnet.sh` and update any contract IDs you've
recorded elsewhere (e.g. in your own notes or a `.env` file) — this script
doesn't persist IDs anywhere itself, it only prints them.
