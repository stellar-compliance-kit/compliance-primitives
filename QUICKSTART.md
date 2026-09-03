# Quick Start Guide

Get from zero to exploring compliance-primitives on testnet in under 10 minutes.

## 1. Clone and set up

```sh
git clone https://github.com/stellar-compliance-kit/compliance-primitives.git
cd compliance-primitives
```

## 2. Install prerequisites

Ensure you have:
- **Rust** with `wasm32v1-none` target (rustup installs it automatically via `rust-toolchain.toml`)
- **Stellar CLI** (v23+, ideally v27+): https://github.com/stellar/stellar-cli

```sh
# Install the wasm target if not already present
rustup target add wasm32v1-none
```

## 3. Run tests

Verify the contracts build and pass all tests:

```sh
cargo test --workspace
```

This runs the full test suite for all three primitives, the audit-log, multisig-admin, and examples.

## 4. Try a local example

Build a single contract to explore the code:

```sh
# Build just one contract to wasm
cargo build -p denylist-gate --target wasm32v1-none --release

# Or use the cargo alias
cargo build-wasm
```

The built contracts are in `target/wasm32v1-none/release/`.

## 5. Deploy to testnet

To deploy a contract to testnet and interact with it, you'll need a Stellar testnet account and identity set up:

```sh
# Generate or import a testnet identity
stellar keys generate my-testnet-key
stellar keys address my-testnet-key

# Copy the address and fund it at https://laboratory.stellar.org/ (testnet tab)
```

Then deploy a contract:

```sh
# Set your testnet identity
export STELLAR_SOURCE=my-testnet-key

# Build all contracts and deploy denylist-gate
./scripts/deploy-testnet.sh denylist-gate

# Or deploy allowlist-token, jurisdiction-flag, or rwa-token
./scripts/deploy-testnet.sh allowlist-token
```

For a full RWA stack (all three primitives initialized together):

```sh
./scripts/deploy-rwa-testnet.sh
```

See `examples/testnet.env.example` for additional configuration options (network choice, source identity, etc.).

## 6. Explore in the web playground

Once a contract is deployed to testnet, explore it interactively:

1. Open [the web playground](./web/index.html) locally:
   ```sh
   # Serve the web playground locally
   python3 -m http.server --directory web 8000
   ```
   Then visit http://localhost:8000 in your browser.

2. Enter the testnet contract ID from step 5 and interact with its functions in real time.

## 7. Explore the examples

Each example demonstrates a specific pattern:

- **[`denylist-gate-consumer`](./examples/denylist-gate-consumer)** — a minimal token calling `denylist-gate.check()` before allowing transfers.
- **[`rwa-token`](./examples/rwa-token)** — composes all three primitives (allowlist, denylist, jurisdiction) in a single token contract.
- **[`jurisdiction-denylist-consumer`](./examples/jurisdiction-denylist-consumer)** — checks jurisdiction before allowing a denylist.
- **[`rwa-compliance-flow`](./examples/rwa-compliance-flow)** — demonstrates a full compliance workflow with multiple primitives.

For a detailed testnet walkthrough of the RWA token, see [`examples/rwa-token/TESTNET.md`](./examples/rwa-token/TESTNET.md).

## 8. Next steps

- **Read the architecture overview** in [README.md](./README.md)
- **Understand the design** of each contract in the top-level comments of its `src/lib.rs`
- **Integrate into your own token** using the patterns in the examples
- **Contributing?** See [CONTRIBUTING.md](./CONTRIBUTING.md) for the workflow and code standards

## Troubleshooting

### Tests fail with "soroban-sdk" version issues
Ensure you're using the correct Rust version. The `rust-toolchain.toml` pins it; rustup will switch automatically when you enter the directory.

### Stellar CLI not found
Check that `stellar` is in your `$PATH` and version ≥23. Install from https://github.com/stellar/stellar-cli.

### Testnet deployment fails
1. Verify your account is funded (check at https://stellar.expert/explorer/testnet/account/<your-address>)
2. Ensure `STELLAR_SOURCE` is set to a valid identity name
3. Try verbose output: `stellar contract deploy --help`

### Web playground doesn't load
Verify the local server is running (`python3 -m http.server --directory web`) and visit `http://localhost:8000`.

## Key files and directories

- **`contracts/`** — the three core compliance primitives
- **`examples/`** — reference implementations and integration patterns
- **`scripts/`** — deployment and documentation generation tools
- **`web/`** — the interactive playground (HTML + JS)
- **`docs/`** — architecture, migration, and interface specs
