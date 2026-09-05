# Glossary of Soroban / Stellar Terms

This glossary defines Soroban- and Stellar-specific terms used throughout this repository's documentation.  It is intended as a quick reference for contributors who are new to the ecosystem.

---

## Ledger

### Ledger Sequence
A monotonically increasing integer that identifies each block (ledger) on the Stellar network.  Every transaction is committed inside a ledger with a specific sequence number.  In Soroban smart contracts, `env.ledger().sequence()` returns the current sequence.

### Ledger Timestamp
The Unix timestamp (in seconds) recorded when the current ledger was closed.  Accessible in contracts via `env.ledger().timestamp()`.

---

## Storage

### Instance Storage
A small, fast key–value store attached to a **deployed contract instance** (not to individual data keys).  Ideal for global configuration, admin addresses, and counters.  Data lives as long as the instance TTL is extended.

### Persistent Storage
A key–value store for data that must survive beyond the instance lifetime.  Each entry has its own independent TTL.  Used for per-user balances, allowances, and other data that grows with usage.

### Temporary Storage
A key–value store whose data is **automatically cleared** at the end of every transaction.  Useful for cross-contract call arguments or scratch state that should never persist.

### TTL (Time-To-Live)
The number of ledgers remaining before a storage entry is considered **archived** (no longer readable without a restore operation).  Every write to an entry can extend its TTL via `extend_ttl(threshold, extend_to)`.

### Archival
When a storage entry's TTL reaches zero, the entry is archived.  It still exists on-chain but cannot be read or written until a `RestoreFootprintOp` is submitted to extend its TTL.

---

## Fees & Resources

### Resource Fee
The fee charged for consuming Soroban VM resources (CPU instructions, memory, ledger I/O) during transaction execution.  Distinct from the base Stellar network fee.

### Base Fee
The minimum fee required for a transaction to be considered for inclusion in a ledger.  On Stellar this is currently 100 stroops (0.00001 XLM).

### Stroop
The smallest unit of XLM, equal to `10^-7` XLM (0.0000001 XLM).

---

## Authentication

### `require_auth()`
A Soroban SDK method that verifies an address has authorised the current invocation.  If the address has not signed the transaction, the host halts execution immediately (before the contract can return a custom error).

### Authorized Invocation
A contract function call where all addresses referenced by `require_auth()` have provided valid signatures.  Authorisation is enforced by the Soroban host, not by contract logic.

---

## Data Types

### `Address`
A Soroban type representing either an **account** (Ed25519 public key) or a **contract**.  Used for ownership, allowances, and role-based access control.

### `Symbol`
A short, human-readable string type optimised for Soroban storage (max 32 characters, ScVal-encoded).  Commonly used for event topics and map keys.

### `BytesN<N>`
A fixed-length byte array (e.g., `BytesN<32>` for a SHA-256 hash).  Used for WASM hashes, identifiers, and cryptographic digests.

---

## Events

### Contract Event
A structured log entry emitted by a smart contract via `env.events().publish(...)`.  Events are stored on-chain and can be queried by off-chain indexers.  Each event has a list of topics and a data payload.

### Topic
A list of up to 4 `ScVal` values that serve as an index for filtering events.  Topics are stored separately from the event body to enable efficient querying.

---

## Testing

### Testnet
The public Stellar test network.  Transactions are free (funded by a friendbot) but the network is occasionally reset, wiping all state.

### Local Sandbox
A standalone Soroban environment (via `soroban-cli` or the Rust `soroban-sdk` test utilities) that runs entirely in-memory.  Ideal for fast unit tests.

### Mock Auth
In tests, `env.mock_all_auths()` bypasses real signature verification so that `require_auth()` calls always succeed.  Used to test contract logic without setting up real keypairs.
