# compliance-indexer

An off-chain reference indexer that subscribes to events emitted by the three
`compliance-primitives` contracts and materialises them into a local SQLite
database. Issuers can query the database directly or build a thin API on top
of it — this is the foundation, not the full product.

## Stack choice

| Component | Choice | Why |
|-----------|--------|-----|
| Runtime | Node.js 20+ | Ships everywhere, native `fetch`, zero install friction |
| Language | TypeScript | Type safety without a heavy compile step (`tsx` for dev) |
| Database | SQLite ([sql.js](https://sql.js.org)) | Pure WebAssembly — no native build step, no compiler toolchain required |
| RPC | Raw JSON-RPC (`getEvents`) | Minimal deps; only one RPC method is needed |

`sql.js` runs SQLite entirely in WebAssembly and holds the database
in-memory. The indexer exports the in-memory state to disk after every
write batch, so restarts resume from the last checkpoint. The database
file (default: `compliance.db`) is a standard SQLite file — you can open
it with any SQLite tool (`sqlite3`, DB Browser for SQLite, etc.).

To use Postgres instead of SQLite, swap `sql.js` for `pg` and translate
the SQL in `src/db.ts` — the schema is plain ANSI SQL.

---

## Setup

**Prerequisite:** Node.js 20 or later.

```sh
cd tools/indexer
npm install

cp .env.example .env
# Edit .env — set RPC_URL, DB_PATH, and at least one contract ID
```

Run in dev mode (no compile step, `tsx` runs TypeScript directly):

```sh
npm run dev
```

Build and run (TypeScript compiled to `dist/`, then executed with `node`):

```sh
npm run build   # emits compiled JS to dist/
npm start       # runs dist/index.js
```

---

## Docker

### Build the image

Run from the **repository root** (so Docker has access to the full build
context) or from within `tools/indexer`:

```sh
# From repository root
docker build -t compliance-indexer:latest tools/indexer

# From tools/indexer
docker build -t compliance-indexer:latest .
```

The image uses a two-stage build: the `builder` stage compiles TypeScript and
prunes dev dependencies; the `runtime` stage copies only the compiled output
and production `node_modules`, keeping the final image small.

### Run the container

Copy `.env.example` to `.env`, fill in your contract IDs and RPC URL, then:

```sh
docker run --rm \
  --env-file tools/indexer/.env \
  -v compliance-db:/data \
  compliance-indexer:latest
```

`-v compliance-db:/data` mounts a named Docker volume so the SQLite database
(`/data/compliance.db`) persists across container restarts. You can swap
`/data` for any host path you prefer.

To override individual variables without a full `.env` file:

```sh
docker run --rm \
  -e RPC_URL=https://soroban-testnet.stellar.org \
  -e NETWORK_PASSPHRASE="Test SDF Network ; September 2015" \
  -e DENYLIST_CONTRACT_ID=C... \
  -v compliance-db:/data \
  compliance-indexer:latest
```

> **Note:** No secrets are baked into the image. All configuration is
> supplied at runtime via environment variables.

---

## npm package

The indexer is published as `compliance-indexer` with compiled JavaScript and TypeScript declarations. Install a released version in an issuer or reporting service with:

```sh
npm install compliance-indexer
```

The package root exposes the reusable `SorobanRpc`, `Indexer`, `ComplianceDb`, and event-decoding primitives without starting the poll loop. The command-line runner remains available as `compliance-indexer` after building or installing the package.

```ts
import { ComplianceDb, Indexer, loadConfig } from "compliance-indexer";

const config = loadConfig();
const db = await ComplianceDb.open(config.dbPath);
const indexer = new Indexer(config, db);
indexer.start();
```

The repository’s `prepublishOnly` hook runs typechecking, lint, build, and tests before a release is packed.

---

## Configuration (`.env`)

| Variable | Default | Description |
|----------|---------|-------------|
| `RPC_URL` | _(required)_ | Absolute Soroban HTTP(S) RPC endpoint |
| `NETWORK_PASSPHRASE` | testnet passphrase | Network passphrase |
| `ALLOWLIST_CONTRACT_ID` | _(optional)_ | Contract ID of your `allowlist-token` deployment; at least one contract ID is required |
| `DENYLIST_CONTRACT_ID` | _(empty)_ | Contract ID of your `denylist-gate` deployment |
| `JURISDICTION_CONTRACT_ID` | _(empty)_ | Contract ID of your `jurisdiction-flag` deployment |
| `DB_PATH` | _(required)_ | SQLite file path |
| `POLL_INTERVAL_MS` | `5000` | How often to poll the RPC node; transient failures use exponential backoff |
| `START_LEDGER` | `0` | Ledger to start from (0 = auto ~24h ago) |

---

## Database schema

`src/db.ts` is the source of truth: it creates the schema in `migrate()` and
keeps the materialised tables up to date in `updateState()`. Every table,
column, index and migration below is taken from those two functions, so you can
build a dashboard or a reporting query against `compliance.db` without reading
the TypeScript first — see
[Keeping this section in sync](#keeping-this-section-in-sync) for the rule that
keeps it that way.

The indexer writes to **seven** tables, in three groups:

| Group | Tables | Purpose |
|-------|--------|---------|
| Raw log | `events` | Every observed event, in ledger order |
| Materialised state | `allowlist`, `denylist`, `jurisdictions`, `audit_log` | Current/append-only views derived from `events` |
| Bookkeeping | `indexer_state`, `schema_migrations` | Resume point and applied migrations |

### `events` — raw audit log

Every compliance event that has ever been observed, in ledger order. This is the
only table that holds the undecoded event payloads (`raw_topics`, `raw_data`).

| Column | Type | Description |
|--------|------|-------------|
| `id` | `INTEGER` PK | Auto-increment |
| `ledger_sequence` | `INTEGER` NOT NULL | Ledger the event landed in |
| `timestamp` | `INTEGER` | Unix seconds (from ledger close time); `NULL` if the RPC node didn't return a close time |
| `contract_id` | `TEXT` NOT NULL | Emitting contract |
| `event_type` | `TEXT` NOT NULL | `AllowAdd` \| `AllowRemove` \| `Blocked` \| `DenyAdd` \| `DenyRemove` \| `JurisdictionSet` \| `ComplianceEvent` |
| `address` | `TEXT` | Primary subject address (for `ComplianceEvent` this is the audit-log *subject*) |
| `address_to` | `TEXT` | Secondary address (`Blocked` only) |
| `amount` | `TEXT` | Transfer amount as decimal string (`Blocked` only) |
| `jurisdiction` | `TEXT` | ISO jurisdiction code (`JurisdictionSet` only) |
| `kind` | `TEXT` | Audit-log event kind symbol (`ComplianceEvent` only, e.g. `deny_add`) |
| `source` | `TEXT` | Address that called `record()` on audit-log (`ComplianceEvent` only) |
| `detail` | `TEXT` | Free-form audit-log detail string (`ComplianceEvent` only) |
| `raw_topics` | `TEXT` NOT NULL | JSON array of base64-XDR topic values |
| `raw_data` | `TEXT` NOT NULL | Base64-XDR data value |
| `source_tx_hash` | `TEXT` | Added in migration v2; source transaction hash when known |

Indexes: `idx_events_contract (contract_id)`, `idx_events_address (address)`,
`idx_events_type (event_type)`, `idx_events_ledger (ledger_sequence)`.

`event_type` decides which materialised table an event also writes to — see each
table below.

### `allowlist` — current membership

`AllowAdd` inserts (`INSERT OR IGNORE`), `AllowRemove` deletes. One row per
allowlisted address per contract.

| Column | Type | Description |
|--------|------|-------------|
| `contract_id` | `TEXT` NOT NULL | Which allowlist-token contract |
| `address` | `TEXT` NOT NULL | Address currently on the allowlist |

Primary key `(contract_id, address)`. Query the full current set with:

```sql
SELECT address FROM allowlist WHERE contract_id = '<your-contract-id>';
```

### `denylist` — current membership

Same structure and same add/remove semantics as `allowlist` (`DenyAdd` /
`DenyRemove`).

| Column | Type | Description |
|--------|------|-------------|
| `contract_id` | `TEXT` NOT NULL | Which denylist-gate contract |
| `address` | `TEXT` NOT NULL | Address currently on the denylist |

Primary key `(contract_id, address)`.

```sql
SELECT address FROM denylist WHERE contract_id = '<your-contract-id>';
```

### `jurisdictions` — current assignments

One row per address per contract; the last `JurisdictionSet` wins (upsert on
`ON CONFLICT (contract_id, address)`).

| Column | Type | Description |
|--------|------|-------------|
| `contract_id` | `TEXT` NOT NULL | Which jurisdiction-flag contract |
| `address` | `TEXT` NOT NULL | Address the code applies to |
| `code` | `TEXT` NOT NULL | ISO jurisdiction code (e.g. `US`) |

Primary key `(contract_id, address)`. Query with:

```sql
SELECT address, code FROM jurisdictions WHERE contract_id = '<your-contract-id>';
-- Filter by jurisdiction:
SELECT address FROM jurisdictions WHERE contract_id = '...' AND code = 'US';
```

### `audit_log` — append-only decisions

Written for `ComplianceEvent` events, so a dashboard can read the audit trail
without decoding `events.raw_data`. Unlike the three tables above this one is
append-only: nothing updates or deletes rows here, and a `ComplianceEvent` does
**not** also change `allowlist`/`denylist`/`jurisdictions` (that only happens
for the `Allow*`/`Deny*`/`JurisdictionSet` event types).

| Column | Type | Description |
|--------|------|-------------|
| `id` | `INTEGER` PK | Auto-increment |
| `contract_id` | `TEXT` NOT NULL | Which audit-log contract emitted it |
| `ledger` | `INTEGER` NOT NULL | Ledger the entry landed in |
| `timestamp` | `INTEGER` | Unix seconds (from ledger close time) |
| `kind` | `TEXT` NOT NULL | Event kind symbol (e.g. `deny_add`, `proposal_approved`) |
| `subject` | `TEXT` NOT NULL | Address the entry is about (from the event's `address`) |
| `source` | `TEXT` NOT NULL | Address that called `record()` |
| `detail` | `TEXT` NOT NULL | Free-form detail string; empty string when the event carries none |

Indexes: `idx_audit_log_contract (contract_id)`,
`idx_audit_log_subject (subject)`, `idx_audit_log_kind (kind)`.

```sql
SELECT ledger, timestamp, kind, subject, source, detail
FROM audit_log
WHERE contract_id = 'C...'
ORDER BY ledger;
```

### `indexer_state` — internal key/value store

| Column | Type | Description |
|--------|------|-------------|
| `key` | `TEXT` PK | Key name |
| `value` | `TEXT` NOT NULL | Value for the key |

Currently stores one row: `key = 'last_ledger'`, `value = <ledger sequence>`. On
startup the indexer reads this row to resume from where it left off rather than
re-scanning from the beginning.

### `schema_migrations` — migration history

| Column | Type | Description |
|--------|------|-------------|
| `version` | `INTEGER` PK | Applied schema version |
| `applied_at` | `TEXT` NOT NULL | ISO-8601 timestamp of when it was applied |

The indexer records each applied schema version here. Migrations are additive
and run at startup (`v1` creates the tables above, `v2` adds
`events.source_tx_hash`), so upgrading the indexer preserves existing events and
materialised state.

### Keeping this section in sync

This reference is maintained alongside `src/db.ts` — it is described from the
same file that creates the schema, and it is updated in the same PR as any
schema change. If you add, rename, or drop a column or table in
`migrate()`/`updateState()`:

1. Add the matching row to the relevant table above.
2. If the change is a new column on an existing database, add a migration block
   (`schema_migrations` version + `ALTER TABLE`) — the tables are created with
   `CREATE TABLE IF NOT EXISTS`, so an existing `compliance.db` only picks up
   changes through a migration.
3. Add or update a focused test in `src/db.test.ts` that asserts the new column
   or table, so the drift is caught in CI rather than in someone's dashboard.

#### Known drift (as of the current `src/db.ts`)

Two mismatches between `src/db.ts` and what it can actually create are worth
knowing about before you query the database:

- The file declares three indexes on columns the `events` table never gets —
  `idx_events_signer (signer_address)`,
  `idx_events_policy_from (policy_from)`, `idx_events_policy_to (policy_to)`.
  `ComplianceDb.open()` runs them in `migrate()` and throws
  `no such column: signer_address`, so the DB layer fails before the indexer
  starts; `src/db.test.ts` fails the same way. Either the columns or the
  indexes need to be reconciled.
- The schema comment at the top of `src/db.ts` lists `multisig_signers`,
  `multisig_threshold`, `aggregator_config`, and `circuit_breaker_state`, but
  `migrate()` creates none of them and `updateState()` never writes them.
  Multisig and aggregator events currently land in `events` only.

Both are code-side issues rather than documentation ones — they are recorded
here so the table list above can be trusted as the schema that actually exists.

---

## Example queries

```sql
-- All addresses currently on the denylist
SELECT address FROM denylist WHERE contract_id = 'C...';

-- Full history for one address
SELECT ledger_sequence, timestamp, event_type, contract_id
FROM events
WHERE address = 'G...' OR address_to = 'G...'
ORDER BY ledger_sequence;

-- Blocked transfer attempts in the last 1000 ledgers
SELECT ledger_sequence, address AS from_addr, address_to, amount
FROM events
WHERE event_type = 'Blocked'
  AND ledger_sequence > (SELECT CAST(value AS INTEGER) FROM indexer_state WHERE key = 'last_ledger') - 1000;

-- Addresses that have ever been on the allowlist but are no longer
SELECT DISTINCT e.address
FROM events e
WHERE e.event_type = 'AllowAdd'
  AND NOT EXISTS (
    SELECT 1 FROM allowlist a WHERE a.contract_id = e.contract_id AND a.address = e.address
  );
```

---

## How it works

1. On startup, reads `last_ledger` from `indexer_state`.
2. Calls `getEvents` on the Soroban RPC node, filtered to the configured
   contract IDs, from `last_ledger + 1` to `latestLedger`.
3. Decodes each event's XDR topics/data into typed structs.
4. Applies events to both the raw `events` log and the materialised state
   tables (`allowlist`, `denylist`, `jurisdictions`, `audit_log`) inside a
   single SQLite transaction per poll cycle.
5. Persists the new `last_ledger` and sleeps until the next poll. Transient HTTP, network, and retryable JSON-RPC failures are retried with bounded exponential backoff before the next scheduled poll.

Run the deterministic integration suite with `npm test`. It starts a local JSON-RPC fixture representing a deployed primitive contract, replays an `AllowAdd` state-changing event, and asserts both the raw event row and materialized allowlist row.

---

## Off-chain indexer vs. on-chain audit-log contract (#108)

These two approaches solve overlapping but different problems:

| | This indexer | On-chain audit-log (#108) |
|---|---|---|
| **Where data lives** | Off-chain SQLite/Postgres | On-chain Soroban storage |
| **Query flexibility** | Arbitrary SQL | Limited to contract views |
| **Cost** | Free (no ledger fees) | Every write costs XLM |
| **Trust model** | Operator must not tamper | Immutable, verifiable by anyone |
| **Queryable from contracts** | No | Yes (cross-contract call) |
| **Historical range** | Back to any indexed ledger | Back to contract deployment |
| **Operational complexity** | Requires a running service | Zero — it's just a contract |

**Use this indexer when** you need rich querying (filters, joins, aggregates),
want to power a dashboard or compliance reporting tool, or need to correlate
events across contracts without paying on-chain storage costs.

**Use the on-chain audit-log (#108) when** other contracts need to read the
compliance history directly, you need a tamper-proof on-chain record, or you
don't want to run a separate service.

**Use both** when you need both: the on-chain log for contract-to-contract
verifiability, and this indexer for cheap, flexible off-chain reporting.

---

## Assumptions and known limitations

- **RPC retention window**: Soroban RPC nodes only retain events for a finite
  window (~7 days on testnet, configurable on mainnet). If the indexer is
  offline for longer than the retention window, events in that gap will be
  permanently missed. For a production deployment, run the indexer
  continuously or bootstrap from an archive node.

- **No gap detection**: the indexer does not detect or fill gaps. If a gap
  occurs, it will silently resume from `last_ledger + 1` with no warning.
  A production implementation should compare `last_ledger` against the
  node's `oldestLedger` response and alert if data has been pruned.

- **Single-node RPC**: there is no failover between multiple RPC endpoints.
  If the configured node is down, polls will error and retry next tick.

- **No XDR SDK dependency**: topics/data are decoded with a hand-rolled XDR
  reader. This covers the five event types in this repo exactly. If contract
  events gain new non-topic fields, `src/decoder.ts` will need updating.

- **Not production-hardened**: no authentication, no rate-limit handling, no
  metrics, no alerting. Treat this as a starting point, not a finished service.
