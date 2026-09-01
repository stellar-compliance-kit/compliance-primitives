/**
 * Database layer — SQLite via sql.js (pure WebAssembly, no native build).
 *
 * sql.js operates in-memory and does not auto-persist to disk; we flush the
 * database file after every write batch so restarts pick up where they left
 * off.
 *
 * Schema
 * ──────
 *
 * events
 *   id              INTEGER PK AUTOINCREMENT
 *   ledger_sequence INTEGER NOT NULL
 *   timestamp       INTEGER            — Unix seconds (ledger close time)
 *   contract_id     TEXT NOT NULL
 *   event_type      TEXT NOT NULL      — AllowAdd | AllowRemove | Blocked |
 *                                        DenyAdd | DenyRemove | JurisdictionSet |
 *                                        SignerAdd | SignerRm | ThreshSet | AuthOk |
 *                                        AdminSet | DenylistGateSet |
 *                                        JurisdictionFlagSet | PolicyResult |
 *                                        Frozen | Unfrozen
 *   address         TEXT               — primary subject address; also holds the
 *                                        newly configured address for aggregator
 *                                        config events (AdminSet etc.)
 *   address_to      TEXT               — secondary address (Blocked only)
 *   amount          TEXT               — i128 as decimal string (Blocked only)
 *   jurisdiction    TEXT               — ISO code (JurisdictionSet only)
 *   signer_address  TEXT               — affected signer (SignerAdd/SignerRm only)
 *   new_threshold   INTEGER            — new threshold value (ThreshSet only)
 *   valid_count     INTEGER            — valid signature count (AuthOk only)
 *   policy_from     TEXT               — sender address (PolicyResult only)
 *   policy_to       TEXT               — receiver address (PolicyResult only)
 *   policy_passed   INTEGER            — 1=pass, 0=fail, NULL otherwise
 *   raw_topics      TEXT NOT NULL      — JSON array of base64-XDR topic strings
 *   raw_data        TEXT NOT NULL      — base64-XDR data value
 *
 * allowlist          — materialised current state
 *   contract_id TEXT NOT NULL
 *   address     TEXT NOT NULL
 *   PRIMARY KEY (contract_id, address)
 *
 * denylist           — materialised current state
 *   contract_id TEXT NOT NULL
 *   address     TEXT NOT NULL
 *   PRIMARY KEY (contract_id, address)
 *
 * jurisdictions      — materialised current state (last write wins)
 *   contract_id TEXT NOT NULL
 *   address     TEXT NOT NULL
 *   code        TEXT NOT NULL
 *   PRIMARY KEY (contract_id, address)
 *
 * multisig_signers     — current signer set per multisig-admin contract
 *   contract_id TEXT NOT NULL
 *   address     TEXT NOT NULL
 *   PRIMARY KEY (contract_id, address)
 *
 * multisig_threshold   — current threshold per multisig-admin contract
 *   contract_id TEXT PK
 *   threshold   INTEGER NOT NULL
 *
 * aggregator_config  — current gate/flag addresses per aggregator contract
 *   contract_id      TEXT NOT NULL     — the aggregator contract
 *   config_key       TEXT NOT NULL     — "admin" | "denylist_gate" | "jurisdiction_flag"
 *   config_address   TEXT NOT NULL     — the currently configured address
 *   PRIMARY KEY (contract_id, config_key)
 *
 * circuit_breaker_state — current frozen/unfrozen state per circuit-breaker
 *   contract_id TEXT PRIMARY KEY
 *   is_frozen   INTEGER NOT NULL       — 1 = frozen, 0 = unfrozen
 *
 * indexer_state      — internal key/value (stores last_ledger)
 *   key   TEXT PK
 *   value TEXT NOT NULL
 */

import fs from "node:fs";
import initSqlJs from "sql.js";
import type { Database, SqlJsStatic } from "sql.js";

export interface RawEvent {
  ledgerSequence: number;
  timestamp: number | null;
  contractId: string;
  eventType: string;
  address: string | null;
  addressTo: string | null;
  amount: string | null;
  jurisdiction: string | null;
  /** For multisig SignerAdd / SignerRm: the signer address affected. */
  signerAddress: string | null;
  /** For multisig ThreshSet: the new threshold value. */
  newThreshold: number | null;
  /** For multisig AuthOk: the number of valid signatures counted. */
  validCount: number | null;
  /** Sender address for PolicyResult events. */
  policyFrom: string | null;
  /** Receiver address for PolicyResult events. */
  policyTo: string | null;
  /** Pass/fail result for PolicyResult events; null for all other event types. */
  policyPassed: boolean | null;
  rawTopics: string;
  rawData: string;
}

// sql.js is loaded once as a module-level singleton
let SQL: SqlJsStatic | null = null;
async function getSql(): Promise<SqlJsStatic> {
  if (!SQL) SQL = await initSqlJs();
  return SQL;
}

export class ComplianceDb {
  private db!: Database;
  private dbPath: string;

  private constructor(dbPath: string) {
    this.dbPath = dbPath;
  }

  static async open(dbPath: string): Promise<ComplianceDb> {
    const sql = await getSql();
    const inst = new ComplianceDb(dbPath);

    if (fs.existsSync(dbPath)) {
      const data = fs.readFileSync(dbPath);
      inst.db = new sql.Database(data);
    } else {
      inst.db = new sql.Database();
    }

    inst.migrate();
    return inst;
  }

  private migrate(): void {
    this.db.run(`
      CREATE TABLE IF NOT EXISTS events (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        ledger_sequence INTEGER NOT NULL,
        timestamp       INTEGER,
        contract_id     TEXT    NOT NULL,
        event_type      TEXT    NOT NULL,
        address         TEXT,
        address_to      TEXT,
        amount          TEXT,
        jurisdiction    TEXT,
        signer_address  TEXT,
        new_threshold   INTEGER,
        valid_count     INTEGER,
        policy_from     TEXT,
        policy_to       TEXT,
        policy_passed   INTEGER,
        raw_topics      TEXT    NOT NULL,
        raw_data        TEXT    NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_events_contract
        ON events (contract_id);
      CREATE INDEX IF NOT EXISTS idx_events_address
        ON events (address);
      CREATE INDEX IF NOT EXISTS idx_events_type
        ON events (event_type);
      CREATE INDEX IF NOT EXISTS idx_events_ledger
        ON events (ledger_sequence);
      CREATE INDEX IF NOT EXISTS idx_events_signer
        ON events (signer_address);
      CREATE INDEX IF NOT EXISTS idx_events_policy_from
        ON events (policy_from);
      CREATE INDEX IF NOT EXISTS idx_events_policy_to
        ON events (policy_to);

      CREATE TABLE IF NOT EXISTS allowlist (
        contract_id TEXT NOT NULL,
        address     TEXT NOT NULL,
        PRIMARY KEY (contract_id, address)
      );

      CREATE TABLE IF NOT EXISTS denylist (
        contract_id TEXT NOT NULL,
        address     TEXT NOT NULL,
        PRIMARY KEY (contract_id, address)
      );

      CREATE TABLE IF NOT EXISTS jurisdictions (
        contract_id TEXT NOT NULL,
        address     TEXT NOT NULL,
        code        TEXT NOT NULL,
        PRIMARY KEY (contract_id, address)
      );

      CREATE TABLE IF NOT EXISTS multisig_signers (
        contract_id TEXT NOT NULL,
        address     TEXT NOT NULL,
        PRIMARY KEY (contract_id, address)
      );

      CREATE TABLE IF NOT EXISTS multisig_threshold (
        contract_id TEXT PRIMARY KEY,
        threshold   INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS aggregator_config (
        contract_id    TEXT NOT NULL,
        config_key     TEXT NOT NULL,
        config_address TEXT NOT NULL,
        PRIMARY KEY (contract_id, config_key)
      );

      CREATE TABLE IF NOT EXISTS circuit_breaker_state (
        contract_id TEXT PRIMARY KEY,
        is_frozen   INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS indexer_state (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
    `);
    this.flush();
  }

  /** Flush the in-memory database to disk. */
  private flush(): void {
    const data = this.db.export();
    fs.writeFileSync(this.dbPath, Buffer.from(data));
  }

  /** Apply a batch of events atomically, then flush to disk. */
  applyEvents(events: RawEvent[]): void {
    this.db.run("BEGIN");
    try {
      for (const e of events) {
        this.insertEvent(e);
        this.updateState(e);
      }
      this.db.run("COMMIT");
    } catch (err) {
      this.db.run("ROLLBACK");
      throw err;
    }
    this.flush();
  }

  private insertEvent(e: RawEvent): void {
    this.db.run(
      `INSERT INTO events
         (ledger_sequence, timestamp, contract_id, event_type,
          address, address_to, amount, jurisdiction,
          signer_address, new_threshold, valid_count,
          policy_from, policy_to, policy_passed,
          raw_topics, raw_data)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      [
        e.ledgerSequence,
        e.timestamp,
        e.contractId,
        e.eventType,
        e.address,
        e.addressTo,
        e.amount,
        e.jurisdiction,
        e.signerAddress,
        e.newThreshold,
        e.validCount,
        e.policyFrom,
        e.policyTo,
        e.policyPassed === null ? null : e.policyPassed ? 1 : 0,
        e.rawTopics,
        e.rawData,
      ]
    );
  }

  private updateState(e: RawEvent): void {
    switch (e.eventType) {
      case "AllowAdd":
        if (e.address) {
          this.db.run(
            "INSERT OR IGNORE INTO allowlist (contract_id, address) VALUES (?,?)",
            [e.contractId, e.address]
          );
        }
        break;
      case "AllowRemove":
        if (e.address) {
          this.db.run(
            "DELETE FROM allowlist WHERE contract_id = ? AND address = ?",
            [e.contractId, e.address]
          );
        }
        break;
      case "DenyAdd":
        if (e.address) {
          this.db.run(
            "INSERT OR IGNORE INTO denylist (contract_id, address) VALUES (?,?)",
            [e.contractId, e.address]
          );
        }
        break;
      case "DenyRemove":
        if (e.address) {
          this.db.run(
            "DELETE FROM denylist WHERE contract_id = ? AND address = ?",
            [e.contractId, e.address]
          );
        }
        break;
      case "JurisdictionSet":
        if (e.address && e.jurisdiction) {
          this.db.run(
            `INSERT INTO jurisdictions (contract_id, address, code) VALUES (?,?,?)
             ON CONFLICT (contract_id, address) DO UPDATE SET code = excluded.code`,
            [e.contractId, e.address, e.jurisdiction]
          );
        }
        break;
      // Blocked: recorded in events log only, no state change

      case "SignerAdd":
        if (e.signerAddress) {
          this.db.run(
            "INSERT OR IGNORE INTO multisig_signers (contract_id, address) VALUES (?,?)",
            [e.contractId, e.signerAddress]
          );
        }
        break;

      case "SignerRm":
        if (e.signerAddress) {
          this.db.run(
            "DELETE FROM multisig_signers WHERE contract_id = ? AND address = ?",
            [e.contractId, e.signerAddress]
          );
        }
        break;

      case "ThreshSet":
        if (e.newThreshold !== null) {
          this.db.run(
            `INSERT INTO multisig_threshold (contract_id, threshold) VALUES (?,?)
             ON CONFLICT (contract_id) DO UPDATE SET threshold = excluded.threshold`,
            [e.contractId, e.newThreshold]
          );
        }
        break;

      // AuthOk: recorded in events log only (valid_count + new_threshold columns),
      // no separate state table — governance history is queryable via the events log.

      // ── compliance-aggregator configuration events ──────────────────────────
      // Upsert into aggregator_config so the current wiring is always queryable.

      case "AdminSet":
        if (e.address) {
          this.db.run(
            `INSERT INTO aggregator_config (contract_id, config_key, config_address) VALUES (?,?,?)
             ON CONFLICT (contract_id, config_key) DO UPDATE SET config_address = excluded.config_address`,
            [e.contractId, "admin", e.address]
          );
        }
        break;

      case "DenylistGateSet":
        if (e.address) {
          this.db.run(
            `INSERT INTO aggregator_config (contract_id, config_key, config_address) VALUES (?,?,?)
             ON CONFLICT (contract_id, config_key) DO UPDATE SET config_address = excluded.config_address`,
            [e.contractId, "denylist_gate", e.address]
          );
        }
        break;

      case "JurisdictionFlagSet":
        if (e.address) {
          this.db.run(
            `INSERT INTO aggregator_config (contract_id, config_key, config_address) VALUES (?,?,?)
             ON CONFLICT (contract_id, config_key) DO UPDATE SET config_address = excluded.config_address`,
            [e.contractId, "jurisdiction_flag", e.address]
          );
        }
        break;

      // PolicyResult: recorded in events log only (policy_from, policy_to,
      // policy_passed columns). No separate state table — full evaluation
      // history is queryable directly via:
      //   SELECT * FROM events WHERE event_type='PolicyResult' AND contract_id=?

      // ── circuit-breaker state-change events ────────────────────────────────
      // Upsert so the current freeze state is always queryable:
      //   SELECT is_frozen FROM circuit_breaker_state WHERE contract_id = ?
      case "Frozen":
        this.db.run(
          `INSERT INTO circuit_breaker_state (contract_id, is_frozen) VALUES (?,1)
           ON CONFLICT (contract_id) DO UPDATE SET is_frozen = 1`,
          [e.contractId]
        );
        break;
      case "Unfrozen":
        this.db.run(
          `INSERT INTO circuit_breaker_state (contract_id, is_frozen) VALUES (?,0)
           ON CONFLICT (contract_id) DO UPDATE SET is_frozen = 0`,
          [e.contractId]
        );
        break;
    }
  }

  getState(key: string): string | undefined {
    const res = this.db.exec(
      "SELECT value FROM indexer_state WHERE key = ?",
      [key]
    );
    if (res.length === 0 || res[0].values.length === 0) return undefined;
    return String(res[0].values[0][0]);
  }

  setState(key: string, value: string): void {
    this.db.run(
      `INSERT INTO indexer_state (key, value) VALUES (?,?)
       ON CONFLICT (key) DO UPDATE SET value = excluded.value`,
      [key, value]
    );
    this.flush();
  }

  getLastIndexedLedger(): number {
    const v = this.getState("last_ledger");
    return v ? Number(v) : 0;
  }

  setLastIndexedLedger(ledger: number): void {
    this.setState("last_ledger", String(ledger));
  }

  close(): void {
    this.flush();
    this.db.close();
  }
}
