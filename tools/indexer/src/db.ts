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
 *                                        DenyAdd | DenyRemove | JurisdictionSet
 *   address         TEXT               — primary subject address
 *   address_to      TEXT               — secondary address (Blocked only)
 *   amount          TEXT               — i128 as decimal string (Blocked only)
 *   jurisdiction    TEXT               — ISO code (JurisdictionSet only)
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
 * indexer_state      — internal key/value (stores last_ledger)
 *   key   TEXT PK
 *   value TEXT NOT NULL
 */

import fs from "node:fs";
import initSqlJs from "sql.js/dist/sql-asm.js";
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
  rawTopics: string;
  rawData: string;
}

// sql.js is loaded once as a module-level singleton
let SQL: SqlJsStatic | null = null;
async function getSql(): Promise<SqlJsStatic> {
  if (!SQL) {
    SQL = await initSqlJs({
      locateFile: (file: string) => new URL(`../node_modules/sql.js/dist/${file}`, import.meta.url).pathname,
    });
  }
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
    this.db.run(`CREATE TABLE IF NOT EXISTS schema_migrations (
      version INTEGER PRIMARY KEY,
      applied_at TEXT NOT NULL
    );`);
    const currentVersion = this.db.exec("SELECT COALESCE(MAX(version), 0) AS version FROM schema_migrations")[0]?.values[0]?.[0] as number ?? 0;
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

      CREATE TABLE IF NOT EXISTS indexer_state (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
    `);
    if (currentVersion < 1) {
      this.db.run("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)", [1, new Date().toISOString()]);
    }
    if (currentVersion < 2) {
      const columns = this.db.exec("PRAGMA table_info(events)")[0]?.values.map((row) => String(row[1])) ?? [];
      if (!columns.includes("source_tx_hash")) this.db.run("ALTER TABLE events ADD COLUMN source_tx_hash TEXT");
      this.db.run("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)", [2, new Date().toISOString()]);
    }
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
          address, address_to, amount, jurisdiction, raw_topics, raw_data)
       VALUES (?,?,?,?,?,?,?,?,?,?)`,
      [
        e.ledgerSequence,
        e.timestamp,
        e.contractId,
        e.eventType,
        e.address,
        e.addressTo,
        e.amount,
        e.jurisdiction,
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

  getEventCount(contractId?: string): number {
    const result = contractId
      ? this.db.exec("SELECT COUNT(*) AS count FROM events WHERE contract_id = ?", [contractId])
      : this.db.exec("SELECT COUNT(*) AS count FROM events");
    return Number(result[0]?.values[0]?.[0] ?? 0);
  }

  isAllowlisted(contractId: string, address: string): boolean {
    const result = this.db.exec("SELECT 1 FROM allowlist WHERE contract_id = ? AND address = ?", [contractId, address]);
    return result.length > 0 && result[0].values.length > 0;
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
