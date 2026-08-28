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
export declare class ComplianceDb {
    private db;
    private dbPath;
    private constructor();
    static open(dbPath: string): Promise<ComplianceDb>;
    private migrate;
    /** Flush the in-memory database to disk. */
    private flush;
    /** Apply a batch of events atomically, then flush to disk. */
    applyEvents(events: RawEvent[]): void;
    private insertEvent;
    private updateState;
    getState(key: string): string | undefined;
    setState(key: string, value: string): void;
    getLastIndexedLedger(): number;
    setLastIndexedLedger(ledger: number): void;
    close(): void;
}
//# sourceMappingURL=db.d.ts.map