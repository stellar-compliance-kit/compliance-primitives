/**
 * Core polling loop.
 *
 * On each tick:
 *  1. Call getEvents from (last_indexed_ledger + 1) to latestLedger
 *  2. Decode each event and apply it to the database
 *  3. Persist the new last_indexed_ledger
 *
 * Gaps / reconnections: this is a *reference* implementation so
 * reconnection and gap-filling are explicitly out of scope. If the process
 * dies and restarts, it resumes from last_indexed_ledger. If the RPC node
 * has pruned ledgers older than its retention window, events in the gap will
 * be missed — document this limitation rather than solving it here.
 */
import type { Config } from "./config.js";
import type { ComplianceDb } from "./db.js";
export declare class Indexer {
    private readonly config;
    private readonly db;
    private rpc;
    private timer;
    private running;
    constructor(config: Config, db: ComplianceDb);
    start(): void;
    stop(): void;
    private schedule;
    private tick;
    private poll;
    /**
     * Soroban RPC nodes only retain events for a finite window (~7 days on
     * testnet). If no startLedger is configured, we start from whatever the
     * node considers its oldest available ledger.
     *
     * We approximate this by fetching the latest ledger and subtracting the
     * typical retention window (17,280 ledgers ≈ 24h at 5s/ledger). A proper
     * implementation would call getLedgerEntries or use the node's
     * getLatestLedger response to discover the exact oldest available ledger.
     */
    private getEarliestAvailableLedger;
}
//# sourceMappingURL=indexer.d.ts.map