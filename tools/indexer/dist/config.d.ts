/**
 * Configuration loaded from environment variables.
 * Copy .env.example to .env and fill in your values.
 */
export interface Config {
    /** Soroban RPC endpoint, e.g. https://soroban-testnet.stellar.org */
    rpcUrl: string;
    /** Network passphrase */
    networkPassphrase: string;
    /** Contract ID of the deployed allowlist-token contract (or empty to skip) */
    allowlistContractId: string;
    /** Contract ID of the deployed denylist-gate contract (or empty to skip) */
    denylistContractId: string;
    /** Contract ID of the deployed jurisdiction-flag contract (or empty to skip) */
    jurisdictionContractId: string;
    /** Path to the SQLite database file */
    dbPath: string;
    /** How often to poll for new events, in milliseconds */
    pollIntervalMs: number;
    /** Ledger sequence to start indexing from (0 = from the earliest available) */
    startLedger: number;
}
export declare function loadConfig(): Config;
//# sourceMappingURL=config.d.ts.map