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
  /** Contract ID of the deployed compliance-aggregator contract (or empty to skip) */
  aggregatorContractId: string;
  /** Contract ID of the deployed policy-engine contract (or empty to skip) */
  policyEngineContractId: string;
  /** Contract ID of the deployed multisig-admin contract (or empty to skip) */
  multisigContractId: string;
  /** Path to the SQLite database file */
  dbPath: string;
  /** How often to poll for new events, in milliseconds */
  pollIntervalMs: number;
  /** Ledger sequence to start indexing from (0 = from the earliest available) */
  startLedger: number;
}

export function loadConfig(): Config {
  const rpcUrl =
    process.env.RPC_URL ?? "https://soroban-testnet.stellar.org";
  const networkPassphrase =
    process.env.NETWORK_PASSPHRASE ??
    "Test SDF Network ; September 2015";

  const allowlistContractId    = process.env.ALLOWLIST_CONTRACT_ID    ?? "";
  const denylistContractId     = process.env.DENYLIST_CONTRACT_ID     ?? "";
  const jurisdictionContractId = process.env.JURISDICTION_CONTRACT_ID ?? "";
  const aggregatorContractId   = process.env.AGGREGATOR_CONTRACT_ID   ?? "";
  const policyEngineContractId = process.env.POLICY_ENGINE_CONTRACT_ID ?? "";
  const multisigContractId = process.env.MULTISIG_CONTRACT_ID ?? "";

  if (
    !allowlistContractId &&
    !denylistContractId &&
    !jurisdictionContractId &&
    !aggregatorContractId &&
    !policyEngineContractId &&
    !multisigContractId
  ) {
    console.warn(
      "Warning: no contract IDs configured — nothing will be indexed.\n" +
        "Set at least one of ALLOWLIST_CONTRACT_ID, DENYLIST_CONTRACT_ID, " +
        "JURISDICTION_CONTRACT_ID, AGGREGATOR_CONTRACT_ID, " +
        "POLICY_ENGINE_CONTRACT_ID, MULTISIG_CONTRACT_ID in your environment."
    );
  }

  return {
    rpcUrl,
    networkPassphrase,
    allowlistContractId,
    denylistContractId,
    jurisdictionContractId,
    aggregatorContractId,
    policyEngineContractId,
    multisigContractId,
    dbPath: process.env.DB_PATH ?? "compliance.db",
    pollIntervalMs: Number(process.env.POLL_INTERVAL_MS ?? "5000"),
    startLedger: Number(process.env.START_LEDGER ?? "0"),
  };
}
