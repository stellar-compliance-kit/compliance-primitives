/**
 * Thin wrapper around Soroban RPC's getEvents endpoint.
 *
 * We deliberately use the raw HTTP JSON-RPC interface rather than pulling in
 * a full SDK — the only call we need is getEvents, and keeping deps minimal
 * makes this easier to port to other runtimes.
 *
 * Spec: https://developers.stellar.org/network/soroban-rpc/api-reference/methods/getEvents
 */

export interface SorobanEventFilter {
  type: "contract";
  contractIds: string[];
}

export interface GetEventsParams {
  startLedger: number;
  filters: SorobanEventFilter[];
  pagination?: { limit?: number; cursor?: string };
}

export interface RawSorobanEvent {
  type: string;
  ledger: number;
  ledgerClosedAt: string; // ISO-8601
  contractId: string;
  id: string;
  pagingToken: string;
  inSuccessfulContractCall: boolean;
  /** XDR-encoded topics */
  topic: string[];
  /** XDR-encoded data value */
  value: string;
}

export interface GetEventsResult {
  events: RawSorobanEvent[];
  latestLedger: number;
}

export interface SorobanRpcOptions {
  maxRetries?: number;
  baseDelayMs?: number;
  maxDelayMs?: number;
}

export class SorobanRpc {
  private nextId = 1;
  private readonly maxRetries: number;
  private readonly baseDelayMs: number;
  private readonly maxDelayMs: number;

  constructor(private readonly url: string, options: SorobanRpcOptions = {}) {
    this.maxRetries = options.maxRetries ?? 4;
    this.baseDelayMs = options.baseDelayMs ?? 250;
    this.maxDelayMs = options.maxDelayMs ?? 5000;
  }

  private async request<T>(method: string, params: object): Promise<T> {
    let lastError: unknown;
    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      try {
        const res = await fetch(this.url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: this.nextId++, method, params }) });
        const text = await res.text();
        if (!res.ok) {
          const error = new Error(`RPC HTTP error ${res.status}: ${text}`);
          if (!this.isTransientStatus(res.status)) throw error;
          throw error;
        }
        const json = JSON.parse(text) as { result?: T; error?: { code: number; message: string } };
        if (json.error) {
          const error = new Error(`RPC error ${json.error.code}: ${json.error.message}`);
          if (!this.isTransientStatus(json.error.code)) throw error;
          throw error;
        }
        if (json.result === undefined) throw new Error(`RPC ${method} returned neither result nor error`);
        return json.result;
      } catch (error) {
        lastError = error;
        if (attempt === this.maxRetries || !this.isTransientError(error)) throw error;
        const delay = Math.min(this.maxDelayMs, this.baseDelayMs * 2 ** attempt);
        await new Promise((resolve) => setTimeout(resolve, delay));
      }
    }
    throw lastError instanceof Error ? lastError : new Error(String(lastError));
  }

  private isTransientStatus(statusOrCode: number): boolean {
    return statusOrCode === 408 || statusOrCode === 425 || statusOrCode === 429 || statusOrCode >= 500 || statusOrCode === -32000 || statusOrCode === -32603;
  }

  private isTransientError(error: unknown): boolean {
    if (!(error instanceof Error)) return true;
    const match = error.message.match(/RPC (?:HTTP error|error) (-?\\d+)/);
    return match ? this.isTransientStatus(Number(match[1])) : true;
  }

  async getEvents(params: GetEventsParams): Promise<GetEventsResult> {
    return this.request<GetEventsResult>("getEvents", { startLedger: params.startLedger, filters: params.filters, pagination: params.pagination ?? { limit: 200 } });
  }

  /** Fetch the latest known ledger sequence (cheap liveness check). */
  async getLatestLedger(): Promise<number> {
    const result = await this.request<{ sequence: number }>("getLatestLedger", {});
    return result.sequence;
  }
}
