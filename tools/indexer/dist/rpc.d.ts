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
    pagination?: {
        limit?: number;
        cursor?: string;
    };
}
export interface RawSorobanEvent {
    type: string;
    ledger: number;
    ledgerClosedAt: string;
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
export declare class SorobanRpc {
    private readonly url;
    private nextId;
    constructor(url: string);
    getEvents(params: GetEventsParams): Promise<GetEventsResult>;
    /** Fetch the latest known ledger sequence (cheap liveness check). */
    getLatestLedger(): Promise<number>;
}
//# sourceMappingURL=rpc.d.ts.map