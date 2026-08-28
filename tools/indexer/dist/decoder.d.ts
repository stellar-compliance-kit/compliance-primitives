/**
 * Decodes raw Soroban event topics/data (base64-encoded XDR) into typed
 * compliance events.
 *
 * Soroban #[contractevent] structs with #[topic] fields are published as
 * a topic array where:
 *   topic[0]  = ScVal::Symbol — the event name (e.g. "AllowAdd")
 *   topic[1+] = the fields annotated #[topic] in declaration order
 *   data      = ScVal — struct-value encoding of any non-topic fields
 *
 * For the five event types in this repo:
 *
 *   AllowAdd        topics: [Symbol("AllowAdd"), Address]          data: Void
 *   AllowRemove     topics: [Symbol("AllowRemove"), Address]        data: Void
 *   Blocked         topics: [Symbol("Blocked"), Address, Address]   data: I128
 *   DenyAdd         topics: [Symbol("DenyAdd"), Address]            data: Void
 *   DenyRemove      topics: [Symbol("DenyRemove"), Address]         data: Void
 *   JurisdictionSet topics: [Symbol("JurisdictionSet"), Address]    data: String(code)
 *
 * We parse XDR manually using DataView — no external XDR lib — because the
 * values we need are simple enough and we want zero extra dependencies.
 * If you need full XDR fidelity, swap in @stellar/stellar-base.
 */
import type { RawSorobanEvent } from "./rpc.js";
import type { RawEvent } from "./db.js";
export declare function decodeEvent(raw: RawSorobanEvent): RawEvent | null;
//# sourceMappingURL=decoder.d.ts.map