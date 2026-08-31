/**
 * Tests for decoder.ts — verifies event decoding logic for each event type.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { decodeEvent } from "./decoder.js";
import type { RawSorobanEvent } from "./rpc.js";

/**
 * Helper to create a minimal RawSorobanEvent for testing.
 * Real events have base64-encoded XDR in topic/value fields.
 */
function makeRawEvent(
  topic: string[],
  value: string,
  contractId = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
): RawSorobanEvent {
  return {
    type: "contract",
    ledger: 12345,
    ledgerClosedAt: "2024-01-15T10:00:00Z",
    contractId,
    id: "0-1",
    pagingToken: "0-1",
    topic,
    value,
    inSuccessfulContractCall: true,
  };
}

/**
 * Manually crafted XDR blobs for testing.
 * These are minimal valid XDR ScVal encodings.
 */
const XDR_SYMBOL_ALLOWADD = "AAAAD0FsbG93QWRkAA=="; // Symbol("AllowAdd")
const XDR_SYMBOL_ALLOWREMOVE = "AAAAD0FsbG93UmVtb3ZlAA=="; // Symbol("AllowRemove")
const XDR_SYMBOL_DENYADD = "AAAAD0RlbnlBZGQA"; // Symbol("DenyAdd")
const XDR_SYMBOL_DENYREMOVE = "AAAAD0RlbnlSZW1vdmUA"; // Symbol("DenyRemove")
const XDR_SYMBOL_BLOCKED = "AAAAD0Jsb2NrZWQA"; // Symbol("Blocked")
const XDR_SYMBOL_JURISDICTIONSET = "AAAAD0p1cmlzZGljdGlvblNldAA=="; // Symbol("JurisdictionSet")

// Sample G-address (account): GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4
const XDR_ADDRESS_ACCOUNT =
  "AAAASAAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";

// Sample contract address (32 zero bytes)
const XDR_ADDRESS_CONTRACT =
  "AAAAEgAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

const XDR_VOID = "AAAAAQ=="; // ScVal::Void
const XDR_STRING_US = "AAAADgAAAAJVUwAA"; // ScVal::String("US")
const XDR_I128_100 = "AAAACgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABk"; // ScVal::I128(100)

test("decodeEvent: AllowAdd", () => {
  const raw = makeRawEvent(
    [XDR_SYMBOL_ALLOWADD, XDR_ADDRESS_ACCOUNT],
    XDR_VOID
  );
  const decoded = decodeEvent(raw);
  assert.ok(decoded);
  assert.equal(decoded.eventType, "AllowAdd");
  assert.equal(decoded.contractId, raw.contractId);
  assert.equal(decoded.ledgerSequence, 12345);
  assert.ok(decoded.address?.startsWith("G"));
  assert.equal(decoded.addressTo, null);
  assert.equal(decoded.amount, null);
  assert.equal(decoded.jurisdiction, null);
});

test("decodeEvent: AllowRemove", () => {
  const raw = makeRawEvent(
    [XDR_SYMBOL_ALLOWREMOVE, XDR_ADDRESS_ACCOUNT],
    XDR_VOID
  );
  const decoded = decodeEvent(raw);
  assert.ok(decoded);
  assert.equal(decoded.eventType, "AllowRemove");
  assert.ok(decoded.address?.startsWith("G"));
});

test("decodeEvent: DenyAdd", () => {
  const raw = makeRawEvent([XDR_SYMBOL_DENYADD, XDR_ADDRESS_ACCOUNT], XDR_VOID);
  const decoded = decodeEvent(raw);
  assert.ok(decoded);
  assert.equal(decoded.eventType, "DenyAdd");
  assert.ok(decoded.address?.startsWith("G"));
});

test("decodeEvent: DenyRemove", () => {
  const raw = makeRawEvent(
    [XDR_SYMBOL_DENYREMOVE, XDR_ADDRESS_ACCOUNT],
    XDR_VOID
  );
  const decoded = decodeEvent(raw);
  assert.ok(decoded);
  assert.equal(decoded.eventType, "DenyRemove");
  assert.ok(decoded.address?.startsWith("G"));
});

test("decodeEvent: Blocked", () => {
  const raw = makeRawEvent(
    [XDR_SYMBOL_BLOCKED, XDR_ADDRESS_ACCOUNT, XDR_ADDRESS_ACCOUNT],
    XDR_I128_100
  );
  const decoded = decodeEvent(raw);
  assert.ok(decoded);
  assert.equal(decoded.eventType, "Blocked");
  assert.ok(decoded.address?.startsWith("G"));
  assert.ok(decoded.addressTo?.startsWith("G"));
  assert.equal(decoded.amount, "100");
});

test("decodeEvent: JurisdictionSet", () => {
  const raw = makeRawEvent(
    [XDR_SYMBOL_JURISDICTIONSET, XDR_ADDRESS_ACCOUNT],
    XDR_STRING_US
  );
  const decoded = decodeEvent(raw);
  assert.ok(decoded);
  assert.equal(decoded.eventType, "JurisdictionSet");
  assert.ok(decoded.address?.startsWith("G"));
  assert.equal(decoded.jurisdiction, "US");
});

test("decodeEvent: contract address", () => {
  const raw = makeRawEvent(
    [XDR_SYMBOL_DENYADD, XDR_ADDRESS_CONTRACT],
    XDR_VOID
  );
  const decoded = decodeEvent(raw);
  assert.ok(decoded);
  assert.equal(decoded.eventType, "DenyAdd");
  // Contract addresses are hex-encoded, 64 chars (32 bytes * 2)
  assert.equal(decoded.address?.length, 64);
  assert.match(decoded.address!, /^[0-9a-f]{64}$/);
});

test("decodeEvent: unknown event type returns null", () => {
  const XDR_SYMBOL_UNKNOWN = "AAAAD1Vua25vd25FdmVudAA="; // Symbol("UnknownEvent")
  const raw = makeRawEvent(
    [XDR_SYMBOL_UNKNOWN, XDR_ADDRESS_ACCOUNT],
    XDR_VOID
  );
  const decoded = decodeEvent(raw);
  assert.equal(decoded, null);
});

test("decodeEvent: malformed event returns null", () => {
  const raw = makeRawEvent([], XDR_VOID);
  const decoded = decodeEvent(raw);
  assert.equal(decoded, null);
});

test("decodeEvent: invalid base64 returns null", () => {
  const raw = makeRawEvent(["INVALID_BASE64!!!"], XDR_VOID);
  const decoded = decodeEvent(raw);
  assert.equal(decoded, null);
 * Unit tests for decoder.ts — multisig-admin event decoding.
 *
 * Fixtures are hand-crafted XDR bytes encoded as base64, produced to match
 * the exact wire format the `multisig-admin` contract emits:
 *
 *   SignerAdd   topics: [Symbol("SignerAdd"), Address]  data: Void
 *   SignerRm    topics: [Symbol("SignerRm"),  Address]  data: Void
 *   ThreshSet   topics: [Symbol("ThreshSet")]           data: U32(threshold)
 *   AuthOk      topics: [Symbol("AuthOk")]              data: Vec[U32(valid), U32(threshold)]
 *
 * The XDR is assembled using the same encoding rules the XdrReader in
 * decoder.ts expects, so these tests also implicitly validate that the
 * hand-rolled reader handles all four shapes correctly.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { decodeEvent } from "./decoder.js";
import type { RawSorobanEvent } from "./rpc.js";

// ─── XDR fixture helpers ──────────────────────────────────────────────────────

function u32Bytes(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, false);
  return b;
}

function xdrString(s: string): Uint8Array {
  const enc = new TextEncoder().encode(s);
  const pad = (4 - (enc.length % 4)) % 4;
  const out = new Uint8Array(4 + enc.length + pad);
  new DataView(out.buffer).setUint32(0, enc.length, false);
  out.set(enc, 4);
  return out;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let pos = 0;
  for (const p of parts) {
    out.set(p, pos);
    pos += p.length;
  }
  return out;
}

function toB64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

// ScType discriminants
const SC_VOID    = 1;
const SC_U32     = 3;
const SC_SYMBOL  = 15;
const SC_VEC     = 16;
const SC_ADDRESS = 18;
const SC_ACCOUNT = 0; // ScAddressType::Account
const SC_ED25519 = 0; // PublicKey type discriminant

function scVoid(): Uint8Array {
  return u32Bytes(SC_VOID);
}

function scSymbol(s: string): Uint8Array {
  return concat(u32Bytes(SC_SYMBOL), xdrString(s));
}

function scU32(n: number): Uint8Array {
  return concat(u32Bytes(SC_U32), u32Bytes(n));
}

/** Build a Vec ScVal containing the given pre-encoded ScVal items. */
function scVec(items: Uint8Array[]): Uint8Array {
  // XDR optional-vec encoding: present=1, then len, then items
  const parts: Uint8Array[] = [u32Bytes(SC_VEC), u32Bytes(1), u32Bytes(items.length)];
  for (const item of items) parts.push(item);
  return concat(...parts);
}

/**
 * Build an Account Address ScVal with a 32-byte key filled with `fill`.
 * Encoding: [SC_ADDRESS=18][SC_ACCOUNT=0][ED25519_type=0][32 bytes]
 */
function scAccountAddress(fill: number): Uint8Array {
  const key = new Uint8Array(32).fill(fill);
  return concat(u32Bytes(SC_ADDRESS), u32Bytes(SC_ACCOUNT), u32Bytes(SC_ED25519), key);
}

// ─── Expected decoded G-addresses ─────────────────────────────────────────────
// These were computed by running encodeG() from decoder.ts on the same keys.
const ADDR_AA = "GCVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVH7N";
const ADDR_BB = "GC53XO53XO53XO53XO53XO53XO53XO53XO53XO53XO53XO53XO53XUGE";

// ─── Shared raw event skeleton ────────────────────────────────────────────────
function makeRaw(
  topic: string[],
  value: string,
  overrides: Partial<RawSorobanEvent> = {}
): RawSorobanEvent {
  return {
    type: "contract",
    ledger: 1234,
    ledgerClosedAt: "2025-01-01T00:00:00Z",
    contractId: "CTEST",
    id: "0000-0001",
    pagingToken: "0000-0001",
    inSuccessfulContractCall: true,
    topic,
    value,
    ...overrides,
  };
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe("decodeEvent — multisig-admin events", () => {
  // ── SignerAdd ──────────────────────────────────────────────────────────────
  describe("SignerAdd", () => {
    it("decodes eventType, contractId, and signerAddress", () => {
      const raw = makeRaw(
        [toB64(scSymbol("SignerAdd")), toB64(scAccountAddress(0xaa))],
        toB64(scVoid())
      );
      const decoded = decodeEvent(raw);
      assert.ok(decoded !== null, "expected non-null decoded event");
      assert.equal(decoded.eventType, "SignerAdd");
      assert.equal(decoded.contractId, "CTEST");
      assert.equal(decoded.signerAddress, ADDR_AA);
      assert.equal(decoded.newThreshold, null);
      assert.equal(decoded.validCount, null);
      assert.equal(decoded.address, null);
    });

    it("records the ledger sequence and timestamp", () => {
      const raw = makeRaw(
        [toB64(scSymbol("SignerAdd")), toB64(scAccountAddress(0xaa))],
        toB64(scVoid())
      );
      const decoded = decodeEvent(raw);
      assert.ok(decoded !== null);
      assert.equal(decoded.ledgerSequence, 1234);
      assert.equal(decoded.timestamp, Math.floor(new Date("2025-01-01T00:00:00Z").getTime() / 1000));
    });

    it("returns null when signer topic is missing", () => {
      const raw = makeRaw([toB64(scSymbol("SignerAdd"))], toB64(scVoid()));
      assert.equal(decodeEvent(raw), null);
    });
  });

  // ── SignerRm ───────────────────────────────────────────────────────────────
  describe("SignerRm", () => {
    it("decodes eventType and signerAddress for the removed signer", () => {
      const raw = makeRaw(
        [toB64(scSymbol("SignerRm")), toB64(scAccountAddress(0xbb))],
        toB64(scVoid())
      );
      const decoded = decodeEvent(raw);
      assert.ok(decoded !== null);
      assert.equal(decoded.eventType, "SignerRm");
      assert.equal(decoded.signerAddress, ADDR_BB);
      assert.equal(decoded.newThreshold, null);
      assert.equal(decoded.validCount, null);
    });

    it("returns null when signer topic is missing", () => {
      const raw = makeRaw([toB64(scSymbol("SignerRm"))], toB64(scVoid()));
      assert.equal(decodeEvent(raw), null);
    });
  });

  // ── ThreshSet ─────────────────────────────────────────────────────────────
  describe("ThreshSet", () => {
    it("decodes newThreshold from the data U32", () => {
      const raw = makeRaw([toB64(scSymbol("ThreshSet"))], toB64(scU32(3)));
      const decoded = decodeEvent(raw);
      assert.ok(decoded !== null);
      assert.equal(decoded.eventType, "ThreshSet");
      assert.equal(decoded.newThreshold, 3);
      assert.equal(decoded.signerAddress, null);
      assert.equal(decoded.validCount, null);
    });

    it("decodes threshold value 1", () => {
      const raw = makeRaw([toB64(scSymbol("ThreshSet"))], toB64(scU32(1)));
      const decoded = decodeEvent(raw);
      assert.ok(decoded !== null);
      assert.equal(decoded.newThreshold, 1);
    });

    it("returns null when data is not a U32", () => {
      // Pass Void instead of U32 — decoder should return null
      const raw = makeRaw([toB64(scSymbol("ThreshSet"))], toB64(scVoid()));
      assert.equal(decodeEvent(raw), null);
    });
  });

  // ── AuthOk ────────────────────────────────────────────────────────────────
  describe("AuthOk", () => {
    it("decodes validCount and newThreshold from the Vec data", () => {
      const raw = makeRaw(
        [toB64(scSymbol("AuthOk"))],
        toB64(scVec([scU32(2), scU32(3)]))
      );
      const decoded = decodeEvent(raw);
      assert.ok(decoded !== null);
      assert.equal(decoded.eventType, "AuthOk");
      assert.equal(decoded.validCount, 2);
      assert.equal(decoded.newThreshold, 3);
      assert.equal(decoded.signerAddress, null);
      assert.equal(decoded.address, null);
    });

    it("decodes a 1-of-1 auth approval", () => {
      const raw = makeRaw(
        [toB64(scSymbol("AuthOk"))],
        toB64(scVec([scU32(1), scU32(1)]))
      );
      const decoded = decodeEvent(raw);
      assert.ok(decoded !== null);
      assert.equal(decoded.validCount, 1);
      assert.equal(decoded.newThreshold, 1);
    });

    it("stores both values as null when data is not a two-element Vec", () => {
      // Pass a Void data value — decoder should not crash but both counts null
      const raw = makeRaw([toB64(scSymbol("AuthOk"))], toB64(scVoid()));
      const decoded = decodeEvent(raw);
      assert.ok(decoded !== null);
      assert.equal(decoded.validCount, null);
      assert.equal(decoded.newThreshold, null);
    });
  });

  // ── Unknown events still rejected ─────────────────────────────────────────
  describe("unknown event type", () => {
    it("returns null for an unrecognised symbol", () => {
      const raw = makeRaw([toB64(scSymbol("Unknown"))], toB64(scVoid()));
      assert.equal(decodeEvent(raw), null);
    });
  });

  // ── Existing compliance-primitives events unaffected ──────────────────────
  describe("existing AllowAdd event still decodes correctly", () => {
    it("returns a non-null event with eventType AllowAdd", () => {
      const raw = makeRaw(
        [toB64(scSymbol("AllowAdd")), toB64(scAccountAddress(0xaa))],
        toB64(scVoid())
      );
      const decoded = decodeEvent(raw);
      assert.ok(decoded !== null);
      assert.equal(decoded.eventType, "AllowAdd");
      assert.equal(decoded.address, ADDR_AA);
      assert.equal(decoded.signerAddress, null);
    });
  });
});
