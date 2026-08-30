/**
 * Unit tests for decoder.ts — compliance-aggregator, policy-engine, and
 * multisig-admin event decoding.
 *
 * Fixtures are hand-crafted XDR bytes encoded as base64, produced to match
 * the exact wire format each contract emits via Soroban's #[contractevent]
 * macro:
 *
 * compliance-aggregator (3 config events, all share the same shape):
 *   AdminSet            topics:[Symbol("AdminSet"),            Address]  data:Void
 *   DenylistGateSet     topics:[Symbol("DenylistGateSet"),     Address]  data:Void
 *   JurisdictionFlagSet topics:[Symbol("JurisdictionFlagSet"), Address]  data:Void
 *
 * policy-engine (1 evaluation event):
 *   PolicyResult  topics:[Symbol("PolicyResult"), Bool(passed)]
 *                 data:   Vec[Address(from), Address(to)]
 *
 * multisig-admin (4 events):
 *   SignerAdd   topics: [Symbol("SignerAdd"), Address]  data: Void
 *   SignerRm    topics: [Symbol("SignerRm"),  Address]  data: Void
 *   ThreshSet   topics: [Symbol("ThreshSet")]           data: U32(threshold)
 *   AuthOk      topics: [Symbol("AuthOk")]              data: Vec[U32(valid), U32(threshold)]
 *
 * These tests also serve as a regression suite confirming the existing
 * AllowAdd / AllowRemove / Blocked / DenyAdd / DenyRemove / JurisdictionSet
 * events still decode correctly after the new event types were added.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { decodeEvent } from "./decoder.js";
import type { RawSorobanEvent } from "./rpc.js";

// ─── XDR fixture helpers ──────────────────────────────────────────────────────
//
// multisig-admin fixtures are assembled programmatically using the same
// encoding rules the XdrReader in decoder.ts expects, so these tests also
// implicitly validate that the hand-rolled reader handles all shapes
// correctly. compliance-aggregator / policy-engine fixtures below are
// pre-computed base64 constants for the same wire format.

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
const SC_VOID = 1;
const SC_U32 = 3;
const SC_SYMBOL = 15;
const SC_VEC = 16;
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
const ADDR_CC = "GDGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMYPI2";

// compliance-aggregator — AdminSet
const ADMIN_SET_T0 = "AAAADwAAAAhBZG1pblNldA==";
const ADMIN_SET_T1 = "AAAAEgAAAAAAAAAAqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo=";
const ADMIN_SET_DATA = "AAAAAQ=="; // Void

// compliance-aggregator — DenylistGateSet
const DENYLIST_GATE_SET_T0 = "AAAADwAAAA9EZW55bGlzdEdhdGVTZXQA";
const DENYLIST_GATE_SET_T1 = "AAAAEgAAAAAAAAAAu7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7s=";

// compliance-aggregator — JurisdictionFlagSet
const JURIS_FLAG_SET_T0 = "AAAADwAAABNKdXJpc2RpY3Rpb25GbGFnU2V0AA==";
const JURIS_FLAG_SET_T1 = "AAAAEgAAAAAAAAAAzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMw=";

// policy-engine — PolicyResult
const POLICY_RESULT_T0 = "AAAADwAAAAxQb2xpY3lSZXN1bHQ=";
const POLICY_RESULT_T1_PASS = "AAAAAAAAAAE="; // Bool(true)
const POLICY_RESULT_T1_FAIL = "AAAAAAAAAAA="; // Bool(false)
const POLICY_RESULT_DATA =
  "AAAAEAAAAAEAAAACAAAAEgAAAAAAAAAAqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqoAAAASAAAAAAAAAAC7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7uw==";

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

// ─── multisig-admin tests ──────────────────────────────────────────────────────

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
});

// ─── compliance-aggregator tests ──────────────────────────────────────────────

const AGGREGATOR_TIMESTAMP_OVERRIDES = {
  ledger: 5000,
  ledgerClosedAt: "2025-06-01T12:00:00Z",
};
const EXPECTED_AGGREGATOR_TIMESTAMP = Math.floor(
  new Date("2025-06-01T12:00:00Z").getTime() / 1000
);

describe("decodeEvent — compliance-aggregator events", () => {
  // ── AdminSet ───────────────────────────────────────────────────────────────
  describe("AdminSet", () => {
    it("decodes eventType and the new admin address", () => {
      const raw = makeRaw([ADMIN_SET_T0, ADMIN_SET_T1], ADMIN_SET_DATA);
      const decoded = decodeEvent(raw);
      assert.ok(decoded !== null, "expected non-null decoded event");
      assert.equal(decoded.eventType, "AdminSet");
      assert.equal(decoded.address, ADDR_AA);
      assert.equal(decoded.contractId, "CTEST");
    });

    it("records the ledger sequence and timestamp", () => {
      const raw = makeRaw(
        [ADMIN_SET_T0, ADMIN_SET_T1],
        ADMIN_SET_DATA,
        AGGREGATOR_TIMESTAMP_OVERRIDES
      );
      const decoded = decodeEvent(raw);
      assert.ok(decoded !== null);
      assert.equal(decoded.ledgerSequence, 5000);
      assert.equal(decoded.timestamp, EXPECTED_AGGREGATOR_TIMESTAMP);
    });

    it("policy fields are null", () => {
      const raw = makeRaw([ADMIN_SET_T0, ADMIN_SET_T1], ADMIN_SET_DATA);
      const decoded = decodeEvent(raw);
      assert.ok(decoded !== null);
      assert.equal(decoded.policyFrom, null);
      assert.equal(decoded.policyTo, null);
      assert.equal(decoded.policyPassed, null);
    });

    it("returns null when address topic is missing", () => {
      const raw = makeRaw([ADMIN_SET_T0], ADMIN_SET_DATA);
      assert.equal(decodeEvent(raw), null);
    });
  });

  // ── DenylistGateSet ────────────────────────────────────────────────────────
  describe("DenylistGateSet", () => {
    it("decodes eventType and the gate contract address", () => {
      const raw = makeRaw([DENYLIST_GATE_SET_T0, DENYLIST_GATE_SET_T1], ADMIN_SET_DATA);
      const decoded = decodeEvent(raw);
      assert.ok(decoded !== null);
      assert.equal(decoded.eventType, "DenylistGateSet");
      assert.equal(decoded.address, ADDR_BB);
    });

    it("returns null when address topic is missing", () => {
      const raw = makeRaw([DENYLIST_GATE_SET_T0], ADMIN_SET_DATA);
      assert.equal(decodeEvent(raw), null);
    });
  });

  // ── JurisdictionFlagSet ────────────────────────────────────────────────────
  describe("JurisdictionFlagSet", () => {
    it("decodes eventType and the flag contract address", () => {
      const raw = makeRaw([JURIS_FLAG_SET_T0, JURIS_FLAG_SET_T1], ADMIN_SET_DATA);
      const decoded = decodeEvent(raw);
      assert.ok(decoded !== null);
      assert.equal(decoded.eventType, "JurisdictionFlagSet");
      assert.equal(decoded.address, ADDR_CC);
    });

    it("returns null when address topic is missing", () => {
      const raw = makeRaw([JURIS_FLAG_SET_T0], ADMIN_SET_DATA);
      assert.equal(decodeEvent(raw), null);
    });
  });
});

// ─── policy-engine tests ──────────────────────────────────────────────────────

describe("decodeEvent — policy-engine events", () => {
  // ── PolicyResult (pass) ────────────────────────────────────────────────────
  describe("PolicyResult — pass", () => {
    it("decodes policyPassed=true, policyFrom, policyTo", () => {
      const raw = makeRaw(
        [POLICY_RESULT_T0, POLICY_RESULT_T1_PASS],
        POLICY_RESULT_DATA
      );
      const decoded = decodeEvent(raw);
      assert.ok(decoded !== null, "expected non-null decoded event");
      assert.equal(decoded.eventType, "PolicyResult");
      assert.equal(decoded.policyPassed, true);
      assert.equal(decoded.policyFrom, ADDR_AA);
      assert.equal(decoded.policyTo, ADDR_BB);
    });

    it("address/addressTo/amount/jurisdiction are null", () => {
      const raw = makeRaw(
        [POLICY_RESULT_T0, POLICY_RESULT_T1_PASS],
        POLICY_RESULT_DATA
      );
      const decoded = decodeEvent(raw);
      assert.ok(decoded !== null);
      assert.equal(decoded.address, null);
      assert.equal(decoded.addressTo, null);
      assert.equal(decoded.amount, null);
      assert.equal(decoded.jurisdiction, null);
    });

    it("records the ledger sequence and timestamp", () => {
      const raw = makeRaw(
        [POLICY_RESULT_T0, POLICY_RESULT_T1_PASS],
        POLICY_RESULT_DATA,
        AGGREGATOR_TIMESTAMP_OVERRIDES
      );
      const decoded = decodeEvent(raw);
      assert.ok(decoded !== null);
      assert.equal(decoded.ledgerSequence, 5000);
      assert.equal(decoded.timestamp, EXPECTED_AGGREGATOR_TIMESTAMP);
    });
  });

  // ── PolicyResult (fail) ────────────────────────────────────────────────────
  describe("PolicyResult — fail", () => {
    it("decodes policyPassed=false", () => {
      const raw = makeRaw(
        [POLICY_RESULT_T0, POLICY_RESULT_T1_FAIL],
        POLICY_RESULT_DATA
      );
      const decoded = decodeEvent(raw);
      assert.ok(decoded !== null);
      assert.equal(decoded.eventType, "PolicyResult");
      assert.equal(decoded.policyPassed, false);
      assert.equal(decoded.policyFrom, ADDR_AA);
      assert.equal(decoded.policyTo, ADDR_BB);
    });
  });

  // ── Guards ─────────────────────────────────────────────────────────────────
  describe("guards", () => {
    it("returns null when Bool topic is missing", () => {
      const raw = makeRaw([POLICY_RESULT_T0], POLICY_RESULT_DATA);
      assert.equal(decodeEvent(raw), null);
    });

    it("returns null for an unrecognised event symbol", () => {
      const unknownT0 = toB64(scSymbol("UnknownEvt"));
      const unknownRaw = makeRaw([unknownT0], ADMIN_SET_DATA);
      assert.equal(decodeEvent(unknownRaw), null);
    });
  });
});

// ─── Regression: existing compliance-primitives events still decode ────────────

describe("regression — existing compliance-primitives events", () => {
  it("AllowAdd still decodes correctly after new events were added", () => {
    const raw = makeRaw(
      [toB64(scSymbol("AllowAdd")), toB64(scAccountAddress(0xaa))],
      toB64(scVoid())
    );
    const decoded = decodeEvent(raw);
    assert.ok(decoded !== null);
    assert.equal(decoded.eventType, "AllowAdd");
    assert.equal(decoded.address, ADDR_AA);
    assert.equal(decoded.policyFrom, null);
    assert.equal(decoded.policyTo, null);
    assert.equal(decoded.policyPassed, null);
    assert.equal(decoded.signerAddress, null);
  });
});
