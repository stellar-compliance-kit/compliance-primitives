# Threat Model

This document enumerates and analyzes attack scenarios for each contract in
the `compliance-primitives` workspace. Each scenario is rated for severity and
likelihood, and cross-referenced to existing mitigations (tests, documented
invariants, or pending issues).

Per-contract sections cover three threat categories:

| Category | Description |
|----------|-------------|
| **Griefing** | Attacks that cost the victim resources or degrade service without directly stealing assets. |
| **Front-running** | Attacks that exploit the ordering of operations within a ledger close. |
| **Admin-key-compromise** | What a compromised privileged key can and cannot do, and how quickly damage can be bounded. |

---

## allowlist-token

### Griefing

| Scenario | Severity | Likelihood | Mitigation |
|----------|----------|------------|------------|
| **Repeated `is_allowed` calls** — an attacker calls `is_allowed` many times to run up resource fees paid by the contract itself. | Low | Low | In Soroban the **caller** pays resource fees, not the contract. Each `is_allowed` invocation costs the caller a small fee and does not write to storage, so the economic burden falls on the attacker. No contract-side drain is possible. |
| **Repeated `transfer` with non-allowlisted addresses** — an attacker repeatedly calls `transfer` from a non-allowlisted address, consuming event-emission resources. | Low | Low | Same caller-pays argument. `transfer` returns `Ok(false)` early without touching the underlying token, so the only cost is the caller's fee for a read + event emission. |
| **Storage junk via `DataKey` writes** — an attacker fills storage with junk `Allowed(Address)` entries. | N/A | N/A | Only the admin can call `add_to_allowlist`/`remove_from_allowlist` (gated by `require_admin`). There is no public write path. See [`contracts/allowlist-token/src/lib.rs`](../contracts/allowlist-token/src/lib.rs:83-100). |

### Front-running

| Scenario | Severity | Likelihood | Mitigation |
|----------|----------|------------|------------|
| **Re-ordering `add_to_allowlist` and `transfer`** — an attacker submits a `transfer` in the same ledger as `add_to_allowlist` for the same address. If the validator orders `transfer` before `add_to_allowlist`, the `transfer` returns `Ok(false)` and is blocked. | Low | Low | The worst outcome is a benign transfer being blocked until the next ledger — no funds move, no state changes incorrectly. The `Blocked` event is always emitted regardless of ordering, so the event is audit trail survives. If `transfer` goes through before a *removal*, the funds move while the address was still allowlisted, which is correct behavior (the removal applies from the next ledger). |
| **Re-ordering `remove_from_allowlist` and `transfer`** — if a validator reorders to run `transfer` before the removal succeeds, the transfer completes while the address is still allowlisted. | Medium | Low | The admin should view removal as applying "as of the next ledger." A malicious validator can only create a one-ledger window. For higher-stakes removals, see [Admin key compromise](#admin-key-compromise) below. |

### Admin key compromise

| Scenario | Severity | Likelihood | Mitigation |
|----------|----------|------------|------------|
| **Compromised admin adds arbitrary addresses to allowlist** — an attacker controlling the admin key can approve any address to send/receive the token. This does **not** let the attacker steal funds from others, because `transfer` still requires `from.require_auth()`. | High | Medium | `transfer` at [`contracts/allowlist-token/src/lib.rs:120`](../contracts/allowlist-token/src/lib.rs:120) requires the sender's auth via `from.require_auth()`. The admin cannot impersonate a user. See **test**: `test_transfer_forwards_to_underlying_token_when_both_allowlisted` in [`contracts/allowlist-token/src/test.rs:48`](../contracts/allowlist-token/src/test.rs:48). |
| **Compromised admin removes all addresses from allowlist** — a denial-of-service that blocks all transfers through the wrapper. | High | Medium | There is no per-address cooldown or rate limit on removals. **Mitigations pending:** [#74/#75/#76](https://github.com/stellar-compliance-kit/compliance-primitives/issues/74) (two-step admin transfer), [#84/#85](https://github.com/stellar-compliance-kit/compliance-primitives/issues/84) (pause capability). Once pause lands, the rightful admin can pause the contract to stop further damage while key recovery proceeds. See [SPEC.md invariants](SPEC.md) (issue #29). |
| **Compromised admin upgrades the contract to malicious code** — with the `upgrade()` function (added in [#113](https://github.com/stellar-compliance-kit/compliance-primitives/issues/113)), an attacker who controls the admin key can replace the contract WASM with arbitrary code. | Critical | Medium | The `upgrade()` function is gated by the same `require_admin` pattern as all other admin operations (see [`contracts/allowlist-token/src/lib.rs:149`](../contracts/allowlist-token/src/lib.rs:149)). There is no timelock or multi-sig requirement. **Mitigations pending:** A timelock or multi-sig requirement on `upgrade()` would turn a single key compromise from a total-loss event into a bounded-risk event during the timelock window. See also [SPEC.md](SPEC.md) (issue #29). |
| **Compromised admin reads the wrapped token address** — the admin can read `DataKey::Token` from instance storage, but this address is already learnable from the deploy transaction history. | Low | Low | The token address in storage provides no additional attack surface; the underlying token's own security model applies independently. |

---

## denylist-gate

### Griefing

| Scenario | Severity | Likelihood | Mitigation |
|----------|----------|------------|------------|
| **Repeated `check` calls** — an attacker calls `check(address)` many times to exhaust resources. | Low | Low | Caller pays fees. `check` is a read-only function with no writes. |
| **Storage junk via `DataKey` writes** — an attacker fills storage with junk `Denied(Address)` entries. | N/A | N/A | Only the admin can write via `add_to_denylist`/`remove_from_denylist`. See [`contracts/denylist-gate/src/lib.rs:66-83`](../contracts/denylist-gate/src/lib.rs:66-83). |

### Front-running

| Scenario | Severity | Likelihood | Mitigation |
|----------|----------|------------|------------|
| **Re-ordering `add_to_denylist` and a consumer's `transfer`** — a validator orders the `transfer` before the `add_to_denylist` call, allowing a transfer to clear even though the sender was being added to the denylist in the same ledger. | Medium | Low | The denylist admin should assume a one-ledger delay between submitting `add_to_denylist` and it taking effect. The consuming contract can add its own front-running mitigations (e.g., checking a recent ledger sequence). |
| **Re-ordering `remove_from_denylist` and a consumer's `transfer`** — if the removal is ordered after the transfer, a denied address might have their transfer blocked even though the removal was submitted. | Low | Low | The denied address benefits from this ordering — the transfer is blocked when it shouldn't have been. The address can retry in the next ledger. |

### Admin key compromise

| Scenario | Severity | Likelihood | Mitigation |
|----------|----------|------------|------------|
| **Compromised admin adds all addresses to denylist** — effectively halts all token transfers that consult this denylist. | High | Medium | No per-address rate limit. Consuming contracts can fall back to secondary denylist checks or pause if multiple gates disagree. **Mitigations pending:** [#84/#85](https://github.com/stellar-compliance-kit/compliance-primitives/issues/84) pause capability. |
| **Compromised admin removes all denylist entries** — allows previously-sanctioned addresses to transact freely. | High | Medium | The damage is immediate and total. Off-chain monitoring of `DenyRemove` events is the primary detection mechanism. Event emissions are guaranteed by the contract (see [`contracts/denylist-gate/src/lib.rs:71`](../contracts/denylist-gate/src/lib.rs:71) and [`contracts/denylist-gate/src/lib.rs:81`](../contracts/denylist-gate/src/lib.rs:81)). |
| **Compromised admin adds/removes individual high-value addresses** — targeted sanction evasion. | High | High | Same event-based detection applies. A real deployment should couple the admin key with a multi-sig or governance process. |

---

## jurisdiction-flag

### Griefing

| Scenario | Severity | Likelihood | Mitigation |
|----------|----------|------------|------------|
| **Repeated `get_jurisdiction` calls** — attacker repeatedly reads jurisdiction data. | Low | Low | Caller pays fees. Read-only function. |
| **Repeated `is_permitted_jurisdiction` calls** — same as above, but iterates over a `Vec<String>`. | Low | Low | Caller pays fees. The iteration cost scales with `allowed_codes.len()`, which is chosen by the caller (or their caller in a composition chain) — the cost is proportional to input. |
| **Storage junk via `DataKey` writes** — an attacker fills storage with junk `Jurisdiction(Address)` entries. | N/A | N/A | Only the issuer can write via `set_jurisdiction`. See [`contracts/jurisdiction-flag/src/lib.rs:62-74`](../contracts/jurisdiction-flag/src/lib.rs:62-74). |

### Front-running

| Scenario | Severity | Likelihood | Mitigation |
|----------|----------|------------|------------|
| **Re-ordering `set_jurisdiction` and a consumer's compliance check** — if a validator orders the consumer's `is_permitted_jurisdiction` call before `set_jurisdiction`, an address that just completed jurisdiction verification is still treated as unverified for one ledger. | Low | Low | The address can retry in the next ledger. No assets are at risk — the check is purely a gating function. |
| **Re-ordering a jurisdiction-change removal** — if an address's jurisdiction is being changed from "US" to "CA", a consumer call reordered before the update sees the old value. | Low | Low | Again, a one-ledger window. If the check passes with the old jurisdiction, the behavior is correct (the update takes effect from the next ledger). |

### Admin (issuer) key compromise

| Scenario | Severity | Likelihood | Mitigation |
|----------|----------|------------|------------|
| **Compromised issuer sets arbitrary jurisdiction codes** — an attacker can assign any jurisdiction code to any address, bypassing off-chain KYC/onboarding. | High | Medium | There is no on-chain mechanism to verify jurisdiction claims — the contract assumes the issuer performs off-chain verification before calling `set_jurisdiction`. Event-based monitoring of `JurisdictionSet` events is the detection mechanism. See [`contracts/jurisdiction-flag/src/lib.rs:72`](../contracts/jurisdiction-flag/src/lib.rs:72). |
| **Compromised issuer removes all jurisdictions (by not re-setting them)** — this is not a single function call but the effect of refusing to set jurisdictions. The actual damage depends on whether consuming contracts treat `None` as "denied" or "permitted." | Medium (varies) | Low | `is_permitted_jurisdiction` correctly returns `false` when no jurisdiction is set (see [`contracts/jurisdiction-flag/src/lib.rs:85-87`](../contracts/jurisdiction-flag/src/lib.rs:85-87)), which means consuming contracts will block addresses with no jurisdiction. This is the safe-by-default behavior. **Test**: `test_is_permitted_jurisdiction_false_when_no_jurisdiction_set` in [`contracts/jurisdiction-flag/src/test.rs:56`](../contracts/jurisdiction-flag/src/test.rs:56). |
| **Compromised issuer upgrades the contract** — with the `upgrade()` function (added in [#27](https://github.com/stellar-compliance-kit/compliance-primitives/issues/27)), an attacker who controls the issuer key can replace the contract WASM with arbitrary code. | Critical | Medium | Same assessment as allowlist-token's upgrade path. No timelock or multi-sig. **Mitigations pending:** A timelock or multi-sig on `upgrade()` would bound the damage. |

---

## Cross-cutting concerns

| Concern | Applicable contracts | Notes |
|---------|---------------------|-------|
| **Event-based monitoring** | All three | All state-mutating operations emit events (`AllowAdd`, `AllowRemove`, `Blocked`, `DenyAdd`, `DenyRemove`, `JurisdictionSet`). Off-chain monitoring of these events is the primary detection mechanism for both legitimate use and attacker activity. |
| **Caller-pays resource fees** | All three | Soroban's fee model means griefing via public read functions is not economically viable — the attacker bears the cost. |
| **Upgrade authority** | allowlist-token, jurisdiction-flag | Both contracts now have an `upgrade()` function gated behind the admin/issuer key. There is no timelock. See [#113](https://github.com/stellar-compliance-kit/compliance-primitives/issues/113) and [#27](https://github.com/stellar-compliance-kit/compliance-primitives/issues/27). |
| **Pause capability** | All three (pending) | [#84/#85](https://github.com/stellar-compliance-kit/compliance-primitives/issues/84) would let an admin pause the contract, bounding the damage window of a compromised key that is detected quickly. |
| **Two-step admin transfer** | All three (pending) | [#74/#75/#76](https://github.com/stellar-compliance-kit/compliance-primitives/issues/74) would replace single-step admin changes with a two-step commit pattern, reducing the risk of accidental or malicious admin changes. |
