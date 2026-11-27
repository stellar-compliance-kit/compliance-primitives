# ComplianceCheck Trait Design

> **Status: Implemented (interface version 1).**
>
> This document describes the shared `ComplianceCheck` trait implemented
> by the three compliance primitives (`allowlist-token`, `denylist-gate`,
> `jurisdiction-flag`). Each contract still exposes its own specialized
> check function (`is_allowed`, `check`, and `is_permitted_jurisdiction`
> respectively); the trait is an additive, unified interface on top of
> them.
>
> The trait is versioned: every implementer must expose
> `interface_version()`, and callers must verify compatibility before
> invoking `is_compliant`. See
> [Interface Versioning and Compatibility](#interface-versioning-and-compatibility)
> and [Migration Guidance](#migration-guidance).

## Overview

This document describes the design for a shared `ComplianceCheck` trait
that would provide a unified interface across the three compliance
primitives (`allowlist-token`, `denylist-gate`, `jurisdiction-flag`).

## Problem Statement

The three compliance contracts have inconsistent calling conventions:

- `allowlist-token.is_allowed(address) -> bool`
- `denylist-gate.check(address) -> bool`
- `jurisdiction-flag.is_permitted_jurisdiction(address, allowed_codes) -> bool`

This inconsistency makes it difficult for external contracts to compose
these primitives polymorphically. The `jurisdiction-flag` in particular
requires additional parameters (`allowed_codes`), making it impossible
to call all three with the same call pattern.

## Proposed Solution: ComplianceCheck Trait

### Design Approach

Introduce a shared `ComplianceCheck` trait that standardizes the check
interface across the three contracts:

```rust
/// Result of a compliance check.
///
/// `allowed` is the pass/fail verdict; `code` explains *why* the verdict
/// was reached so aggregators and wallets can surface a reason without
/// re-deriving it from contract state.
#[contracttype]
pub struct CheckResult {
    pub allowed: bool,
    pub code: u32,
}

pub trait ComplianceCheck {
    /// Interface version implemented by this contract. Callers MUST
    /// verify this before calling `is_compliant`.
    fn interface_version(env: Env) -> u32;

    /// Check if an address passes this compliance check.
    /// Returns a `CheckResult` with the verdict and a reason code.
    fn is_compliant(env: Env, address: Address) -> CheckResult;
}
```

### Reason Codes

`CheckResult.code` is a `u32` reason code. `0` always means "no reason
code" and is only valid when `allowed == true`. Non-zero codes are
grouped by range so new codes can be added without renumbering:

| Code | Name | Meaning |
|------|------|---------|
| `0` | `OK` | Address is compliant; no further detail. |
| `1` | `NOT_ALLOWLISTED` | Address is not on the allowlist. |
| `2` | `ALLOWLIST_EXPIRED` | Address is allowlisted but its entry has expired. |
| `3` | `DENYLISTED` | Address is on the denylist. |
| `4` | `DENYLIST_REASON_UNSPECIFIED` | Address is denylisted; no reason recorded. |
| `5` | `NO_JURISDICTION` | Address has no jurisdiction code assigned. |
| `6` | `JURISDICTION_NOT_PERMITTED` | Address has a jurisdiction code that is not permitted. |
| `7` | `CONTRACT_PAUSED` | The checking contract is paused. |
| `8` | `UNKNOWN_ADDRESS` | Address has no record in the checking contract. |
| `9` | `INTERFACE_VERSION_MISMATCH` | Reserved for callers; never returned by an implementer. |

Codes `10..=99` are reserved for future shared reason codes; codes
`>= 100` are contract-specific and must be documented by the emitting
contract. Implementers MUST return `allowed == false` for any non-zero
code, and MUST return `code == 0` when `allowed == true`.

### Key Design Decisions

1. **Additive Implementation**: The trait is added WITHOUT modifying
   existing contract functions. All current contracts maintain backward
   compatibility.

2. **Reason Codes**: The result carries a `code` alongside the verdict so
   aggregators and wallets can distinguish "denylisted" from "not
   allowlisted" from "no jurisdiction" without extra calls.

3. **Versioned Interface**: `interface_version()` is a required method so
   callers can detect incompatible implementers instead of silently
   misinterpreting results.

4. **Address-Only Semantics**:
   - `allowlist-token`: `allowed` is `is_allowed(address)`; codes `1`,
     `2`, `7`, `8`.
   - `denylist-gate`: `allowed` is `check(address)`; codes `3`, `4`, `7`,
     `8`.
   - `jurisdiction-flag`: `allowed` is `true` if the address has ANY
     jurisdiction code set (indicating the address has been
     flagged/verified); codes `5`, `6`, `7`, `8`. It does **not** check
     against a permitted-codes list — that remains the role of
     `is_permitted_jurisdiction`. Note that this is purely a "has a
     jurisdiction been assigned?" check, not a "is the assigned
     jurisdiction permitted?" check.

### Alternatives Considered

1. **Generic Trait with Associated Types**: Would be more flexible but
   requires type complexity at call sites.
   - **Rejected**: Soroban contracts don't support generic trait
     implementations well.

2. **Trait with Multiple Methods**: Could have both `is_compliant` and
   specialized check methods.
   - **Rejected**: Adds complexity; the goal is a unified interface.

3. **Wrapper Contracts**: Create separate wrapper contracts around each
   primitive.
   - **Rejected**: Adds deployment overhead and makes debugging harder.

4. **Runtime Polymorphism via Enum**: Pass contract type as enum parameter.
   - **Rejected**: Less idiomatic Rust; doesn't leverage Soroban's
     contract system.

## Proposed Implementation Strategy

### Phase 1: Trait Definition

The trait, `CheckResult`, and the reason-code constants live in the
shared `contracts/compliance-check` crate.

### Phase 2: Implement for Each Contract

Each contract has a `#[contractimpl]` block implementing the trait:
- `AllowlistToken` — delegates to `is_allowed`
- `DenylistGate` — delegates to `check`
- `JurisdictionFlag` — returns `true` if any code is set (see
  "Address-Only Semantics" above)

### Phase 3: Client Generation

`#[contractclient]` generates clients that can call
`interface_version` and `is_compliant` on any of the three contracts.

### Phase 4: Integration Example

`rwa-compliance-flow` demonstrates the version check plus the unified
call pattern:

```rust
// Callers MUST verify compatibility before calling is_compliant.
fn assert_compatible(client: &ComplianceCheckClient) {
    let version = client.interface_version();
    assert_eq!(version, COMPLIANCE_CHECK_INTERFACE_VERSION);
}

// All three can be called with the same pattern:
let allowlist = allowlist_client.is_compliant(&alice);
let denylist  = denylist_client.is_compliant(&alice);
let jurisdiction = jurisdiction_client.is_compliant(&alice);

// All pass -> address is compliant; otherwise surface the reason codes.
if allowlist.allowed && denylist.allowed && jurisdiction.allowed {
    // Safe to transfer
} else {
    // e.g. emit (allowlist.code, denylist.code, jurisdiction.code)
}
```

## Current State

All three contracts implement `interface_version()` and `is_compliant`,
returning `CheckResult`. The `rwa-compliance-flow` example uses the
`#[contractclient]` trait for cross-contract calls and performs the
version check before invoking `is_compliant`.

## Interface Versioning and Compatibility

- `COMPLIANCE_CHECK_INTERFACE_VERSION` is currently `1`.
- `interface_version()` is a **required** method; there is no default
  implementation, so an implementer that omits it fails to compile
  rather than silently exposing an incompatible ABI.
- Callers MUST call `interface_version()` and compare it against the
  version they were built against **before** calling `is_compliant`. If
  the versions differ, the caller must not call `is_compliant` and
  should treat the check as failed (reason code `9`,
  `INTERFACE_VERSION_MISMATCH`).
- The version is bumped whenever the trait's method signatures, the
  `CheckResult` shape, or the meaning of an existing reason code
  changes. Adding new reason codes in the reserved ranges is **not** a
  breaking change and does not bump the version.
- Implementers MUST NOT change the meaning of an existing reason code
  within a version.

## Migration Guidance

### For existing implementers (pre-trait contracts)

1. Add the `compliance-check` dependency and implement
   `interface_version()` returning `COMPLIANCE_CHECK_INTERFACE_VERSION`.
2. Implement `is_compliant` by delegating to the existing specialized
   function and mapping its outcome to a `CheckResult` using the reason
   codes above.
3. Keep the existing specialized functions unchanged; the trait is
   additive and existing callers are unaffected.
4. Add tests asserting the reason code for each failure path.

### For callers

1. Replace direct `is_compliant(...) -> bool` usage with the
   `CheckResult` form.
2. Add the `interface_version()` check before the first
   `is_compliant` call (see Phase 4 above).
3. Handle non-zero reason codes explicitly; do not assume a single
   generic failure.

## Backward Compatibility

- ✅ All existing contract functions (`is_allowed`, `check`,
  `is_permitted_jurisdiction`) remain unchanged
- ✅ All existing tests continue to pass without modification
- ✅ The `is_compliant` method is purely additive
- ✅ Calling contracts can use either the unified interface or the
  existing specialized functions
- ⚠️ Callers that previously assumed `is_compliant -> bool` must migrate
  to `CheckResult` and add the `interface_version()` check (see
  "Migration Guidance")

## Trade-offs

### Simplicity vs. Flexibility

The unified `(address) -> CheckResult` interface sacrifices some
flexibility (e.g., `jurisdiction-flag` loses access to permitted-codes
list) for:
- Easier composition
- Uniform calling convention
- Reduced cognitive load for integrators
- Actionable failure reasons via `CheckResult.code`
=======

### Jurisdiction-Flag Special Case

`jurisdiction-flag` requires additional context (permitted codes) that
doesn't fit the minimal interface. The proposed behavior is:
- `is_compliant` returns `true` if the address has ANY jurisdiction code
  set (i.e., the address has been KYC'd/verified with some jurisdiction)
- The check for specific permitted codes remains in
  `is_permitted_jurisdiction`

This is different from `is_permitted_jurisdiction` — it answers "has
this address been assigned a jurisdiction?" not "is its jurisdiction on
the allowlist?".

## Future Enhancements

1. **Permit Storage**: Allow contracts to store permitted jurisdiction
   lists and have `is_compliant` check against them.
2. **Metadata**: Extend trait to include a method returning compliance
   check type/description.
3. **Composable Checks**: Define a `ComplianceCheckCompositor` trait
   for AND/OR logic.
4. **Event Standardization**: Standard events emitted on compliance
   check failures.

## Testing Strategy

- Verify each contract's `is_compliant` behaves consistently with its
  specialized check, including the returned reason code
- Test that external contracts can call any of the three through the
  unified interface
- Test that `interface_version()` returns
  `COMPLIANCE_CHECK_INTERFACE_VERSION` for every implementer
- Ensure all existing tests still pass
- Add new tests specifically for the `is_compliant` method on each
  contract
