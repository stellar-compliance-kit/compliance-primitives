# compliance-aggregator

A composition point for evaluating multiple compliance primitives as one
AND-composed decision.

| Method | Purpose |
| --- | --- |
| `initialize(admin, checks)` | Configure the checks and administrator. |
| `evaluate(from, to) -> CheckResult` | Evaluate the configured policy for a transfer. |
| `get_checks() -> checks` | Inspect configured compliance checks. |

Use the deployed contract’s generated interface for exact enum and address encoding.

## CheckResult

`evaluate` returns a `CheckResult` rather than a bare boolean:

```
CheckResult {
    allowed: bool,
    code: u32,
}
```

- `allowed` — whether the transfer is permitted by the composed policy.
- `code` — a reason code describing the outcome. When `allowed` is `true` the code is the success code (`0`). When `allowed` is `false` the code identifies why the transfer was rejected.

## Reason codes

The aggregator does not invent reason codes. Each configured primitive returns its own `CheckResult`, and the aggregator propagates the code from the primitive that caused the rejection:

- If every primitive allows the transfer, the aggregator returns `allowed = true` with the success code.
- If one or more primitives reject the transfer, the aggregator returns `allowed = false` with the `code` of the first rejecting primitive (in configured check order).
- If a primitive cannot be called because it is incompatible (see below), the aggregator returns `allowed = false` with the incompatibility code.

Consumers should treat unknown codes as a rejection and surface the raw code for diagnostics rather than assuming a fixed enumeration.

## Interface versioning

The compliance-check trait is versioned. Every primitive exposes a required `interface_version()` method, and the aggregator verifies compatibility before calling a primitive:

- On `initialize`, and again before each `evaluate` call to a primitive, the aggregator reads the primitive’s `interface_version()`.
- If the version is not compatible with the version the aggregator was built against, the primitive is not called. The aggregator records the incompatibility and returns `allowed = false` with the incompatibility code.
- A primitive that does not implement `interface_version()` is treated as incompatible.

This prevents silently calling a deployed implementer whose trait shape has changed (for example, one that still returns a bare boolean instead of a `CheckResult`).

## Migration notes

- Implementers of the compliance-check trait must add the required `interface_version()` method and return `CheckResult { allowed, code }` from their check entry point.
- Callers that previously consumed a boolean result must read `CheckResult.allowed` and may use `CheckResult.code` for diagnostics.
- Implementers that have not been migrated will fail the compatibility check and be treated as rejecting, rather than being called with a mismatched interface.
