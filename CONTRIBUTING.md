# Contributing to compliance-primitives

Thanks for your interest in contributing. This repo is part of the **Drips
Wave Stellar Program**, and issues are labeled by complexity
(`complexity: trivial`, `complexity: medium`, `complexity: high`) so you can
pick something that matches how deep you want to go. Issues good for a first
contribution are also tagged `good first issue`.

For details on how issues are triaged, labeled, and prioritized, see
[GOVERNANCE.md](./GOVERNANCE.md).

## Workflow

1. **Fork** the repository and clone your fork.
2. **Branch** off `main` with a descriptive name, e.g. `add-jurisdiction-remove-fn`.
3. **Make your change**, keeping it scoped to the issue you're addressing.
   Each contract crate is meant to stay small, single-responsibility, and
   under ~300 lines — if a change grows a contract past that, consider
   whether it belongs in a new crate or `/examples` instead.
4. **Add tests.** Every public function needs coverage for its happy path
   and at least one failure/auth case. New functionality without tests
   won't be merged.
5. **If you've changed a `DataKey` enum or any other `#[contracttype]` used
   for storage in a contract with (or expected to gain) an `upgrade()`
   entrypoint**, read
   [`STORAGE_VERSIONING.md`](./STORAGE_VERSIONING.md) first — some
   storage-layout changes require a documented migration path before they
   can ship.
6. **If you've changed any public function signature or interface-related
   attribute on a contract, regenerate the docs interfaces:**
   ```sh
   ./scripts/regenerate-docs.sh
   ```
   This rebuilds all contracts to wasm and extracts each contract's Soroban
   XDR interface spec into `docs/interfaces/`.  Commit the updated files.
6. **If you've bumped the workspace version in `Cargo.toml`**, add a corresponding entry to `CHANGELOG.md`. CI enforces this via `./scripts/check-changelog.sh`, which ensures every version bump is accompanied by a changelog entry.

7. **Before submitting a PR, run:**
   ```sh
   make test
   make lint
   ```
   Both must pass locally — the same checks run in CI on every PR.
7. **If your change touches `contracts/multisig-admin` or
   `contracts/circuit-breaker`**, work through
   [`docs/admin-control-review-checklist.md`](./docs/admin-control-review-checklist.md)
   before opening the PR — these two contracts have a larger blast radius
   than the rest of the workspace, and the PR template will ask you to
   confirm you've done this.
8. **Open a pull request** against `main`, referencing the issue it closes
   (e.g. `Closes #12`). Describe what changed and why.

## How reviews get assigned (CODEOWNERS)

You don't pick reviewers here, and you don't need to ping anyone: every path in
this repository has an owner in
[`.github/CODEOWNERS`](./.github/CODEOWNERS), and GitHub reads that file when
your pull request is opened.

- **One area touched** — the owner of that path is requested for review
  automatically. A PR that only changes `contracts/denylist-gate/` asks that
  contract's owner.
- **Several areas touched** — every affected owner is requested, and the PR
  needs all of them. A PR that changes both `contracts/policy-engine/` and
  `tools/indexer/` asks both owners, because a change to one can break the
  other.
- **A path with no entry of its own** — falls to the `*` catch-all at the
  bottom of the file. That is why a new top-level directory still gets a
  reviewer without a CODEOWNERS change.

The owner requested in the sidebar is the source of truth: if the list looks
wrong for what you changed, the fix belongs in `.github/CODEOWNERS` (open an
issue for it) rather than in manual re-assignment on the PR.

If CODEOWNERS is pointing at a stale handle, say so in the PR description —
maintainers can still pull in the right reviewer while the file is being
updated.

### PRs that cross owned areas

Some changes genuinely span owned areas — a contract change plus the indexer
that reads its events, or a primitive plus the example that demonstrates it.
Those PRs are welcome, but they are reviewed by several people, so keep them
reviewable:

1. **Open separate PRs when the parts are independent.** A docs fix and an
   unrelated contract change are reviewed faster as two PRs with one owner
   each than as one PR that needs two approvals.
2. **When it can't be split, say why in the description.** List the owned
   areas the diff touches and how they relate, so each owner knows what they
   are being asked to check.
3. **Keep each area's change self-contained.** Structure the commits so an
   owner can review their part without holding the whole PR in their head.
4. **Expect more rounds of feedback.** A cross-cutting PR is blocked until
   every requested owner has approved; if one review is slow, it is usually
   the reviewer waiting on the other area's decision rather than on you.
5. **Flag the interface in one place.** If the change crosses a boundary
   (a contract interface consumed by `tools/` or `web/`), describe the new
   contract in the PR description and link the files on both sides, so the
   owners are reviewing the same picture.

## Complexity labels and expected PR size

The complexity label on an issue is also a signal for how big the resulting
PR should be. Before you start, gut-check your planned change against the
issue's label:

- **`complexity: trivial`** — typically a single file, or a small
  documentation/test addition. No new public API surface. Example: adding an
  issue template, or a single focused unit test like the one requested in
  this same batch (`check()` returns true immediately after
  `remove_from_denylist`).
- **`complexity: medium`** — typically adds one new public function, or a
  new test category, to a single contract. Example: adding a `get_admin()`
  view function to `allowlist-token`, including happy-path and
  not-initialized test coverage.
- **`complexity: high`** — typically involves a design or threat-model
  writeup, changes that span multiple contracts, or new tooling/CI. Example:
  introducing a new cross-contract composition pattern or a new primitive
  crate.

If your planned PR looks a lot bigger (or smaller) than the label suggests,
that's worth flagging in the issue before you start — the label may be
wrong, or the issue may need to be split.

## Picking up an issue

Comment on the issue to let others know you're working on it. If you go
quiet for a while, don't worry — someone else may pick it up, and you're
welcome to jump back in on something else.

## Fuzz targets

This repo uses lightweight seeded-PRNG sequence fuzzers inside each
contract's `#[cfg(test)]` tree rather than a separate `cargo-fuzz`
workspace — see [`/fuzz/README.md`](./fuzz/README.md) for the full
rationale and the list of contracts already covered.

**Running the existing fuzz targets locally:**

```sh
# Short run (also covered by `cargo test` / CI), e.g. jurisdiction-flag
cargo test -p jurisdiction-flag fuzz_jurisdiction_set_get_sequences -- --nocapture

# Periodic longer campaign — run after non-trivial changes to the
# fuzzed functions, or as part of a release checklist
FUZZ_ITERATIONS=2000 FUZZ_OPS=64 \
  cargo test -p jurisdiction-flag fuzz_jurisdiction_set_get_sequences -- --nocapture
```

A failing run prints the failing `seed`, so the exact operation sequence
that triggered it is reproducible by re-running with that seed.

**Adding a new fuzz target for a contract:**

1. Add a `fuzz.rs` module to the contract crate (see
   `contracts/jurisdiction-flag/src/fuzz.rs` for the reference shape) and
   wire it in with `#[cfg(test)] mod fuzz;` in `lib.rs`.
2. Write a tiny xorshift-style PRNG (or reuse the pattern from an existing
   `fuzz.rs`) to generate a bounded sequence of random operations against
   the contract's public functions, using `soroban_sdk::testutils` to set
   up the `Env`, `mock_all_auths`, and generated `Address`es.
3. After each generated operation, assert the invariant(s) that must hold
   regardless of the operation sequence (e.g. "last write wins", "a
   read-only check's result is consistent with the underlying state").
4. Read iteration/operation counts from env vars (e.g. `FUZZ_ITERATIONS`,
   `FUZZ_OPS`) with small defaults so the target runs quickly under normal
   `cargo test` / CI, and print the seed on failure so a crash is
   reproducible.
5. Document the new target in [`/fuzz/README.md`](./fuzz/README.md):
   the harness location, the invariants it checks, and the short-run vs.
   longer-campaign commands.

**Interpreting a crash artifact:** since these are plain `#[test]` loops
rather than libFuzzer targets, a failure surfaces as a normal test
failure — there's no binary corpus file to inspect. Each iteration's
`seed` doubles as its loop index (`1..=FUZZ_ITERATIONS`) and is included
in every assertion message (e.g. `seed=57 addr=2: last-write-wins
mismatch`), so the run is already deterministic and reproducible: rerun
with `FUZZ_ITERATIONS` set to at least that seed and add a temporary
`if seed == 57 { std::eprintln!("{:?}", ...); }` (or similar) inside the
loop to print the operation sequence and state at the point of failure.

## Code style

- `#![no_std]` throughout; no `std`-only dependencies in contract crates.
- Public functions should have doc comments explaining behavior, especially
  auth requirements and failure conditions.
- Prefer returning `Result<T, Error>` with a `#[contracterror]` enum over
  panicking, except where `require_auth()`'s own panic behavior is the
  expected failure mode.
- Keep events auditable: if a function's outcome should be visible off-chain
  (e.g. a blocked transfer), don't put it behind a code path that would
  cause the whole invocation to revert — Soroban rolls back events emitted
  during any invocation that ultimately fails.

## Verifying reproducible builds

The contracts are intended to be reproducible builds — meaning the wasm binaries should be identical byte-for-byte when built in isolated environments. To verify this locally:

```sh
./scripts/verify-reproducible-builds.sh
```

This script builds each contract twice in isolated Docker containers and compares the resulting wasm binaries. All contracts should produce matching SHA256 hashes. Reproducible builds let external parties (issuers deploying these contracts) independently verify that the wasm they're using matches this repository's source.

## Questions

Open an issue with your question, or comment on the relevant existing issue.
