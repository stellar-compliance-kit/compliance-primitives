# Governance: Issue Triage and Complexity Labeling

This document describes how issues in the `compliance-primitives` repository are triaged, labeled, and prioritized. It's intended to help both maintainers and contributors understand how to pick up work and what to expect from different issue types.

## Complexity Labels

Every issue gets a `complexity` label that reflects both the scope of work and the PR size you should expect. Use this label to find issues that match your available time and expertise.

### `complexity: trivial`

**Scope**: Single file, documentation, or small test addition. No new public API.

**Examples**:
- Adding an issue template
- Fixing a typo in docs or code comments
- Adding a single focused unit test (e.g., testing a specific behavior of one function)
- Updating a README section
- Small documentation additions that don't require API changes

**Expected PR size**: < 50 lines changed, typically < 5 files touched

**Characteristics**:
- No changes to contract interfaces
- No cross-contract implications
- Can be completed in < 1 hour
- Low risk of regression

**When you're done**: Run `make test && make lint` locally to verify. No need to regenerate docs.

### `complexity: medium`

**Scope**: Adds one new public function or test category to a single contract, or moderate documentation work. May require regenerating interface docs.

**Examples**:
- Adding a `get_admin()` view function to `allowlist-token`, including happy-path and auth test coverage
- Extending benchmarks with a new measurement scenario
- Adding a new example contract or example code under `/examples`
- Refactoring test coverage for an existing function
- Adding a new section to an architecture/design document

**Expected PR size**: 100–500 lines changed, typically 3–10 files touched

**Characteristics**:
- May change contract public API surface
- Typically single-contract impact (but review for composition implications)
- Can be completed in 2–4 hours
- Moderate risk; needs thorough testing

**When you're done**:
1. Run `make test && make lint` locally.
2. If you changed any public function signature or interface-related attribute, run `./scripts/regenerate-docs.sh` and commit the updated files.
3. Open the PR with a description of what changed and why.

### `complexity: high`

**Scope**: Spans multiple contracts, introduces a new design, or changes core infrastructure (CI, tooling, build). Requires a design writeup and careful review.

**Examples**:
- Introducing a new cross-contract composition pattern or new compliance primitive crate
- Refactoring auth or event-emission patterns across multiple contracts
- Major changes to CI/CD or testing infrastructure
- Adding a new language binding or build target
- Writing significant documentation (migration guides, design specs, governance docs)

**Expected PR size**: 500+ lines changed, 5+ files touched, may span multiple PRs

**Characteristics**:
- Changes affect multiple contracts or system-level concerns
- High risk of introducing regressions or composition bugs
- Requires architecture review and buy-in before starting
- Can take 1–2 weeks of sustained work

**When you're done**:
1. Run `make test && make lint` locally.
2. Run `./scripts/regenerate-docs.sh` if any interface changed.
3. Ensure all tests pass and document any breaking changes clearly in the PR.
4. Be prepared to discuss trade-offs and alternatives with reviewers.

## Triage Process

### For Maintainers: Labeling a New Issue

1. **Understand the scope**: Read the issue description and acceptance criteria carefully. Does it touch one contract or many? Does it require a new design or is it straightforward?

2. **Assign complexity**:
   - **trivial**: Single-file changes, docs, or small test additions (no API changes)
   - **medium**: One new public function, new test category, or moderate docs (may need interface regen)
   - **high**: Multiple contracts, infrastructure, or major design changes

3. **Add other labels as needed**:
   - `good first issue` — suitable for someone new to the repo; has clear acceptance criteria and no hidden dependencies
   - `help wanted` — explicitly inviting community contributions
   - `question` — discussion or clarification needed before work starts
   - `bug` — unintended behavior or defect
   - `enhancement` — new feature or improvement

4. **Link related issues**: If this issue is blocked by or depends on another, add a comment linking them.

### For Contributors: Picking Up an Issue

1. **Comment on the issue** to let others know you're interested. Include "I'm working on this" or similar.

2. **Verify the complexity label** matches your available time. If it looks significantly bigger or smaller than described, ask in the issue before starting.

3. **Reread the acceptance criteria** — this is your done checklist.

4. **Check for blockers**:
   - Does the issue reference another open issue? Check if it's merged first.
   - Are there any questions posted in comments? Reply or ask before proceeding.

5. **Start work**:
   - Create a branch: `git checkout -b descriptive-branch-name`
   - Make your changes, keeping them scoped to the issue.
   - Write tests for new public functions (happy path + at least one failure case).
   - If you changed any contract interface, run `./scripts/regenerate-docs.sh` and commit the output.

6. **Before opening a PR**:
   - Run `make test && make lint` locally — both must pass.
   - Verify all acceptance criteria are met.
   - Review your own diff for clarity and adherence to code style.

## Code Size Expectations per Complexity

Keeping contracts small and single-responsibility is a core principle of this repo. Each contract crate should stay under ~300 lines — if a change pushes it beyond that, consider whether the change belongs in a new crate or under `/examples` instead.

**Trivial**: Crate size unchanged; documentation or test-only additions.

**Medium**: Crate grows by 20–50 lines; new public function plus test coverage.

**High**: Crate grows significantly or a new crate is introduced; requires design discussion before work starts.

## Backlog Prioritization

The maintainers prioritize the backlog based on:

1. **Dependencies**: Issues that unblock other issues get priority.
2. **User requests**: Issues reported by users or ecosystem members get weighted higher.
3. **Technical debt**: Security or correctness issues take precedence over nice-to-haves.
4. **Balance**: Mix of feature work, documentation, and debt paydown.

If you want to propose a large feature, open an issue with a design sketch and tag `complexity: high` — we can discuss trade-offs before you invest the time.

## Review Expectations

All PRs are reviewed against:

- **Correctness**: Does the code do what the issue asks?
- **Testing**: Do new functions have tests? Do existing tests still pass?
- **Style**: Does it follow the code style of the repo? (See [CONTRIBUTING.md](./CONTRIBUTING.md#code-style))
- **Scope**: Does the PR stay focused on the issue, or does it drift into unrelated changes?
- **Documentation**: If interfaces changed, are docs regenerated? Is the commit message clear?

`complexity: medium` and `complexity: high` PRs may be reviewed more thoroughly and may require multiple rounds of feedback.

## Merging conflicting contract PRs

Several feature PRs in this repo have touched the same contract file — pause,
compliance-officer, audit-log, TTL extension, and multisig signer work have all
landed in one `lib.rs` at different times. When two of them are merged without
being reconciled, the result still *compiles*: `cargo check` is happy with a
file that ends up with a function body defined twice, or with an orphaned block
kept from one side of the conflict. The damage only shows up later, as a
confusing error in an unrelated PR or a wasm export collision at link time.

When you resolve a conflict in a shared contract file, work through this list
before you push the merge commit:

- [ ] **Resolve the hunk, not the file.** Never take `--ours` or `--theirs`
      wholesale for a conflict in a contract `lib.rs` — in these merges both
      sides are usually wanted, just once each.
- [ ] **Read the merged file, not the diff.** For every function either branch
      touched (including ones the other branch added nearby), confirm it is
      defined exactly once and that no helper the merged code calls was dropped
      with the other side of the conflict.
- [ ] **Run `cargo test -p <affected-crate>` — not just `cargo check`.** This is
      the step this section exists for. `check` proves the file type-checks;
      only the test build compiles the merged set of `#[contractimpl]` exports
      and fails on a duplicated entrypoint or a stale call left behind.
- [ ] **If the conflict was in an interface**, run `./scripts/regenerate-docs.sh`
      and commit the regenerated `docs/interfaces/` — a merge can leave the
      extracted XDR spec describing the pre-merge signature.
- [ ] **If the shared file involves storage keys** (`DataKey` or any other
      `#[contracttype]` used for storage), re-read
      [`STORAGE_VERSIONING.md`](./STORAGE_VERSIONING.md) after the merge: a
      conflict can silently drop a variant one branch added.
- [ ] **Run `make test` and `make lint` across the workspace** before merging,
      not only the crate in conflict — a fix in one crate can mask a break in a
      sibling that was merged alongside it.
- [ ] **Make the merge commit message describe the reconciliation**: name both
      PRs and say which hunks you kept or dropped, so the next person reading
      `git log` on that file knows what was intentional.

The same rules apply when a *contributor* rebases onto `main` after a sibling
PR merged into the same contract file: a clean rebase is not the same as a
correct one. Run the crate's tests after the rebase, not only after the
original commit.

## Questions?

If you're unsure about complexity, scope, or whether an issue is a good fit, open an issue with your question or comment on the relevant existing issue. The maintainers are here to help.
