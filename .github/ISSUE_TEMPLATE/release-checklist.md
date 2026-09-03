---
name: Release checklist
about: Cutting a new release of compliance-primitives
title: "Release: v"
labels: release
assignees: ""
---

## Release Preparation

- [ ] Determine the new version number (e.g., v0.1.0, v0.2.0) and update all instances
  - [ ] Update version in `Cargo.toml` files (workspace members)
  - [ ] Update version in any documentation that references it
  
- [ ] Update CHANGELOG.md
  - [ ] Add new section for the release with the version and date
  - [ ] Document all features, bug fixes, and breaking changes since the last release
  - [ ] Verify links to related issues/PRs are correct
  
- [ ] Run tests locally
  - [ ] `cargo test --workspace` passes
  - [ ] `cargo clippy --workspace` passes
  - [ ] No warnings or errors in build output

- [ ] Rebuild WASM binaries
  - [ ] Run the WASM build process for all contracts
  - [ ] Verify all `.wasm` artifacts are updated
  - [ ] Commit updated WASM binaries

- [ ] Regenerate documentation
  - [ ] Run doc regeneration scripts (if any)
  - [ ] Update generated docs in the repository
  - [ ] Verify docs build cleanly: `cargo doc --workspace --no-deps`

## Release Finalization

- [ ] Commit all changes
  - [ ] Version bumps, CHANGELOG, and docs are committed
  - [ ] Commit message follows project conventions
  
- [ ] Create and push release tag
  - [ ] Tag format: `v<version>` (e.g., `v0.2.0`)
  - [ ] Annotated tag with release notes: `git tag -a v<version> -m "Release v<version>"`
  - [ ] Push tag to repository: `git push origin v<version>`

- [ ] Create GitHub release
  - [ ] Draft release notes from CHANGELOG
  - [ ] Attach any release artifacts (WASM binaries if applicable)
  - [ ] Mark as latest release (unless pre-release)

## Deployment

- [ ] Deploy to testnet
  - [ ] Deploy new contract instances to Stellar testnet
  - [ ] Record deployed contract IDs in deployment manifest/docs
  - [ ] Run smoke tests against testnet deployment
  - [ ] Verify all core functionality works end-to-end

- [ ] Post-release verification
  - [ ] Verify GitHub release is visible and properly formatted
  - [ ] Verify tag is pushed and visible in repository
  - [ ] Announce release in project channels if applicable

## Rollback Plan

If issues are discovered after release, document any rollback steps here:
- Revert tag: `git tag -d v<version> && git push origin :v<version>`
- If mainnet was affected, create a hotfix branch and release v<version>.1
