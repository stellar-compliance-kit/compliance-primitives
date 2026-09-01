# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-08-27

### Added

- **multisig-admin**: Proposal workflow with ledger-sequence-based expiry
  - `propose()` — Create a new governance proposal with an expiry ledger
  - `approve()` — Approve a proposal (restricted to registered signers)
  - `execute()` — Execute a proposal once threshold is met
  - `get_proposal()` — Query proposal details and current approvals
  - `ExpiredProposal` error variant — Rejects approval/execution after expiry

- **multisig-audit-trail**: New example demonstrating governance audit trail
  - Shows how to integrate `multisig-admin` proposals with `audit-log`
  - Pattern for recording proposal creation, approvals, execution, and expiry
  - Test suite covering successful proposal flow, expiry handling, and approval history

- **CI**: Changelog version sync check
  - `scripts/check-changelog.sh` enforces CHANGELOG.md updates alongside version bumps
  - New GitHub Actions job `changelog-version-sync` validates in CI

- **Documentation**: QUICKSTART.md
  - Step-by-step guide from clone → build → test → example → testnet → web playground
  - Linked prominently from README.md
  - Includes troubleshooting and key file reference

### Changed

- README.md: Added prominent link to QUICKSTART.md for new contributors
- CONTRIBUTING.md: Documented CHANGELOG.md requirement for version bumps
