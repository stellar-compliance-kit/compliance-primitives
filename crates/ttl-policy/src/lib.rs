// Copyright (c) 2026 Stellar Compliance Kit contributors
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

//! Shared storage TTL policy for the compliance primitives contracts.
//!
//! Every contract that extends an instance or persistent entry's TTL should
//! take its values from this crate, so the policy stays consistent and is
//! changed in one place. All values are ledger counts, assuming ~5 seconds
//! per ledger on mainnet.
#![no_std]

/// Standard threshold: extend an entry's TTL when its remaining TTL drops
/// below this many ledgers (~7 days).
pub const TTL_THRESHOLD: u32 = 120_960;

/// Standard target: remaining TTL, in ledgers, after an extension (~90 days).
pub const TTL_EXTEND_TO: u32 = 1_555_200;

/// Denylist entries are extended to this maximum remaining TTL (~365 days).
/// Long-lived so that a denial is never silently archived (fail-open).
pub const DENYLIST_ENTRY_TTL_EXTEND_TO: u32 = 6_311_520;

/// Denylist entries are re-extended once their remaining TTL falls below half
/// of [`DENYLIST_ENTRY_TTL_EXTEND_TO`] (~182 days).
pub const DENYLIST_ENTRY_TTL_THRESHOLD: u32 = DENYLIST_ENTRY_TTL_EXTEND_TO / 2;
