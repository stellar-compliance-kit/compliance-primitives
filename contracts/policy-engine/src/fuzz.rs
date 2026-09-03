//! Lightweight sequence fuzzer for `policy-engine` tree-build + evaluation
//! invariants.
//!
//! ## Approach
//!
//! Full `cargo-fuzz` / libFuzzer targets are awkward for `#![no_std]` Soroban
//! contracts (host `Env`, auth mocking, and no OS entropy inside the wasm
//! build). Instead this harness is a seeded PRNG loop living in the crate's
//! test binary — the same shape used by `jurisdiction-flag` (#87) — so the
//! policy-engine gets the same random-sequence coverage without a separate
//! fuzz workspace.
//!
//! The harness uses **inline mock contracts** (defined in `test_utils`) for
//! the denylist and jurisdiction check dependencies so it is fully
//! self-contained and models exactly the interfaces `policy-engine` calls
//! via `DenylistCheckInterface` and `JurisdictionCheckInterface`.
//!
//! ## What is fuzzed
//!
//! Each iteration:
//! 1. Creates a fresh `Env` with two inline mock contracts pre-deployed.
//! 2. Runs a random sequence of `AddDenylist`, `AddJurisdiction`, and
//!    `RemoveCheck` mutations, respecting `MAX_CHECKS`.
//! 3. Randomly arms addresses on the mock denylist / assigns jurisdiction codes.
//! 4. Calls `evaluate` for a random (from, to) pair and asserts no panic.
//! 5. Verifies the result matches the oracle model.
//!
//! ## How to run
//!
//! Default short run (also covered by `cargo test -p policy-engine`):
//!
//! ```sh
//! cargo test -p policy-engine fuzz_policy_engine_tree -- --nocapture
//! ```
//!
//! Longer periodic campaign:
//!
//! ```sh
//! FUZZ_ITERATIONS=2000 FUZZ_OPS=64 \
//!   cargo test -p policy-engine fuzz_policy_engine_tree -- --nocapture
//! ```
//!
//! Not wired into CI — keep the default iteration count small so
//! `cargo test --workspace` stays fast; bump the env vars when hunting for
//! regressions.

extern crate std;

use super::*;
use crate::test_utils::{
    MockDenylist, MockDenylistClient, MockJurisdiction, MockJurisdictionClient,
};
use soroban_sdk::testutils::{Address as _, EnvTestConfig};
use soroban_sdk::{vec, Env, String};

// ---------------------------------------------------------------------------
// xorshift32 PRNG — no extra RNG crate needed in tests
// ---------------------------------------------------------------------------

fn next_u32(state: &mut u32) -> u32 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = if x == 0 { 0x9E37_79B9 } else { x };
    *state
}

fn next_usize(state: &mut u32, upper: usize) -> usize {
    (next_u32(state) as usize) % upper
}

fn next_bool(state: &mut u32) -> bool {
    next_u32(state) & 1 == 1
}

// ---------------------------------------------------------------------------
// Operation type for random mutations
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
enum Op {
    /// Append a denylist check to the policy.
    AddDenylist,
    /// Append a jurisdiction check to the policy.
    AddJurisdiction,
    /// Remove the check at a random index (no-op if the list is empty).
    RemoveCheck,
}

const OPS: [Op; 3] = [Op::AddDenylist, Op::AddJurisdiction, Op::RemoveCheck];

// ---------------------------------------------------------------------------
// Fuzz test
// ---------------------------------------------------------------------------

/// Randomly builds policy-engine combinator trees and evaluates them,
/// asserting no panic and result consistency with the oracle model.
///
/// Invariants checked after every random sequence:
///
/// 1. **No panic** — neither `add_check`, `remove_check`, nor `evaluate`
///    should ever panic regardless of the input sequence.
/// 2. **MaxDepthExceeded is returned** — `add_check` returns
///    `Err(Error::MaxDepthExceeded)` when at capacity; it never panics.
/// 3. **All semantics oracle** — with `CombineOp::All`, `evaluate` returns
///    `true` iff every registered check passes for both `from` and `to`.
/// 4. **Any semantics oracle** — with `CombineOp::Any`, `evaluate` returns
///    `true` iff at least one registered check passes for both `from` and `to`.
#[test]
fn fuzz_policy_engine_tree() {
    let iterations: u32 = std::env::var("FUZZ_ITERATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(128);
    let ops_per_iter: u32 = std::env::var("FUZZ_OPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(24);

    let juri_code_strs = ["US", "CA", "GB", "DE", "JP"];
    // Fixed allowed-codes list used by every jurisdiction check in the engine
    // so the oracle stays simple.
    let allowed_strs = ["US", "CA", "GB"];

    for seed in 1..=iterations {
        // Fresh environment for each iteration.  Disable snapshot-at-drop so
        // the harness doesn't write 10k JSON files to disk during a long run.
        let env = Env::new_with_config(EnvTestConfig {
            capture_snapshot_at_drop: false,
        });
        env.mock_all_auths();

        // Deploy inline mock contracts.
        let deny_id = env.register(MockDenylist, ());
        let juri_id = env.register(MockJurisdiction, ());

        // Pick a random CombineOp for this iteration.
        let mut rng: u32 = seed;
        let use_all = next_bool(&mut rng);
        let op_enum = if use_all { CombineOp::All } else { CombineOp::Any };

        // Deploy policy engine.
        let admin = Address::generate(&env);
        let engine_id = env.register(PolicyEngine, ());
        let client = PolicyEngineClient::new(&env, &engine_id);
        client.initialize(&admin, &op_enum);

        // Small pool of addresses used for from/to and arming.
        const POOL: usize = 4;
        let addrs: [Address; POOL] = [
            Address::generate(&env),
            Address::generate(&env),
            Address::generate(&env),
            Address::generate(&env),
        ];

        // Build jurisdiction code values.
        let codes: [String; 5] = [
            String::from_str(&env, juri_code_strs[0]),
            String::from_str(&env, juri_code_strs[1]),
            String::from_str(&env, juri_code_strs[2]),
            String::from_str(&env, juri_code_strs[3]),
            String::from_str(&env, juri_code_strs[4]),
        ];
        let allowed_codes = vec![
            &env,
            String::from_str(&env, allowed_strs[0]),
            String::from_str(&env, allowed_strs[1]),
            String::from_str(&env, allowed_strs[2]),
        ];

        // ----------------------------------------------------------------
        // Random mutation sequence — build the check list
        // ----------------------------------------------------------------

        // Oracle model: true = denylist check, false = jurisdiction check.
        let mut check_is_deny: std::vec::Vec<bool> = std::vec::Vec::new();

        for _ in 0..ops_per_iter {
            let op = OPS[next_usize(&mut rng, OPS.len())];
            match op {
                Op::AddDenylist => {
                    if check_is_deny.len() < MAX_CHECKS as usize {
                        client.add_check(
                            &admin,
                            &CheckKind::Denylist(DenylistCheck {
                                contract: deny_id.clone(),
                            }),
                        );
                        check_is_deny.push(true);
                    } else {
                        // At capacity — must return MaxDepthExceeded, no panic.
                        let res = client.try_add_check(
                            &admin,
                            &CheckKind::Denylist(DenylistCheck {
                                contract: deny_id.clone(),
                            }),
                        );
                        assert!(
                            matches!(res, Err(Ok(Error::MaxDepthExceeded))),
                            "seed={seed}: expected MaxDepthExceeded at capacity, got {res:?}"
                        );
                    }
                }
                Op::AddJurisdiction => {
                    if check_is_deny.len() < MAX_CHECKS as usize {
                        client.add_check(
                            &admin,
                            &CheckKind::Jurisdiction(JurisdictionCheck {
                                contract: juri_id.clone(),
                                allowed_codes: allowed_codes.clone(),
                            }),
                        );
                        check_is_deny.push(false);
                    } else {
                        // At capacity — must return MaxDepthExceeded.
                        let res = client.try_add_check(
                            &admin,
                            &CheckKind::Jurisdiction(JurisdictionCheck {
                                contract: juri_id.clone(),
                                allowed_codes: allowed_codes.clone(),
                            }),
                        );
                        assert!(
                            matches!(res, Err(Ok(Error::MaxDepthExceeded))),
                            "seed={seed}: expected MaxDepthExceeded at capacity, got {res:?}"
                        );
                    }
                }
                Op::RemoveCheck => {
                    if !check_is_deny.is_empty() {
                        let idx = next_usize(&mut rng, check_is_deny.len());
                        client.remove_check(&admin, &(idx as u32));
                        check_is_deny.remove(idx);
                    }
                    // If the list is empty, skip — nothing to remove.
                }
            }
        }

        // ----------------------------------------------------------------
        // Arm addresses randomly
        // ----------------------------------------------------------------

        // Randomly add some addresses to the mock denylist.
        let mock_deny = MockDenylistClient::new(&env, &deny_id);
        let mut denied: [bool; POOL] = [false; POOL];
        for i in 0..POOL {
            if next_bool(&mut rng) {
                mock_deny.add_to_denylist(&addrs[i]);
                denied[i] = true;
            }
        }

        // Randomly assign jurisdiction codes to some addresses.
        let mock_juri = MockJurisdictionClient::new(&env, &juri_id);
        let mut juri_code: [Option<usize>; POOL] = [None; POOL];
        for i in 0..POOL {
            if next_bool(&mut rng) {
                let ci = next_usize(&mut rng, codes.len());
                mock_juri.set_jurisdiction(&addrs[i], &codes[ci]);
                juri_code[i] = Some(ci);
            }
        }

        // ----------------------------------------------------------------
        // Evaluate and verify oracle
        // ----------------------------------------------------------------

        let addr_passes_denylist = |i: usize| -> bool { !denied[i] };
        let addr_passes_jurisdiction = |i: usize| -> bool {
            match juri_code[i] {
                None => false,
                Some(ci) => allowed_strs.contains(&juri_code_strs[ci]),
            }
        };

        let check_passes = |is_deny: bool, i: usize| -> bool {
            if is_deny {
                addr_passes_denylist(i)
            } else {
                addr_passes_jurisdiction(i)
            }
        };

        // Pick a random (from, to) pair.
        let from_i = next_usize(&mut rng, POOL);
        let to_i = next_usize(&mut rng, POOL);

        // Oracle result.
        let oracle_result = if check_is_deny.is_empty() {
            // No checks: All → true (vacuously), Any → false.
            use_all
        } else if use_all {
            check_is_deny.iter().all(|&is_deny| {
                check_passes(is_deny, from_i) && check_passes(is_deny, to_i)
            })
        } else {
            check_is_deny.iter().any(|&is_deny| {
                check_passes(is_deny, from_i) && check_passes(is_deny, to_i)
            })
        };

        // evaluate must not panic.
        let result = client.evaluate(&addrs[from_i], &addrs[to_i]);

        assert_eq!(
            result, oracle_result,
            "seed={seed} from={from_i} to={to_i} op={} checks={:?} denied={denied:?} juri={juri_code:?}",
            if use_all { "All" } else { "Any" },
            check_is_deny,
        );
    }
}
