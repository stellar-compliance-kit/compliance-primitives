//! Lightweight sequence fuzzer for `jurisdiction-flag` set/get invariants.
//!
//! ## Approach
//!
//! Full `cargo-fuzz` / libFuzzer targets are awkward for `#![no_std]` Soroban
//! contracts (host `Env`, auth mocking, and no OS entropy inside the wasm
//! build). Instead this harness is a seeded PRNG loop living in the crate's
//! test binary — the same shape intended for denylist-gate (#86), so both
//! contracts can share the "small address pool + last-write-wins model"
//! pattern without a separate fuzz workspace.
//!
//! ## How to run
//!
//! Default short run (also covered by `cargo test -p jurisdiction-flag`):
//!
//! ```sh
//! cargo test -p jurisdiction-flag fuzz_jurisdiction_set_get_sequences -- --nocapture
//! ```
//!
//! Longer periodic campaign (raise iterations / ops via env vars):
//!
//! ```sh
//! FUZZ_ITERATIONS=2000 FUZZ_OPS=64 \
//!   cargo test -p jurisdiction-flag fuzz_jurisdiction_set_get_sequences -- --nocapture
//! ```
//!
//! Not wired into CI — keep the default iteration count small so `cargo test
//! --workspace` stays fast; bump the env vars when hunting for regressions.

extern crate std;

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{vec, Env};

/// Tiny xorshift32 so we don't need an extra RNG crate in tests.
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

#[test]
fn fuzz_jurisdiction_set_get_sequences() {
    let iterations: u32 = std::env::var("FUZZ_ITERATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(128);
    let ops_per_iter: u32 = std::env::var("FUZZ_OPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(24);

    let code_strs = ["US", "CA", "GB", "DE", "JP", "FR", "AU"];
    // Membership list used by `is_permitted_jurisdiction` checks — a fixed
    // subset so the fuzzer's oracle stays simple.
    let permitted_strs = ["US", "CA", "GB"];

    for seed in 1..=iterations {
        let env = Env::default();
        env.mock_all_auths();
        let issuer = Address::generate(&env);
        let contract_id = env.register(JurisdictionFlag, ());
        let client = JurisdictionFlagClient::new(&env, &contract_id);
        client.initialize(&issuer);

        let addresses: [Address; 5] = [
            Address::generate(&env),
            Address::generate(&env),
            Address::generate(&env),
            Address::generate(&env),
            Address::generate(&env),
        ];

        let codes: [String; 7] = [
            String::from_str(&env, code_strs[0]),
            String::from_str(&env, code_strs[1]),
            String::from_str(&env, code_strs[2]),
            String::from_str(&env, code_strs[3]),
            String::from_str(&env, code_strs[4]),
            String::from_str(&env, code_strs[5]),
            String::from_str(&env, code_strs[6]),
        ];

        let allowed_codes = vec![
            &env,
            String::from_str(&env, permitted_strs[0]),
            String::from_str(&env, permitted_strs[1]),
            String::from_str(&env, permitted_strs[2]),
        ];

        // Model: last set code per address index (None until first write).
        let mut model: [Option<usize>; 5] = [None; 5];
        let mut rng = seed;

        for _ in 0..ops_per_iter {
            let addr_i = next_usize(&mut rng, addresses.len());
            let code_i = next_usize(&mut rng, codes.len());
            client.set_jurisdiction(&issuer, &addresses[addr_i], &codes[code_i]);
            model[addr_i] = Some(code_i);
        }

        for (addr_i, address) in addresses.iter().enumerate() {
            let got = client.get_jurisdiction(address);
            match model[addr_i] {
                None => assert_eq!(
                    got, None,
                    "seed={seed} addr={addr_i}: expected None after no writes"
                ),
                Some(code_i) => assert_eq!(
                    got,
                    Some(codes[code_i].clone()),
                    "seed={seed} addr={addr_i}: last-write-wins mismatch"
                ),
            }

            let permitted = client.is_permitted_jurisdiction(address, &allowed_codes);
            let expected_permitted = match &got {
                Some(code) => allowed_codes.iter().any(|c| c == *code),
                None => false,
            };
            assert_eq!(
                permitted, expected_permitted,
                "seed={seed} addr={addr_i}: is_permitted_jurisdiction inconsistent with get"
            );
        }
    }
}

/// Fuzz `validate_jurisdiction_code` with arbitrary byte-derived strings.
///
/// Mirrors the `cargo-fuzz` target `fuzz_validate_jurisdiction_code`: the
/// validator must never panic and must accept a string iff it is exactly two
/// uppercase ASCII letters (`A`..=`Z`).
#[test]
fn fuzz_validate_jurisdiction_code_bytes() {
    let iterations: u32 = std::env::var("FUZZ_ITERATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(256);

    // Interesting fixed inputs: empty, lowercase, mixed, non-ASCII, overlong.
    let fixed: [&str; 10] = [
        "",
        "U",
        "US",
        "us",
        "Us",
        "USA",
        "U1",
        "1S",
        "ÜS",
        "🇺🇸",
    ];

    for input in fixed {
        check_validate_oracle(input);
    }

    for seed in 1..=iterations {
        let mut rng = seed;
        // Bias length toward the interesting 0..=4 range, occasionally longer.
        let len = match next_u32(&mut rng) % 8 {
            0 => 0,
            1 => 1,
            2..=4 => 2,
            5 => 3,
            6 => 4,
            _ => next_usize(&mut rng, 16),
        };
        let mut bytes = std::vec::Vec::with_capacity(len);
        for _ in 0..len {
            // Mix printable ASCII, uppercase, lowercase, and arbitrary bytes.
            let b = match next_u32(&mut rng) % 4 {
                0 => b'A' + (next_u32(&mut rng) % 26) as u8,
                1 => b'a' + (next_u32(&mut rng) % 26) as u8,
                2 => (next_u32(&mut rng) % 128) as u8,
                _ => (next_u32(&mut rng) % 256) as u8,
            };
            bytes.push(b);
        }
        // Only feed valid UTF-8; invalid sequences are covered by the
        // cargo-fuzz target which operates on raw bytes.
        if let Ok(s) = std::str::from_utf8(&bytes) {
            check_validate_oracle(s);
        }
    }
}

fn check_validate_oracle(input: &str) {
    let env = Env::default();
    let s = String::from_str(&env, input);
    let got = validate_jurisdiction_code(&s);

    let expected = {
        let bytes = input.as_bytes();
        bytes.len() == 2 && bytes.iter().all(|b| b.is_ascii_uppercase())
    };
    assert_eq!(
        got, expected,
        "validate_jurisdiction_code({input:?}) = {got}, expected {expected}"
    );
}

#[test]
fn fuzz_jurisdiction_multicode_add_remove_sequences() {
    let iterations: u32 = std::env::var("FUZZ_ITERATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(128);
    let ops_per_iter: u32 = std::env::var("FUZZ_OPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(24);
    let code_strs = ["US", "CA", "GB", "DE", "JP", "FR", "AU"];

    for seed in 1..=iterations {
        let env = Env::default();
        env.mock_all_auths();
        let issuer = Address::generate(&env);
        let contract_id = env.register(JurisdictionFlag, ());
        let client = JurisdictionFlagClient::new(&env, &contract_id);
        client.initialize(&issuer);
        let address = Address::generate(&env);
        let codes: [String; 7] = [
            String::from_str(&env, code_strs[0]),
            String::from_str(&env, code_strs[1]),
            String::from_str(&env, code_strs[2]),
            String::from_str(&env, code_strs[3]),
            String::from_str(&env, code_strs[4]),
            String::from_str(&env, code_strs[5]),
            String::from_str(&env, code_strs[6]),
        ];
        let mut model = [false; 7];
        let mut rng = seed;

        for op in 0..ops_per_iter {
            let code_i = next_usize(&mut rng, codes.len());
            if next_u32(&mut rng) & 1 == 0 {
                client.add_jurisdiction(&issuer, &address, &codes[code_i]);
                model[code_i] = true;
            } else {
                client.remove_jurisdiction(&issuer, &address, &codes[code_i]);
                model[code_i] = false;
            }

            let listed = client.list_jurisdictions(&address);
            let expected_count = model.iter().filter(|present| **present).count();
            assert_eq!(
                listed.len() as usize,
                expected_count,
                "seed={seed} op={op}: jurisdiction list size mismatch"
            );
            for (code_i, expected) in model.iter().enumerate() {
                assert_eq!(
                    listed.iter().any(|listed_code| listed_code == codes[code_i]),
                    *expected,
                    "seed={seed} op={op} code={}: jurisdiction membership mismatch",
                    code_strs[code_i]
                );
            }
        }
    }
}
