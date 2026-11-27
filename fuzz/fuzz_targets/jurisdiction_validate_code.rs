#![no_main]

use libfuzzer_sys::fuzz_target;
use jurisdiction_flag::validate_jurisdiction_code;

fuzz_target!(|data: &[u8]| {
    // Interpret arbitrary bytes as a (lossy) UTF-8 string, mirroring how
    // user-supplied input may reach the validator.
    let input = String::from_utf8_lossy(data);

    // The validator must never panic on arbitrary input.
    let result = validate_jurisdiction_code(&input);

    // The documented contract: a valid jurisdiction code is exactly two
    // uppercase ASCII letters. Verify the validator agrees with that contract.
    let expected = input.len() == 2
        && input.bytes().all(|b| b.is_ascii_uppercase());

    assert_eq!(
        result, expected,
        "validate_jurisdiction_code({:?}) returned {}, expected {}",
        input, result, expected
    );
});