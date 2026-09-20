#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Any input must yield None or a well-formed hex build ID —
    // never a panic, never a corrupted ID.
    if let Some(id) = vdr_core::build_id_from_bytes(data) {
        assert!(!id.is_empty() && id.len() % 2 == 0);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }
});
