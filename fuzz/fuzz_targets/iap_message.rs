//! The fuzz target `iap_message`: `podcrates_fuzz::targets::iap_message` says what it checks.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| podcrates_fuzz::targets::iap_message(data));
