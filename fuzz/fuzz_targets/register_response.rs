//! The fuzz target `register_response`: `podcrates_fuzz::targets::register_response` says what it checks.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| podcrates_fuzz::targets::register_response(data));
