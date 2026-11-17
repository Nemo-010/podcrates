//! The fuzz target `request_head`: `podcrates_fuzz::targets::request_head` says what it checks.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| podcrates_fuzz::targets::request_head(data));
