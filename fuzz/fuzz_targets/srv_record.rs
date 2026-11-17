//! The fuzz target `srv_record`: `podcrates_fuzz::targets::srv_record` says what it checks.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| podcrates_fuzz::targets::srv_record(data));
