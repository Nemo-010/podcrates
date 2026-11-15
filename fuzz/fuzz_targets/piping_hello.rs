//! The fuzz target `piping_hello`: `podcrates_fuzz::targets::piping_hello` says what it checks.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| podcrates_fuzz::targets::piping_hello(data));
