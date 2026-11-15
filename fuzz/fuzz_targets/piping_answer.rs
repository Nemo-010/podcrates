//! The fuzz target `piping_answer`: `podcrates_fuzz::targets::piping_answer` says what it checks.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| podcrates_fuzz::targets::piping_answer(data));
