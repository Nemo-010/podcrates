//! The fuzz target `ntfy_message`: `podcrates_fuzz::targets::ntfy_message` says what it checks.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| podcrates_fuzz::targets::ntfy_message(data));
