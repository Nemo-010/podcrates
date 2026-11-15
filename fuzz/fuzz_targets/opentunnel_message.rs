//! The fuzz target `opentunnel_message`: `podcrates_fuzz::targets::opentunnel_message` says what it checks.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| podcrates_fuzz::targets::opentunnel_message(data));
