//! The fuzz target `wisp_packet`: `podcrates_fuzz::targets::wisp_packet` says what it checks.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| podcrates_fuzz::targets::wisp_packet(data));
