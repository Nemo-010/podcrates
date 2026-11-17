//! The fuzz target `h2_header_block`: `podcrates_fuzz::targets::h2_header_block` says what it checks.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| podcrates_fuzz::targets::h2_header_block(data));
