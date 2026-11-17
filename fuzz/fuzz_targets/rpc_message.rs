//! The fuzz target `rpc_message`: `podcrates_fuzz::targets::rpc_message` says what it checks.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| podcrates_fuzz::targets::rpc_message(data));
