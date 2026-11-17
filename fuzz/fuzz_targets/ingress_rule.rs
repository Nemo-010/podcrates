//! The fuzz target `ingress_rule`: `podcrates_fuzz::targets::ingress_rule` says what it checks.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| podcrates_fuzz::targets::ingress_rule(data));
