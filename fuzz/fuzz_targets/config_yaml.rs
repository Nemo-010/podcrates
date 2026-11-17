//! The fuzz target `config_yaml`: `podcrates_fuzz::targets::config_yaml` says what it checks.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| podcrates_fuzz::targets::config_yaml(data));
