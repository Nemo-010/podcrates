//! The fuzz target `nostr_message`: `podcrates_fuzz::targets::nostr_message` says what it checks.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| podcrates_fuzz::targets::nostr_message(data));
