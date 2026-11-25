#![no_main]

use libfuzzer_sys::fuzz_target;
use p2p_identity::{ContactPayload, Fingerprint};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(contact) = ContactPayload::parse(text) {
        let _ = format!("{contact:?}");
    }
    if let Ok(fingerprint) = Fingerprint::parse(text) {
        let _ = fingerprint.to_string();
    }
});
