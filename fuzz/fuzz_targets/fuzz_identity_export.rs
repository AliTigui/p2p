#![no_main]

use libfuzzer_sys::fuzz_target;
use p2p_identity::EncryptedIdentity;

fuzz_target!(|data: &[u8]| {
    if let Ok(envelope) = EncryptedIdentity::from_bytes(data.to_vec()) {
        let _ = format!("{envelope:?}");
    }
});
