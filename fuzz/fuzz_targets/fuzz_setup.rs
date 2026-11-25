#![no_main]

use libfuzzer_sys::fuzz_target;
use p2p_chat::SetupEnvelope;

fuzz_target!(|data: &[u8]| {
    let Ok(envelope) = SetupEnvelope::from_bytes(data) else {
        return;
    };
    let _ = format!("{envelope:?}");
    let _ = envelope.verify(&envelope.sender);

    if envelope.verify(&envelope.sender).is_ok() {
        let encoded = envelope.to_bytes().expect("verified setup frame encodes");
        let decoded = SetupEnvelope::from_bytes(&encoded).expect("encoded setup frame decodes");
        assert_eq!(decoded, envelope);
    }
});
