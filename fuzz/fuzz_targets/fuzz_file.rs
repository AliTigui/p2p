#![no_main]

use libfuzzer_sys::fuzz_target;
use p2p_files::FileEnvelope;

fuzz_target!(|data: &[u8]| {
    let Ok(envelope) = FileEnvelope::from_bytes(data) else {
        return;
    };
    let _ = format!("{envelope:?}");
    let _ = envelope.verify(&envelope.sender);

    if envelope.verify(&envelope.sender).is_ok() {
        let encoded = envelope.to_bytes().expect("verified file frame encodes");
        let decoded = FileEnvelope::from_bytes(&encoded).expect("encoded file frame decodes");
        assert_eq!(decoded, envelope);
    }
});
