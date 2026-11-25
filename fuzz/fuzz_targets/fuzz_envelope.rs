#![no_main]

use libfuzzer_sys::fuzz_target;
use p2p_messaging::Envelope;

fuzz_target!(|data: &[u8]| {
    let Ok(envelope) = Envelope::from_bytes(data) else {
        return;
    };
    let _ = format!("{envelope:?}");
    if envelope.verify().is_err() {
        return;
    }

    // A verified envelope must canonicalize to itself.
    let encoded = envelope.to_bytes().expect("verified envelope encodes");
    let decoded = Envelope::from_bytes(&encoded).expect("encoded envelope decodes");
    assert_eq!(decoded, envelope);
});
