#![no_main]

use libfuzzer_sys::fuzz_target;
use p2p_messaging::{EnvelopeV3, V3_MAC_LEN, V3InnerFrame};

fuzz_target!(|data: &[u8]| {
    // Parsing must be total for arbitrary bytes, including every truncated
    // prefix of a valid frame.
    if let Ok(envelope) = EnvelopeV3::from_bytes(data) {
        let _ = format!("{envelope:?}");
        let _ = envelope.header_bytes();
        let encoded = envelope.to_bytes().expect("parsed v3 envelope encodes");
        let decoded = EnvelopeV3::from_bytes(&encoded).expect("encoded v3 envelope decodes");
        assert_eq!(decoded, envelope);

        // A fixed, non-secret test key lets the harness cover MAC verification
        // without inventing or exporting any key material.
        let key = [0x42u8; V3_MAC_LEN];
        if envelope.verify_mac(&key).is_ok() {
            decoded
                .verify_mac(&key)
                .expect("verified mac stays verified after canonical re-encoding");
        }
    }

    if let Ok(inner) = V3InnerFrame::from_bytes(data) {
        let _ = format!("{inner:?}");
        let encoded = inner.to_bytes().expect("parsed v3 inner frame encodes");
        let decoded = V3InnerFrame::from_bytes(&encoded).expect("encoded v3 inner frame decodes");
        assert_eq!(decoded, inner);
    }
});
