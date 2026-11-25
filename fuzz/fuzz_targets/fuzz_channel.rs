#![no_main]

use libfuzzer_sys::fuzz_target;
use p2p_chat::ChannelFrame;

fuzz_target!(|data: &[u8]| {
    let Ok(frame) = ChannelFrame::from_bytes(data) else {
        return;
    };
    let _ = format!("{frame:?}");

    let encoded = frame.to_bytes().expect("decoded channel frame encodes");
    let decoded = ChannelFrame::from_bytes(&encoded).expect("encoded channel frame decodes");
    assert_eq!(decoded, frame);
});
