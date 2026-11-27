//! Versioned message envelopes, local conversation state, and ciphertext-only
//! persistence for the P2P messenger.
//!
//! This crate deliberately does **not** encrypt or send messages. Payloads are
//! ciphertext produced by the `p2p-groups` MLS layer; this crate authenticates
//! the envelope boundary and tracks state after a higher layer decrypts. No
//! delivery status is invented from a local compose or send action.

#![forbid(unsafe_code)]

mod conversation;
mod envelope;
mod error;
mod receipt;

pub use conversation::{Conversation, DeliveryState, ReceivedMessage};
pub use envelope::{ENVELOPE_V3_VERSION, now_seconds};
pub use envelope::{
    Envelope, EnvelopeParams, EnvelopeV3, MAX_ENVELOPE_BYTES, MAX_PAYLOAD_BYTES, MessageKind,
    PROTOCOL_MAGIC, V3_INNER_MAGIC, V3_INNER_VERSION, V3_MAC_LEN, V3_MAGIC, V3_NONCE_LEN,
    V3_ROUTE_TAG_LEN, V3InnerFrame, random_id,
};
pub use error::MessageError;
pub use receipt::{Receipt, ReceiptStatus};
