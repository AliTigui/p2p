use p2p_identity::IdentityError;
use p2p_storage::StorageError;
use thiserror::Error;

/// Errors from envelope parsing, verification, replay checks, and state
/// transitions. Strings deliberately omit payload bytes and key material.
#[derive(Debug, Error)]
pub enum MessageError {
    #[error("unsupported message envelope version {0}")]
    UnsupportedVersion(u16),
    #[error("message envelope uses the wrong protocol magic")]
    BadProtocol,
    #[error("message envelope is too large: {len} bytes (maximum {max})")]
    TooLarge { len: usize, max: usize },
    #[error("message envelope is truncated or has an invalid length field")]
    Truncated,
    #[error("message envelope has trailing bytes")]
    TrailingBytes,
    #[error("unknown message kind code {0}")]
    BadKind(u8),
    #[error("message signature is invalid")]
    BadSignature,
    #[error("sender public key does not match the envelope PeerId")]
    BadPeerId,
    #[error("only Ed25519 sender keys are accepted")]
    NotEd25519,
    #[error("message was already seen")]
    Replay,
    #[error("sender sequence regressed or repeated")]
    SequenceRegression,
    #[error("message id is not known to this conversation")]
    UnknownMessage,
    #[error("message belongs to a different conversation")]
    WrongConversation,
    #[error("message epoch {actual} does not match local epoch {expected}")]
    EpochMismatch { expected: u64, actual: u64 },
    #[error("sender sequence counter is exhausted")]
    SequenceExhausted,
    #[error("receipt payload is malformed")]
    InvalidReceipt,
    #[error("delivery state transition is not allowed")]
    InvalidStateTransition,
    #[error("conversation id is required")]
    MissingConversationId,
    #[error("local identity does not own this conversation")]
    WrongLocalIdentity,
    #[error("message replay cache is full")]
    ReplayCacheFull,
    #[error("system randomness source failed")]
    Randomness,
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error(transparent)]
    Storage(#[from] StorageError),
}
