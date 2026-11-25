//! Application-level conversation controller for the P2P messenger.
//!
//! This crate connects the direct transport, signed MLS setup frames, and
//! `MlsConversation` state. It never invents delivery, group-join, or
//! verification status: connection state comes from the Swarm, setup status
//! comes from verified signed frames, and delivery state changes only when a
//! verified MLS-encrypted receipt is received.
//!
//! MLS state and displayed plaintext are memory-only. Nothing here persists a
//! restored conversation or claims that encrypted envelope rows can rebuild
//! MLS group state.

#![forbid(unsafe_code)]

mod channel;
mod controller;
mod setup;

pub use channel::{
    CHANNEL_MAGIC, ChannelFrame, ChannelFrameKind, DEFAULT_CHANNEL_ID, MAX_CHANNEL_MEMBERS,
    MAX_CHANNEL_NAME_BYTES, MAX_CHANNEL_TEXT_BYTES,
};
pub use controller::{
    ChannelInfo, ChatMessage, ConversationInfo, ConversationStatus, MessageOrigin,
    MessengerController, RedialState,
};
use libp2p::Multiaddr;
pub use libp2p_identity::PeerId;
pub use p2p_files::{
    FileConfig, FileTransferInfo, QuarantineDeletionPolicy, ReleaseApproval, ReleasedFile,
    TransferDirection, TransferStatus,
};
pub use p2p_groups::{CommitOutcome, GroupError as GroupCryptoError, GroupOperation};
pub use p2p_security::{
    FileFormat, FileScanner, MAX_RELEASE_BYTES, MAX_RELEASE_CHUNKS, MAX_RELEASE_NAME_BYTES,
    ReleasePolicy, ReleaseRejection, ScanOutcome, ScanRequest, ScanResult, ScanStatus,
    SecurityConfig, is_safe_file_name,
};
pub use setup::{SETUP_MAGIC, SETUP_VERSION, SetupEnvelope, SetupMessage};
use thiserror::Error;

/// Errors from the application controller. Error text carries only static
/// categories, public identifiers, or lengths; no plaintext or key material.
#[derive(Debug, Error)]
pub enum ChatError {
    #[error(transparent)]
    Identity(#[from] p2p_identity::IdentityError),
    #[error(transparent)]
    Group(#[from] p2p_groups::GroupError),
    #[error(transparent)]
    Message(#[from] p2p_messaging::MessageError),
    #[error(transparent)]
    Network(#[from] p2p_network::NetworkError),
    #[error(transparent)]
    File(#[from] p2p_files::FileError),
    #[error("a file transfer is already active with this peer")]
    FileTransferLimit,
    #[error("file transfer is not tracked for this peer")]
    FileTransferMissing,
    #[error("invalid file frame: {0}")]
    InvalidFileFrame(&'static str),
    #[error("invalid MLS setup frame: {0}")]
    InvalidSetup(&'static str),
    #[error("signed setup sender does not match the authenticated peer")]
    UnexpectedSender,
    #[error("peer is not connected")]
    PeerNotConnected,
    #[error("a conversation with this peer already exists")]
    AlreadyEstablished,
    #[error("no active conversation is selected")]
    NoActiveConversation,
    #[error("conversation is unknown")]
    UnknownConversation,
    #[error("conversation setup is not complete")]
    ConversationNotReady,
    #[error("only the group administrator may perform this action")]
    NotAdmin,
    #[error("peer is not an active member of this group")]
    NotGroupMember,
    #[error("another group operation is still pending")]
    GroupOperationPending,
    #[error("group operation target is invalid: {0}")]
    InvalidGroupTarget(&'static str),
    #[error("group operation was rejected by a member")]
    GroupOperationRejected,
    #[error("invalid channel frame: {0}")]
    InvalidChannelFrame(&'static str),
    #[error("channel is unknown in this conversation")]
    ChannelNotFound,
    #[error("channel already exists in this conversation")]
    ChannelAlreadyExists,
    #[error("channel limit reached for this conversation")]
    ChannelLimit,
    #[error("peer is not allowed in this channel")]
    NotChannelMember,
    #[error("channel policy revision conflicts with local state")]
    ChannelRevisionConflict,
    #[error("no pending KeyPackage for this conversation")]
    PendingKeyPackageMissing,
    #[error("message text cannot be empty")]
    EmptyMessage,
    #[error("invalid peer identifier: {0}")]
    InvalidPeerId(String),
}

/// Parse a user-supplied peer ID. The value is public and verified for its
/// encoding only; it does not prove that the person is the intended contact.
pub fn parse_peer_id(input: &str) -> Result<PeerId, ChatError> {
    input
        .trim()
        .parse::<PeerId>()
        .map_err(|error| ChatError::InvalidPeerId(error.to_string()))
}

/// Parse a user-supplied direct-connect address. The `/p2p/<peer-id>` suffix
/// is required so Noise has an expected remote identity before dialing.
pub fn parse_address(input: &str) -> Result<Multiaddr, ChatError> {
    Ok(p2p_network::Network::parse_address(input)?)
}
