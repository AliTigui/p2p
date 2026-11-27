//! Bounded request-response codec for the v1 P2P protocols.
//!
//! The codec carries opaque bytes only. Signature verification, replay
//! checks, MLS setup validation, and delivery-state transitions belong to the
//! application layer and are never performed by this transport module.

use std::{future::Future, io};

use libp2p::futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p_request_response::Codec;

/// Maximum bytes accepted in one request or response frame. This matches the
/// messaging envelope cap and prevents an unbounded allocation from malicious
/// length prefixes.
pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024;

/// Message delivery protocol negotiated with libp2p multistream-select over
/// the existing Noise-authenticated connection.
pub const MESSAGE_PROTOCOL: &str = "/p2p-messenger/message/1";

/// MLS setup protocol for exchanging signed KeyPackage and Welcome frames.
/// It is a separate, explicitly versioned protocol; unknown versions are
/// rejected by multistream-select rather than negotiated by "highest wins".
pub const MLS_SETUP_PROTOCOL: &str = "/p2p-messenger/mls-setup/2";

/// Legacy setup protocol. It is deliberately not registered; an old peer
/// cannot negotiate a downgraded setup frame with this build.
pub const LEGACY_MLS_SETUP_PROTOCOL: &str = "/p2p-messenger/mls-setup/1";

/// Encrypted file-transfer protocol. It is separate from messaging and setup
/// so a peer can decline file transfer without affecting chat delivery.
pub const FILE_PROTOCOL: &str = "/p2p-messenger/file/1";

/// Versioned capability/control protocol. It carries bounded opaque frames and
/// is used for explicit protocol checks; it never carries messages, MLS setup
/// state, file keys, or identity material.
pub const CONTROL_PROTOCOL: &str = "/p2p-messenger/control/1";

/// Canonical framed codec for the v1 protocols.
///
/// Wire format: `u32 big-endian length || payload`. Empty and oversized frames
/// are rejected before the body is read.
#[derive(Debug, Clone, Copy, Default)]
pub struct MessageCodec;

impl Codec for MessageCodec {
    type Protocol = String;
    type Request = Vec<u8>;
    type Response = Vec<u8>;

    fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> impl Future<Output = io::Result<Self::Request>> + Send
    where
        T: AsyncRead + Unpin + Send,
    {
        read_frame(io)
    }

    fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> impl Future<Output = io::Result<Self::Response>> + Send
    where
        T: AsyncRead + Unpin + Send,
    {
        read_frame(io)
    }

    fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        request: Self::Request,
    ) -> impl Future<Output = io::Result<()>> + Send
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_frame(io, request)
    }

    fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        response: Self::Response,
    ) -> impl Future<Output = io::Result<()>> + Send
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_frame(io, response)
    }
}

async fn read_frame<T>(io: &mut T) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin + Send,
{
    let mut length = [0u8; 4];
    io.read_exact(&mut length).await?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message frame length is outside safe bounds",
        ));
    }
    let mut bytes = vec![0u8; length];
    io.read_exact(&mut bytes).await?;
    Ok(bytes)
}

async fn write_frame<T>(io: &mut T, bytes: Vec<u8>) -> io::Result<()>
where
    T: AsyncWrite + Unpin + Send,
{
    if bytes.is_empty() || bytes.len() > MAX_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "message frame length is outside safe bounds",
        ));
    }
    let length = u32::try_from(bytes.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "message frame length is outside safe bounds",
        )
    })?;
    io.write_all(&length.to_be_bytes()).await?;
    io.write_all(&bytes).await?;
    io.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::futures::io::Cursor;

    #[test]
    fn control_protocol_is_explicitly_versioned() {
        assert_eq!(CONTROL_PROTOCOL, "/p2p-messenger/control/1");
    }

    #[tokio::test]
    async fn control_protocol_round_trips_an_opaque_frame() {
        let protocol = CONTROL_PROTOCOL.to_owned();
        let mut codec = MessageCodec;
        let mut buffer = Cursor::new(Vec::new());
        codec
            .write_request(&protocol, &mut buffer, b"capability-probe".to_vec())
            .await
            .expect("write control frame");
        buffer.set_position(0);
        let decoded = codec
            .read_request(&protocol, &mut buffer)
            .await
            .expect("read control frame");
        assert_eq!(decoded, b"capability-probe".to_vec());
    }

    #[tokio::test]
    async fn codec_round_trips_a_bounded_frame() {
        let protocol = MESSAGE_PROTOCOL.to_owned();
        let mut codec = MessageCodec;
        let mut buffer = Cursor::new(Vec::new());
        codec
            .write_request(&protocol, &mut buffer, b"opaque envelope".to_vec())
            .await
            .expect("write frame");
        buffer.set_position(0);
        let decoded = codec
            .read_request(&protocol, &mut buffer)
            .await
            .expect("read frame");
        assert_eq!(decoded, b"opaque envelope".to_vec());
    }

    #[tokio::test]
    async fn codec_rejects_empty_and_oversized_length_prefixes() {
        let protocol = MESSAGE_PROTOCOL.to_owned();
        let mut codec = MessageCodec;

        let mut empty = Cursor::new(0u32.to_be_bytes().to_vec());
        assert!(codec.read_request(&protocol, &mut empty).await.is_err());

        let oversized = u32::try_from(MAX_MESSAGE_BYTES + 1).expect("fits in u32");
        let mut oversized = Cursor::new(oversized.to_be_bytes().to_vec());
        assert!(codec.read_request(&protocol, &mut oversized).await.is_err());
    }

    #[tokio::test]
    async fn codec_rejects_writing_invalid_frames() {
        let protocol = MESSAGE_PROTOCOL.to_owned();
        let mut codec = MessageCodec;
        let mut buffer = Cursor::new(Vec::new());
        assert!(
            codec
                .write_response(&protocol, &mut buffer, vec![])
                .await
                .is_err()
        );
        assert!(
            codec
                .write_response(&protocol, &mut buffer, vec![0u8; MAX_MESSAGE_BYTES + 1])
                .await
                .is_err()
        );
    }
}
