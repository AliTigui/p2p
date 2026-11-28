//! Optional pinned post-quantum transport security over libp2p Noise.
//!
//! This is a local, opt-in transport experiment. It first runs ordinary Noise
//! to learn the classically authenticated PeerId, then requires that PeerId to
//! have a locally pinned ML-DSA-65 `Application` verifying key. Both endpoints
//! authenticate a fresh ML-KEM-768 exchange with those pinned keys, and all
//! subsequent bytes are additionally encrypted with keys derived from the
//! ML-KEM shared secret. A quantum attacker who can forge the classical
//! transport signature still cannot pass this layer without the pinned PQ key.
//!
//! This is not a vendored Noise handshake: the classical and PQ layers are
//! composed, not mixed into one Noise KDF. The QUIC path is disabled when this
//! mode is enabled so every accepted connection uses the pinned upgrade.

use std::collections::BTreeMap;
use std::future::Future;
use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use hkdf::Hkdf;
use libp2p::PeerId;
use libp2p::core::upgrade::{InboundConnectionUpgrade, OutboundConnectionUpgrade, UpgradeInfo};
use libp2p::futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::identity::Keypair;
use libp2p::noise::Output as NoiseOutput;
use ml_kem::MlKem768;
use ml_kem::kem::{Decapsulate, Encapsulate, Kem, KeyExport};
use p2p_crypto::{KEY_LEN, decrypt_bytes, encrypt_bytes};
use p2p_identity::{
    Identity, IdentityError, IdentityRole, PQ_PUBLIC_KEY_BYTES, PQ_SIGNATURE_BYTES,
    verify_pq_role_signature_with_key,
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

const PQ_NOISE_PROTOCOL: &str = "/p2p-messenger/noise-pq/1";
const PQ_TRANSPORT_DOMAIN: &[u8] = b"p2p-messenger/pq-transport/challenge/v1";
const EK_BYTES: usize = 1184;
const CIPHERTEXT_BYTES: usize = 1088;
const NONCE_BYTES: usize = 32;
const MIN_FRAME_BYTES: usize = 24 + 16;
const MAX_FRAME_BYTES: usize = 32 * 1024 + MIN_FRAME_BYTES;
const MAX_HANDSHAKE_BYTES: usize = 8 * 1024;
const TAG_SERVER_HELLO: u8 = 1;
const TAG_CLIENT_FINISH: u8 = 2;

/// Locally pinned ML-DSA-65 `Application` verifying keys, keyed by the
/// classically authenticated libp2p PeerId. These pins are the trust anchor;
/// self-contained PQ proofs presented by the peer are not accepted here.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PqTransportConfig {
    pub application_keys: BTreeMap<PeerId, [u8; PQ_PUBLIC_KEY_BYTES]>,
}

impl PqTransportConfig {
    /// Pin one exact ML-DSA-65 `Application` key for a PeerId.
    pub fn insert(&mut self, peer: PeerId, public_key: &[u8]) -> Result<(), String> {
        let key: [u8; PQ_PUBLIC_KEY_BYTES] = public_key
            .try_into()
            .map_err(|_| "unexpected ML-DSA public key length".to_owned())?;
        if key.iter().all(|byte| *byte == 0) {
            return Err("all-zero ML-DSA public key".to_owned());
        }
        self.application_keys.insert(peer, key);
        Ok(())
    }
}

#[derive(Debug, Error)]
pub(crate) enum PqTransportError {
    #[error("pinned PQ transport I/O failed: {0}")]
    Io(String),
    #[error("classical Noise upgrade failed: {0}")]
    Noise(String),
    #[error("peer {0} has no pinned ML-DSA-65 application key")]
    UnpinnedPeer(String),
    #[error("invalid PQ transport message: {0}")]
    InvalidMessage(String),
    #[error("PQ authentication failed: {0}")]
    Authentication(String),
}

impl From<io::Error> for PqTransportError {
    fn from(error: io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

impl From<IdentityError> for PqTransportError {
    fn from(error: IdentityError) -> Self {
        Self::Authentication(error.to_string())
    }
}

fn io_error(message: impl Into<String>) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message.into())
}

fn update_transcript(hash: &mut Sha256, label: &[u8], value: &[u8]) {
    hash.update((label.len() as u64).to_be_bytes());
    hash.update(label);
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value);
}

fn responder_transcript(
    initiator: &PeerId,
    responder: &PeerId,
    ek: &[u8],
    nonce_r: &[u8; NONCE_BYTES],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(PQ_TRANSPORT_DOMAIN);
    update_transcript(&mut hash, b"initiator", &initiator.to_bytes());
    update_transcript(&mut hash, b"responder", &responder.to_bytes());
    update_transcript(&mut hash, b"ek", ek);
    update_transcript(&mut hash, b"nonce_r", nonce_r);
    hash.finalize().into()
}

fn full_transcript(
    initiator: &PeerId,
    responder: &PeerId,
    ek: &[u8],
    nonce_r: &[u8; NONCE_BYTES],
    nonce_i: &[u8; NONCE_BYTES],
    ciphertext: &[u8],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(PQ_TRANSPORT_DOMAIN);
    update_transcript(&mut hash, b"initiator", &initiator.to_bytes());
    update_transcript(&mut hash, b"responder", &responder.to_bytes());
    update_transcript(&mut hash, b"ek", ek);
    update_transcript(&mut hash, b"nonce_r", nonce_r);
    update_transcript(&mut hash, b"nonce_i", nonce_i);
    update_transcript(&mut hash, b"ciphertext", ciphertext);
    hash.finalize().into()
}

fn derive_keys(
    shared: &[u8],
    transcript: &[u8; 32],
) -> Result<([u8; KEY_LEN], [u8; KEY_LEN]), PqTransportError> {
    let hkdf = Hkdf::<Sha256>::new(Some(transcript), shared);
    let mut client = [0u8; KEY_LEN];
    let mut server = [0u8; KEY_LEN];
    hkdf.expand(b"p2p-messenger/pq-transport/client/key", &mut client)
        .map_err(|error| PqTransportError::Authentication(error.to_string()))?;
    hkdf.expand(b"p2p-messenger/pq-transport/server/key", &mut server)
        .map_err(|error| PqTransportError::Authentication(error.to_string()))?;
    Ok((client, server))
}

async fn write_message<T: AsyncWrite + Unpin>(
    io: &mut T,
    tag: u8,
    payload: &[u8],
) -> Result<(), PqTransportError> {
    if payload.len() > MAX_HANDSHAKE_BYTES {
        return Err(PqTransportError::InvalidMessage(
            "oversized handshake frame".to_owned(),
        ));
    }
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(tag);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    io.write_all(&frame).await?;
    // libp2p Noise buffers encrypted writes until an explicit flush, so a
    // handshake message is not observable by the peer until this completes.
    io.flush().await?;
    Ok(())
}

async fn read_message<T: AsyncRead + Unpin>(io: &mut T) -> Result<(u8, Vec<u8>), PqTransportError> {
    let mut header = [0u8; 5];
    io.read_exact(&mut header).await?;
    let tag = header[0];
    let length = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if length > MAX_HANDSHAKE_BYTES {
        return Err(PqTransportError::InvalidMessage(
            "oversized handshake frame".to_owned(),
        ));
    }
    let mut payload = vec![0u8; length];
    io.read_exact(&mut payload).await?;
    Ok((tag, payload))
}

#[derive(Clone)]
pub(crate) struct PqNoiseConfig {
    noise: libp2p::noise::Config,
    identity: Identity,
    pins: Arc<BTreeMap<PeerId, [u8; PQ_PUBLIC_KEY_BYTES]>>,
}

impl PqNoiseConfig {
    pub(crate) fn new(
        keypair: &Keypair,
        identity: Identity,
        config: PqTransportConfig,
    ) -> Result<Self, String> {
        let noise = libp2p::noise::Config::new(keypair).map_err(|error| error.to_string())?;
        Ok(Self {
            noise,
            identity,
            pins: Arc::new(config.application_keys),
        })
    }

    fn pin(&self, peer: &PeerId) -> Result<&[u8; PQ_PUBLIC_KEY_BYTES], PqTransportError> {
        self.pins
            .get(peer)
            .ok_or_else(|| PqTransportError::UnpinnedPeer(peer.to_string()))
    }

    fn sign(&self, transcript: &[u8]) -> Result<Vec<u8>, PqTransportError> {
        Ok(self
            .identity
            .pq_sign_with_role(IdentityRole::Application, transcript)?)
    }

    fn verify(
        &self,
        peer: &PeerId,
        transcript: &[u8],
        signature: &[u8],
    ) -> Result<(), PqTransportError> {
        verify_pq_role_signature_with_key(
            IdentityRole::Application,
            self.pin(peer)?,
            transcript,
            signature,
        )?;
        Ok(())
    }

    async fn inbound<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
        self,
        socket: T,
    ) -> Result<(PeerId, PqStream<NoiseOutput<T>>), PqTransportError> {
        let noise = self.noise.clone();
        let (remote, mut io) = noise
            .upgrade_inbound(socket, "/noise")
            .await
            .map_err(|error| PqTransportError::Noise(error.to_string()))?;
        self.pin(&remote)?;

        let (decapsulation_key, encapsulation_key) = MlKem768::generate_keypair();
        let ek = encapsulation_key.to_bytes();
        let ek_bytes: [u8; EK_BYTES] = (*ek.as_slice()).try_into().map_err(|_| {
            PqTransportError::InvalidMessage("unexpected ML-KEM key size".to_owned())
        })?;
        let mut nonce_r = [0u8; NONCE_BYTES];
        getrandom::fill(&mut nonce_r)
            .map_err(|_| PqTransportError::Authentication("randomness unavailable".to_owned()))?;
        let local = self.identity.peer_id();
        let responder_transcript = responder_transcript(&remote, &local, &ek_bytes, &nonce_r);
        let signature_r = self.sign(&responder_transcript)?;

        let mut hello = Vec::with_capacity(EK_BYTES + NONCE_BYTES + PQ_SIGNATURE_BYTES);
        hello.extend_from_slice(&ek_bytes);
        hello.extend_from_slice(&nonce_r);
        hello.extend_from_slice(&signature_r);
        write_message(&mut io, TAG_SERVER_HELLO, &hello).await?;

        let (tag, finish) = read_message(&mut io).await?;
        if tag != TAG_CLIENT_FINISH
            || finish.len() != NONCE_BYTES + CIPHERTEXT_BYTES + PQ_SIGNATURE_BYTES
        {
            return Err(PqTransportError::InvalidMessage(
                "unexpected client finish".to_owned(),
            ));
        }
        let mut nonce_i = [0u8; NONCE_BYTES];
        nonce_i.copy_from_slice(&finish[..NONCE_BYTES]);
        let mut ciphertext = [0u8; CIPHERTEXT_BYTES];
        ciphertext.copy_from_slice(&finish[NONCE_BYTES..NONCE_BYTES + CIPHERTEXT_BYTES]);
        let signature_i = &finish[NONCE_BYTES + CIPHERTEXT_BYTES..];
        let transcript =
            full_transcript(&remote, &local, &ek_bytes, &nonce_r, &nonce_i, &ciphertext);
        self.verify(&remote, &transcript, signature_i)?;
        let shared = decapsulation_key
            .decapsulate_slice(&ciphertext)
            .map_err(|_| {
                PqTransportError::Authentication("ML-KEM decapsulation failed".to_owned())
            })?;
        let (client_key, server_key) = derive_keys(shared.as_slice(), &transcript)?;
        Ok((
            remote,
            PqStream::new(io, server_key, client_key, transcript),
        ))
    }

    async fn outbound<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
        self,
        socket: T,
    ) -> Result<(PeerId, PqStream<NoiseOutput<T>>), PqTransportError> {
        let noise = self.noise.clone();
        let (remote, mut io) = noise
            .upgrade_outbound(socket, "/noise")
            .await
            .map_err(|error| PqTransportError::Noise(error.to_string()))?;
        self.pin(&remote)?;

        let (tag, hello) = read_message(&mut io).await?;
        if tag != TAG_SERVER_HELLO || hello.len() != EK_BYTES + NONCE_BYTES + PQ_SIGNATURE_BYTES {
            return Err(PqTransportError::InvalidMessage(
                "unexpected server hello".to_owned(),
            ));
        }
        let mut ek_bytes = [0u8; EK_BYTES];
        ek_bytes.copy_from_slice(&hello[..EK_BYTES]);
        let mut nonce_r = [0u8; NONCE_BYTES];
        nonce_r.copy_from_slice(&hello[EK_BYTES..EK_BYTES + NONCE_BYTES]);
        let signature_r = &hello[EK_BYTES + NONCE_BYTES..];
        let local = self.identity.peer_id();
        let responder_transcript = responder_transcript(&local, &remote, &ek_bytes, &nonce_r);
        self.verify(&remote, &responder_transcript, signature_r)?;

        let encoded_key =
            <ml_kem::Key<ml_kem::EncapsulationKey<MlKem768>> as TryFrom<&[u8]>>::try_from(
                ek_bytes.as_slice(),
            )
            .map_err(|_| PqTransportError::InvalidMessage("invalid ML-KEM key".to_owned()))?;
        let encapsulation_key = ml_kem::EncapsulationKey::<MlKem768>::new(&encoded_key)
            .map_err(|_| PqTransportError::InvalidMessage("invalid ML-KEM key".to_owned()))?;
        let (ciphertext, shared) = encapsulation_key.encapsulate();
        let ct_bytes: [u8; CIPHERTEXT_BYTES] =
            (*ciphertext.as_slice()).try_into().map_err(|_| {
                PqTransportError::InvalidMessage("unexpected ML-KEM ciphertext size".to_owned())
            })?;
        let mut nonce_i = [0u8; NONCE_BYTES];
        getrandom::fill(&mut nonce_i)
            .map_err(|_| PqTransportError::Authentication("randomness unavailable".to_owned()))?;
        let transcript = full_transcript(&local, &remote, &ek_bytes, &nonce_r, &nonce_i, &ct_bytes);
        let signature_i = self.sign(&transcript)?;

        let mut finish = Vec::with_capacity(NONCE_BYTES + CIPHERTEXT_BYTES + PQ_SIGNATURE_BYTES);
        finish.extend_from_slice(&nonce_i);
        finish.extend_from_slice(&ct_bytes);
        finish.extend_from_slice(&signature_i);
        write_message(&mut io, TAG_CLIENT_FINISH, &finish).await?;
        let (client_key, server_key) = derive_keys(shared.as_slice(), &transcript)?;
        Ok((
            remote,
            PqStream::new(io, client_key, server_key, transcript),
        ))
    }
}

impl UpgradeInfo for PqNoiseConfig {
    type Info = &'static str;
    type InfoIter = std::iter::Once<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        std::iter::once(PQ_NOISE_PROTOCOL)
    }
}

impl<T> InboundConnectionUpgrade<T> for PqNoiseConfig
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Output = (PeerId, PqStream<NoiseOutput<T>>);
    type Error = PqTransportError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    fn upgrade_inbound(self, socket: T, _: Self::Info) -> Self::Future {
        Box::pin(self.inbound(socket))
    }
}

impl<T> OutboundConnectionUpgrade<T> for PqNoiseConfig
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Output = (PeerId, PqStream<NoiseOutput<T>>);
    type Error = PqTransportError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    fn upgrade_outbound(self, socket: T, _: Self::Info) -> Self::Future {
        Box::pin(self.outbound(socket))
    }
}

/// A Noise stream with an additional ML-KEM-derived AEAD layer. Frames are
/// `u32_be length || nonce || ciphertext || tag`. Sequence numbers and the
/// handshake transcript are included in AAD, so replay and reorder are rejected.
pub(crate) struct PqStream<T> {
    inner: T,
    write_key: Zeroizing<[u8; KEY_LEN]>,
    read_key: Zeroizing<[u8; KEY_LEN]>,
    transcript: [u8; 32],
    write_seq: u64,
    read_seq: u64,
    write_buf: Vec<u8>,
    write_pos: usize,
    read_len: [u8; 4],
    read_len_pos: usize,
    read_frame: Vec<u8>,
    read_frame_pos: usize,
    read_plain: Zeroizing<Vec<u8>>,
    read_plain_pos: usize,
}

impl<T> PqStream<T> {
    fn new(
        inner: T,
        write_key: [u8; KEY_LEN],
        read_key: [u8; KEY_LEN],
        transcript: [u8; 32],
    ) -> Self {
        Self {
            inner,
            write_key: Zeroizing::new(write_key),
            read_key: Zeroizing::new(read_key),
            transcript,
            write_seq: 0,
            read_seq: 0,
            write_buf: Vec::new(),
            write_pos: 0,
            read_len: [0u8; 4],
            read_len_pos: 0,
            read_frame: Vec::new(),
            read_frame_pos: 0,
            read_plain: Zeroizing::new(Vec::new()),
            read_plain_pos: 0,
        }
    }

    fn aad(&self, sequence: u64) -> Vec<u8> {
        let mut aad = Vec::with_capacity(PQ_TRANSPORT_DOMAIN.len() + 8 + 32);
        aad.extend_from_slice(PQ_TRANSPORT_DOMAIN);
        aad.extend_from_slice(&sequence.to_be_bytes());
        aad.extend_from_slice(&self.transcript);
        aad
    }
}

impl<T: AsyncWrite + Unpin> PqStream<T> {
    fn flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.write_pos < self.write_buf.len() {
            let inner = Pin::new(&mut self.inner);
            match inner.poll_write(cx, &self.write_buf[self.write_pos..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io_error("PQ transport write returned zero bytes")));
                }
                Poll::Ready(Ok(written)) => self.write_pos += written,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            }
        }
        self.write_buf.clear();
        self.write_pos = 0;
        // libp2p Noise buffers writes internally and only sends on flush.
        // Flush here so the AEAD frame actually reaches the peer even if the
        // caller never calls `poll_flush` on this stream.
        Pin::new(&mut self.inner).poll_flush(cx)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for PqStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match this.flush_pending(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if buf.len() + MIN_FRAME_BYTES > MAX_FRAME_BYTES {
            return Poll::Ready(Err(io_error("PQ transport frame is too large")));
        }
        let aad = this.aad(this.write_seq);
        let framed = match encrypt_bytes(&this.write_key, buf, &aad) {
            Ok(framed) => framed,
            Err(error) => return Poll::Ready(Err(io_error(error.to_string()))),
        };
        this.write_seq = match this.write_seq.checked_add(1) {
            Some(sequence) => sequence,
            None => return Poll::Ready(Err(io_error("PQ transport sequence exhausted"))),
        };
        this.write_buf.extend_from_slice(
            &u32::try_from(framed.len())
                .expect("bounded frame")
                .to_be_bytes(),
        );
        this.write_buf.extend_from_slice(&framed);
        // The bytes are now owned by this stream's buffer. Returning Pending
        // here would let callers retry the same bytes and duplicate the frame;
        // report acceptance instead and let `poll_flush` finish the write.
        match this.flush_pending(cx) {
            Poll::Pending | Poll::Ready(Ok(())) => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.flush_pending(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.flush_pending(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        Pin::new(&mut this.inner).poll_close(cx)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for PqStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        loop {
            if this.read_plain_pos < this.read_plain.len() {
                let remaining = this.read_plain.len() - this.read_plain_pos;
                let take = remaining.min(buf.len());
                buf[..take].copy_from_slice(
                    &this.read_plain[this.read_plain_pos..this.read_plain_pos + take],
                );
                this.read_plain_pos += take;
                return Poll::Ready(Ok(take));
            }
            if this.read_len_pos < 4 {
                let inner = &mut this.inner;
                match Pin::new(inner).poll_read(cx, &mut this.read_len[this.read_len_pos..]) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(0)) if this.read_len_pos == 0 => return Poll::Ready(Ok(0)),
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io_error("truncated PQ transport frame length")));
                    }
                    Poll::Ready(Ok(count)) => this.read_len_pos += count,
                }
                continue;
            }
            let length = u32::from_be_bytes(this.read_len) as usize;
            if !(MIN_FRAME_BYTES..=MAX_FRAME_BYTES).contains(&length) {
                return Poll::Ready(Err(io_error("invalid PQ transport frame length")));
            }
            if this.read_frame.len() != length {
                this.read_frame = vec![0u8; length];
                this.read_frame_pos = 0;
            }
            while this.read_frame_pos < length {
                let inner = &mut this.inner;
                match Pin::new(inner).poll_read(cx, &mut this.read_frame[this.read_frame_pos..]) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io_error("truncated PQ transport frame")));
                    }
                    Poll::Ready(Ok(count)) => this.read_frame_pos += count,
                }
            }
            let aad = this.aad(this.read_seq);
            let plaintext = match decrypt_bytes(&this.read_key, &this.read_frame, &aad) {
                Ok(plaintext) => plaintext,
                Err(error) => return Poll::Ready(Err(io_error(error.to_string()))),
            };
            this.read_seq = match this.read_seq.checked_add(1) {
                Some(sequence) => sequence,
                None => return Poll::Ready(Err(io_error("PQ transport sequence exhausted"))),
            };
            this.read_plain = plaintext;
            this.read_plain_pos = 0;
            this.read_frame.clear();
            this.read_frame_pos = 0;
            this.read_len_pos = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::futures::executor::block_on;
    use libp2p::futures::io::Cursor;

    fn peer() -> PeerId {
        let keypair = libp2p::identity::Keypair::generate_ed25519();
        keypair.public().to_peer_id()
    }

    fn key(byte: u8) -> [u8; KEY_LEN] {
        [byte; KEY_LEN]
    }

    fn transcript(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn frame(key: [u8; KEY_LEN], transcript: [u8; 32], plaintext: &[u8]) -> Vec<u8> {
        block_on(async {
            let mut stream =
                PqStream::new(Cursor::new(Vec::new()), key, [0u8; KEY_LEN], transcript);
            stream.write_all(plaintext).await.expect("frame write");
            stream.flush().await.expect("frame flush");
            stream.inner.into_inner()
        })
    }

    #[test]
    fn pinning_rejects_wrong_length_and_zero_keys() {
        let mut config = PqTransportConfig::default();
        assert!(config.insert(peer(), b"short").is_err());
        assert!(config.insert(peer(), &[0u8; PQ_PUBLIC_KEY_BYTES]).is_err());
    }

    #[test]
    fn pq_stream_round_trips_aead_frames() {
        let plaintext = b"pinned transport payload";
        let bytes = frame(key(7), transcript(9), plaintext);
        let mut decoded = vec![0u8; plaintext.len()];
        block_on(async {
            let mut stream =
                PqStream::new(Cursor::new(bytes), [0u8; KEY_LEN], key(7), transcript(9));
            stream
                .read_exact(&mut decoded)
                .await
                .expect("frame decrypt");
        });
        assert_eq!(decoded, plaintext);
    }

    #[test]
    fn pq_stream_rejects_tampered_frames() {
        let mut bytes = frame(key(7), transcript(9), b"tamper me");
        let last = bytes.last_mut().expect("nonempty frame");
        *last ^= 0x01;
        let mut decoded = vec![0u8; 9];
        let error = block_on(async {
            let mut stream =
                PqStream::new(Cursor::new(bytes), [0u8; KEY_LEN], key(7), transcript(9));
            stream.read_exact(&mut decoded).await.err()
        });
        assert!(error.is_some(), "tampered frame was accepted");
    }

    #[test]
    fn pq_stream_rejects_replayed_frames() {
        let plaintext = b"replay me";
        let original = frame(key(7), transcript(9), plaintext);
        let mut bytes = original.clone();
        bytes.extend_from_slice(&original);
        let result = block_on(async {
            let mut stream =
                PqStream::new(Cursor::new(bytes), [0u8; KEY_LEN], key(7), transcript(9));
            let mut first = vec![0u8; plaintext.len()];
            stream.read_exact(&mut first).await.expect("first frame");
            let mut second = vec![0u8; first.len()];
            stream.read_exact(&mut second).await.map(|_| second)
        });
        assert!(result.is_err(), "replayed frame was accepted");
    }
}
