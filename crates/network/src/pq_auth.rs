//! Mandatory ML-DSA-65 connection admission over libp2p.
//!
//! This module proves possession of the certified PQ `Application` key on every
//! accepted libp2p connection before application request/response events or
//! peer-scoped optional observations are delivered. The challenge is
//! domain-separated and binds both PeerIds and a fresh per-connection nonce.
//! Verification reuses the existing self-contained PQ identity proof, so no new
//! cryptographic primitive or identity format is introduced.
//!
//! This is an admission gate, not a replacement for libp2p Noise/TLS PeerId
//! authentication. A quantum attacker who can impersonate the classical
//! transport PeerId could mint a fresh self-contained PQ proof bound to that
//! PeerId. The gate therefore authenticates PQ-key possession bound to a
//! classically authenticated PeerId.

use std::collections::{HashMap, HashSet};

use libp2p::PeerId;
use libp2p::swarm::ConnectionId;
use libp2p_request_response::{Event, Message, OutboundRequestId, ResponseChannel};
#[cfg(test)]
use p2p_identity::unix_time_seconds;
use p2p_identity::{
    Identity, IdentityError, IdentityRole, MAX_PQ_IDENTITY_PROOF_BYTES, PQ_SIGNATURE_BYTES,
    verify_pq_application_signature,
};

/// All PQ auth frames use one explicit version. An unknown version is rejected
/// rather than negotiated by "highest wins".
const VERSION: u8 = 1;
const MAGIC: [u8; 4] = *b"PQA1";
const NONCE_BYTES: usize = 32;
const ACK_OK: u8 = 0;
const CHALLENGE_DOMAIN: &[u8] = b"p2p-messenger/pq-auth/challenge/v1";

/// An inbound PQ authentication request.
#[derive(Clone)]
pub(crate) struct Request {
    pub(crate) nonce: [u8; NONCE_BYTES],
    pub(crate) proof: Vec<u8>,
    pub(crate) signature: Vec<u8>,
}

/// An acknowledgement for the nonce in the sender's request.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Ack {
    pub(crate) nonce: [u8; NONCE_BYTES],
}

/// Worker-side state for one connection's PQ admission exchange.
struct Session {
    peer: PeerId,
    outbound: OutboundRequestId,
    local_nonce: [u8; NONCE_BYTES],
    peer_verified: bool,
    ack_received: bool,
}

/// Actions returned to the network worker. The worker owns all channel sends,
/// connection closes, and state events; this module only computes decisions.
pub(crate) enum Action {
    Respond {
        channel: ResponseChannel<Vec<u8>>,
        bytes: Vec<u8>,
    },
    Authenticated {
        connection_id: ConnectionId,
        peer: PeerId,
    },
    Reject {
        connection_id: ConnectionId,
        peer: PeerId,
        reason: &'static str,
    },
}

/// Connection-scoped PQ admission state. A connection is usable for receiving
/// application traffic after we verify the peer's request (`can_receive`). It
/// is reported as `Connected` and usable for sending only after our own request
/// is acknowledged too (`is_authenticated`).
#[derive(Default)]
pub(crate) struct PqAuth {
    sessions: HashMap<ConnectionId, Session>,
    by_outbound: HashMap<OutboundRequestId, ConnectionId>,
    can_receive: HashSet<ConnectionId>,
    authenticated: HashSet<ConnectionId>,
}

impl PqAuth {
    /// Register the outbound request created after `ConnectionEstablished`.
    pub(crate) fn start(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        outbound: OutboundRequestId,
        local_nonce: [u8; NONCE_BYTES],
    ) {
        self.by_outbound.insert(outbound, connection_id);
        self.sessions.insert(
            connection_id,
            Session {
                peer,
                outbound,
                local_nonce,
                peer_verified: false,
                ack_received: false,
            },
        );
    }

    /// Inbound application traffic is accepted only after the peer's PQ proof
    /// and signature have been verified on this exact connection.
    pub(crate) fn can_receive(&self, connection_id: ConnectionId) -> bool {
        self.can_receive.contains(&connection_id)
    }

    /// Full admission: both directions verified. Only these connections are
    /// inserted into the worker's `connected` peer set.
    pub(crate) fn is_authenticated(&self, connection_id: ConnectionId) -> bool {
        self.authenticated.contains(&connection_id)
    }

    /// True when at least one connection for this peer has completed full
    /// admission. Used to release peer-scoped optional observations only after
    /// PQ authentication; `max_connections_per_peer == 1` keeps this unambiguous.
    pub(crate) fn is_peer_authenticated(&self, peer: PeerId) -> bool {
        self.sessions.iter().any(|(connection_id, session)| {
            session.peer == peer && self.authenticated.contains(connection_id)
        })
    }

    /// True while a connection has registered a PQ session but has not reached
    /// full admission. Used to report a close during the handshake as a failure
    /// rather than as a normal disconnect.
    pub(crate) fn is_pending(&self, connection_id: ConnectionId) -> bool {
        self.sessions.contains_key(&connection_id) && !self.authenticated.contains(&connection_id)
    }

    /// Drop all state for a closed connection.
    pub(crate) fn on_closed(&mut self, connection_id: ConnectionId) {
        if let Some(session) = self.sessions.remove(&connection_id) {
            self.by_outbound.remove(&session.outbound);
        }
        self.can_receive.remove(&connection_id);
        self.authenticated.remove(&connection_id);
    }

    /// Consume one PQ protocol event and return the worker action it implies.
    pub(crate) fn handle_event(
        &mut self,
        event: Event<Vec<u8>, Vec<u8>>,
        local_peer: PeerId,
        now: u64,
    ) -> Vec<Action> {
        match event {
            Event::Message {
                peer,
                connection_id,
                message:
                    Message::Request {
                        request, channel, ..
                    },
            } => self.on_request(peer, connection_id, &request, channel, local_peer, now),
            Event::Message {
                peer,
                connection_id,
                message:
                    Message::Response {
                        request_id,
                        response,
                    },
            } => self.on_response(peer, connection_id, request_id, &response),
            Event::OutboundFailure {
                peer,
                connection_id,
                ..
            } => self.reject(connection_id, peer, "pq authentication request failed"),
            Event::InboundFailure {
                peer,
                connection_id,
                ..
            } => self.reject(
                connection_id,
                peer,
                "pq authentication acknowledgement failed",
            ),
            Event::ResponseSent { .. } => Vec::new(),
        }
    }

    fn on_request(
        &mut self,
        peer: PeerId,
        connection_id: ConnectionId,
        bytes: &[u8],
        channel: ResponseChannel<Vec<u8>>,
        local_peer: PeerId,
        now: u64,
    ) -> Vec<Action> {
        let Some(session) = self.sessions.get_mut(&connection_id) else {
            return self.reject(
                connection_id,
                peer,
                "pq authentication request had no session",
            );
        };
        if session.peer != peer {
            return self.reject(connection_id, peer, "pq authentication peer mismatch");
        }
        let request = match decode_request(bytes) {
            Ok(request) => request,
            Err(_) => {
                return self.reject(
                    connection_id,
                    peer,
                    "pq authentication request is malformed",
                );
            }
        };
        if let Err(error) = verify_request(&request, peer, local_peer, now) {
            return self.reject(connection_id, peer, verification_reason(&error));
        }
        session.peer_verified = true;
        self.can_receive.insert(connection_id);
        let mut actions = vec![Action::Respond {
            channel,
            bytes: encode_ack(&request.nonce),
        }];
        if self.maybe_authenticate(connection_id) {
            actions.push(Action::Authenticated {
                connection_id,
                peer,
            });
        }
        actions
    }

    fn on_response(
        &mut self,
        peer: PeerId,
        connection_id: ConnectionId,
        request_id: OutboundRequestId,
        bytes: &[u8],
    ) -> Vec<Action> {
        let Some(mapped) = self.by_outbound.remove(&request_id) else {
            return Vec::new();
        };
        if mapped != connection_id {
            return self.reject(
                connection_id,
                peer,
                "pq authentication response used wrong connection",
            );
        }
        let Some(session) = self.sessions.get_mut(&connection_id) else {
            return self.reject(
                connection_id,
                peer,
                "pq authentication response had no session",
            );
        };
        if session.peer != peer || session.outbound != request_id {
            return self.reject(connection_id, peer, "pq authentication response mismatch");
        }
        let ack = match decode_ack(bytes) {
            Ok(ack) => ack,
            Err(_) => {
                return self.reject(
                    connection_id,
                    peer,
                    "pq authentication acknowledgement is malformed",
                );
            }
        };
        if ack.nonce != session.local_nonce {
            return self.reject(connection_id, peer, "pq authentication nonce echo mismatch");
        }
        session.ack_received = true;
        if self.maybe_authenticate(connection_id) {
            vec![Action::Authenticated {
                connection_id,
                peer,
            }]
        } else {
            Vec::new()
        }
    }

    fn maybe_authenticate(&mut self, connection_id: ConnectionId) -> bool {
        let Some(session) = self.sessions.get(&connection_id) else {
            return false;
        };
        session.peer_verified && session.ack_received && self.authenticated.insert(connection_id)
    }

    fn reject(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        reason: &'static str,
    ) -> Vec<Action> {
        self.on_closed(connection_id);
        vec![Action::Reject {
            connection_id,
            peer,
            reason,
        }]
    }
}

/// Generate a fresh 32-byte nonce from the system randomness source.
pub(crate) fn random_nonce() -> Result<[u8; NONCE_BYTES], IdentityError> {
    let mut nonce = [0u8; NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(|_| IdentityError::Randomness)?;
    Ok(nonce)
}

/// Build a signed, self-contained PQ admission request.
pub(crate) fn encode_request(
    identity: &Identity,
    initiator: PeerId,
    responder: PeerId,
    nonce: &[u8; NONCE_BYTES],
) -> Result<Vec<u8>, IdentityError> {
    let challenge = challenge_bytes(initiator, responder, nonce);
    let signature = identity.pq_sign_with_role(IdentityRole::Application, &challenge)?;
    let proof = identity.pq_proof_bytes();
    require_bounded_length(proof.len(), MAX_PQ_IDENTITY_PROOF_BYTES, "pq proof")?;
    require_bounded_length(signature.len(), PQ_SIGNATURE_BYTES, "pq signature")?;

    let mut bytes =
        Vec::with_capacity(MAGIC.len() + 1 + NONCE_BYTES + 4 + proof.len() + 2 + signature.len());
    bytes.extend_from_slice(&MAGIC);
    bytes.push(VERSION);
    bytes.extend_from_slice(nonce);
    bytes.extend_from_slice(&u32_length(proof.len(), MAX_PQ_IDENTITY_PROOF_BYTES)?);
    bytes.extend_from_slice(&proof);
    bytes.extend_from_slice(&u16_length(signature.len(), PQ_SIGNATURE_BYTES)?);
    bytes.extend_from_slice(&signature);
    Ok(bytes)
}

/// Decode and strictly validate a PQ admission request.
pub(crate) fn decode_request(bytes: &[u8]) -> Result<Request, IdentityError> {
    let mut reader = Reader::new(bytes);
    require_bytes(reader.take(MAGIC.len())? == MAGIC, "pq auth magic")?;
    require_bytes(reader.take_u8()? == VERSION, "pq auth version")?;
    let nonce: [u8; NONCE_BYTES] = reader
        .take(NONCE_BYTES)?
        .try_into()
        .map_err(|_| malformed("pq auth nonce"))?;
    let proof_len = reader.take_u32()? as usize;
    require_bounded_length(proof_len, MAX_PQ_IDENTITY_PROOF_BYTES, "pq proof")?;
    let proof = reader.take(proof_len)?.to_vec();
    let signature_len = reader.take_u16()? as usize;
    require_bytes(
        signature_len == PQ_SIGNATURE_BYTES,
        "pq auth signature length",
    )?;
    let signature = reader.take(signature_len)?.to_vec();
    reader.finished("pq authentication request")?;
    Ok(Request {
        nonce,
        proof,
        signature,
    })
}

/// Verify a decoded request against the PeerIds reported by the libp2p
/// connection and a caller-supplied time.
pub(crate) fn verify_request(
    request: &Request,
    initiator: PeerId,
    responder: PeerId,
    now: u64,
) -> Result<(), IdentityError> {
    verify_pq_application_signature(
        &request.proof,
        IdentityRole::Application,
        &initiator,
        &challenge_bytes(initiator, responder, &request.nonce),
        &request.signature,
        now,
    )
    .map(|_| ())
}

/// Encode the readiness acknowledgement. It is sent only after verification.
pub(crate) fn encode_ack(nonce: &[u8; NONCE_BYTES]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(MAGIC.len() + 1 + 1 + NONCE_BYTES);
    bytes.extend_from_slice(&MAGIC);
    bytes.push(VERSION);
    bytes.push(ACK_OK);
    bytes.extend_from_slice(nonce);
    bytes
}

/// Decode and strictly validate an acknowledgement.
pub(crate) fn decode_ack(bytes: &[u8]) -> Result<Ack, IdentityError> {
    let mut reader = Reader::new(bytes);
    require_bytes(reader.take(MAGIC.len())? == MAGIC, "pq auth ack magic")?;
    require_bytes(reader.take_u8()? == VERSION, "pq auth ack version")?;
    require_bytes(reader.take_u8()? == ACK_OK, "pq auth ack status")?;
    let nonce: [u8; NONCE_BYTES] = reader
        .take(NONCE_BYTES)?
        .try_into()
        .map_err(|_| malformed("pq auth ack nonce"))?;
    reader.finished("pq authentication acknowledgement")?;
    Ok(Ack { nonce })
}

fn challenge_bytes(initiator: PeerId, responder: PeerId, nonce: &[u8; NONCE_BYTES]) -> Vec<u8> {
    let initiator = initiator.to_bytes();
    let responder = responder.to_bytes();
    let mut bytes = Vec::with_capacity(
        CHALLENGE_DOMAIN.len()
            + 1
            + 1
            + 2
            + initiator.len()
            + 2
            + responder.len()
            + 2
            + nonce.len(),
    );
    bytes.extend_from_slice(CHALLENGE_DOMAIN);
    // Phase 1 separates this connection-admission signature from any future
    // PQ handshake version that may reuse the same role key.
    bytes.push(1);
    bytes.push(IdentityRole::Application.code());
    bytes.extend_from_slice(
        &u16_length(initiator.len(), u16::MAX as usize).expect("PeerId is bounded"),
    );
    bytes.extend_from_slice(&initiator);
    bytes.extend_from_slice(
        &u16_length(responder.len(), u16::MAX as usize).expect("PeerId is bounded"),
    );
    bytes.extend_from_slice(&responder);
    bytes.extend_from_slice(&u16_length(nonce.len(), u16::MAX as usize).expect("nonce is bounded"));
    bytes.extend_from_slice(nonce);
    bytes
}

fn verification_reason(error: &IdentityError) -> &'static str {
    match error {
        IdentityError::PeerIdMismatch => "pq auth proof is bound to a different PeerId",
        IdentityError::ExpiredCertificate => "pq auth proof has expired",
        IdentityError::RevokedIdentity => "pq auth identity is revoked",
        IdentityError::InvalidSignature => "pq auth signature is invalid",
        IdentityError::WrongRole => "pq auth proof lacks the application role",
        IdentityError::InvalidIdentityProof(_) => "pq auth proof is invalid",
        _ => "pq auth verification failed",
    }
}

fn malformed(context: &str) -> IdentityError {
    IdentityError::InvalidIdentityProof(format!("{context} is malformed"))
}

fn require_bytes(condition: bool, context: &str) -> Result<(), IdentityError> {
    if condition {
        Ok(())
    } else {
        Err(malformed(context))
    }
}

fn require_bounded_length(
    actual: usize,
    maximum: usize,
    context: &str,
) -> Result<(), IdentityError> {
    if actual > maximum {
        Err(IdentityError::InvalidIdentityProof(format!(
            "{context} is outside safe bounds"
        )))
    } else {
        Ok(())
    }
}

fn u16_length(value: usize, maximum: usize) -> Result<[u8; 2], IdentityError> {
    require_bounded_length(value, maximum, "length prefix")?;
    Ok(u16::try_from(value)
        .map_err(|_| malformed("length prefix"))?
        .to_be_bytes())
}

fn u32_length(value: usize, maximum: usize) -> Result<[u8; 4], IdentityError> {
    require_bounded_length(value, maximum, "length prefix")?;
    Ok(u32::try_from(value)
        .map_err(|_| malformed("length prefix"))?
        .to_be_bytes())
}

#[derive(Debug)]
struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], IdentityError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or_else(|| malformed("length"))?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| malformed("truncated frame"))?;
        self.position = end;
        Ok(bytes)
    }

    fn take_u8(&mut self) -> Result<u8, IdentityError> {
        Ok(self.take(1)?[0])
    }

    fn take_u16(&mut self) -> Result<u16, IdentityError> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("two bytes"),
        ))
    }

    fn take_u32(&mut self) -> Result<u32, IdentityError> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("four bytes"),
        ))
    }

    fn finished(self, context: &str) -> Result<(), IdentityError> {
        require_bytes(
            self.position == self.bytes.len(),
            &format!("{context} has trailing bytes"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identities() -> (Identity, Identity) {
        (
            Identity::generate().expect("initiator identity"),
            Identity::generate().expect("responder identity"),
        )
    }

    #[test]
    fn request_round_trips_and_verifies() {
        let (alice, bob) = identities();
        let nonce = random_nonce().expect("nonce");
        let bytes =
            encode_request(&alice, alice.peer_id(), bob.peer_id(), &nonce).expect("request");
        let decoded = decode_request(&bytes).expect("decode request");
        assert_eq!(decoded.nonce, nonce);
        verify_request(
            &decoded,
            alice.peer_id(),
            bob.peer_id(),
            unix_time_seconds(),
        )
        .expect("verify request");
    }

    #[test]
    fn wrong_peer_pair_or_nonce_does_not_verify() {
        let (alice, bob) = identities();
        let other = Identity::generate().expect("other identity");
        let nonce = random_nonce().expect("nonce");
        let bytes =
            encode_request(&alice, alice.peer_id(), bob.peer_id(), &nonce).expect("request");
        let request = decode_request(&bytes).expect("decode request");

        assert!(
            verify_request(
                &request,
                other.peer_id(),
                bob.peer_id(),
                unix_time_seconds()
            )
            .is_err()
        );
        assert!(
            verify_request(
                &request,
                alice.peer_id(),
                other.peer_id(),
                unix_time_seconds()
            )
            .is_err()
        );

        let mut wrong_nonce = request.clone();
        wrong_nonce.nonce[0] ^= 1;
        assert!(
            verify_request(
                &wrong_nonce,
                alice.peer_id(),
                bob.peer_id(),
                unix_time_seconds()
            )
            .is_err()
        );
    }

    #[test]
    fn tampered_proof_or_signature_does_not_verify() {
        let (alice, bob) = identities();
        let nonce = random_nonce().expect("nonce");
        let bytes =
            encode_request(&alice, alice.peer_id(), bob.peer_id(), &nonce).expect("request");
        let request = decode_request(&bytes).expect("decode request");

        let mut tampered_proof = request.clone();
        tampered_proof.proof[0] ^= 1;
        assert!(
            verify_request(
                &tampered_proof,
                alice.peer_id(),
                bob.peer_id(),
                unix_time_seconds()
            )
            .is_err()
        );

        let mut tampered_signature = request.clone();
        tampered_signature.signature[0] ^= 1;
        assert!(
            verify_request(
                &tampered_signature,
                alice.peer_id(),
                bob.peer_id(),
                unix_time_seconds()
            )
            .is_err()
        );
    }

    #[test]
    fn malformed_request_frames_are_rejected() {
        let (alice, bob) = identities();
        let nonce = random_nonce().expect("nonce");
        let bytes =
            encode_request(&alice, alice.peer_id(), bob.peer_id(), &nonce).expect("request");

        for index in [0, 4] {
            let mut bad = bytes.clone();
            bad[index] ^= 1;
            assert!(decode_request(&bad).is_err(), "byte {index}");
        }
        let mut short = bytes.clone();
        short.pop();
        assert!(decode_request(&short).is_err());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode_request(&trailing).is_err());
    }

    #[test]
    fn ack_round_trips_and_rejects_wrong_nonce() {
        let nonce = random_nonce().expect("nonce");
        let bytes = encode_ack(&nonce);
        assert_eq!(decode_ack(&bytes).expect("decode ack").nonce, nonce);

        let mut wrong = bytes.clone();
        let last = wrong.len() - 1;
        wrong[last] ^= 1;
        assert_ne!(decode_ack(&wrong).expect("decode wrong ack").nonce, nonce);
        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode_ack(&trailing).is_err());
    }
}
