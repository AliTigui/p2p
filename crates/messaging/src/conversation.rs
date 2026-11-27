//! Local conversation state: outgoing sequence numbers, replay protection,
//! delivery transitions, and ciphertext-at-rest envelope persistence.

use std::collections::{HashMap, VecDeque};

use libp2p_identity::PeerId;
use p2p_identity::Identity;
use p2p_storage::Session;

use crate::envelope::{now_seconds, random_id};
use crate::{
    Envelope, EnvelopeParams, MessageError, MessageKind, Receipt, ReceiptStatus, V3InnerFrame,
};

const DEFAULT_REPLAY_CAPACITY: usize = 4096;

/// Honest delivery state. `SentToPeer` is never treated as `Delivered`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryState {
    Composed,
    Queued,
    SentToPeer,
    Delivered,
    Read,
    Failed,
}

impl DeliveryState {
    pub fn description(self) -> &'static str {
        match self {
            Self::Composed => "Composed (not sent)",
            Self::Queued => "Queued (offline)",
            Self::SentToPeer => "Sent to peer (delivery unconfirmed)",
            Self::Delivered => "Delivered (explicit receipt)",
            Self::Read => "Read (explicit receipt)",
            Self::Failed => "Failed",
        }
    }

    fn can_receive_receipt(self, status: ReceiptStatus) -> bool {
        match status {
            // Group broadcasts can receive one Delivered receipt per member.
            // Re-applying Delivered is idempotent; replay protection still
            // rejects duplicate receipts from the same sender.
            ReceiptStatus::Delivered => matches!(
                self,
                Self::Composed | Self::Queued | Self::SentToPeer | Self::Delivered
            ),
            ReceiptStatus::Read => matches!(
                self,
                Self::Composed | Self::Queued | Self::SentToPeer | Self::Delivered
            ),
        }
    }
}

/// A verified incoming envelope returned to the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedMessage {
    pub message_id: [u8; 16],
    pub sender: PeerId,
    pub kind: MessageKind,
    pub epoch: u64,
    pub sender_sequence: u64,
    /// Set when the incoming envelope carried a receipt that changed the state
    /// of a known outgoing message.
    pub receipt: Option<Receipt>,
}

/// State for one local conversation. The application layer supplies opaque,
/// already-encrypted payload bytes; this type never sees message plaintext.
pub struct Conversation {
    id: [u8; 16],
    local: PeerId,
    epoch: u64,
    next_sequence: u64,
    replay: ReplayCache,
    outgoing: HashMap<[u8; 16], DeliveryState>,
    incoming: Vec<Envelope>,
}

impl Conversation {
    /// Start a new conversation with a random ID and the local identity.
    pub fn new(identity: &Identity) -> Result<Self, MessageError> {
        Ok(Self::with_id(identity.peer_id(), random_id()?))
    }

    /// Rebuild or test a conversation with a known ID. No key material is
    /// stored; only the public PeerId is retained.
    pub fn with_id(local: PeerId, id: [u8; 16]) -> Self {
        Self {
            id,
            local,
            epoch: 0,
            next_sequence: 1,
            replay: ReplayCache::new(DEFAULT_REPLAY_CAPACITY),
            outgoing: HashMap::new(),
            incoming: Vec::new(),
        }
    }

    pub fn id(&self) -> [u8; 16] {
        self.id
    }

    pub fn local_peer_id(&self) -> PeerId {
        self.local
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    /// Move to a newer MLS epoch. Future MLS commits will call this after a
    /// successful group operation; regression is rejected.
    pub fn advance_epoch(&mut self, epoch: u64) -> Result<(), MessageError> {
        if epoch < self.epoch {
            return Err(MessageError::EpochMismatch {
                expected: self.epoch,
                actual: epoch,
            });
        }
        self.epoch = epoch;
        Ok(())
    }

    /// Sign a new outgoing envelope and mark it `Composed`. The payload must be
    /// ciphertext from a higher layer; this method does not encrypt anything.
    pub fn compose(
        &mut self,
        identity: &Identity,
        kind: MessageKind,
        payload: Vec<u8>,
    ) -> Result<Envelope, MessageError> {
        if identity.peer_id() != self.local {
            return Err(MessageError::WrongLocalIdentity);
        }
        let sequence = self.next_sequence;
        let next = sequence
            .checked_add(1)
            .ok_or(MessageError::SequenceExhausted)?;
        let envelope = Envelope::new(
            identity,
            EnvelopeParams {
                conversation_id: self.id,
                epoch: self.epoch,
                message_id: random_id()?,
                sender_sequence: sequence,
                created_at: now_seconds(),
                kind,
            },
            payload,
        )?;
        self.replay.check_and_record(&envelope)?;
        self.outgoing
            .insert(envelope.message_id, DeliveryState::Composed);
        self.next_sequence = next;
        Ok(envelope)
    }

    /// Build the metadata that will be encrypted inside a v3 MLS body. No
    /// state is consumed until [`Self::record_outgoing_v3`] succeeds, so a
    /// failed MLS encryption cannot skip a sequence number.
    pub fn prepare_v3_inner(
        &self,
        identity: &Identity,
        kind: MessageKind,
        application_body: &[u8],
    ) -> Result<V3InnerFrame, MessageError> {
        if identity.peer_id() != self.local {
            return Err(MessageError::WrongLocalIdentity);
        }
        if application_body.is_empty() {
            return Err(MessageError::BadV3Inner);
        }
        Ok(V3InnerFrame {
            conversation_id: self.id,
            message_id: random_id()?,
            sender: identity.peer_id(),
            sender_sequence: self.next_sequence,
            created_at: now_seconds(),
            kind,
            body: application_body.to_vec(),
        })
    }

    /// Commit local state for an outgoing v3 frame after MLS encryption and
    /// MAC computation have succeeded.
    pub fn record_outgoing_v3(&mut self, inner: &V3InnerFrame) -> Result<(), MessageError> {
        if inner.sender == self.local
            && inner.conversation_id == self.id
            && inner.sender_sequence == self.next_sequence
            && inner.sender_sequence > 0
        {
            let next = inner
                .sender_sequence
                .checked_add(1)
                .ok_or(MessageError::SequenceExhausted)?;
            self.replay.check_and_record_values(
                self.id,
                inner.sender.to_bytes(),
                inner.message_id,
                inner.sender_sequence,
            )?;
            self.outgoing
                .insert(inner.message_id, DeliveryState::Composed);
            self.next_sequence = next;
            return Ok(());
        }
        Err(MessageError::InvalidStateTransition)
    }

    /// Apply a v3 inner frame only after the outer MAC and MLS decryption have
    /// bound it to this group. Replay, sequence, and receipt policy are still
    /// enforced here; no clear wire field is trusted.
    pub fn receive_v3(&mut self, inner: V3InnerFrame) -> Result<ReceivedMessage, MessageError> {
        if inner.conversation_id != self.id {
            return Err(MessageError::WrongConversation);
        }
        if inner.sender_sequence == 0 {
            return Err(MessageError::SequenceRegression);
        }
        self.replay.check_and_record_values(
            self.id,
            inner.sender.to_bytes(),
            inner.message_id,
            inner.sender_sequence,
        )?;

        let receipt = if inner.kind == MessageKind::Receipt {
            let receipt = Receipt::from_bytes(&inner.body)?;
            self.apply_receipt(receipt)?;
            Some(receipt)
        } else {
            None
        };
        Ok(ReceivedMessage {
            message_id: inner.message_id,
            sender: inner.sender,
            kind: inner.kind,
            epoch: self.epoch,
            sender_sequence: inner.sender_sequence,
            receipt,
        })
    }

    /// Verify envelope authenticity, conversation binding, and epoch without
    /// mutating state. A higher MLS layer should call this before decrypting an
    /// untrusted payload.
    pub fn verify_envelope(&self, envelope: &Envelope) -> Result<(), MessageError> {
        envelope.verify()?;
        if envelope.conversation_id != self.id {
            return Err(MessageError::WrongConversation);
        }
        if envelope.epoch != self.epoch {
            return Err(MessageError::EpochMismatch {
                expected: self.epoch,
                actual: envelope.epoch,
            });
        }
        Ok(())
    }

    /// Verify and record an incoming envelope whose payload is already known.
    /// Replay, sequence, epoch, and conversation checks happen before any state
    /// transition is applied. `application_bytes` is the decrypted application
    /// body for MLS messages; the legacy `receive` path passes the raw payload.
    pub fn receive_with_plaintext(
        &mut self,
        envelope: Envelope,
        application_bytes: &[u8],
    ) -> Result<ReceivedMessage, MessageError> {
        self.verify_envelope(&envelope)?;
        self.replay.check_and_record(&envelope)?;

        let receipt = if envelope.kind == MessageKind::Receipt {
            let receipt = Receipt::from_bytes(application_bytes)?;
            self.apply_receipt(receipt)?;
            Some(receipt)
        } else {
            None
        };

        let received = ReceivedMessage {
            message_id: envelope.message_id,
            sender: envelope.sender,
            kind: envelope.kind,
            epoch: envelope.epoch,
            sender_sequence: envelope.sender_sequence,
            receipt,
        };
        self.incoming.push(envelope);
        self.incoming
            .sort_by_key(|item| (item.epoch, item.sender_sequence, item.message_id));
        Ok(received)
    }

    /// Verify and record an incoming envelope with an opaque payload. This is
    /// a compatibility interface for callers that already know the plaintext;
    /// MLS callers should decrypt first and call [`Self::receive_with_plaintext`].
    pub fn receive(&mut self, envelope: Envelope) -> Result<ReceivedMessage, MessageError> {
        let application_bytes = envelope.payload.clone();
        self.receive_with_plaintext(envelope, &application_bytes)
    }

    /// Local queue accepted the message; no network send has occurred.
    pub fn mark_queued(&mut self, message_id: &[u8; 16]) -> Result<(), MessageError> {
        let state = self
            .outgoing
            .get_mut(message_id)
            .ok_or(MessageError::UnknownMessage)?;
        if *state != DeliveryState::Composed {
            return Err(MessageError::InvalidStateTransition);
        }
        *state = DeliveryState::Queued;
        Ok(())
    }

    /// Handed to an encrypted transport stream. This is not proof of delivery.
    pub fn mark_sent_to_peer(&mut self, message_id: &[u8; 16]) -> Result<(), MessageError> {
        let state = self
            .outgoing
            .get_mut(message_id)
            .ok_or(MessageError::UnknownMessage)?;
        if !matches!(state, DeliveryState::Composed | DeliveryState::Queued) {
            return Err(MessageError::InvalidStateTransition);
        }
        *state = DeliveryState::SentToPeer;
        Ok(())
    }

    pub fn mark_failed(&mut self, message_id: &[u8; 16]) -> Result<(), MessageError> {
        let state = self
            .outgoing
            .get_mut(message_id)
            .ok_or(MessageError::UnknownMessage)?;
        if matches!(
            state,
            DeliveryState::Delivered | DeliveryState::Read | DeliveryState::Failed
        ) {
            return Err(MessageError::InvalidStateTransition);
        }
        *state = DeliveryState::Failed;
        Ok(())
    }

    /// Rebuild one outbound message from an authenticated local restore record.
    /// Only non-delivered states are accepted: a receipt must still be observed
    /// before the application may show `Delivered`.
    pub fn restore_outgoing(
        &mut self,
        message_id: &[u8; 16],
        state: DeliveryState,
    ) -> Result<(), MessageError> {
        if !matches!(state, DeliveryState::Queued | DeliveryState::SentToPeer) {
            return Err(MessageError::InvalidStateTransition);
        }
        self.outgoing.insert(*message_id, state);
        Ok(())
    }

    /// Restore the next local sequence from an authenticated snapshot so a new
    /// message cannot reuse a sequence number that predates the restart.
    pub fn restore_sequence(&mut self, sequence: u64) -> Result<(), MessageError> {
        if sequence == 0 {
            return Err(MessageError::SequenceExhausted);
        }
        self.next_sequence = self.next_sequence.max(sequence);
        Ok(())
    }

    pub fn delivery_state(&self, message_id: &[u8; 16]) -> Option<DeliveryState> {
        self.outgoing.get(message_id).copied()
    }

    pub fn incoming(&self) -> &[Envelope] {
        &self.incoming
    }

    /// Persist an authenticated envelope as vault ciphertext. The conversation
    /// ID and message ID are used only for blind indexes and AAD binding.
    pub fn persist(&self, session: &Session, envelope: &Envelope) -> Result<(), MessageError> {
        if envelope.conversation_id != self.id {
            return Err(MessageError::WrongConversation);
        }
        session.store_message(&self.id, &envelope.message_id, &envelope.to_bytes()?)?;
        Ok(())
    }

    /// Rebuild a conversation from vault ciphertext. Envelopes are verified
    /// again on load; a damaged or wrong-vault row fails closed.
    ///
    /// This legacy path parses receipt bodies directly from the envelope
    /// payload. It is only correct for opaque pre-MLS receipts: an MLS receipt
    /// is ciphertext and cannot be rebuilt here before MLS state persistence
    /// exists. `MlsConversation` does not expose a load path yet.
    pub fn load(session: &Session, conversation_id: [u8; 16]) -> Result<Self, MessageError> {
        let mut conversation = Self::with_id(session.identity().peer_id(), conversation_id);
        let mut receipts = Vec::new();
        for bytes in session.messages_for_conversation(&conversation_id)? {
            let envelope = Envelope::from_bytes(&bytes)?;
            envelope.verify()?;
            if envelope.conversation_id != conversation_id {
                return Err(MessageError::WrongConversation);
            }
            conversation.replay.check_and_record(&envelope)?;
            if envelope.kind == MessageKind::Receipt {
                receipts.push(envelope);
                continue;
            }
            if envelope.sender == conversation.local {
                conversation
                    .outgoing
                    .insert(envelope.message_id, DeliveryState::Composed);
                conversation.next_sequence = conversation.next_sequence.max(
                    envelope
                        .sender_sequence
                        .checked_add(1)
                        .ok_or(MessageError::SequenceExhausted)?,
                );
            } else {
                conversation.incoming.push(envelope);
            }
        }
        for envelope in receipts {
            let receipt = Receipt::from_bytes(&envelope.payload)?;
            let _ = conversation.apply_receipt(receipt);
            conversation.incoming.push(envelope);
        }
        conversation
            .incoming
            .sort_by_key(|item| (item.epoch, item.sender_sequence, item.message_id));
        Ok(conversation)
    }

    fn apply_receipt(&mut self, receipt: Receipt) -> Result<(), MessageError> {
        let state = self
            .outgoing
            .get_mut(&receipt.message_id)
            .ok_or(MessageError::UnknownMessage)?;
        if !state.can_receive_receipt(receipt.status) {
            return Err(MessageError::InvalidStateTransition);
        }
        *state = match receipt.status {
            ReceiptStatus::Delivered => DeliveryState::Delivered,
            ReceiptStatus::Read => DeliveryState::Read,
        };
        Ok(())
    }
}

impl std::fmt::Debug for Conversation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Conversation")
            .field("id", &format_args!("{:02x?}", self.id))
            .field("local", &self.local.to_string())
            .field("epoch", &self.epoch)
            .field("next_sequence", &self.next_sequence)
            .field("outgoing", &self.outgoing.len())
            .field("incoming", &self.incoming.len())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ReplayKey {
    conversation: [u8; 16],
    sender: Vec<u8>,
    message_id: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SequenceKey {
    conversation: [u8; 16],
    sender: Vec<u8>,
}

/// Bounded replay cache plus a monotonic high-water mark per sender. Entries
/// are recorded only after signature, conversation, and epoch checks.
#[derive(Debug)]
struct ReplayCache {
    capacity: usize,
    seen: HashMap<ReplayKey, ()>,
    order: VecDeque<ReplayKey>,
    last_sequence: HashMap<SequenceKey, u64>,
}

impl ReplayCache {
    fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            seen: HashMap::new(),
            order: VecDeque::new(),
            last_sequence: HashMap::new(),
        }
    }

    fn check_and_record(&mut self, envelope: &Envelope) -> Result<(), MessageError> {
        self.check_and_record_values(
            envelope.conversation_id,
            envelope.sender.to_bytes(),
            envelope.message_id,
            envelope.sender_sequence,
        )
    }

    fn check_and_record_values(
        &mut self,
        conversation: [u8; 16],
        sender: Vec<u8>,
        message_id: [u8; 16],
        sender_sequence: u64,
    ) -> Result<(), MessageError> {
        let key = ReplayKey {
            conversation,
            sender: sender.clone(),
            message_id,
        };
        if self.seen.contains_key(&key) {
            return Err(MessageError::Replay);
        }
        let sequence_key = SequenceKey {
            conversation,
            sender,
        };
        if let Some(&last) = self.last_sequence.get(&sequence_key)
            && sender_sequence <= last
        {
            return Err(MessageError::SequenceRegression);
        }
        if self.last_sequence.len() >= self.capacity
            && !self.last_sequence.contains_key(&sequence_key)
        {
            return Err(MessageError::ReplayCacheFull);
        }

        while self.seen.len() >= self.capacity {
            match self.order.pop_front() {
                Some(old) => {
                    self.seen.remove(&old);
                }
                None => break,
            }
        }
        self.seen.insert(key.clone(), ());
        self.order.push_back(key);
        self.last_sequence.insert(sequence_key, sender_sequence);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identities() -> (Identity, Identity) {
        (
            Identity::generate().expect("local identity"),
            Identity::generate().expect("remote identity"),
        )
    }

    #[test]
    fn delivery_states_never_collapse_sent_to_peer_into_delivered() {
        let (local, _) = identities();
        let mut conversation = Conversation::with_id(local.peer_id(), [1u8; 16]);
        let envelope = conversation
            .compose(&local, MessageKind::Text, b"cipher".to_vec())
            .expect("compose");
        assert_eq!(
            conversation.delivery_state(&envelope.message_id),
            Some(DeliveryState::Composed)
        );
        conversation
            .mark_sent_to_peer(&envelope.message_id)
            .expect("sent to peer");
        assert_eq!(
            conversation.delivery_state(&envelope.message_id),
            Some(DeliveryState::SentToPeer)
        );
        assert!(
            conversation
                .delivery_state(&envelope.message_id)
                .expect("state")
                .description()
                .contains("unconfirmed")
        );
    }

    #[test]
    fn receipt_transitions_require_an_known_outgoing_message() {
        let (local, _) = identities();
        let mut conversation = Conversation::with_id(local.peer_id(), [1u8; 16]);
        let envelope = conversation
            .compose(&local, MessageKind::Text, vec![])
            .expect("compose");
        conversation
            .mark_sent_to_peer(&envelope.message_id)
            .expect("sent");

        let unknown_receipt = Receipt::new(ReceiptStatus::Delivered, [99u8; 16]);
        assert!(matches!(
            conversation.apply_receipt(unknown_receipt),
            Err(MessageError::UnknownMessage)
        ));

        // A receipt envelope from another peer is verified and applied.
        let (_local, remote) = identities();
        let mut conversation = Conversation::with_id(local.peer_id(), [1u8; 16]);
        let outgoing = conversation
            .compose(&local, MessageKind::Text, vec![])
            .expect("compose");
        conversation
            .mark_sent_to_peer(&outgoing.message_id)
            .expect("sent");
        let receipt = Receipt::new(ReceiptStatus::Delivered, outgoing.message_id);
        let receipt_envelope = conversation
            .receive(
                Envelope::new(
                    &remote,
                    EnvelopeParams {
                        conversation_id: [1u8; 16],
                        epoch: 0,
                        message_id: [8u8; 16],
                        sender_sequence: 1,
                        created_at: 0,
                        kind: MessageKind::Receipt,
                    },
                    receipt.to_bytes(),
                )
                .expect("receipt envelope"),
            )
            .expect("receive receipt");
        assert_eq!(
            receipt_envelope.receipt,
            Some(Receipt::new(ReceiptStatus::Delivered, outgoing.message_id))
        );
        assert_eq!(
            conversation.delivery_state(&outgoing.message_id),
            Some(DeliveryState::Delivered)
        );
    }

    #[test]
    fn replay_and_sequence_regression_are_rejected() {
        let (local, remote) = identities();
        let mut conversation = Conversation::with_id(local.peer_id(), [2u8; 16]);
        let envelope = Envelope::new(
            &remote,
            EnvelopeParams {
                conversation_id: [2u8; 16],
                epoch: 0,
                message_id: [3u8; 16],
                sender_sequence: 1,
                created_at: 0,
                kind: MessageKind::Text,
            },
            b"cipher".to_vec(),
        )
        .expect("envelope");

        conversation
            .receive(envelope.clone())
            .expect("first receive");
        assert!(matches!(
            conversation.receive(envelope),
            Err(MessageError::Replay)
        ));

        let old_sequence = Envelope::new(
            &remote,
            EnvelopeParams {
                conversation_id: [2u8; 16],
                epoch: 0,
                message_id: [4u8; 16],
                sender_sequence: 1,
                created_at: 0,
                kind: MessageKind::Text,
            },
            vec![],
        )
        .expect("envelope");
        assert!(matches!(
            conversation.receive(old_sequence),
            Err(MessageError::SequenceRegression)
        ));
    }

    #[test]
    fn v3_inner_replay_and_sequence_regression_are_rejected_after_decryption() {
        let (local, remote) = identities();
        let mut conversation = Conversation::with_id(local.peer_id(), [9u8; 16]);
        let inner = V3InnerFrame {
            conversation_id: [9u8; 16],
            message_id: [10u8; 16],
            sender: remote.peer_id(),
            sender_sequence: 1,
            created_at: 0,
            kind: MessageKind::Text,
            body: b"MLS-protected body".to_vec(),
        };

        conversation
            .receive_v3(inner.clone())
            .expect("first receive");
        assert!(matches!(
            conversation.receive_v3(inner),
            Err(MessageError::Replay)
        ));

        let old_sequence = V3InnerFrame {
            conversation_id: [9u8; 16],
            message_id: [11u8; 16],
            sender: remote.peer_id(),
            sender_sequence: 1,
            created_at: 0,
            kind: MessageKind::Text,
            body: b"older frame".to_vec(),
        };
        assert!(matches!(
            conversation.receive_v3(old_sequence),
            Err(MessageError::SequenceRegression)
        ));

        let wrong_conversation = V3InnerFrame {
            conversation_id: [12u8; 16],
            message_id: [13u8; 16],
            sender: remote.peer_id(),
            sender_sequence: 2,
            created_at: 0,
            kind: MessageKind::Text,
            body: b"foreign frame".to_vec(),
        };
        assert!(matches!(
            conversation.receive_v3(wrong_conversation),
            Err(MessageError::WrongConversation)
        ));
    }

    #[test]
    fn v3_outgoing_sequence_is_consumed_only_after_a_successful_compose() {
        let (local, _) = identities();
        let mut conversation = Conversation::with_id(local.peer_id(), [14u8; 16]);
        let inner = conversation
            .prepare_v3_inner(&local, MessageKind::Text, b"cipher")
            .expect("prepared inner frame");
        assert_eq!(inner.sender_sequence, 1);
        assert_eq!(conversation.next_sequence(), 1);

        conversation
            .record_outgoing_v3(&inner)
            .expect("committed outgoing frame");
        assert_eq!(conversation.next_sequence(), 2);
        assert_eq!(
            conversation.delivery_state(&inner.message_id),
            Some(DeliveryState::Composed)
        );
        assert!(matches!(
            conversation.record_outgoing_v3(&inner),
            Err(MessageError::InvalidStateTransition)
        ));
    }

    #[test]
    fn wrong_conversation_and_epoch_are_rejected() {
        let (local, remote) = identities();
        let mut conversation = Conversation::with_id(local.peer_id(), [5u8; 16]);
        let envelope = Envelope::new(
            &remote,
            EnvelopeParams {
                conversation_id: [6u8; 16],
                epoch: 0,
                message_id: [7u8; 16],
                sender_sequence: 1,
                created_at: 0,
                kind: MessageKind::Text,
            },
            vec![],
        )
        .expect("envelope");
        assert!(matches!(
            conversation.receive(envelope),
            Err(MessageError::WrongConversation)
        ));

        let future = Envelope::new(
            &remote,
            EnvelopeParams {
                conversation_id: [5u8; 16],
                epoch: 1,
                message_id: [8u8; 16],
                sender_sequence: 1,
                created_at: 0,
                kind: MessageKind::Text,
            },
            vec![],
        )
        .expect("envelope");
        assert!(matches!(
            conversation.receive(future),
            Err(MessageError::EpochMismatch { .. })
        ));
    }
}
