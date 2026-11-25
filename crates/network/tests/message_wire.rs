//! Milestone 5 wire acceptance test: real MLS ciphertext travels inside a
//! signed envelope over the Noise-authenticated direct connection, and only an
//! explicit MLS-encrypted receipt advances delivery state.

use std::str::FromStr;
use std::thread;
use std::time::{Duration, Instant};

use libp2p::{Multiaddr, PeerId as SwarmPeerId};
use p2p_groups::MlsConversation;
use p2p_identity::Identity;
use p2p_messaging::{DeliveryState, Envelope, MessageKind, Receipt, ReceiptStatus};
use p2p_network::{ConnectionState, MessageEvent, Network, NetworkConfig};

fn local_config() -> NetworkConfig {
    NetworkConfig {
        listen_addr: Multiaddr::from_str("/ip4/127.0.0.1/tcp/0").expect("valid multiaddr"),
        ..NetworkConfig::default()
    }
}

fn wait_until<F>(network: &mut Network, predicate: F, timeout: Duration) -> bool
where
    F: Fn(&ConnectionState) -> bool,
{
    let deadline = Instant::now() + timeout;
    loop {
        while network.poll_event().is_some() {}
        if predicate(network.state()) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_message<F>(network: &mut Network, predicate: F, timeout: Duration) -> Option<MessageEvent>
where
    F: Fn(&MessageEvent) -> bool,
{
    let deadline = Instant::now() + timeout;
    loop {
        while let Some(event) = network.poll_message_event() {
            if predicate(&event) {
                return Some(event);
            }
        }
        if Instant::now() >= deadline {
            return None;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn connected_networks() -> (Identity, Identity, Network, Network) {
    let alice_identity = Identity::generate().expect("alice identity");
    let bob_identity = Identity::generate().expect("bob identity");
    let mut alice = Network::start(&alice_identity, local_config()).expect("alice network");
    let mut bob = Network::start(&bob_identity, local_config()).expect("bob network");

    let listening = |state: &ConnectionState| matches!(state, ConnectionState::Listening { addresses } if !addresses.is_empty());
    assert!(wait_until(&mut alice, listening, Duration::from_secs(10)));
    assert!(wait_until(&mut bob, listening, Duration::from_secs(10)));

    let bob_address = bob
        .listen_addresses()
        .into_iter()
        .next()
        .expect("bob listen address");
    let target = format!("{bob_address}/p2p/{}", bob_identity.peer_id());
    let target = Network::parse_address(&target).expect("valid target address");
    alice.dial(target).expect("dial queued");

    let connected = |state: &ConnectionState| matches!(state, ConnectionState::Connected { peers } if peers.len() == 1);
    assert!(wait_until(&mut alice, connected, Duration::from_secs(10)));
    assert!(wait_until(&mut bob, connected, Duration::from_secs(10)));

    (alice_identity, bob_identity, alice, bob)
}

fn swarm_peer(identity: &Identity) -> SwarmPeerId {
    SwarmPeerId::from_str(&identity.peer_id().to_string()).expect("swarm peer id")
}

fn mls_conversations(
    alice_identity: &Identity,
    bob_identity: &Identity,
) -> (MlsConversation, MlsConversation) {
    let mut alice = MlsConversation::new(alice_identity).expect("alice MLS conversation");
    let key_package = MlsConversation::key_package(bob_identity).expect("bob key package");
    let welcome = alice
        .add_member(
            key_package.bytes(),
            bob_identity.peer_id(),
            &bob_identity.public_key_bytes(),
        )
        .expect("add bob to MLS group");
    let bob = MlsConversation::join(bob_identity, alice.id(), key_package, &welcome)
        .expect("bob joins MLS group");
    assert_eq!(alice.epoch(), bob.epoch());
    (alice, bob)
}

#[test]
fn mls_encrypted_envelope_and_receipt_exchange_over_direct_connection() {
    assert_eq!(
        p2p_network::MAX_MESSAGE_BYTES,
        p2p_messaging::MAX_ENVELOPE_BYTES
    );
    let (alice_identity, bob_identity, mut alice, mut bob) = connected_networks();
    let (mut alice_conversation, mut bob_conversation) =
        mls_conversations(&alice_identity, &bob_identity);

    let plaintext = b"plaintext is only present after MLS decryption";
    let outgoing = alice_conversation
        .compose(&alice_identity, MessageKind::Text, plaintext)
        .expect("compose encrypted outgoing");
    assert!(
        !outgoing
            .payload
            .windows(plaintext.len())
            .any(|window| window == plaintext)
    );
    let outgoing_id = outgoing.message_id;
    let request_id = alice
        .send_message(
            swarm_peer(&bob_identity),
            outgoing.to_bytes().expect("encode envelope"),
        )
        .expect("send message");

    let sent = wait_message(
        &mut alice,
        |event| {
            matches!(
                event,
                MessageEvent::SentToPeer { request_id: id, .. } if *id == request_id
            )
        },
        Duration::from_secs(5),
    )
    .expect("sent-to-peer event");
    assert!(matches!(sent, MessageEvent::SentToPeer { .. }));

    alice_conversation
        .mark_sent_to_peer(&outgoing_id)
        .expect("mark sent to peer");
    assert_eq!(
        alice_conversation.delivery_state(&outgoing_id),
        Some(DeliveryState::SentToPeer)
    );

    let request = wait_message(
        &mut bob,
        |event| {
            matches!(
                event,
                MessageEvent::RequestReceived { peer, .. }
                    if peer.to_string() == alice_identity.peer_id().to_string()
            )
        },
        Duration::from_secs(5),
    )
    .expect("request received by bob");
    let (response_id, envelope_bytes) = match request {
        MessageEvent::RequestReceived {
            response_id, bytes, ..
        } => (response_id, bytes),
        other => panic!("expected request, got {other:?}"),
    };

    let envelope = Envelope::from_bytes(&envelope_bytes).expect("decode envelope");
    let received = bob_conversation
        .receive(envelope)
        .expect("verify and decrypt envelope");
    assert_eq!(received.metadata.sender, alice_identity.peer_id());
    assert_eq!(received.plaintext.as_slice(), plaintext.as_slice());
    assert!(received.metadata.receipt.is_none());

    let expected_receipt = Receipt::new(ReceiptStatus::Delivered, outgoing_id);
    let receipt_envelope = bob_conversation
        .receipt(&bob_identity, ReceiptStatus::Delivered, outgoing_id)
        .expect("compose encrypted receipt");
    bob.respond_to_message(
        response_id,
        receipt_envelope.to_bytes().expect("encode receipt"),
    )
    .expect("respond with receipt");

    let response = wait_message(
        &mut alice,
        |event| {
            matches!(
                event,
                MessageEvent::ResponseReceived { request_id: id, .. } if *id == request_id
            )
        },
        Duration::from_secs(5),
    )
    .expect("response received by alice");
    let response_bytes = match response {
        MessageEvent::ResponseReceived { bytes, .. } => bytes,
        other => panic!("expected response, got {other:?}"),
    };

    let receipt_envelope = Envelope::from_bytes(&response_bytes).expect("decode receipt envelope");
    let receipt_result = alice_conversation
        .receive(receipt_envelope)
        .expect("decrypt and verify receipt");
    assert_eq!(receipt_result.metadata.receipt, Some(expected_receipt));
    assert_eq!(
        alice_conversation.delivery_state(&outgoing_id),
        Some(DeliveryState::Delivered)
    );
}

#[test]
fn tampered_envelope_is_rejected_without_a_delivery_claim() {
    let (alice_identity, bob_identity, mut alice, mut bob) = connected_networks();
    let (mut alice_conversation, mut bob_conversation) =
        mls_conversations(&alice_identity, &bob_identity);

    let mut outgoing = alice_conversation
        .compose(&alice_identity, MessageKind::Text, b"original plaintext")
        .expect("compose outgoing");
    outgoing.payload.push(1);
    let outgoing_id = outgoing.message_id;
    let request_id = alice
        .send_message(
            swarm_peer(&bob_identity),
            outgoing.to_bytes().expect("encode envelope"),
        )
        .expect("send tampered envelope");

    let sent = wait_message(
        &mut alice,
        |event| {
            matches!(
                event,
                MessageEvent::SentToPeer { request_id: id, .. } if *id == request_id
            )
        },
        Duration::from_secs(5),
    )
    .expect("sent-to-peer event");
    assert!(matches!(sent, MessageEvent::SentToPeer { .. }));
    alice_conversation
        .mark_sent_to_peer(&outgoing_id)
        .expect("mark sent to peer");

    let request = wait_message(
        &mut bob,
        |event| {
            matches!(
                event,
                MessageEvent::RequestReceived { peer, .. }
                    if peer.to_string() == alice_identity.peer_id().to_string()
            )
        },
        Duration::from_secs(5),
    )
    .expect("request received by bob");
    let (response_id, envelope_bytes) = match request {
        MessageEvent::RequestReceived {
            response_id, bytes, ..
        } => (response_id, bytes),
        other => panic!("expected request, got {other:?}"),
    };

    let envelope = Envelope::from_bytes(&envelope_bytes).expect("decode tampered envelope");
    assert!(bob_conversation.receive(envelope).is_err());
    bob.respond_to_message(response_id, b"application rejected envelope".to_vec())
        .expect("send rejection marker");

    let response = wait_message(
        &mut alice,
        |event| {
            matches!(
                event,
                MessageEvent::ResponseReceived { request_id: id, .. } if *id == request_id
            )
        },
        Duration::from_secs(5),
    )
    .expect("rejection marker received");
    let response_bytes = match response {
        MessageEvent::ResponseReceived { bytes, .. } => bytes,
        other => panic!("expected response, got {other:?}"),
    };
    assert!(Envelope::from_bytes(&response_bytes).is_err());
    assert_eq!(
        alice_conversation.delivery_state(&outgoing_id),
        Some(DeliveryState::SentToPeer)
    );
}
