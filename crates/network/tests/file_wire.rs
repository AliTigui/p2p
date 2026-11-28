//! Milestone 7 wire acceptance test: the separate file protocol carries signed
//! frames over the same Noise-authenticated direct connection.

use std::str::FromStr;
use std::thread;
use std::time::{Duration, Instant};

use libp2p::{Multiaddr, PeerId as SwarmPeerId};
use p2p_files::{FileEnvelope, FileMessage, MAX_CHUNK_PLAINTEXT_BYTES};
use p2p_identity::Identity;
use p2p_network::{ConnectionState, FileEvent, Network, NetworkConfig};
use zeroize::Zeroizing;

fn local_config() -> NetworkConfig {
    NetworkConfig {
        listen_addr: Multiaddr::from_str("/ip4/127.0.0.1/tcp/0").expect("valid multiaddr"),
        ..NetworkConfig::direct()
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

fn wait_file<F>(network: &mut Network, predicate: F, timeout: Duration) -> Option<FileEvent>
where
    F: Fn(&FileEvent) -> bool,
{
    let deadline = Instant::now() + timeout;
    loop {
        while let Some(event) = network.poll_file_event() {
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

#[test]
fn signed_file_frames_travel_over_the_separate_file_protocol() {
    assert_eq!(p2p_network::FILE_PROTOCOL, "/p2p-messenger/file/1");
    let (alice_identity, bob_identity, mut alice, mut bob) = connected_networks();
    let transfer_id = [4u8; 16];
    let offer = FileEnvelope::new(
        &alice_identity,
        FileMessage::Offer {
            transfer_id,
            name: "wire.txt".to_owned(),
            size: 128,
            chunk_count: 1,
            chunk_size: MAX_CHUNK_PLAINTEXT_BYTES as u32,
            manifest_hash: [5; 32],
            content_key: Zeroizing::new([6; 32]),
        },
    )
    .expect("signed offer");

    let request_id = alice
        .send_file(
            swarm_peer(&bob_identity),
            offer.to_bytes().expect("encode offer"),
        )
        .expect("send offer");
    let sent = wait_file(
        &mut alice,
        |event| matches!(event, FileEvent::SentToPeer { request_id: id, .. } if *id == request_id),
        Duration::from_secs(5),
    )
    .expect("sent-to-peer event");
    assert!(matches!(sent, FileEvent::SentToPeer { .. }));

    let request = wait_file(
        &mut bob,
        |event| {
            matches!(event, FileEvent::RequestReceived { peer, .. }
                if peer.to_string() == alice_identity.peer_id().to_string())
        },
        Duration::from_secs(5),
    )
    .expect("offer received by bob");
    let (response_id, bytes) = match request {
        FileEvent::RequestReceived {
            response_id, bytes, ..
        } => (response_id, bytes),
        other => panic!("expected request, got {other:?}"),
    };
    let decoded = FileEnvelope::from_bytes(&bytes).expect("decode offer");
    decoded
        .verify(&alice_identity.peer_id())
        .expect("verify authenticated sender");
    assert!(matches!(decoded.message, FileMessage::Offer { .. }));

    let accept = FileEnvelope::new(
        &bob_identity,
        FileMessage::Accept {
            transfer_id,
            accepted: true,
        },
    )
    .expect("signed accept");
    bob.respond_to_file(response_id, accept.to_bytes().expect("encode accept"))
        .expect("respond with accept");

    let response = wait_file(
        &mut alice,
        |event| {
            matches!(event, FileEvent::ResponseReceived { request_id: id, .. } if *id == request_id)
        },
        Duration::from_secs(5),
    )
    .expect("accept received by alice");
    let bytes = match response {
        FileEvent::ResponseReceived { bytes, .. } => bytes,
        other => panic!("expected response, got {other:?}"),
    };
    let decoded = FileEnvelope::from_bytes(&bytes).expect("decode accept");
    decoded
        .verify(&bob_identity.peer_id())
        .expect("verify authenticated responder");
    match decoded.message {
        FileMessage::Accept { accepted, .. } => assert!(accepted),
        other => panic!("expected accept, got {other:?}"),
    }
}
