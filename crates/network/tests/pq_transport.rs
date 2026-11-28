//! Acceptance and adversarial checks for pinned post-quantum transport.

use std::str::FromStr;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use libp2p::core::transport::Transport;
use libp2p::futures::StreamExt;
use libp2p::swarm::NetworkBehaviour;
use libp2p::{Multiaddr, PeerId, SwarmBuilder};
use libp2p_request_response as request_response;
use libp2p_request_response::ProtocolSupport;
use p2p_identity::{Identity, IdentityRole};
use p2p_network::{
    ConnectionState, MESSAGE_PROTOCOL, MessageCodec, MessageEvent, Network, NetworkConfig,
    PqTransportConfig,
};

fn peer_id(identity: &Identity) -> PeerId {
    PeerId::from_str(&identity.peer_id().to_string()).expect("valid PeerId")
}

fn pin_identity(config: &mut PqTransportConfig, identity: &Identity) {
    let key = identity
        .pq_role_public_bytes(IdentityRole::Application)
        .expect("application key");
    config
        .insert(peer_id(identity), &key)
        .expect("valid pin insertion");
}

fn config_with_pins(pins: PqTransportConfig) -> NetworkConfig {
    NetworkConfig {
        listen_addr: Multiaddr::from_str("/ip4/127.0.0.1/tcp/0").expect("valid multiaddr"),
        pq_transport: Some(pins),
        ..NetworkConfig::default()
    }
}

fn mutual_config(a: &Identity, b: &Identity) -> NetworkConfig {
    let mut pins = PqTransportConfig::default();
    pin_identity(&mut pins, a);
    pin_identity(&mut pins, b);
    config_with_pins(pins)
}

fn wait_for_listener(network: &mut Network) -> Multiaddr {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        while let Some(state) = network.poll_event() {
            if let ConnectionState::Listening { addresses } = state
                && let Some(address) = addresses
                    .into_iter()
                    .find(|address| address.to_string().contains("/tcp/"))
            {
                return address;
            }
        }
        assert!(
            Instant::now() < deadline,
            "network never reported a TCP listener"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_connected(network: &mut Network, peer: PeerId) -> Result<(), Vec<String>> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut trace = Vec::new();
    while Instant::now() < deadline {
        while let Some(state) = network.poll_event() {
            if matches!(state, ConnectionState::Connected { ref peers } if peers.contains(&peer)) {
                return Ok(());
            }
            trace.push(format!("{state:?}"));
        }
        thread::sleep(Duration::from_millis(10));
    }
    Err(trace)
}

fn wait_for_failure(network: &mut Network, needle: &str) -> Result<(), Vec<String>> {
    let needle = needle.to_ascii_lowercase();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut trace = Vec::new();
    while Instant::now() < deadline {
        while let Some(state) = network.poll_event() {
            if let ConnectionState::Failed { reason, .. } = &state
                && reason.to_ascii_lowercase().contains(&needle)
            {
                return Ok(());
            }
            if matches!(state, ConnectionState::Connected { .. }) {
                return Err(trace);
            }
            trace.push(format!("{state:?}"));
        }
        thread::sleep(Duration::from_millis(10));
    }
    Err(trace)
}

#[derive(NetworkBehaviour)]
struct ClassicalNoiseBehaviour {
    messages: request_response::Behaviour<MessageCodec>,
}

/// A peer that only speaks ordinary libp2p Noise. It cannot negotiate the
/// pinned `/p2p-messenger/noise-pq/1` security upgrade.
fn spawn_classical_noise_peer(
    target: Multiaddr,
    attempted: mpsc::Sender<()>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("classical peer runtime");
        runtime.block_on(async move {
            let key = libp2p::identity::Keypair::generate_ed25519();
            let transport = libp2p::tcp::tokio::Transport::new(Default::default())
                .upgrade(libp2p::core::upgrade::Version::V1Lazy)
                .authenticate(libp2p::noise::Config::new(&key).expect("classical noise config"))
                .multiplex(libp2p::yamux::Config::default())
                .map(|(peer, connection), _| {
                    (peer, libp2p::core::muxing::StreamMuxerBox::new(connection))
                })
                .boxed();
            let mut swarm = SwarmBuilder::with_existing_identity(key)
                .with_tokio()
                .with_other_transport(|_| transport)
                .map_err(|never| -> String { match never {} })
                .expect("classical transport")
                .with_behaviour(|_| ClassicalNoiseBehaviour {
                    messages: request_response::Behaviour::<MessageCodec>::new(
                        [(MESSAGE_PROTOCOL.to_owned(), ProtocolSupport::Full)],
                        request_response::Config::default()
                            .with_request_timeout(Duration::from_secs(3)),
                    ),
                })
                .map_err(|never| -> String { match never {} })
                .expect("classical behaviour")
                .build();
            let _ = attempted.send(());
            swarm.dial(target).expect("classical dial queued");
            let deadline = Instant::now() + Duration::from_secs(4);
            while Instant::now() < deadline {
                if tokio::time::timeout(Duration::from_millis(250), swarm.next())
                    .await
                    .ok()
                    .is_none()
                {
                    break;
                }
            }
        });
    })
}

#[test]
fn mutually_pinned_pq_transport_accepts_application_traffic() {
    let alice_identity = Identity::generate().expect("alice identity");
    let bob_identity = Identity::generate().expect("bob identity");
    let config = mutual_config(&alice_identity, &bob_identity);
    let mut alice = Network::start(&alice_identity, config.clone()).expect("alice network");
    let mut bob = Network::start(&bob_identity, config).expect("bob network");
    let bob_listener = wait_for_listener(&mut bob);
    let bob_peer = peer_id(&bob_identity);
    let alice_peer = peer_id(&alice_identity);
    let target = format!("{bob_listener}/p2p/{bob_peer}")
        .parse::<Multiaddr>()
        .expect("bob target");

    alice.dial(target).expect("dial queued");
    if let Err(reasons) = wait_for_connected(&mut alice, bob_peer) {
        panic!("mutually pinned PQ transport never completed: {reasons:?}");
    }
    if let Err(reasons) = wait_for_connected(&mut bob, alice_peer) {
        panic!("responder never observed the PQ-authenticated connection: {reasons:?}");
    }

    let payload = b"application bytes over pinned PQ transport".to_vec();
    alice
        .send_message(bob_peer, payload.clone())
        .expect("message queued");
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut received = false;
    while Instant::now() < deadline {
        while let Some(event) = bob.poll_message_event() {
            if matches!(event, MessageEvent::RequestReceived { peer, bytes, .. } if peer == alice_peer && bytes == payload)
            {
                received = true;
            }
        }
        if received {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(received, "application request did not cross the PQ stream");
    drop(alice);
    drop(bob);
}

#[test]
fn unpinned_responder_is_failed_closed() {
    let alice_identity = Identity::generate().expect("alice identity");
    let outsider_identity = Identity::generate().expect("outsider identity");
    let peer_identity = Identity::generate().expect("unrelated pin identity");

    let mut alice_pins = PqTransportConfig::default();
    // Alice has a valid configuration pin table, but not for the dialing peer.
    pin_identity(&mut alice_pins, &peer_identity);
    let mut outsider_pins = PqTransportConfig::default();
    pin_identity(&mut outsider_pins, &alice_identity);

    let mut alice =
        Network::start(&alice_identity, config_with_pins(alice_pins)).expect("alice network");
    let mut outsider = Network::start(&outsider_identity, config_with_pins(outsider_pins))
        .expect("outsider network");
    let listener = wait_for_listener(&mut alice);
    let target = format!("{listener}/p2p/{}", peer_id(&alice_identity))
        .parse::<Multiaddr>()
        .expect("alice target");

    outsider.dial(target).expect("dial queued");
    if let Err(trace) = wait_for_failure(&mut alice, "no pinned") {
        panic!("unpinned peer was not rejected by the PQ transport upgrade: {trace:?}");
    }
    assert!(
        alice
            .poll_event()
            .map(|state| !matches!(state, ConnectionState::Connected { .. }))
            .unwrap_or(true),
        "unpinned peer was reported as connected"
    );
    drop(outsider);
    drop(alice);
}

#[test]
fn wrong_pq_pin_is_failed_closed() {
    let alice_identity = Identity::generate().expect("alice identity");
    let bob_identity = Identity::generate().expect("bob identity");
    let impostor_identity = Identity::generate().expect("impostor identity");

    // Alice associates Bob's PeerId with an impostor's application key.
    let mut alice_pins = PqTransportConfig::default();
    let impostor_key = impostor_identity
        .pq_role_public_bytes(IdentityRole::Application)
        .expect("impostor application key");
    alice_pins
        .insert(peer_id(&bob_identity), &impostor_key)
        .expect("wrong pin insertion");
    let mut bob_pins = PqTransportConfig::default();
    pin_identity(&mut bob_pins, &alice_identity);

    let mut alice =
        Network::start(&alice_identity, config_with_pins(alice_pins)).expect("alice network");
    let mut bob = Network::start(&bob_identity, config_with_pins(bob_pins)).expect("bob network");
    let bob_listener = wait_for_listener(&mut bob);
    let target = format!("{bob_listener}/p2p/{}", peer_id(&bob_identity))
        .parse::<Multiaddr>()
        .expect("bob target");

    alice.dial(target).expect("dial queued");
    if let Err(trace) = wait_for_failure(&mut alice, "PQ authentication failed") {
        panic!("wrong pinned key was not rejected: {trace:?}");
    }
    drop(bob);
    drop(alice);
}

#[test]
fn classical_noise_downgrade_is_failed_closed() {
    let identity = Identity::generate().expect("identity");
    let mut pins = PqTransportConfig::default();
    pin_identity(&mut pins, &identity);
    let mut network = Network::start(&identity, config_with_pins(pins)).expect("network");
    let listener = wait_for_listener(&mut network);
    let target = format!("{listener}/p2p/{}", peer_id(&identity))
        .parse::<Multiaddr>()
        .expect("target");

    let (attempted_tx, attempted_rx) = mpsc::channel();
    let classical = spawn_classical_noise_peer(target, attempted_tx);
    attempted_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("classical peer did not attempt a dial");

    if let Err(trace) = wait_for_failure(&mut network, "protocol") {
        panic!("classical Noise downgrade was not rejected during upgrade negotiation: {trace:?}");
    }
    assert!(
        network
            .poll_event()
            .map(|state| !matches!(state, ConnectionState::Connected { .. }))
            .unwrap_or(true),
        "classical peer was reported as connected"
    );
    drop(network);
    let _ = classical.join();
}

#[test]
fn pinned_transport_rejects_empty_pin_table_and_relay_paths() {
    let identity = Identity::generate().expect("identity");

    let mut empty = config_with_pins(PqTransportConfig::default());
    let error = match Network::start(&identity, empty.clone()) {
        Ok(_) => panic!("empty pin table was accepted"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("at least one"));

    let mut pins = PqTransportConfig::default();
    pin_identity(&mut pins, &identity);
    empty.pq_transport = Some(pins);
    empty.relay_mode = p2p_network::RelayMode::Client;
    let error = match Network::start(&identity, empty) {
        Ok(_) => panic!("relay with pinned PQ transport was accepted"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("relay"));
}
