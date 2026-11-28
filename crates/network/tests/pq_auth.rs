//! Adversarial acceptance checks for mandatory PQ connection admission.

use std::str::FromStr;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use libp2p::core::transport::Transport;
use libp2p::futures::StreamExt;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{Multiaddr, PeerId, SwarmBuilder, identify};
use libp2p_request_response as request_response;
use libp2p_request_response::ProtocolSupport;
use p2p_identity::Identity;
use p2p_network::{
    ConnectionState, IdentifyEvent, MESSAGE_PROTOCOL, MessageCodec, Network, NetworkConfig,
};

fn local_config() -> NetworkConfig {
    NetworkConfig {
        listen_addr: Multiaddr::from_str("/ip4/127.0.0.1/tcp/0").expect("valid multiaddr"),
        ..NetworkConfig::default()
    }
}

fn identify_config() -> NetworkConfig {
    NetworkConfig {
        enable_identify: true,
        ..local_config()
    }
}

/// Minimal pre-PQ peer with both identify and the message protocol. It performs
/// optional libp2p protocol work immediately after the classical upgrade and
/// never registers `/p2p-messenger/pq-auth/1`.
#[allow(unreachable_code)]
#[derive(NetworkBehaviour)]
struct LegacyBehaviour {
    identify: identify::Behaviour,
    messages: request_response::Behaviour<MessageCodec>,
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

/// Drive a minimal libp2p peer that deliberately omits the PQ admission
/// protocol. It opens the application message protocol immediately after the
/// classical Noise/Yamux upgrade.
fn spawn_legacy_peer(target: Multiaddr, attempted: mpsc::Sender<()>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("legacy peer runtime");
        runtime.block_on(async move {
            let key = libp2p::identity::Keypair::generate_ed25519();
            let transport = libp2p::tcp::tokio::Transport::new(Default::default())
                .upgrade(libp2p::core::upgrade::Version::V1Lazy)
                .authenticate(libp2p::noise::Config::new(&key).expect("legacy noise config"))
                .multiplex(libp2p::yamux::Config::default())
                .map(|(peer, connection), _| {
                    (peer, libp2p::core::muxing::StreamMuxerBox::new(connection))
                })
                .boxed();
            let mut swarm = SwarmBuilder::with_existing_identity(key)
                .with_tokio()
                .with_other_transport(|_| transport)
                .map_err(|never| -> String { match never {} })
                .expect("legacy transport")
                .with_behaviour(|key| LegacyBehaviour {
                    identify: identify::Behaviour::new(identify::Config::new(
                        "legacy-peer/1".to_owned(),
                        key.public(),
                    )),
                    messages: request_response::Behaviour::<MessageCodec>::new(
                        [(MESSAGE_PROTOCOL.to_owned(), ProtocolSupport::Full)],
                        request_response::Config::default()
                            .with_request_timeout(Duration::from_secs(3)),
                    ),
                })
                .map_err(|never| -> String { match never {} })
                .expect("legacy behaviour")
                .build();

            swarm.dial(target).expect("legacy dial queued");
            let deadline = Instant::now() + Duration::from_secs(4);
            while Instant::now() < deadline {
                let Some(event) = tokio::time::timeout(Duration::from_millis(500), swarm.next())
                    .await
                    .ok()
                    .flatten()
                else {
                    continue;
                };
                if let SwarmEvent::ConnectionEstablished { peer_id, .. } = event {
                    swarm
                        .behaviour_mut()
                        .messages
                        .send_request(&peer_id, b"application traffic without PQ auth".to_vec());
                    let _ = attempted.send(());
                }
            }
        });
    })
}

#[test]
fn legacy_peer_without_pq_admission_is_failed_closed() {
    let identity = Identity::generate().expect("identity");
    let mut network = Network::start(&identity, local_config()).expect("network");
    let listener = wait_for_listener(&mut network);
    let target = format!("{listener}/p2p/{}", identity.peer_id())
        .parse::<Multiaddr>()
        .expect("target address");

    let (attempted_tx, attempted_rx) = mpsc::channel();
    let legacy = spawn_legacy_peer(target, attempted_tx);
    attempted_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("legacy peer did not establish a connection");

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut saw_failure = false;
    let mut saw_connected = false;
    let mut saw_identify = false;
    while Instant::now() < deadline {
        while let Some(state) = network.poll_event() {
            match state {
                ConnectionState::Connected { .. } => saw_connected = true,
                ConnectionState::Failed { reason, .. }
                    if reason.to_ascii_lowercase().contains("pq authentication") =>
                {
                    saw_failure = true;
                }
                _ => {}
            }
        }
        while network.poll_identify_event().is_some() {
            saw_identify = true;
        }
        if saw_failure {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    while network.poll_identify_event().is_some() {
        saw_identify = true;
    }

    assert!(
        saw_failure,
        "legacy peer was not failed closed by PQ admission"
    );
    assert!(!saw_connected, "legacy peer was reported as connected");
    assert!(
        !saw_identify,
        "identify observation was promoted without PQ admission"
    );
    assert!(
        network.poll_message_event().is_none(),
        "application traffic was delivered without PQ admission"
    );
    drop(network);
    let _ = legacy.join();
}

#[test]
fn identify_observation_is_released_only_after_pq_admission() {
    let alice_identity = Identity::generate().expect("alice identity");
    let bob_identity = Identity::generate().expect("bob identity");
    let mut alice = Network::start(&alice_identity, identify_config()).expect("alice network");
    let mut bob = Network::start(&bob_identity, identify_config()).expect("bob network");
    let bob_listener = wait_for_listener(&mut bob);
    let bob_peer = PeerId::from_str(&bob_identity.peer_id().to_string()).expect("bob PeerId");
    let bob_target = format!("{bob_listener}/p2p/{}", bob_identity.peer_id())
        .parse::<Multiaddr>()
        .expect("bob target address");
    alice.dial(bob_target).expect("dial queued");

    let deadline = Instant::now() + Duration::from_secs(8);
    let mut saw_connected = false;
    let mut leaked_before_admission = false;
    while Instant::now() < deadline {
        while let Some(state) = alice.poll_event() {
            if matches!(state, ConnectionState::Connected { .. }) {
                saw_connected = true;
            }
        }
        if saw_connected {
            break;
        }
        while let Some(event) = alice.poll_identify_event() {
            if matches!(event, IdentifyEvent::Identified { peer, .. } if peer == bob_peer) {
                leaked_before_admission = true;
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(saw_connected, "PQ admission never completed");
    assert!(
        !leaked_before_admission,
        "identify observation leaked before PQ admission"
    );

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut saw_identify = false;
    while Instant::now() < deadline {
        while let Some(event) = alice.poll_identify_event() {
            if matches!(event, IdentifyEvent::Identified { peer, .. } if peer == bob_peer) {
                saw_identify = true;
            }
        }
        if saw_identify {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        saw_identify,
        "identify observation was not released after PQ admission"
    );
    drop(alice);
    drop(bob);
}
