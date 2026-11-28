//! Milestone 6 resilience acceptance tests: duplicate dials, connection
//! admission limits, and per-peer application request budgets.

use std::io::Read;
use std::net::TcpStream;
use std::str::FromStr;
use std::thread;
use std::time::{Duration, Instant};

use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;
use p2p_identity::Identity;
use p2p_network::{
    ConnectionState, ControlEvent, MessageEvent, Network, NetworkConfig, NetworkError,
};

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

fn wait_control<F>(network: &mut Network, predicate: F, timeout: Duration) -> Option<ControlEvent>
where
    F: Fn(&ControlEvent) -> bool,
{
    let deadline = Instant::now() + timeout;
    loop {
        while let Some(event) = network.poll_control_event() {
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

fn start_listener(config: NetworkConfig) -> (Identity, Network) {
    let identity = Identity::generate().expect("identity");
    let network = Network::start(&identity, config).expect("network");
    (identity, network)
}

fn listening_address(network: &mut Network) -> Multiaddr {
    assert!(wait_until(
        network,
        |state| matches!(state, ConnectionState::Listening { addresses } if !addresses.is_empty()),
        Duration::from_secs(10),
    ));
    network
        .listen_addresses()
        .into_iter()
        .next()
        .expect("listen address")
}

fn target_for(address: Multiaddr, identity: &Identity) -> Multiaddr {
    Network::parse_address(&format!("{address}/p2p/{}", identity.peer_id())).expect("valid target")
}

#[test]
fn duplicate_dial_is_rejected_until_the_address_settles() {
    let (_, mut alice) = start_listener(local_config());
    let (bob_identity, mut bob) = start_listener(local_config());
    let target = target_for(listening_address(&mut bob), &bob_identity);

    alice.dial(target.clone()).expect("first dial queued");
    assert!(matches!(
        alice.dial(target.clone()),
        Err(NetworkError::DuplicateAddress)
    ));

    let connected = |state: &ConnectionState| matches!(state, ConnectionState::Connected { peers } if peers.len() == 1);
    assert!(wait_until(&mut alice, connected, Duration::from_secs(10)));

    // A settled address is cleared, so a later explicit reconnect is allowed.
    alice.dial(target).expect("reconnect dial queued");
}

#[test]
fn total_connection_limit_blocks_an_extra_peer() {
    let alice_config = NetworkConfig {
        max_total_connections: 1,
        max_connections_per_peer: 1,
        max_connections_per_ip: 4,
        ..local_config()
    };
    let (_, mut alice) = start_listener(alice_config);
    let (bob_identity, mut bob) = start_listener(local_config());
    let (carol_identity, mut carol) = start_listener(local_config());
    let bob_target = target_for(listening_address(&mut bob), &bob_identity);
    let carol_target = target_for(listening_address(&mut carol), &carol_identity);

    alice.dial(bob_target).expect("bob dial queued");
    assert!(wait_until(
        &mut alice,
        |state| state.connected_count() == 1,
        Duration::from_secs(10)
    ));

    // Dial the extra peer only after the first connection is authenticated.
    // This keeps the admission assertion deterministic instead of depending on
    // which of two simultaneous handshakes libp2p reports first under load.
    alice.dial(carol_target).expect("carol dial queued");
    thread::sleep(Duration::from_millis(300));
    while alice.poll_event().is_some() {}
    assert!(
        alice.state().connected_count() <= 1,
        "the extra authenticated connection must be closed"
    );
}

#[test]
fn per_peer_request_budget_drops_excess_requests() {
    let bob_config = NetworkConfig {
        rate_window: Duration::from_secs(10),
        max_requests_per_peer_per_window: 1,
        max_request_bytes_per_peer_per_window: 1024,
        ..local_config()
    };
    let (alice_identity, mut alice) = start_listener(local_config());
    let (bob_identity, mut bob) = start_listener(bob_config);
    let alice_swarm_peer =
        libp2p::PeerId::from_str(&alice_identity.peer_id().to_string()).expect("swarm peer id");
    let bob_swarm_peer =
        libp2p::PeerId::from_str(&bob_identity.peer_id().to_string()).expect("swarm peer id");

    alice
        .dial(target_for(listening_address(&mut bob), &bob_identity))
        .expect("dial queued");
    assert!(wait_until(
        &mut alice,
        |state| matches!(state, ConnectionState::Connected { peers } if peers.contains(&bob_swarm_peer)),
        Duration::from_secs(10)
    ));
    assert!(wait_until(
        &mut bob,
        |state| matches!(state, ConnectionState::Connected { peers } if peers.contains(&alice_swarm_peer)),
        Duration::from_secs(10)
    ));

    alice
        .send_message(bob_swarm_peer, b"first opaque request".to_vec())
        .expect("first request queued");
    let first = wait_message(
        &mut bob,
        |event| matches!(event, MessageEvent::RequestReceived { .. }),
        Duration::from_secs(5),
    )
    .expect("first request received");
    assert!(matches!(first, MessageEvent::RequestReceived { .. }));

    alice
        .send_message(bob_swarm_peer, b"second opaque request".to_vec())
        .expect("second request queued");
    let denied = wait_message(
        &mut bob,
        |event| {
            matches!(
                event,
                MessageEvent::Failed { reason, .. } if reason == "peer request rate limit exceeded"
            )
        },
        Duration::from_secs(5),
    )
    .expect("second request rejected by the rate limiter");
    assert!(matches!(denied, MessageEvent::Failed { .. }));
}

#[test]
fn saturated_control_traffic_does_not_block_messages() {
    let bob_config = NetworkConfig {
        rate_window: Duration::from_secs(10),
        max_requests_per_peer_per_window: 8,
        max_request_bytes_per_peer_per_window: 1024,
        ..local_config()
    };
    let (alice_identity, mut alice) = start_listener(local_config());
    let (bob_identity, mut bob) = start_listener(bob_config);
    let alice_swarm_peer =
        libp2p::PeerId::from_str(&alice_identity.peer_id().to_string()).expect("swarm peer id");
    let bob_swarm_peer =
        libp2p::PeerId::from_str(&bob_identity.peer_id().to_string()).expect("swarm peer id");

    alice
        .dial(target_for(listening_address(&mut bob), &bob_identity))
        .expect("dial queued");
    assert!(wait_until(
        &mut alice,
        |state| matches!(state, ConnectionState::Connected { peers } if peers.contains(&bob_swarm_peer)),
        Duration::from_secs(10)
    ));
    assert!(wait_until(
        &mut bob,
        |state| matches!(state, ConnectionState::Connected { peers } if peers.contains(&alice_swarm_peer)),
        Duration::from_secs(10)
    ));

    for index in 0..2 {
        alice
            .send_control(
                bob_swarm_peer,
                format!("opaque-control-{index}").into_bytes(),
            )
            .expect("control request queued");
        assert!(
            wait_control(
                &mut bob,
                |event| matches!(event, ControlEvent::RequestReceived { .. }),
                Duration::from_secs(5),
            )
            .is_some(),
            "control request {index} reached the receiver"
        );
    }

    alice
        .send_control(bob_swarm_peer, b"third opaque control".to_vec())
        .expect("saturating control request queued");
    assert!(
        wait_control(
            &mut bob,
            |event| {
                matches!(
                    event,
                    ControlEvent::Failed { reason, .. }
                        if reason == "peer request rate limit exceeded"
                )
            },
            Duration::from_secs(5),
        )
        .is_some(),
        "the control protocol's own share must be saturated"
    );

    alice
        .send_message(bob_swarm_peer, b"message after saturation".to_vec())
        .expect("message queued");
    assert!(
        wait_message(
            &mut bob,
            |event| matches!(event, MessageEvent::RequestReceived { .. }),
            Duration::from_secs(5),
        )
        .is_some(),
        "saturated control traffic must not consume the message share"
    );
}

#[test]
fn pending_incoming_limit_blocks_a_stalled_socket_before_noise() {
    let listener_config = NetworkConfig {
        max_pending_incoming_connections: 1,
        ..local_config()
    };
    let (listener_identity, mut listener) = start_listener(listener_config);
    let listen_address = listening_address(&mut listener);
    let port = listen_address
        .iter()
        .find_map(|protocol| match protocol {
            Protocol::Tcp(port) => Some(port),
            _ => None,
        })
        .expect("TCP listen port");

    // Hold one unauthenticated socket open so the listener's pending socket
    // budget is exhausted before any Noise handshake can begin.
    let stalled = TcpStream::connect(("127.0.0.1", port)).expect("stalled inbound socket");
    thread::sleep(Duration::from_millis(250));

    let (_, mut peer) = start_listener(local_config());
    let target = target_for(listen_address.clone(), &listener_identity);
    peer.dial(target.clone()).expect("dial queued");
    thread::sleep(Duration::from_millis(500));

    while peer.poll_event().is_some() {}
    assert_eq!(
        peer.state().connected_count(),
        0,
        "a dial must not complete while the pre-auth socket budget is full"
    );

    let listener_peer =
        libp2p::PeerId::from_str(&listener_identity.peer_id().to_string()).expect("listener peer");
    let saw_limit_failure = std::iter::from_fn(|| listener.poll_event()).any(|state| {
        matches!(
            state,
            ConnectionState::Failed { reason, .. } if reason.contains("connection limit exceeded")
        )
    });
    assert!(
        saw_limit_failure,
        "the listener must report transport-level connection-limit denial"
    );

    drop(stalled);
    thread::sleep(Duration::from_millis(100));
    peer.dial(target).expect("retry dial queued");
    assert!(wait_until(
        &mut peer,
        |state| matches!(state, ConnectionState::Connected { peers } if peers.contains(&listener_peer)),
        Duration::from_secs(10)
    ));
}

#[test]
fn pending_incoming_per_ip_limit_drops_extra_socket_before_noise() {
    let listener_config = NetworkConfig {
        max_connections_per_ip: 2,
        max_pending_incoming_connections: 16,
        ..local_config()
    };
    let (listener_identity, mut listener) = start_listener(listener_config);
    let listen_address = listening_address(&mut listener);
    let port = listen_address
        .iter()
        .find_map(|protocol| match protocol {
            Protocol::Tcp(port) => Some(port),
            _ => None,
        })
        .expect("TCP listen port");

    // Two raw sockets from the same IP occupy the per-IP pre-auth budget. They
    // never speak Noise, so they remain pending until dropped below.
    let mut held = Vec::new();
    for _ in 0..2 {
        held.push(TcpStream::connect(("127.0.0.1", port)).expect("stalled inbound socket"));
    }
    thread::sleep(Duration::from_millis(300));
    while listener.poll_event().is_some() {}

    // A third connection from the same IP must be closed by the transport
    // wrapper before any Noise handshake. A connect failure is also a denial;
    // a connected socket must reach EOF or reset promptly, not time out.
    let mut extra = TcpStream::connect(("127.0.0.1", port)).ok();
    if let Some(stream) = extra.as_mut() {
        stream
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("read timeout");
        let mut byte = [0u8; 1];
        match stream.read(&mut byte) {
            Ok(0) => {}
            Ok(_) => panic!("denied pre-auth socket unexpectedly produced data"),
            Err(error) => assert!(
                error.kind() != std::io::ErrorKind::WouldBlock
                    && error.kind() != std::io::ErrorKind::TimedOut,
                "third socket was admitted instead of being dropped before Noise: {error}"
            ),
        }
    }
    drop(extra);

    // Releasing one stalled socket frees exactly one slot, so a real peer can
    // complete Noise through the remaining slot.
    held.pop();
    thread::sleep(Duration::from_millis(150));
    let (_, mut peer) = start_listener(local_config());
    let target = target_for(listen_address, &listener_identity);
    peer.dial(target).expect("dial queued");
    assert!(wait_until(
        &mut peer,
        |state| state.connected_count() == 1,
        Duration::from_secs(10)
    ));

    drop(held);
}
