//! Milestone 6 resilience acceptance tests: duplicate dials, connection
//! admission limits, and per-peer application request budgets.

use std::str::FromStr;
use std::thread;
use std::time::{Duration, Instant};

use libp2p::Multiaddr;
use p2p_identity::Identity;
use p2p_network::{ConnectionState, MessageEvent, Network, NetworkConfig, NetworkError};

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

    alice
        .dial(target_for(listening_address(&mut bob), &bob_identity))
        .expect("bob dial queued");
    alice
        .dial(target_for(listening_address(&mut carol), &carol_identity))
        .expect("carol dial queued");

    assert!(wait_until(
        &mut alice,
        |state| state.connected_count() >= 1,
        Duration::from_secs(10)
    ));
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
