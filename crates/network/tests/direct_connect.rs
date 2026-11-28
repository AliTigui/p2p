//! Direct-connect acceptance test: two independent processes/instances with
//! explicit addresses and no bootstrap, DHT, or relay configuration.

use std::str::FromStr;
use std::thread;
use std::time::{Duration, Instant};

use libp2p::Multiaddr;
use p2p_identity::Identity;
use p2p_network::{ConnectionState, Network, NetworkConfig};

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

#[test]
fn two_instances_connect_directly_with_zero_infrastructure() {
    let alice_identity = Identity::generate().expect("alice identity");
    let bob_identity = Identity::generate().expect("bob identity");
    let mut alice = Network::start(&alice_identity, local_config()).expect("alice network");
    let mut bob = Network::start(&bob_identity, local_config()).expect("bob network");

    let listening = |state: &ConnectionState| matches!(state, ConnectionState::Listening { addresses } if !addresses.is_empty());
    assert!(
        wait_until(&mut alice, listening, Duration::from_secs(5)),
        "alice never reported a listening address"
    );
    assert!(
        wait_until(&mut bob, listening, Duration::from_secs(5)),
        "bob never reported a listening address"
    );

    let bob_address = bob
        .listen_addresses()
        .into_iter()
        .next()
        .expect("bob listen address");
    let target = format!("{bob_address}/p2p/{}", bob_identity.peer_id());
    let target = Network::parse_address(&target).expect("valid target address");
    alice.dial(target).expect("dial queued");

    let connected = |state: &ConnectionState| matches!(state, ConnectionState::Connected { peers } if peers.len() == 1);
    assert!(
        wait_until(&mut alice, connected, Duration::from_secs(10)),
        "alice never observed an authenticated connection"
    );
    assert!(
        wait_until(&mut bob, connected, Duration::from_secs(10)),
        "bob never observed an authenticated connection"
    );

    match alice.state() {
        ConnectionState::Connected { peers } => {
            assert_eq!(peers[0].to_string(), bob_identity.peer_id().to_string());
        }
        other => panic!("expected connected state, got {other:?}"),
    }
    match bob.state() {
        ConnectionState::Connected { peers } => {
            assert_eq!(peers[0].to_string(), alice_identity.peer_id().to_string());
        }
        other => panic!("expected connected state, got {other:?}"),
    }

    alice.disconnect_all().expect("disconnect queued");
    let disconnected = |state: &ConnectionState| {
        !matches!(
            state,
            ConnectionState::Connected { .. } | ConnectionState::Connecting { .. }
        )
    };
    assert!(
        wait_until(&mut bob, disconnected, Duration::from_secs(10)),
        "bob did not observe the disconnect"
    );
}

#[test]
fn two_instances_connect_over_hybrid_key_exchange_quic() {
    let alice_identity = Identity::generate().expect("alice identity");
    let bob_identity = Identity::generate().expect("bob identity");
    let mut alice = Network::start(&alice_identity, local_config()).expect("alice network");
    let mut bob = Network::start(&bob_identity, local_config()).expect("bob network");

    let quic_listening = |state: &ConnectionState| matches!(state, ConnectionState::Listening { addresses } if addresses.iter().any(|address| address.to_string().contains("/quic-v1")));
    assert!(
        wait_until(&mut alice, quic_listening, Duration::from_secs(5)),
        "alice never reported a QUIC listener"
    );
    assert!(
        wait_until(&mut bob, quic_listening, Duration::from_secs(5)),
        "bob never reported a QUIC listener"
    );

    let bob_address = bob
        .listen_addresses()
        .into_iter()
        .find(|address| address.to_string().contains("/quic-v1"))
        .expect("bob QUIC listen address");
    let target = format!("{bob_address}/p2p/{}", bob_identity.peer_id());
    let target = Network::parse_address(&target).expect("valid QUIC target address");
    alice.dial(target).expect("QUIC dial queued");

    let alice_connected = |state: &ConnectionState| matches!(state, ConnectionState::Connected { peers } if peers.len() == 1);
    let bob_connected = |state: &ConnectionState| matches!(state, ConnectionState::Connected { peers } if peers.len() == 1);
    assert!(
        wait_until(&mut alice, alice_connected, Duration::from_secs(10)),
        "alice never completed the QUIC connection"
    );
    assert!(
        wait_until(&mut bob, bob_connected, Duration::from_secs(10)),
        "bob never completed the QUIC connection"
    );

    match alice.state() {
        ConnectionState::Connected { peers } => {
            assert_eq!(peers[0], bob_identity.peer_id());
        }
        other => panic!("expected connected state, got {other:?}"),
    }
    match bob.state() {
        ConnectionState::Connected { peers } => {
            assert_eq!(peers[0], alice_identity.peer_id());
        }
        other => panic!("expected connected state, got {other:?}"),
    }
}

#[test]
fn address_without_peer_id_is_rejected_before_dialing() {
    assert!(Network::parse_address("/ip4/127.0.0.1/tcp/4001").is_err());
}
