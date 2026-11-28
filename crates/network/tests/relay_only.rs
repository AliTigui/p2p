//! Relay-only route acceptance test with a real libp2p relay server.
//!
//! The two clients have no direct TCP listener. Their application traffic must
//! use a circuit through the explicitly configured relay, and the relay must
//! observe the actual source/destination of that circuit.

use std::str::FromStr;
use std::thread;
use std::time::{Duration, Instant};

use libp2p::{Multiaddr, PeerId, multiaddr::Protocol};
use p2p_identity::Identity;
use p2p_network::{ConnectionState, DialPolicy, Network, NetworkConfig, RelayEvent, RelayMode};

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

fn wait_relay_event<F>(network: &mut Network, predicate: F, timeout: Duration) -> bool
where
    F: Fn(&RelayEvent) -> bool,
{
    let deadline = Instant::now() + timeout;
    loop {
        while let Some(event) = network.poll_relay_event() {
            if predicate(&event) {
                return true;
            }
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn relay_only_config(relay: Multiaddr) -> NetworkConfig {
    NetworkConfig {
        dial_policy: DialPolicy::RelayOnly,
        relay_mode: RelayMode::Client,
        relay_servers: vec![relay],
        ..local_config()
    }
}

#[test]
fn relay_only_clients_have_no_direct_listener_and_use_a_real_circuit() {
    let relay_identity = Identity::generate().expect("relay identity");
    let alice_identity = Identity::generate().expect("alice identity");
    let bob_identity = Identity::generate().expect("bob identity");

    let mut relay = Network::start(
        &relay_identity,
        NetworkConfig {
            relay_mode: RelayMode::Server,
            ..local_config()
        },
    )
    .expect("relay network");
    let listening = |state: &ConnectionState| matches!(state, ConnectionState::Listening { addresses } if !addresses.is_empty());
    assert!(
        wait_until(&mut relay, listening, Duration::from_secs(10)),
        "relay never reported a listening address"
    );
    let relay_address = relay
        .listen_addresses()
        .into_iter()
        .next()
        .expect("relay listen address");
    let relay_address =
        Multiaddr::from_str(&format!("{relay_address}/p2p/{}", relay_identity.peer_id()))
            .expect("relay peer address");

    let mut alice = Network::start(&alice_identity, relay_only_config(relay_address.clone()))
        .expect("alice network");
    let mut bob = Network::start(&bob_identity, relay_only_config(relay_address.clone()))
        .expect("bob network");

    let relay_peer = PeerId::from_str(&relay_identity.peer_id().to_string()).expect("relay PeerId");
    let alice_peer = PeerId::from_str(&alice_identity.peer_id().to_string()).expect("alice PeerId");
    let bob_peer = PeerId::from_str(&bob_identity.peer_id().to_string()).expect("bob PeerId");

    assert!(
        wait_relay_event(
            &mut relay,
            |event| matches!(event, RelayEvent::ServerReservationAccepted { source } if *source == alice_peer || *source == bob_peer),
            Duration::from_secs(15)
        ),
        "relay server did not accept a reservation"
    );
    let reservation = |event: &RelayEvent| matches!(event, RelayEvent::ReservationAccepted { relay } if *relay == relay_peer);
    assert!(
        wait_relay_event(&mut alice, reservation, Duration::from_secs(15)),
        "alice did not obtain a relay reservation"
    );
    assert!(
        wait_relay_event(&mut bob, reservation, Duration::from_secs(15)),
        "bob did not obtain a relay reservation"
    );

    let circuit_listener = |state: &ConnectionState| match state {
        ConnectionState::Listening { addresses } => {
            !addresses.is_empty()
                && addresses.iter().all(|address| {
                    address
                        .iter()
                        .any(|protocol| matches!(protocol, Protocol::P2pCircuit))
                })
        }
        _ => false,
    };
    assert!(
        wait_until(&mut alice, circuit_listener, Duration::from_secs(10)),
        "alice never reported a circuit-only listener"
    );
    assert!(
        wait_until(&mut bob, circuit_listener, Duration::from_secs(10)),
        "bob never reported a circuit-only listener"
    );

    let direct_target = Multiaddr::from_str(&format!(
        "/ip4/127.0.0.1/tcp/9/p2p/{}",
        bob_identity.peer_id()
    ))
    .expect("direct target address");
    assert!(
        alice.dial(direct_target).is_err(),
        "relay-only policy must reject a direct application dial"
    );

    alice.dial_relayed(bob_peer).expect("relayed dial queued");

    let connected = |state: &ConnectionState| matches!(state, ConnectionState::Connected { peers } if peers.contains(&bob_peer));
    assert!(
        wait_until(&mut alice, connected, Duration::from_secs(15)),
        "alice never connected to bob"
    );
    assert!(
        wait_until(
            &mut bob,
            |state| matches!(state, ConnectionState::Connected { peers } if peers.contains(&alice_peer)),
            Duration::from_secs(15)
        ),
        "bob never connected to alice"
    );

    let circuit = |event: &RelayEvent| {
        matches!(
            event,
            RelayEvent::ServerCircuitAccepted { source, destination }
                if *source == alice_peer && *destination == bob_peer
        )
    };
    assert!(
        wait_relay_event(&mut relay, circuit, Duration::from_secs(15)),
        "relay did not observe the alice-to-bob circuit"
    );
    assert!(
        wait_relay_event(
            &mut bob,
            |event| matches!(event, RelayEvent::InboundCircuitEstablished { source } if *source == alice_peer),
            Duration::from_secs(15)
        ),
        "bob did not observe an inbound relayed connection"
    );
}
