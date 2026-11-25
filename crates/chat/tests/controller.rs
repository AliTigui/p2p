//! Acceptance tests for the application-level MLS setup and message path.
//! Two controllers use only explicit loopback addresses; no discovery infra.

use std::fs;
use std::thread;
use std::time::{Duration, Instant};

use p2p_chat::{
    ChatError, ConversationStatus, DEFAULT_CHANNEL_ID, FileConfig, FileFormat, FileScanner,
    GroupOperation, MessageOrigin, MessengerController, QuarantineDeletionPolicy, RedialState,
    ReleaseApproval, ReleasePolicy, SETUP_VERSION, ScanRequest, ScanResult, ScanStatus,
    SecurityConfig, SetupEnvelope, SetupMessage, TransferDirection, TransferStatus, parse_address,
};
use p2p_identity::Identity;
use p2p_messaging::DeliveryState;
use p2p_network::{ConnectionState, NetworkConfig};
use p2p_storage::Vault;
use std::str::FromStr;

struct FixedScanner(ScanResult);

impl FileScanner for FixedScanner {
    fn scan(&self, _request: &ScanRequest<'_>) -> ScanResult {
        self.0
    }
}

fn local_config() -> NetworkConfig {
    NetworkConfig {
        listen_addr: libp2p::Multiaddr::from_str("/ip4/127.0.0.1/tcp/0").expect("valid multiaddr"),
        max_redial_attempts: 0,
        ..NetworkConfig::default()
    }
}

fn redial_config() -> NetworkConfig {
    NetworkConfig {
        max_redial_attempts: 2,
        redial_base_delay: Duration::from_millis(80),
        redial_max_delay: Duration::from_millis(200),
        ..local_config()
    }
}

fn wait_for<F>(label: &str, mut predicate: F, timeout: Duration)
where
    F: FnMut() -> bool,
{
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if predicate() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("{label} was not met before the timeout");
}

fn connected_controllers() -> (
    Identity,
    Identity,
    MessengerController,
    MessengerController,
    String,
) {
    connected_controllers_with_config(local_config())
}

fn connected_controllers_with_config(
    alice_config: NetworkConfig,
) -> (
    Identity,
    Identity,
    MessengerController,
    MessengerController,
    String,
) {
    let alice_identity = Identity::generate().expect("alice identity");
    let bob_identity = Identity::generate().expect("bob identity");
    let mut alice = MessengerController::start(&alice_identity, alice_config).expect("alice");
    let mut bob = MessengerController::start(&bob_identity, local_config()).expect("bob");
    let target = connect_controllers(&mut alice, &mut bob, &bob_identity);
    (alice_identity, bob_identity, alice, bob, target)
}

fn connect_controllers(
    alice: &mut MessengerController,
    bob: &mut MessengerController,
    bob_identity: &Identity,
) -> String {
    let listening = |state: &p2p_network::ConnectionState| matches!(state, p2p_network::ConnectionState::Listening { addresses } if !addresses.is_empty());
    wait_for(
        "alice listening",
        || {
            alice.poll();
            listening(alice.connection_state())
        },
        Duration::from_secs(10),
    );
    wait_for(
        "bob listening",
        || {
            bob.poll();
            listening(bob.connection_state())
        },
        Duration::from_secs(10),
    );

    let address = bob
        .listen_addresses()
        .into_iter()
        .next()
        .expect("bob listen address");
    let target = format!("{address}/p2p/{}", bob_identity.peer_id());
    alice
        .connect(parse_address(&target).expect("valid target"))
        .expect("dial queued");

    let connected = |state: &p2p_network::ConnectionState| matches!(state, p2p_network::ConnectionState::Connected { peers } if peers.len() == 1);
    wait_for(
        "alice connected",
        || {
            alice.poll();
            connected(alice.connection_state())
        },
        Duration::from_secs(10),
    );
    wait_for(
        "bob connected",
        || {
            bob.poll();
            connected(bob.connection_state())
        },
        Duration::from_secs(10),
    );
    target
}

fn wait_for_joined(alice: &mut MessengerController, bob: &mut MessengerController) {
    wait_for(
        "setup joined",
        || {
            alice.poll();
            bob.poll();
            let alice_ready = alice
                .active_info()
                .is_some_and(|info| info.status == ConversationStatus::Joined);
            let bob_ready = bob
                .active_info()
                .is_some_and(|info| info.status == ConversationStatus::Joined);
            alice_ready && bob_ready
        },
        Duration::from_secs(10),
    );
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty()
        || haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn hex_id(id: &[u8; 16]) -> String {
    id.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn every_file(directory: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    let Ok(entries) = fs::read_dir(directory) else {
        return files;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            files.extend(every_file(&path));
        } else {
            files.push(path);
        }
    }
    files
}

#[test]
fn mls_setup_exchange_and_text_delivery_work_end_to_end() {
    let (_alice_identity, bob_identity, mut alice, mut bob, _bob_target) = connected_controllers();

    let conversation_id = alice
        .start_conversation(bob_identity.peer_id())
        .expect("start MLS setup");
    assert_eq!(
        alice.active_info().expect("alice active").conversation_id,
        conversation_id
    );
    assert_eq!(
        alice.active_info().expect("alice active").status,
        ConversationStatus::KeyPackageRequested
    );

    wait_for(
        "setup joined",
        || {
            alice.poll();
            bob.poll();
            let alice_ready = alice
                .active_info()
                .is_some_and(|info| info.status == ConversationStatus::Joined);
            let bob_ready = bob
                .active_info()
                .is_some_and(|info| info.status == ConversationStatus::Joined);
            alice_ready && bob_ready
        },
        Duration::from_secs(10),
    );

    let alice_info = alice.active_info().expect("alice conversation");
    let bob_info = bob.active_info().expect("bob conversation");
    assert_eq!(alice_info.peer, bob_identity.peer_id());
    assert_eq!(bob_info.peer, _alice_identity.peer_id());
    assert_eq!(alice_info.conversation_id, bob_info.conversation_id);
    assert_eq!(alice_info.epoch, bob_info.epoch);

    let secret = "plaintext exists only after MLS decryption";
    let message_id = alice
        .send_text(bob_identity.peer_id(), secret)
        .expect("send text");

    wait_for(
        "message delivered",
        || {
            alice.poll();
            bob.poll();
            let alice_delivered = alice.active_messages().iter().any(|message| {
                message.message_id == message_id
                    && message.origin == MessageOrigin::Local
                    && message.delivery == Some(DeliveryState::Delivered)
            });
            let bob_received = bob
                .active_messages()
                .iter()
                .any(|message| message.origin == MessageOrigin::Remote && message.text == secret);
            alice_delivered && bob_received
        },
        Duration::from_secs(10),
    );

    let received = bob
        .active_messages()
        .into_iter()
        .find(|message| message.origin == MessageOrigin::Remote)
        .expect("received message");
    assert!(!format!("{received:?}").contains(secret));
    assert_eq!(alice.last_error(), None);
    assert_eq!(bob.last_error(), None);
}

#[test]
fn setup_requires_an_authenticated_connection() {
    let alice_identity = Identity::generate().expect("alice identity");
    let bob_identity = Identity::generate().expect("bob identity");
    let mut alice = MessengerController::start(&alice_identity, local_config()).expect("alice");

    assert!(matches!(
        alice.start_conversation(bob_identity.peer_id()),
        Err(p2p_chat::ChatError::PeerNotConnected)
    ));
    assert!(alice.active_info().is_none());
}

#[test]
fn offline_text_is_queued_and_retried_only_after_reconnect() {
    let (_alice_identity, bob_identity, mut alice, mut bob, bob_target) = connected_controllers();
    let bob_peer = bob_identity.peer_id();

    alice.start_conversation(bob_peer).expect("start MLS setup");
    wait_for_joined(&mut alice, &mut bob);

    alice.disconnect_all().expect("disconnect all");
    wait_for(
        "alice disconnected",
        || {
            alice.poll();
            matches!(
                alice.connection_state(),
                ConnectionState::Disconnected { .. }
            )
        },
        Duration::from_secs(10),
    );
    wait_for(
        "bob disconnected",
        || {
            bob.poll();
            matches!(bob.connection_state(), ConnectionState::Disconnected { .. })
        },
        Duration::from_secs(10),
    );

    let secret = "OFFLINE_QUEUE_SENTINEL_42";
    let message_id = alice
        .send_text(bob_peer, secret)
        .expect("queue offline text");
    let queued = alice
        .active_messages()
        .into_iter()
        .find(|message| message.message_id == message_id)
        .expect("queued local line");
    assert_eq!(queued.delivery, Some(DeliveryState::Queued));
    assert_eq!(alice.queued_count(&bob_peer), 1);

    // Polling while disconnected must not hand the envelope to the transport.
    for _ in 0..5 {
        alice.poll();
    }
    assert_eq!(alice.queued_count(&bob_peer), 1);
    assert!(
        alice
            .active_messages()
            .iter()
            .all(|message| message.delivery != Some(DeliveryState::SentToPeer))
    );
    assert!(
        bob.active_messages()
            .iter()
            .all(|message| message.text != secret)
    );

    alice
        .connect(parse_address(&bob_target).expect("valid reconnect address"))
        .expect("reconnect queued");
    wait_for(
        "alice reconnected",
        || {
            alice.poll();
            matches!(
                alice.connection_state(),
                ConnectionState::Connected { peers } if peers
                    .iter()
                    .any(|peer| peer.to_string() == bob_peer.to_string())
            )
        },
        Duration::from_secs(10),
    );

    // Bob is deliberately not polled yet: without a verified receipt Alice may
    // reach SentToPeer, but it must never claim Delivered.
    wait_for(
        "queued send handed to transport",
        || {
            alice.poll();
            alice.active_messages().iter().any(|message| {
                message.message_id == message_id
                    && message.delivery == Some(DeliveryState::SentToPeer)
            })
        },
        Duration::from_secs(10),
    );
    let sent = alice
        .active_messages()
        .into_iter()
        .find(|message| message.message_id == message_id)
        .expect("retried local line");
    assert_eq!(sent.delivery, Some(DeliveryState::SentToPeer));
    assert_ne!(sent.delivery, Some(DeliveryState::Delivered));
    assert_eq!(alice.queued_count(&bob_peer), 0);

    wait_for(
        "retried message delivered",
        || {
            alice.poll();
            bob.poll();
            let delivered = alice.active_messages().iter().any(|message| {
                message.message_id == message_id
                    && message.delivery == Some(DeliveryState::Delivered)
            });
            let received = bob
                .active_messages()
                .iter()
                .any(|message| message.origin == MessageOrigin::Remote && message.text == secret);
            delivered && received
        },
        Duration::from_secs(10),
    );
    assert_eq!(alice.last_error(), None);
    assert_eq!(bob.last_error(), None);
}

#[test]
fn queued_text_is_not_persisted_in_plaintext() {
    let (alice_identity, bob_identity, mut alice, mut bob, _bob_target) = connected_controllers();
    let bob_peer = bob_identity.peer_id();

    alice.start_conversation(bob_peer).expect("start MLS setup");
    wait_for_joined(&mut alice, &mut bob);

    let directory = tempfile::tempdir().expect("temp vault directory");
    let vault = Vault::open(directory.path()).expect("open vault");
    let _session = vault
        .create("offline-user", "offline-password", &alice_identity)
        .expect("create vault");

    alice.disconnect_all().expect("disconnect all");
    wait_for(
        "alice disconnected before queueing",
        || {
            alice.poll();
            matches!(
                alice.connection_state(),
                ConnectionState::Disconnected { .. }
            )
        },
        Duration::from_secs(10),
    );

    let secret = "PERSISTENCE_SENTINEL_77";
    alice
        .send_text(bob_peer, secret)
        .expect("queue offline text");
    assert_eq!(alice.queued_count(&bob_peer), 1);
    assert!(!format!("{alice:?}").contains(secret));

    for name in ["profile.db", "profile.db-wal", "profile.db-shm"] {
        let bytes = fs::read(directory.path().join(name)).unwrap_or_default();
        assert!(
            !contains(&bytes, secret.as_bytes()),
            "{name} contains queued plaintext"
        );
    }
}

#[test]
fn automatic_redial_is_bounded_and_reports_honest_state() {
    let alice_identity = Identity::generate().expect("alice identity");
    let bob_identity = Identity::generate().expect("bob identity");
    let mut alice =
        MessengerController::start(&alice_identity, redial_config()).expect("alice controller");
    let bob_peer = bob_identity.peer_id();

    wait_for(
        "alice listening before redial test",
        || {
            alice.poll();
            matches!(alice.connection_state(), ConnectionState::Listening { .. })
        },
        Duration::from_secs(10),
    );
    assert_eq!(alice.redial_state(&bob_peer), RedialState::NoSavedAddress);

    // Port 1 is a user-supplied address with no listener; every retry must
    // fail and the scheduler must stop at the configured limit.
    let unreachable = format!("/ip4/127.0.0.1/tcp/1/p2p/{bob_peer}");
    alice
        .connect(parse_address(&unreachable).expect("valid unreachable address"))
        .expect("initial dial queued");
    assert_eq!(alice.redial_peers().len(), 1);

    wait_for(
        "bounded redial reaches its limit",
        || {
            alice.poll();
            matches!(
                alice.redial_state(&bob_peer),
                RedialState::Exhausted { attempts: 2 }
            )
        },
        Duration::from_secs(10),
    );
    assert!(
        !matches!(alice.connection_state(), ConnectionState::Connected { .. }),
        "a failed dial must never become a connected claim"
    );
}

#[test]
fn user_disconnect_suppresses_redial_until_a_new_explicit_dial() {
    let (_alice_identity, bob_identity, mut alice, mut bob, bob_target) =
        connected_controllers_with_config(redial_config());
    let bob_peer = bob_identity.peer_id();
    assert_eq!(alice.redial_state(&bob_peer), RedialState::Idle);

    alice.disconnect_all().expect("user disconnect");
    wait_for(
        "alice disconnected",
        || {
            alice.poll();
            matches!(
                alice.connection_state(),
                ConnectionState::Disconnected { .. }
            )
        },
        Duration::from_secs(10),
    );
    assert_eq!(alice.redial_state(&bob_peer), RedialState::Suppressed);

    for _ in 0..20 {
        alice.poll();
        thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(alice.redial_state(&bob_peer), RedialState::Suppressed);
    assert!(!matches!(
        alice.connection_state(),
        ConnectionState::Connected { .. }
    ));

    alice
        .connect(parse_address(&bob_target).expect("valid reconnect address"))
        .expect("fresh explicit dial");
    wait_for(
        "explicit reconnect",
        || {
            alice.poll();
            bob.poll();
            matches!(alice.connection_state(), ConnectionState::Connected { .. })
        },
        Duration::from_secs(10),
    );
    assert_eq!(alice.redial_state(&bob_peer), RedialState::Idle);
}

#[test]
fn encrypted_file_transfer_verifies_integrity_without_claiming_a_scan() {
    let directory = tempfile::tempdir().expect("temp file directory");
    let source = directory.path().join("report.bin");
    let sentinel = b"FILE_TRANSFER_PLAINTEXT_SENTINEL_9182";
    let mut payload = vec![0x5au8; 300 * 1024];
    payload.extend_from_slice(sentinel);
    fs::write(&source, &payload).expect("source file");

    let alice_identity = Identity::generate().expect("alice identity");
    let bob_identity = Identity::generate().expect("bob identity");
    let file_config = FileConfig {
        quarantine_dir: directory.path().join("quarantine"),
        quarantine_deletion: QuarantineDeletionPolicy::Retain,
    };
    let mut alice = MessengerController::start_with_file_config(
        &alice_identity,
        local_config(),
        file_config.clone(),
    )
    .expect("alice controller");
    let mut bob =
        MessengerController::start_with_file_config(&bob_identity, local_config(), file_config)
            .expect("bob controller");
    connect_controllers(&mut alice, &mut bob, &bob_identity);

    let bob_peer = bob_identity.peer_id();
    alice.start_conversation(bob_peer).expect("start MLS setup");
    wait_for_joined(&mut alice, &mut bob);

    let transfer_id = alice.send_file(bob_peer, &source).expect("offer file");
    wait_for(
        "both sides reach integrity verified",
        || {
            alice.poll();
            bob.poll();
            let sender_done = alice.file_transfers().into_iter().any(|info| {
                info.transfer_id == transfer_id
                    && info.direction == TransferDirection::Outgoing
                    && info.status == TransferStatus::IntegrityVerified
            });
            let receiver_done = bob.file_transfers().into_iter().any(|info| {
                info.transfer_id == transfer_id
                    && info.direction == TransferDirection::Incoming
                    && info.status == TransferStatus::IntegrityVerified
            });
            sender_done && receiver_done
        },
        Duration::from_secs(20),
    );

    for info in alice
        .file_transfers()
        .into_iter()
        .chain(bob.file_transfers())
    {
        assert_eq!(info.scan, ScanStatus::Unavailable);
        assert!(info.status.completed());
        assert_eq!(info.chunks_done, info.chunks_total);
        assert_eq!(info.size, payload.len() as u64);
    }
    assert_eq!(alice.last_error(), None);
    assert_eq!(bob.last_error(), None);

    let mut quarantine = Vec::new();
    let transfer_dir = directory.path().join("quarantine").join(
        transfer_id
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    );
    for entry in fs::read_dir(&transfer_dir).expect("quarantine transfer directory") {
        let path = entry.expect("quarantine entry").path();
        if path.is_file() {
            quarantine.extend(fs::read(path).expect("quarantine file"));
        }
    }
    assert!(
        !contains(&quarantine, sentinel),
        "quarantine contains plaintext file content"
    );
    assert!(!format!("{alice:?}").contains(std::str::from_utf8(sentinel).expect("sentinel")));
    assert!(!format!("{bob:?}").contains(std::str::from_utf8(sentinel).expect("sentinel")));
}

#[test]
fn stalled_transfer_times_out_and_terminal_state_allows_a_new_transfer() {
    let directory = tempfile::tempdir().expect("temp file directory");
    let source = directory.path().join("stalled.txt");
    fs::write(&source, b"stalled transfer payload").expect("source file");
    let timeout = Duration::from_secs(2);
    let file_config = |name: &str| FileConfig {
        quarantine_dir: directory.path().join(name),
        quarantine_deletion: QuarantineDeletionPolicy::Retain,
    };

    let alice_identity = Identity::generate().expect("alice identity");
    let bob_identity = Identity::generate().expect("bob identity");
    let mut alice = MessengerController::start_with_transfer_timeout(
        &alice_identity,
        local_config(),
        file_config("alice-quarantine"),
        SecurityConfig::default(),
        timeout,
    )
    .expect("alice controller");
    let mut bob = MessengerController::start_with_transfer_timeout(
        &bob_identity,
        local_config(),
        file_config("bob-quarantine"),
        SecurityConfig::default(),
        timeout,
    )
    .expect("bob controller");
    let _target = connect_controllers(&mut alice, &mut bob, &bob_identity);
    let alice_peer = alice_identity.peer_id();
    let bob_peer = bob_identity.peer_id();
    alice.start_conversation(bob_peer).expect("start MLS setup");
    wait_for_joined(&mut alice, &mut bob);

    let transfer_id = alice.send_file(bob_peer, &source).expect("offer file");
    wait_for(
        "bob observes the active offer",
        || {
            bob.poll();
            bob.file_transfers()
                .into_iter()
                .any(|info| info.transfer_id == transfer_id && info.status.active())
        },
        Duration::from_secs(10),
    );
    assert!(bob.cancel_file(alice_peer).is_err());

    // Keep Bob's controller unpolled so no chunk acknowledgement is emitted.
    // Alice's transfer must still fail after its own inactivity deadline.
    wait_for(
        "sender times out without progress",
        || {
            alice.poll();
            alice.file_transfers().into_iter().any(|info| {
                info.transfer_id == transfer_id
                    && info.status == TransferStatus::Failed("Transfer timed out")
            })
        },
        Duration::from_secs(10),
    );
    assert_eq!(alice.pending_file_requests(), 0);

    wait_for(
        "receiver times out without progress",
        || {
            bob.poll();
            bob.file_transfers().into_iter().any(|info| {
                info.transfer_id == transfer_id
                    && info.status == TransferStatus::Failed("Transfer timed out")
            })
        },
        Duration::from_secs(10),
    );
    assert_eq!(bob.pending_file_requests(), 0);
    assert!(
        !directory
            .path()
            .join("bob-quarantine")
            .join(hex_id(&transfer_id))
            .exists()
    );

    let replacement = alice
        .send_file(bob_peer, &source)
        .expect("replacement offer");
    wait_for(
        "replacement transfer completes",
        || {
            alice.poll();
            bob.poll();
            let sender_done = alice.file_transfers().into_iter().any(|info| {
                info.transfer_id == replacement && info.status == TransferStatus::IntegrityVerified
            });
            let receiver_done = bob.file_transfers().into_iter().any(|info| {
                info.transfer_id == replacement && info.status == TransferStatus::IntegrityVerified
            });
            sender_done && receiver_done
        },
        Duration::from_secs(15),
    );
    assert!(bob.abort_file(alice_peer).is_err());
    bob.cancel_file(alice_peer)
        .expect("cancel completed release");
}

#[test]
fn configured_scanner_releases_only_after_validation_and_approval() {
    let directory = tempfile::tempdir().expect("temp file directory");
    let sentinel = b"CONTROLLER_RELEASE_PLAINTEXT_SENTINEL";
    let source = directory.path().join("report.txt");
    let cancel_source = directory.path().join("cancel.txt");
    fs::write(&source, sentinel).expect("source file");
    fs::write(&cancel_source, b"cancelled controller payload").expect("cancel source file");

    let alice_identity = Identity::generate().expect("alice identity");
    let bob_identity = Identity::generate().expect("bob identity");
    let file_config = FileConfig {
        quarantine_dir: directory.path().join("quarantine"),
        quarantine_deletion: QuarantineDeletionPolicy::Retain,
    };
    let security = SecurityConfig::default()
        .with_scanner(FixedScanner(ScanResult::CleanNoThreatDetected))
        .with_release_policy(ReleasePolicy::new(u64::MAX, vec!["txt".to_owned()]));

    let mut alice = MessengerController::start_with_security_config(
        &alice_identity,
        local_config(),
        file_config.clone(),
        SecurityConfig::default(),
    )
    .expect("alice controller");
    let mut bob = MessengerController::start_with_security_config(
        &bob_identity,
        local_config(),
        file_config,
        security,
    )
    .expect("bob controller");
    connect_controllers(&mut alice, &mut bob, &bob_identity);

    let alice_peer = alice_identity.peer_id();
    let bob_peer = bob_identity.peer_id();
    alice.start_conversation(bob_peer).expect("start MLS setup");
    wait_for_joined(&mut alice, &mut bob);

    let transfer_id = alice.send_file(bob_peer, &source).expect("offer file");
    wait_for(
        "both sides reach integrity verified",
        || {
            alice.poll();
            bob.poll();
            alice.file_transfers().into_iter().any(|info| {
                info.transfer_id == transfer_id && info.status == TransferStatus::IntegrityVerified
            }) && bob.file_transfers().into_iter().any(|info| {
                info.transfer_id == transfer_id && info.status == TransferStatus::IntegrityVerified
            })
        },
        Duration::from_secs(20),
    );

    assert_eq!(
        bob.scan_file(alice_peer)
            .expect("scan by configured scanner"),
        ScanStatus::CleanNoThreatDetected
    );
    let before_approval = bob
        .file_transfers()
        .into_iter()
        .find(|info| info.transfer_id == transfer_id)
        .expect("bob transfer info");
    assert_eq!(before_approval.approval, ReleaseApproval::Pending);
    assert_eq!(before_approval.format, Some(FileFormat::Text));
    assert!(bob.release_file(alice_peer).is_err());

    let released = bob
        .approve_and_release_file(alice_peer)
        .expect("approved in-memory release");
    assert_eq!(released.name(), "report.txt");
    assert_eq!(released.bytes(), sentinel.as_slice());
    assert!(!format!("{released:?}").contains(std::str::from_utf8(sentinel).expect("sentinel")));

    let bob_info = bob
        .file_transfers()
        .into_iter()
        .find(|info| info.transfer_id == transfer_id)
        .expect("bob transfer info");
    assert!(bob_info.released);
    assert_eq!(bob_info.scan, ScanStatus::CleanNoThreatDetected);
    assert_eq!(bob_info.approval, ReleaseApproval::Approved);
    let alice_info = alice
        .file_transfers()
        .into_iter()
        .find(|info| info.transfer_id == transfer_id)
        .expect("alice transfer info");
    assert!(!alice_info.released);
    assert_eq!(alice_info.scan, ScanStatus::Unavailable);
    assert_eq!(alice_info.approval, ReleaseApproval::NotApplicable);

    let cancel_transfer = alice
        .send_file(bob_peer, &cancel_source)
        .expect("offer cancel file");
    wait_for(
        "cancel transfer reaches integrity verified",
        || {
            alice.poll();
            bob.poll();
            bob.file_transfers().into_iter().any(|info| {
                info.transfer_id == cancel_transfer
                    && info.status == TransferStatus::IntegrityVerified
            })
        },
        Duration::from_secs(20),
    );
    assert_eq!(
        bob.scan_file(alice_peer).expect("scan cancel file"),
        ScanStatus::CleanNoThreatDetected
    );
    bob.cancel_file(alice_peer).expect("cancel release");
    let cancelled = bob
        .file_transfers()
        .into_iter()
        .find(|info| info.transfer_id == cancel_transfer)
        .expect("cancelled transfer info");
    assert_eq!(cancelled.approval, ReleaseApproval::Cancelled);
    assert!(!cancelled.released);
    assert!(bob.release_file(alice_peer).is_err());

    let transfer_dir = directory.path().join("quarantine").join(
        transfer_id
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    );
    let mut quarantine = Vec::new();
    for entry in fs::read_dir(transfer_dir).expect("quarantine transfer directory") {
        let path = entry.expect("quarantine entry").path();
        if path.is_file() {
            quarantine.extend(fs::read(path).expect("quarantine file"));
        }
    }
    assert!(
        !contains(&quarantine, sentinel),
        "quarantine contains plaintext file content after release"
    );
}

#[test]
fn released_file_is_stored_encrypted_and_quarantine_deleted_only_on_request() {
    let directory = tempfile::tempdir().expect("temp directory");
    let sentinel = b"ENCRYPTED_ATTACHMENT_STORE_SENTINEL_6142";
    let source = directory.path().join("attachment.txt");
    fs::write(&source, sentinel).expect("source file");

    let alice_identity = Identity::generate().expect("alice identity");
    let bob_identity = Identity::generate().expect("bob identity");
    let file_config = FileConfig {
        quarantine_dir: directory.path().join("quarantine"),
        quarantine_deletion: QuarantineDeletionPolicy::Explicit,
    };
    let security = SecurityConfig::default()
        .with_scanner(FixedScanner(ScanResult::CleanNoThreatDetected))
        .with_release_policy(ReleasePolicy::new(u64::MAX, vec!["txt".to_owned()]));

    let mut alice = MessengerController::start_with_security_config(
        &alice_identity,
        local_config(),
        file_config.clone(),
        SecurityConfig::default(),
    )
    .expect("alice controller");
    let mut bob = MessengerController::start_with_security_config(
        &bob_identity,
        local_config(),
        file_config,
        security,
    )
    .expect("bob controller");
    connect_controllers(&mut alice, &mut bob, &bob_identity);

    let alice_peer = alice_identity.peer_id();
    let bob_peer = bob_identity.peer_id();
    alice.start_conversation(bob_peer).expect("start MLS setup");
    wait_for_joined(&mut alice, &mut bob);

    let transfer_id = alice.send_file(bob_peer, &source).expect("offer file");
    wait_for(
        "attachment transfer reaches integrity verified",
        || {
            alice.poll();
            bob.poll();
            bob.file_transfers().into_iter().any(|info| {
                info.transfer_id == transfer_id && info.status == TransferStatus::IntegrityVerified
            })
        },
        Duration::from_secs(20),
    );
    assert_eq!(
        bob.scan_file(alice_peer).expect("scan attachment"),
        ScanStatus::CleanNoThreatDetected
    );
    let released = bob
        .approve_and_release_file(alice_peer)
        .expect("approved release");

    let vault = Vault::open(directory.path().join("vault")).expect("open vault");
    let session = vault
        .create("attachment-user", "attachment-password", &bob_identity)
        .expect("create vault");
    let attachment_id = session
        .store_attachment(
            released.name(),
            released.bytes(),
            released.plaintext_hash(),
            released.format_label(),
        )
        .expect("store encrypted attachment");
    let infos = session.attachment_infos().expect("attachment infos");
    assert_eq!(infos.len(), 1);
    assert_eq!(infos[0].id, attachment_id);
    assert_eq!(infos[0].name, "attachment.txt");
    assert_eq!(infos[0].size, sentinel.len() as u64);
    assert_eq!(infos[0].format.as_deref(), Some("TXT"));
    assert_eq!(
        session
            .read_attachment(&attachment_id)
            .expect("read encrypted attachment")
            .as_slice(),
        sentinel
    );

    let transfer_dir = directory.path().join("quarantine").join(
        transfer_id
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    );
    assert!(transfer_dir.is_dir());
    let before_delete = bob
        .file_transfers()
        .into_iter()
        .find(|info| info.transfer_id == transfer_id)
        .expect("transfer info");
    assert!(before_delete.released);
    assert!(!before_delete.quarantine_deleted);

    bob.delete_file_quarantine(alice_peer)
        .expect("explicit quarantine deletion");
    let after_delete = bob
        .file_transfers()
        .into_iter()
        .find(|info| info.transfer_id == transfer_id)
        .expect("transfer info after deletion");
    assert!(after_delete.quarantine_deleted);
    assert!(!transfer_dir.exists());
    assert!(bob.delete_file_quarantine(alice_peer).is_err());

    for path in every_file(&directory.path().join("vault")) {
        let bytes = fs::read(&path).expect("vault raw file");
        assert!(!contains(&bytes, sentinel), "vault blob contains plaintext");
        assert!(
            !contains(&bytes, b"attachment.txt"),
            "vault blob contains a plaintext filename"
        );
    }
    assert!(!format!("{released:?}").contains(std::str::from_utf8(sentinel).unwrap()));
}

struct Trio {
    alice_identity: Identity,
    bob_identity: Identity,
    charlie_identity: Identity,
    alice: MessengerController,
    bob: MessengerController,
    charlie: MessengerController,
    conversation_id: [u8; 16],
}

fn three_connected_controllers() -> Trio {
    let (alice_identity, bob_identity, mut alice, mut bob, _bob_target) = connected_controllers();
    let charlie_identity = Identity::generate().expect("charlie identity");
    let mut charlie =
        MessengerController::start(&charlie_identity, local_config()).expect("charlie");

    wait_for(
        "charlie listening",
        || {
            charlie.poll();
            matches!(
                charlie.connection_state(),
                ConnectionState::Listening { addresses } if !addresses.is_empty()
            )
        },
        Duration::from_secs(10),
    );
    let address = charlie
        .listen_addresses()
        .into_iter()
        .next()
        .expect("charlie listen address");
    let target = format!("{address}/p2p/{}", charlie_identity.peer_id());
    alice
        .connect(parse_address(&target).expect("valid charlie target"))
        .expect("charlie dial queued");
    wait_for(
        "alice connected to charlie",
        || {
            alice.poll();
            charlie.poll();
            matches!(
                alice.connection_state(),
                ConnectionState::Connected { peers } if peers.len() == 2
            ) && matches!(
                charlie.connection_state(),
                ConnectionState::Connected { peers } if peers.len() == 1
            )
        },
        Duration::from_secs(10),
    );

    let conversation_id = alice
        .start_conversation(bob_identity.peer_id())
        .expect("start MLS setup");
    wait_for_joined(&mut alice, &mut bob);

    Trio {
        alice_identity,
        bob_identity,
        charlie_identity,
        alice,
        bob,
        charlie,
        conversation_id,
    }
}

fn wait_for_add_completion(trio: &mut Trio) {
    let label = format!(
        "add operation acknowledged; alice={:?} bob={:?} charlie={:?} errors=({:?}, {:?}, {:?})",
        trio.alice.active_info(),
        trio.bob.active_info(),
        trio.charlie.active_info(),
        trio.alice.last_error(),
        trio.bob.last_error(),
        trio.charlie.last_error()
    );
    wait_for(
        &label,
        || {
            trio.alice.poll();
            trio.bob.poll();
            trio.charlie.poll();
            let alice = trio.alice.active_info();
            let bob = trio.bob.active_info();
            let charlie = trio.charlie.active_info();
            alice.as_ref().is_some_and(|info| {
                info.pending_operation.is_none()
                    && info.members.len() == 3
                    && info.epoch == bob.as_ref().map_or(0, |info| info.epoch)
                    && info.epoch == charlie.as_ref().map_or(0, |info| info.epoch)
            }) && bob.as_ref().is_some_and(|info| {
                info.pending_operation.is_none()
                    && info.members.len() == 3
                    && info.status == ConversationStatus::Joined
            }) && charlie.as_ref().is_some_and(|info| {
                info.pending_operation.is_none()
                    && info.members.len() == 3
                    && info.status == ConversationStatus::Joined
            })
        },
        Duration::from_secs(15),
    );
    assert_eq!(trio.alice.last_error(), None);
    assert_eq!(trio.bob.last_error(), None);
    assert_eq!(trio.charlie.last_error(), None);
}

fn add_charlie(trio: &mut Trio) {
    trio.alice
        .add_member(trio.conversation_id, trio.charlie_identity.peer_id())
        .expect("admin adds charlie");
    wait_for_add_completion(trio);
}

#[test]
fn admin_adds_member_and_group_text_waits_for_every_receipt() {
    let mut trio = three_connected_controllers();
    let alice_peer = trio.alice_identity.peer_id();
    let bob_peer = trio.bob_identity.peer_id();
    let charlie_peer = trio.charlie_identity.peer_id();

    assert!(matches!(
        trio.bob.remove_member(trio.conversation_id, charlie_peer),
        Err(ChatError::NotAdmin)
    ));
    trio.alice
        .add_member(trio.conversation_id, charlie_peer)
        .expect("admin starts add");
    wait_for_add_completion(&mut trio);

    for info in [
        trio.alice.active_info().expect("alice active"),
        trio.bob.active_info().expect("bob active"),
        trio.charlie.active_info().expect("charlie active"),
    ] {
        assert_eq!(info.admin, alice_peer);
        assert_eq!(info.members.len(), 3);
        assert_eq!(info.pending_operation, None);
    }

    let secret = "MLS text reaches both group members";
    let message_id = trio
        .alice
        .send_text(bob_peer, secret)
        .expect("broadcast text");
    wait_for(
        "broadcast delivered after all receipts",
        || {
            trio.alice.poll();
            trio.bob.poll();
            trio.charlie.poll();
            let alice_delivered = trio.alice.active_messages().iter().any(|message| {
                message.message_id == message_id
                    && message.origin == MessageOrigin::Local
                    && message.delivery == Some(DeliveryState::Delivered)
            });
            let bob_received =
                trio.bob.active_messages().iter().any(|message| {
                    message.origin == MessageOrigin::Remote && message.text == secret
                });
            let charlie_received =
                trio.charlie.active_messages().iter().any(|message| {
                    message.origin == MessageOrigin::Remote && message.text == secret
                });
            alice_delivered && bob_received && charlie_received
        },
        Duration::from_secs(15),
    );
    assert_eq!(trio.alice.last_error(), None);
    assert_eq!(trio.bob.last_error(), None);
    assert_eq!(trio.charlie.last_error(), None);
}

#[test]
fn admin_removes_member_and_removed_member_cannot_read_new_epoch() {
    let mut trio = three_connected_controllers();
    add_charlie(&mut trio);

    let bob_peer = trio.bob_identity.peer_id();
    let charlie_peer = trio.charlie_identity.peer_id();
    let old_epoch = trio
        .charlie
        .active_info()
        .expect("charlie before removal")
        .epoch;

    trio.alice
        .remove_member(trio.conversation_id, charlie_peer)
        .expect("admin removes charlie");
    assert_eq!(
        trio.alice
            .active_info()
            .expect("alice active")
            .pending_operation,
        Some(GroupOperation::Remove)
    );
    wait_for(
        "remove operation acknowledged",
        || {
            trio.alice.poll();
            trio.bob.poll();
            trio.charlie.poll();
            let alice = trio.alice.active_info();
            let bob = trio.bob.active_info();
            alice.as_ref().is_some_and(|info| {
                info.pending_operation.is_none()
                    && info.epoch > old_epoch
                    && !info.members.contains(&charlie_peer)
            }) && bob.as_ref().is_some_and(|info| {
                info.pending_operation.is_none()
                    && info.epoch == alice.as_ref().map_or(0, |info| info.epoch)
                    && !info.members.contains(&charlie_peer)
            })
        },
        Duration::from_secs(15),
    );

    assert_eq!(
        trio.charlie
            .active_info()
            .expect("charlie after removal")
            .epoch,
        old_epoch,
        "removed member must stay on the excluded epoch"
    );

    let fresh = "plaintext for remaining members only";
    trio.alice
        .send_text(bob_peer, fresh)
        .expect("send after removal");
    wait_for(
        "remaining member receives new-epoch text",
        || {
            trio.alice.poll();
            trio.bob.poll();
            trio.charlie.poll();
            trio.bob
                .active_messages()
                .iter()
                .any(|message| message.origin == MessageOrigin::Remote && message.text == fresh)
        },
        Duration::from_secs(10),
    );

    let stale = "plaintext from the excluded epoch";
    trio.charlie
        .send_text(bob_peer, stale)
        .expect("removed member can only compose on its old epoch");
    for _ in 0..50 {
        trio.alice.poll();
        trio.bob.poll();
        trio.charlie.poll();
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        !trio
            .bob
            .active_messages()
            .iter()
            .any(|message| message.text == stale),
        "old-epoch ciphertext must not decrypt in the new epoch"
    );
}

#[test]
fn admin_key_update_is_acknowledged_by_every_member() {
    let mut trio = three_connected_controllers();
    add_charlie(&mut trio);

    let before = trio.alice.active_info().expect("alice before update").epoch;
    trio.alice
        .update_member_key(trio.conversation_id)
        .expect("admin starts key update");
    assert_eq!(
        trio.alice
            .active_info()
            .expect("alice active")
            .pending_operation,
        Some(GroupOperation::Update)
    );
    wait_for(
        "update operation acknowledged",
        || {
            trio.alice.poll();
            trio.bob.poll();
            trio.charlie.poll();
            let alice = trio.alice.active_info();
            alice.as_ref().is_some_and(|info| {
                info.pending_operation.is_none()
                    && info.epoch == before + 1
                    && info.members.len() == 3
            }) && [&trio.bob, &trio.charlie].iter().all(|controller| {
                controller.active_info().is_some_and(|info| {
                    info.pending_operation.is_none()
                        && info.epoch == before + 1
                        && info.members.len() == 3
                        && info.status == ConversationStatus::Joined
                })
            })
        },
        Duration::from_secs(15),
    );
    assert_eq!(trio.alice.last_error(), None);
    assert_eq!(trio.bob.last_error(), None);
    assert_eq!(trio.charlie.last_error(), None);
}

#[test]
fn non_admin_cannot_start_group_operations() {
    let mut trio = three_connected_controllers();
    let charlie_peer = trio.charlie_identity.peer_id();

    // `add_member` requires a direct connection to the candidate, so this
    // denial is checked with operations that have no extra transport precondition.
    assert!(matches!(
        trio.bob.remove_member(trio.conversation_id, charlie_peer),
        Err(ChatError::NotAdmin)
    ));
    assert!(matches!(
        trio.bob.update_member_key(trio.conversation_id),
        Err(ChatError::NotAdmin)
    ));
}

#[test]
fn channels_are_logical_partitions_inside_one_mls_group() {
    let (alice_identity, bob_identity, mut alice, mut bob, _bob_target) = connected_controllers();
    let alice_peer = alice_identity.peer_id();
    let bob_peer = bob_identity.peer_id();

    alice.start_conversation(bob_peer).expect("start MLS setup");
    wait_for_joined(&mut alice, &mut bob);

    let conversation_id = alice.active_info().expect("alice active").conversation_id;
    for controller in [&alice, &bob] {
        let info = controller.active_info().expect("joined info");
        assert_eq!(info.channels.len(), 1);
        assert_eq!(info.channels[0].channel_id, DEFAULT_CHANNEL_ID);
        assert_eq!(info.channels[0].name, "general");
        assert_eq!(info.active_channel, Some(DEFAULT_CHANNEL_ID));
    }

    let channel_id = alice
        .create_channel(conversation_id, "ops", vec![alice_peer, bob_peer])
        .expect("admin creates channel");
    assert_ne!(channel_id, DEFAULT_CHANNEL_ID);

    wait_for(
        "bob receives signed channel metadata",
        || {
            alice.poll();
            bob.poll();
            bob.active_info().is_some_and(|info| {
                info.channels.iter().any(|channel| {
                    channel.channel_id == channel_id
                        && channel.name == "ops"
                        && channel.revision == 1
                        && channel.members.len() == 2
                })
            })
        },
        Duration::from_secs(10),
    );
    wait_for(
        "channel policy receipt is acknowledged",
        || {
            alice.poll();
            bob.poll();
            alice
                .active_info()
                .and_then(|info| {
                    info.channels
                        .into_iter()
                        .find(|channel| channel.channel_id == channel_id)
                })
                .is_some_and(|channel| channel.acknowledged)
        },
        Duration::from_secs(10),
    );

    alice
        .select_channel(conversation_id, channel_id)
        .expect("alice selects ops");
    bob.select_channel(conversation_id, channel_id)
        .expect("bob selects ops");
    assert_eq!(
        alice.active_info().unwrap().active_channel,
        Some(channel_id)
    );
    assert_eq!(bob.active_info().unwrap().active_channel, Some(channel_id));

    let secret = "channel-only plaintext";
    let message_id = alice
        .send_channel_text(bob_peer, channel_id, secret)
        .expect("send channel text");
    wait_for(
        "channel text delivered and decrypted",
        || {
            alice.poll();
            bob.poll();
            let delivered = alice.active_messages().iter().any(|message| {
                message.message_id == message_id
                    && message.channel_id == channel_id
                    && message.delivery == Some(DeliveryState::Delivered)
            });
            let received = bob.active_messages().iter().any(|message| {
                message.channel_id == channel_id
                    && message.origin == MessageOrigin::Remote
                    && message.text == secret
            });
            delivered && received
        },
        Duration::from_secs(10),
    );

    alice
        .select_channel(conversation_id, DEFAULT_CHANNEL_ID)
        .expect("return to general");
    assert!(
        alice
            .active_messages()
            .iter()
            .all(|message| message.channel_id == DEFAULT_CHANNEL_ID && message.text != secret)
    );
    assert_eq!(alice.last_error(), None);
    assert_eq!(bob.last_error(), None);
}

#[test]
fn channel_policy_is_admin_only_and_membership_is_enforced() {
    let (alice_identity, bob_identity, mut alice, mut bob, _bob_target) = connected_controllers();
    let alice_peer = alice_identity.peer_id();
    let bob_peer = bob_identity.peer_id();

    alice.start_conversation(bob_peer).expect("start MLS setup");
    wait_for_joined(&mut alice, &mut bob);
    let conversation_id = alice.active_info().expect("alice active").conversation_id;

    assert!(matches!(
        bob.create_channel(conversation_id, "ops", vec![bob_peer]),
        Err(ChatError::NotAdmin)
    ));
    assert!(matches!(
        bob.rename_channel(conversation_id, DEFAULT_CHANNEL_ID, "ops"),
        Err(ChatError::NotAdmin)
    ));
    assert!(matches!(
        bob.set_channel_members(conversation_id, DEFAULT_CHANNEL_ID, vec![bob_peer]),
        Err(ChatError::NotAdmin)
    ));

    let channel_id = alice
        .create_channel(conversation_id, "ops", vec![alice_peer, bob_peer])
        .expect("admin creates channel");
    wait_for(
        "bob sees channel before policy change",
        || {
            alice.poll();
            bob.poll();
            bob.active_info().is_some_and(|info| {
                info.channels
                    .iter()
                    .any(|channel| channel.channel_id == channel_id)
            })
        },
        Duration::from_secs(10),
    );

    alice
        .set_channel_members(conversation_id, channel_id, vec![alice_peer])
        .expect("admin restricts channel");
    wait_for(
        "bob sees restricted channel",
        || {
            alice.poll();
            bob.poll();
            bob.active_info().is_some_and(|info| {
                info.channels.iter().any(|channel| {
                    channel.channel_id == channel_id
                        && channel.revision == 2
                        && channel.members == vec![alice_peer]
                })
            })
        },
        Duration::from_secs(10),
    );

    assert!(matches!(
        bob.send_channel_text(alice_peer, channel_id, "blocked local"),
        Err(ChatError::NotChannelMember)
    ));
    assert!(matches!(
        alice.send_channel_text(bob_peer, channel_id, "blocked peer"),
        Err(ChatError::NotChannelMember)
    ));
    assert!(matches!(
        alice.select_channel(conversation_id, [1; 16]),
        Err(ChatError::ChannelNotFound)
    ));

    alice
        .set_channel_members(conversation_id, channel_id, vec![alice_peer, bob_peer])
        .expect("admin restores channel membership");
    wait_for(
        "bob sees restored channel",
        || {
            alice.poll();
            bob.poll();
            bob.active_info().is_some_and(|info| {
                info.channels.iter().any(|channel| {
                    channel.channel_id == channel_id
                        && channel.revision == 3
                        && channel.members.len() == 2
                })
            })
        },
        Duration::from_secs(10),
    );
    alice
        .select_channel(conversation_id, channel_id)
        .expect("alice selects ops");
    bob.select_channel(conversation_id, channel_id)
        .expect("bob selects ops");

    let message_id = alice
        .send_channel_text(bob_peer, channel_id, "allowed now")
        .expect("send after restore");
    wait_for(
        "restored channel delivers text",
        || {
            alice.poll();
            bob.poll();
            alice.active_messages().iter().any(|message| {
                message.message_id == message_id
                    && message.delivery == Some(DeliveryState::Delivered)
            }) && bob
                .active_messages()
                .iter()
                .any(|message| message.text == "allowed now")
        },
        Duration::from_secs(10),
    );
    assert_eq!(alice.last_error(), None);
    assert_eq!(bob.last_error(), None);
}

#[test]
fn restricted_channel_text_reaches_only_allowed_members() {
    let mut trio = three_connected_controllers();
    add_charlie(&mut trio);
    let conversation_id = trio.conversation_id;
    let alice_peer = trio.alice_identity.peer_id();
    let bob_peer = trio.bob_identity.peer_id();

    let channel_id = trio
        .alice
        .create_channel(conversation_id, "ops", vec![alice_peer, bob_peer])
        .expect("admin creates restricted channel");
    let metadata_label = format!(
        "all members see channel metadata; alice={:?} bob={:?} charlie={:?} errors=({:?}, {:?}, {:?})",
        trio.alice.active_info(),
        trio.bob.active_info(),
        trio.charlie.active_info(),
        trio.alice.last_error(),
        trio.bob.last_error(),
        trio.charlie.last_error()
    );
    wait_for(
        &metadata_label,
        || {
            trio.alice.poll();
            trio.bob.poll();
            trio.charlie.poll();
            [&trio.alice, &trio.bob, &trio.charlie]
                .iter()
                .all(|controller| {
                    controller.active_info().is_some_and(|info| {
                        info.channels.iter().any(|channel| {
                            channel.channel_id == channel_id
                                && channel.members.len() == 2
                                && channel.members.contains(&alice_peer)
                                && channel.members.contains(&bob_peer)
                        })
                    })
                })
        },
        Duration::from_secs(15),
    );

    trio.alice
        .select_channel(conversation_id, channel_id)
        .expect("alice selects ops");
    trio.bob
        .select_channel(conversation_id, channel_id)
        .expect("bob selects ops");
    trio.charlie
        .select_channel(conversation_id, channel_id)
        .expect("charlie can view the channel entry");

    let secret = "restricted channel plaintext";
    let message_id = trio
        .alice
        .send_channel_text(bob_peer, channel_id, secret)
        .expect("send to allowed member only");
    wait_for(
        "allowed member receives restricted channel text",
        || {
            trio.alice.poll();
            trio.bob.poll();
            trio.charlie.poll();
            let delivered = trio.alice.active_messages().iter().any(|message| {
                message.message_id == message_id
                    && message.channel_id == channel_id
                    && message.delivery == Some(DeliveryState::Delivered)
            });
            let bob_received = trio.bob.active_messages().iter().any(|message| {
                message.channel_id == channel_id
                    && message.origin == MessageOrigin::Remote
                    && message.text == secret
            });
            delivered && bob_received
        },
        Duration::from_secs(15),
    );

    for _ in 0..30 {
        trio.alice.poll();
        trio.bob.poll();
        trio.charlie.poll();
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        trio.charlie
            .active_messages()
            .iter()
            .all(|message| message.text != secret),
        "excluded member must not receive channel ciphertext"
    );
    assert_eq!(trio.alice.last_error(), None);
    assert_eq!(trio.bob.last_error(), None);
    assert_eq!(trio.charlie.last_error(), None);
}

#[test]
fn setup_frames_carry_and_sign_transaction_ids_and_reject_v1() {
    let identity = Identity::generate().expect("identity");
    let conversation_id = [7u8; 16];
    let transaction_id = [8u8; 16];
    let envelope = SetupEnvelope::new(
        &identity,
        SetupMessage::WelcomeAck {
            conversation_id,
            transaction_id,
            accepted: true,
        },
    )
    .expect("signed ack");
    let mut bytes = envelope.to_bytes().expect("encoded ack");

    assert_eq!(&bytes[..4], b"MLS1");
    assert_eq!(&bytes[4..6], &SETUP_VERSION.to_le_bytes());
    assert_eq!(&bytes[6..22], &transaction_id);

    let decoded = SetupEnvelope::from_bytes(&bytes).expect("decoded ack");
    decoded
        .verify(&identity.peer_id())
        .expect("valid signature");

    bytes[6] ^= 1;
    let tampered = SetupEnvelope::from_bytes(&bytes).expect("decoded tampered ack");
    assert!(matches!(
        tampered.verify(&identity.peer_id()),
        Err(ChatError::InvalidSetup(_))
    ));

    bytes[6] ^= 1;
    bytes[4..6].copy_from_slice(&1u16.to_le_bytes());
    let legacy = SetupEnvelope::from_bytes(&bytes).expect_err("version 1 is rejected");
    assert!(legacy.to_string().contains("version 1"));
}
