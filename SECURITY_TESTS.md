# Security Test Execution

This document explains how to execute the security-relevant tests that exist in the repository and records exact local results. All results in this document are local-only; no CI, release, commit, push, PR, review, merge, user/manual, or external verification claim is made. The authoritative milestone records are in `PROJECT_STATUS.md` and `SECURITY_MILESTONE_REPORTS.md`, with test-suite history in `tests/README.md`.

## 1. Baseline locked verification

Run from the repository root:

```bash
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets
cargo test --locked --workspace -- --test-threads=1
cargo clippy --locked --workspace --all-targets -- -D warnings
```

Feature builds:

```bash
cargo check --locked -p p2p-desktop --features gui
cargo clippy --locked -p p2p-desktop --features gui --all-targets -- -D warnings
cargo check --locked -p p2p-desktop --features native
cargo clippy --locked -p p2p-desktop --features native --all-targets -- -D warnings
cargo build --locked -p p2p-desktop --features native
```

Diagnostic guard:

```bash
python3 scripts/check_diagnostics.py
```

Targeted channel-isolation primitive:

```bash
cargo +1.100.0 test -p p2p-groups --test channel_isolation --locked
cargo +1.100.0 test -p p2p-groups --test channel_group_lifecycle --locked
cargo +1.100.0 test -p p2p-chat --lib --locked
```

The first command is the adversarial proof for the P1a primitive; the second proves the P1b bound lifecycle API; the third covers P1c channel-scope round trips, tampering/substitution rejection, controller scope binding, excluded-parent-member rejection, the P1d controller tests for injected ciphertext, derived-group receipts, and rejection of non-default text on the parent group, and the P1e restart tests for bound receipts, queued ciphertext, tampered/incomplete records, and lifecycle deletion. These tests prove cryptographic exclusion and authenticated channel-group restore for non-default controller text, not parent policy metadata confidentiality. P1f adds GUI model tests for default parent-group status, derived readiness, derived setup state, and absence of a complete-ACL claim; the post-v3 GUI-feature run passed **22 tests, 0 failures**, and the exact command and result are recorded in the final local gate table below.

Targeted P2/P3/P4 adversarial gates:

```bash
cargo +1.100.0 test -p p2p-identity --locked -- --test-threads=1
cargo +1.100.0 test -p p2p-messaging -p p2p-files --locked -- --test-threads=1
cargo +1.100.0 test -p p2p-chat --lib --locked -- --test-threads=1
cargo +1.100.0 test -p p2p-storage --locked -- --test-threads=1
cargo +1.100.0 test -p p2p-crypto --locked -- --test-threads=1
```

The identity run covers wrong-role/expired/revoked/substituted-proof rejection and certified role-key extraction. The messaging/files runs cover role-domain rejection at the envelope, setup, and file layers plus transport-signature reuse rejection. The chat run covers channel-bound durable acks and parent/channel ack separation. The storage run covers the dedicated MLS HKDF purpose, legacy key-version migration, fail-closed unknown versions, full control-log fail-closed behavior, and anchor-first crash recovery. Exact counts and results are recorded in `PROJECT_STATUS.md`.

Targeted P5–P13 adversarial gates:

```bash
cargo +1.100.0 test -p p2p-network --lib --locked -- --test-threads=1
cargo +1.100.0 test -p p2p-identity --lib --locked -- --test-threads=1
cargo +1.100.0 test -p p2p-chat --lib --locked -- --test-threads=1
cargo +1.100.0 test -p p2p-groups --lib --locked -- --test-threads=1
cargo +1.100.0 test -p p2p-messaging --lib --locked -- --test-threads=1
cargo +1.100.0 test -p p2p-identity --test identity_flow --locked -- --test-threads=1
cargo +1.100.0 test -p p2p-desktop --features gui --locked -- --test-threads=1
```

These cover P5 fail-closed `TorRequired`, P6 delegation conflicts/expiry/wrong-role/redacted `Debug`, P7 outbound/inbound relay-policy symmetry and native-picker copy, P8 queue-full rejection before composing, the historical pre-v3 P9 classical-only OpenMLS and P10 clear-metadata evidence (superseded locally by the hybrid suite and v3 wire below), P11 independent devices plus portable bundle restore, and P13 oversized requests on every protocol. P12 uses the separate audit/deny/fuzz/SBOM commands in sections 5 and 6. The serialized workspace run is the authoritative aggregate gate; its post-v3 result is recorded in the final local gate table below.

### Q3/Q4 targeted adversarial gates (post-v3, local, uncommitted)

```bash
cargo +1.100.0 test -p p2p-messaging -p p2p-groups --offline -- --test-threads=1
cargo +1.100.0 test -p p2p-chat --lib --offline -- --test-threads=1
cargo +1.100.0 test -p p2p-chat --test controller --offline -- --test-threads=1
cargo +1.100.0 test -p p2p-desktop --features gui --offline -- --test-threads=1
```

Messaging (`v3` wire): `v3_wire_has_no_stable_sender_or_message_metadata`, `v3_mac_rejects_body_nonce_route_tag_and_version_tampering`, `v3_inner_frame_round_trips_and_rejects_tampering`, `every_v3_prefix_is_rejected_without_panics`, `v3_inner_replay_and_sequence_regression_are_rejected_after_decryption`, `v3_outgoing_sequence_is_consumed_only_after_a_successful_compose`. Groups: `pinned_openmls_advertises_the_enabled_hybrid_ciphersuite`, `hybrid_key_packages_and_welcomes_round_trip`, `v3_round_trip_hides_stable_metadata_from_third_parties`, `v3_rejects_tampering_wrong_route_legacy_wire_and_foreign_groups`, `v3_replay_and_sequence_regression_fail_after_decryption`, `v3_route_tag_and_exporter_keys_are_epoch_bound`. `signed_envelope_exposes_transferable_authorship_and_clear_metadata` is retained only as the historical v2 compatibility test; production rejects v1/v2 application envelopes. Chat/controller tests cover v3 queued frames/receipts and restore-sequence consistency; GUI tests cover 30 status rows and honest hybrid/v3/deniability/proxy wording.

These gates exercise the EnvelopeV3 route tag, nonce, wrapped MLS body, and HMAC-SHA256 tag; stable metadata inside the MLS-protected inner frame; the additional XChaCha20-Poly1305 wrap under a purpose-separated exporter key; the local-only epoch-bound route tag `SHA-256(domain separator, group ID, epoch)` with fail-closed zero/ambiguous route and `BadRouteTag` on mismatch; and setup v4 signed ciphersuite ID (bytes 6..8), transaction ID (bytes 8..24), and `/p2p-messenger/mls-setup/2`, rejecting legacy versions 1–3 and unknown suites. Q4 is bounded wire-level deniability, not delegated application keys: no third-party-verifiable long-term-key authorship proof, but group members with MLS state can still attribute. The hybrid suite `MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519` (`0x004F`) is enabled via the pinned OpenMLS draft feature; `0x004D` is unsupported and signatures/Noise remain classical, so no full-PQ or custom-primitive claim is made. Targeted results are recorded in `SECURITY_MILESTONE_REPORTS.md`; final post-v3 aggregate workspace/GUI/audit/deny/fuzz/SBOM results are recorded in the final local gate table below and in `PROJECT_STATUS.md`.

Fuzz targets:

```bash
cargo check --manifest-path fuzz/Cargo.toml
cargo clippy --manifest-path fuzz/Cargo.toml --all-targets -- -D warnings
cd fuzz
cargo fuzz build
for target in fuzz_envelope fuzz_v3_envelope fuzz_setup fuzz_file fuzz_channel fuzz_identity_export fuzz_contact_uri; do
  cargo fuzz run "$target" -- -max_total_time=30 -max_len=8192 -timeout=5 -rss_limit_mb=2048
done
```

## 2. Test categories

| Category | Command / location | Properties covered |
|---|---|---|
| Unit security tests | `cargo test --locked --workspace -- --test-threads=1` | Bounded codecs, signatures, key derivation, redacted `Debug`, redacted local paths, static untrusted-field errors, scanner policy, privacy defaults |
| Envelope replay | `cargo test --locked -p p2p-messaging` | Duplicate IDs, sequence regression, conversation/epoch mismatch, tampered signature, deterministic bit-flip and truncation smoke tests |
| MLS group isolation | `cargo test --locked -p p2p-groups` | 1:1 and three-member setup, Add/Remove/Update, epoch exclusion, stale-epoch rejection |
| Channel-group primitive | `cargo test --locked -p p2p-groups --test channel_isolation` | Domain-separated ID derivation; excluded parent member cannot decrypt captured ciphertext; locally created same-ID group is not an oracle; channel update does not grant parent access |
| Bound channel lifecycle | `cargo test --locked -p p2p-groups --test channel_group_lifecycle` | Explicit parent/channel binding; wrong-parent and wrong-channel KeyPackage/Welcome rejection; Add/Update/Remove commits; wrong-sender commit rejection; parent ciphertext rejection |
| Setup/group control | `cargo test --locked -p p2p-chat` | Signed `MLS1` frames, peer/sender binding, acknowledgement state, strict parsers, signed v4 transaction/ciphersuite binding with legacy-version rejection, stale/cross-transaction rejection, bounded 512-entry digest cache, exact request/response replay suppression, durable control-log rejection of exact authenticated terminal replays after restart, idempotent request retry after restart (two controller restart regressions) |
| Channel policy and routing | `cargo test --locked -p p2p-chat` | Bounded `CHN1` frames, admin-only policy changes, revision checks, parent policy receipts, readiness-gated non-default text, derived-group ciphertext/receipts, exclusion of non-members, and rejection of misplaced frames |
| Direct network | `cargo test --locked -p p2p-network` | Zero-bootstrap loopback connect, PeerId authentication, duplicate dial rejection, public `dial` circuit rejection before queueing, address validation |
| Network resilience | `cargo test --locked -p p2p-network` | Pre-authentication global and per-IP socket caps, stalled-socket and extra-per-IP rejection before Noise, established connection caps, aggregate and per-protocol request/byte budgets, denied-request non-charging, expired rate-limiter entry cleanup, malformed/oversized frame handling, peerless-failure state preservation |
| Relay policy | `cargo test --locked -p p2p-network` | Inbound relayed file requests emit only a policy failure, no pending response or `RequestReceived` |
| Privacy honesty | `cargo test --locked -p p2p-network` and `cargo test --locked -p p2p-desktop --features gui` | No fabricated AutoNAT confidence, cumulative observations labelled since startup, live relayed-connection count distinct |
| File security | `cargo test --locked -p p2p-files` | Fresh keys, AEAD chunks, manifest verification, quarantine ciphertext-only, cancellation/release gates, abort clears partial state and quarantine |
| File lifetime | `cargo test --locked -p p2p-chat --test controller` | Inactivity timeout, late-frame rejection, pending-request cleanup, terminal-state replacement transfer, cancellation only after verification |
| Scanner policy | `cargo test --locked -p p2p-security` | Exact status categories, no-scanner `Unavailable`, default deny, narrow format validation |
| Storage security | `cargo test --locked -p p2p-storage` | Wrong password, password change, DB/WAL/SHM plaintext scans, symlink refusal on Unix, schema v4 `control_log`/`control_state`, durable idempotent requests and non-repeatable terminal frames across reopen, chain/blind-index/anchor verification on unlock, older-DB-with-current-anchor rollback detection, anchor bit-flip detection, full-log fail-closed behavior, and dedicated/legacy MLS key-version handling |
| GUI model | `cargo test --locked -p p2p-desktop --features gui` | Honest status rows, address validation, no fake connection state |
| Diagnostic guard | `python3 scripts/check_diagnostics.py` | Unmarked raw output macros, derived `Debug` on protected types, secret-named types/fields, self-tests for fail-closed behavior |
| Fuzz smoke | `cargo fuzz run` in `fuzz/` and `cargo clippy --manifest-path fuzz/Cargo.toml` | Canonical legacy/v3 codec decoding, signature/MAC verification, redacted `Debug`, canonical re-encoding, hostile identity export and contact text |
| SBOM generation | `python3 scripts/generate_sbom.py` | Locked package graph, SPDX identifiers, license normalization, relative paths, dangling-relationship rejection, byte-identical regeneration |

## 3. Adversarial tests to preserve

When modifying a codec or state machine, add a test for each applicable case:

- wrong magic, unknown version, truncated field, trailing bytes, oversized field, invalid UTF-8, duplicate/empty member sets;
- tampered signature, wrong expected PeerId, wrong public key, cross-conversation substitution, stale epoch;
- captured restricted-channel ciphertext injected into an excluded parent member, a locally created group with the same derived channel ID, post-update channel ciphertext, an allowed controller whose receipt must use the derived group, and non-default text injected into the parent group;
- duplicate request with a different transaction ID, exact signed-frame replay, stale acknowledgement, out-of-order operations;
- durable control-log cases: an exact authenticated terminal frame must not be re-applied after restart, while an idempotent `KeyPackageRequest`/`GroupJoinRequest` retry must stay idempotent after restart;
- older database restored while keeping the current anchor and anchor bit flip must fail unlock (both tested); a missing anchor after a nonempty log and a broken chain (non-contiguous sequence or mismatched `chain_hash`, blind index, or record AEAD) must fail `verify_control_log` — these are source-backed fail-closed checks, but no dedicated missing-anchor or broken-chain test is recorded in the original 207-test run or its later reruns;
- replayed message after reload where a load path exists;
- file chunk tampering, missing manifest, oversized file, unsupported/mismatched format, scanner failure, no scanner;
- invalid bootstrap/relay address, `/p2p-circuit` in a direct address, missing `/p2p/<peer-id>` suffix;
- stalled raw socket before Noise, zero/oversized connection-limit configuration, and advisory peerless failures that must not erase live connections;
- local directory paths in `Debug`, unknown untrusted query fields reflected into errors, and any new stdout/stderr/diagnostic path that could print passwords, private keys, plaintext, or opaque frames; the diagnostic guard must reject unmarked raw output macros, derived `Debug` on protected types, and secret-named fields;
- a saturated protocol bucket that must not consume another protocol's reserved capacity, and a per-protocol denial that must not charge the aggregate request budget;
- saturated control/setup/file traffic that must not consume the message reservation, a per-protocol denial that must not charge the aggregate budget, and an aggregate ceiling that must still apply;
- relay observation injection that must not create a contact, verified peer, capability, receipt, or delivery claim;
- arbitrary bytes reaching the legacy envelope, production v3 outer/inner envelope, setup, file, channel, identity-export, and contact/fingerprint parsers without panic, with successfully parsed frames re-encoding canonically.

## 4. Network privacy tests

Local tests cover codec bounds, configuration defaults, address validation, status snapshots, direct loopback transport, relay-only policy, MLS padding, and SOCKS5 route behavior. Q1 adds adversarial validation of relay-only conflicts, circuit address shape/destination, direct-dial rejection, queued relayed dials, and observed-path application gating; `crates/network/tests/relay_only.rs` starts a real local relay and proves circuit-only listeners, reservations, a relay-observed circuit, and relayed alice/bob connectivity. Q2 adds MLS padding boundary and hostile-padding tests. Q5 adds SOCKS5 target conversion, unsupported-target failure, no-listener/no-direct-dial proofs, and a fake-proxy test proving that `example.onion` reaches the proxy as a domain CONNECT target rather than through a local lookup.

The following require external hardware, a real proxy/Tor service, or a controlled volunteer relay and are therefore documented as pending, not claimed:

1. Two machines on the same LAN using manual addresses and optional mDNS.
2. Two machines behind separate NATs with a user-operated relay and optional AutoNAT/DCUtR.
3. A three-node relay harness that records raw relay-side bytes, searches for signed Offer/file-key sentinels, and attempts ciphertext tampering.
4. Packet capture proving no direct TCP fallback against a real proxy/Tor service; the local proof is a fake proxy plus source-level transport selection and no-listener tests.
5. DNS, IPv6, and relay-reservation leak tests with a real SOCKS5/Tor proxy; proxy identity and reachability remain unverified.

## 5. Fuzz smoke tests

`fuzz/` contains seven real libFuzzer targets: legacy `P2P1` envelopes, production `P2P3` v3 envelopes and inner frames, `MLS1` setup and group-control frames, `CHN1` channel frames, signed file frames, encrypted identity envelopes, and contact URI/fingerprint text. The security workflow builds them with nightly `cargo-fuzz` and runs each for a bounded 30 seconds. Locally, all seven binaries also completed plain-libFuzzer 1000-input smoke runs without crashes; those local runs were not coverage-instrumented, so they do not constitute a long campaign.

A dependency-free deterministic smoke test still flips one bit at every offset of a signed legacy v2 `P2P1` envelope and asserts that any successfully parsed mutation fails signature verification; it also asserts that every truncated prefix is rejected. A v3-specific unit test rejects every truncated prefix of an `EnvelopeV3`, and the new `fuzz_v3_envelope` target parses arbitrary v3 outer and inner bytes and checks canonical re-encoding. These are regression/smoke guards, not proof of parser correctness.

Not covered by these targets: internal transport codec state machines, backup/vault import formats (no such formats exist yet), and a long sanitizer-enabled corpus-building campaign. Treat fuzzing as a bounded smoke control; historical CI was green for earlier baselines, but it is not evidence for this uncommitted work, and a longer coverage-guided campaign is still required before making a broader fuzzing claim.

## 6. Dependency and supply-chain checks

Install the tools outside the repository, then run:

```bash
cargo audit --file Cargo.lock
cargo deny --locked --manifest-path Cargo.toml check
cargo audit --file fuzz/Cargo.lock
cargo deny --locked --manifest-path fuzz/Cargo.toml check
```

`deny.toml` defines advisory, license, bans, and source policy. A `security.yml` workflow runs these gates on pushes and pull requests. Locally installed `cargo-audit 0.23.0` and `cargo-deny 0.22.1` execute the same checks. After aligning `deny.toml` with cargo-deny 0.22, declaring the fuzz workspace license, moving to libp2p 0.57.1/libp2p-request-response 0.30.0, moving to the OpenMLS 0.10.0-rc.1 provider stack, and adding the pinned SOCKS5/tokio-util dependencies with refreshed root/fuzz lockfiles, **all four local commands pass**: `cargo audit` reports zero vulnerabilities with five non-failing unmaintained warnings, and `cargo deny` ends with `advisories ok, bans ok, licenses ok, sources ok` for both lockfiles. The unmaintained warnings are `paste`, `proc-macro-error2`, `zbus_names`, `zvariant`, and `zvariant_derive`; they remain documented residual risk. GitHub Security gates run `45690333396` passed all four jobs on 2026-11-25.

### Workflow action pinning

All external GitHub Actions used by `ci.yml`, `build.yml`, and `security.yml` are pinned to 40-character commit SHAs resolved from GitHub API refs on 2026-11-25. The inline comment records the source tag or branch; `dtolnay/rust-toolchain` uses branch heads, so those pins freeze `stable` and `nightly` at the recorded commits.

| Action | Pinned commit | Source ref |
|---|---|---|
| `actions/checkout` | `11d5960a326750d5838078e36cf38b85af677262` | `v4` tag |
| `dtolnay/rust-toolchain` | `39008827e6b4319a349e9a42dfc90579dd25f1ca` | `stable` branch |
| `dtolnay/rust-toolchain` | `6a52aad76a94a5fbc50d567bb5be24419801c1fb` | `nightly` branch |
| `Swatinem/rust-cache` | `d1527c8f67ef9af357290475d4af4b0fab8f12e0` | annotated `v2` tag, dereferenced to commit |
| `actions/upload-artifact` | `ea165f8d65b6e75b540449e92b4886f43607fa02` | `v4` tag |
| `actions/download-artifact` | `d3f86a106a0bac45b974a628896c90dbdf5c8093` | `v4` tag |
| `softprops/action-gh-release` | `3bb12739c298aeb8a4eeaf626c5b8d85266b0e65` | `v2` tag |

A SHA pin freezes the action revision used by a run; it does not review the action code, verify signatures or provenance, or establish reproducible builds. The green audit/deny CI gate verifies the configured checks, not action-code trust.

SBOM generation and determinism:

```bash
python3 scripts/generate_sbom.py \
  --manifest-path Cargo.toml \
  --workspace-name root \
  --output /tmp/root.spdx.json

python3 scripts/generate_sbom.py \
  --manifest-path fuzz/Cargo.toml \
  --workspace-name fuzz \
  --output /tmp/fuzz.spdx.json
```

Run each command twice and compare outputs with `cmp`. The generator's fail-closed self-tests, relationship validation, absolute-path rejection, and license normalization run before Cargo is invoked. See `docs/SBOM.md` for scope limits.

Release verification:

```bash
cargo build --locked --release -p p2p-desktop --features native
bash packaging/linux/package.sh target/x86_64-unknown-linux-gnu/release/p2p-desktop 0.1.0 x86_64 dist
cd dist && sha256sum -c SHA256SUMS
```

Checksum sidecars use bare filenames; verification must run from `dist/`. Checksums prove artifact consistency with the release channel, not developer identity. The GitHub release job generates `sbom-root.spdx.json` and `sbom-fuzz.spdx.json` in `dist/` before building `SHA256SUMS`; the local `packaging/linux/package.sh` command above does not generate SBOMs by itself.

## 7. Commands that must not be represented as security evidence

- `cargo build` alone does not prove a security property.
- A passing unit test does not prove an end-to-end network, anonymity, or deployment property.
- A GUI status row derived from local configuration is not a connection, verification, delivery, or safety claim.
- Structural file validation is not malware detection.
- Absence of a plaintext sentinel in one database snapshot is not proof for every platform or future schema.
- Absence of local detection after restoring the entire vault directory including `control.anchor` is not evidence of rollback resistance; it only shows that no external anchor exists. An external anchor would be an optional, future, user-controlled design, not a current control.

## 8. Final post-v3 local gates (2026-11-27, uncommitted)

All commands below were run locally from the repository root with Rust 1.100.0 and `--offline` where supported. They are evidence for the exact final uncommitted source state only; no CI, release, commit, push, PR, review, merge, user/manual, external, two-machine, visual-GUI, or production-readiness claim follows.

| Gate | Command | Final post-v3 result |
|---|---|---|
| Formatting | `cargo +1.100.0 fmt --all -- --check`; `cargo +1.100.0 fmt --manifest-path fuzz/Cargo.toml -- --check` | Passed. |
| Diff hygiene | `git diff --check` | Passed. |
| Diagnostics | `python3 scripts/check_diagnostics.py` | Passed; **65 Rust sources** checked, including the new v3 fuzz target. |
| Workspace check | `cargo +1.100.0 check --locked --offline --workspace --all-targets` | Passed. |
| Workspace clippy | `cargo +1.100.0 clippy --locked --offline --workspace --all-targets -- -D warnings` | Passed; two pre-existing advisory manifest warnings remain non-fatal (`p2p-core` in `p2p-crypto`, `zeroize` in `p2p-security`). |
| Workspace tests | `cargo +1.100.0 test --workspace --locked --offline -- --test-threads=1` | **369 passed, 0 failed** across 26 test suites; 11 doc-test suites and 0 doc-tests. Breakdown: chat 86 (66 unit + 20 integration), core 4, crypto 8, desktop 19, files 20, groups 27 (9 unit + 6 lifecycle + 3 isolation + 9 MLS integration), identity 61 (58 unit + 3 integration), messaging 26 (23 unit + 3 integration), network 58 (46 unit + 12 integration), security 11, storage 49 (12 unit + 28 vault + 9 provider integration). |
| GUI feature | `cargo +1.100.0 check --locked --offline -p p2p-desktop --features gui`, matching clippy, and `cargo +1.100.0 test --locked --offline -p p2p-desktop --features gui -- --test-threads=1` | Passed; **22 tests, 0 failures**. No visual inspection is claimed. |
| Native feature | `cargo +1.100.0 check --locked --offline -p p2p-desktop --features native`, matching clippy, and `cargo +1.100.0 build --locked --offline -p p2p-desktop --features native` | Passed; no visual inspection or release claim. |
| Fuzz locked build | `cargo +1.100.0 check/clippy --locked --offline --manifest-path fuzz/Cargo.toml --all-targets -- -D warnings` and `cargo +1.100.0 build --locked --offline --release --manifest-path fuzz/Cargo.toml --bins` | Passed. |
| Fuzz smoke | Seven release fuzz binaries, 1000 plain-libFuzzer inputs each | `fuzz_envelope`, `fuzz_v3_envelope`, `fuzz_setup`, `fuzz_file`, `fuzz_channel`, `fuzz_identity_export`, and `fuzz_contact_uri` each completed `Done 1000 runs` without crashes; not coverage-instrumented and not a long campaign. |
| Root advisories | `cargo audit --file Cargo.lock`; `cargo deny --locked --manifest-path Cargo.toml check` | Zero vulnerabilities across 713 crates with five allowed unmaintained warnings; `advisories ok, bans ok, licenses ok, sources ok`. |
| Fuzz advisories | `cargo audit --file fuzz/Cargo.lock`; `cargo deny --locked --manifest-path fuzz/Cargo.toml check` | Zero vulnerabilities across 489 crates with two allowed unmaintained warnings; `advisories ok, bans ok, licenses ok, sources ok`. |
| SBOM | Two `python3 scripts/generate_sbom.py` runs per graph, compared with `cmp` | Root and fuzz documents regenerated byte-for-byte: 489 packages/1633 relationships and 489 packages/1604 relationships. Root lock SHA-256 `fb658b439b66e58aa24a6c7a84dabc3aa635e7cae9c8880dabbbb2c29da1e353`; fuzz lock SHA-256 `a65a47cc41aa3ab99a28ae612ca03f26888f52e0c8954783d4efd39e3fca9c36`. |

Historical CI run IDs and 207/257/285/339/358-test workspace results remain historical baselines and are not evidence for this uncommitted workstream. No result in this table establishes availability, anonymity, full rollback resistance, distributed-flood capacity, signed release identity, reproducibility, or production readiness.

## 9. Historical pre-v3 recorded local gates (2026-11-27)

These are local-only, **historical pre-v3** results for the then-final uncommitted P0–P14 code state plus the Q1/Q2/Q5 privacy follow-up. They do not claim CI, release, commit, push, PR, review, merge, user/manual, external, two-machine, visual-GUI, or production verification. Historical 207/257/285/339-test results remain in `PROJECT_STATUS.md` and are not evidence for the SOCKS5, relay-only, or padding changes. Documentation-only reconciliation after those gates changed no Rust source or lockfile; `git diff --check` was re-run and passed, so the recorded code/build/test results remain valid for that code state. These counts are **not** the current post-v3 results: the Q3/Q4 wire, hybrid ciphersuite, and setup v4 changes came afterwards. They are superseded by the final post-v3 local gate table above; no CI, release, or external verification follows from either table.

| Gate | Command | Result |
|---|---|---|
| Format | `cargo +1.100.0 fmt --all -- --check` | Passed. |
| Diff hygiene | `git diff --check` | Passed. |
| Diagnostics | `python3 scripts/check_diagnostics.py` | Passed; 64 Rust sources checked. |
| Workspace check | `cargo +1.100.0 check --locked --workspace --all-targets` | Passed. |
| Workspace clippy | `cargo +1.100.0 clippy --locked --workspace --all-targets -- -D warnings` | Passed; two pre-existing advisory manifest warnings remain non-fatal (`p2p-core` in `p2p-crypto`, `zeroize` in `p2p-security`). |
| Workspace tests | `cargo +1.100.0 test --workspace --locked -- --test-threads=1` | Historical pre-v3: **358 passed, 0 failed** across 37 suites, 0 doc-tests: chat 86 (66 unit + 20 integration), core 4, crypto 8, desktop 19, files 20, groups 22 (4 unit + 6 lifecycle + 3 isolation + 9 MLS integration), identity 61 (58 unit + 3 integration), messaging 20 (17 unit + 3 integration), network 58 (46 unit + 12 integration), security 11, storage 49 (12 unit + 28 vault + 9 provider integration). |
| GUI feature | `cargo +1.100.0 check --locked -p p2p-desktop --features gui`, matching clippy, and `cargo +1.100.0 test -p p2p-desktop --features gui --locked -- --test-threads=1` | Historical pre-v3: passed; **22 tests, 0 failures**. |
| Native feature | `cargo +1.100.0 check --locked -p p2p-desktop --features native`, matching clippy, and `cargo +1.100.0 build --locked -p p2p-desktop --features native` | Passed; no visual inspection claimed. |
| Fuzz locked build | `cargo +1.100.0 check/clippy --locked --manifest-path fuzz/Cargo.toml --all-targets` and `cargo +1.100.0 build --release --locked --manifest-path fuzz/Cargo.toml --bins` | Passed. |
| Fuzz smoke | Six release fuzz binaries, 1000 plain-libFuzzer inputs each | All six completed without crashes; not coverage-instrumented and not a long campaign. |
| Root advisories | `cargo audit --file Cargo.lock`; `cargo deny --locked --manifest-path Cargo.toml check` | Zero vulnerabilities with five allowed unmaintained warnings; `advisories ok, bans ok, licenses ok, sources ok`. |
| Fuzz advisories | `cargo audit --file fuzz/Cargo.lock`; `cargo deny --locked --manifest-path fuzz/Cargo.toml check` | Zero vulnerabilities with two allowed unmaintained warnings; `advisories ok, bans ok, licenses ok, sources ok` after the SOCKS5 dependency and lock refresh. |
| SBOM | Two `python3 scripts/generate_sbom.py` runs per graph, compared with `cmp` | Root and fuzz documents regenerated byte-for-byte, 480 packages each; root lock SHA-256 `03e4451bab061e6c08950669c66a91ffbc0d368fb27691d10cc654132bf90ba0`, fuzz lock SHA-256 `fc1c7a4e7f644e06686cf6d0cff1437985219062034bc581aba71e5ccf3312fb`. |

The workspace and GUI test runs recorded in this section are historical pre-v3 results, authoritative only for that code state; targeted commands above are retained for diagnosis. Current post-v3 aggregate results are recorded in the final local gate table above. No result in this document establishes availability, anonymity, full rollback resistance, distributed-flood capacity, signed release identity, reproducibility, or production readiness.
