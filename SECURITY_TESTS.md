# Security Test Execution

This document explains how to execute the security-relevant tests that exist in the repository. It does not claim that any command has passed in this document; exact results are recorded in `PROJECT_STATUS.md` and `tests/README.md` after each verified run.

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

Fuzz targets:

```bash
cargo check --manifest-path fuzz/Cargo.toml
cargo clippy --manifest-path fuzz/Cargo.toml --all-targets -- -D warnings
cd fuzz
cargo fuzz build
for target in fuzz_envelope fuzz_setup fuzz_file fuzz_channel fuzz_identity_export fuzz_contact_uri; do
  cargo fuzz run "$target" -- -max_total_time=30 -max_len=8192 -timeout=5 -rss_limit_mb=2048
done
```

## 2. Test categories

| Category | Command / location | Properties covered |
|---|---|---|
| Unit security tests | `cargo test --locked --workspace -- --test-threads=1` | Bounded codecs, signatures, key derivation, redacted `Debug`, redacted local paths, static untrusted-field errors, scanner policy, privacy defaults |
| Envelope replay | `cargo test --locked -p p2p-messaging` | Duplicate IDs, sequence regression, conversation/epoch mismatch, tampered signature, deterministic bit-flip and truncation smoke tests |
| MLS group isolation | `cargo test --locked -p p2p-groups` | 1:1 and three-member setup, Add/Remove/Update, epoch exclusion, stale-epoch rejection |
| Setup/group control | `cargo test --locked -p p2p-chat` | Signed `MLS1` frames, peer/sender binding, acknowledgement state, strict parsers, signed v2 transaction binding, stale/cross-transaction rejection, bounded 512-entry digest cache, exact request/response replay suppression, durable control-log rejection of exact authenticated terminal replays after restart, idempotent request retry after restart (two controller restart regressions) |
| Channel policy | `cargo test --locked -p p2p-chat` | Bounded `CHN1` frames, admin-only policy changes, revision checks, restricted honest delivery |
| Direct network | `cargo test --locked -p p2p-network` | Zero-bootstrap loopback connect, PeerId authentication, duplicate dial rejection, public `dial` circuit rejection before queueing, address validation |
| Network resilience | `cargo test --locked -p p2p-network` | Pre-authentication global and per-IP socket caps, stalled-socket and extra-per-IP rejection before Noise, established connection caps, aggregate and per-protocol request/byte budgets, denied-request non-charging, expired rate-limiter entry cleanup, malformed/oversized frame handling, peerless-failure state preservation |
| Relay policy | `cargo test --locked -p p2p-network` | Inbound relayed file requests emit only a policy failure, no pending response or `RequestReceived` |
| Privacy honesty | `cargo test --locked -p p2p-network` and `cargo test --locked -p p2p-desktop --features gui` | No fabricated AutoNAT confidence, cumulative observations labelled since startup, live relayed-connection count distinct |
| File security | `cargo test --locked -p p2p-files` | Fresh keys, AEAD chunks, manifest verification, quarantine ciphertext-only, cancellation/release gates, abort clears partial state and quarantine |
| File lifetime | `cargo test --locked -p p2p-chat --test controller` | Inactivity timeout, late-frame rejection, pending-request cleanup, terminal-state replacement transfer, cancellation only after verification |
| Scanner policy | `cargo test --locked -p p2p-security` | Exact status categories, no-scanner `Unavailable`, default deny, narrow format validation |
| Storage security | `cargo test --locked -p p2p-storage` | Wrong password, password change, DB/WAL/SHM plaintext scans, symlink refusal on Unix, schema v4 `control_log`/`control_state`, durable idempotent requests and non-repeatable terminal frames across reopen, chain/blind-index/anchor verification on unlock, older-DB-with-current-anchor rollback detection, anchor bit-flip detection (15 crate tests) |
| GUI model | `cargo test --locked -p p2p-desktop --features gui` | Honest status rows, address validation, no fake connection state |
| Diagnostic guard | `python3 scripts/check_diagnostics.py` | Unmarked raw output macros, derived `Debug` on protected types, secret-named types/fields, self-tests for fail-closed behavior |
| Fuzz smoke | `cargo fuzz run` in `fuzz/` and `cargo clippy --manifest-path fuzz/Cargo.toml` | Canonical codec decoding, signature verification, redacted `Debug`, canonical re-encoding, hostile identity export and contact text |
| SBOM generation | `python3 scripts/generate_sbom.py` | Locked package graph, SPDX identifiers, license normalization, relative paths, dangling-relationship rejection, byte-identical regeneration |

## 3. Adversarial tests to preserve

When modifying a codec or state machine, add a test for each applicable case:

- wrong magic, unknown version, truncated field, trailing bytes, oversized field, invalid UTF-8, duplicate/empty member sets;
- tampered signature, wrong expected PeerId, wrong public key, cross-conversation substitution, stale epoch;
- duplicate request with a different transaction ID, exact signed-frame replay, stale acknowledgement, out-of-order operations;
- durable control-log cases: an exact authenticated terminal frame must not be re-applied after restart, while an idempotent `KeyPackageRequest`/`GroupJoinRequest` retry must stay idempotent after restart;
- older database restored while keeping the current anchor and anchor bit flip must fail unlock (both tested); a missing anchor after a nonempty log and a broken chain (non-contiguous sequence or mismatched `chain_hash`, blind index, or record AEAD) must fail `verify_control_log` — these are source-backed fail-closed checks, but no dedicated missing-anchor or broken-chain test is recorded in the final 207-test run;
- replayed message after reload where a load path exists;
- file chunk tampering, missing manifest, oversized file, unsupported/mismatched format, scanner failure, no scanner;
- invalid bootstrap/relay address, `/p2p-circuit` in a direct address, missing `/p2p/<peer-id>` suffix;
- stalled raw socket before Noise, zero/oversized connection-limit configuration, and advisory peerless failures that must not erase live connections;
- local directory paths in `Debug`, unknown untrusted query fields reflected into errors, and any new stdout/stderr/diagnostic path that could print passwords, private keys, plaintext, or opaque frames; the diagnostic guard must reject unmarked raw output macros, derived `Debug` on protected types, and secret-named fields;
- a saturated protocol bucket that must not consume another protocol's reserved capacity, and a per-protocol denial that must not charge the aggregate request budget;
- saturated control/setup/file traffic that must not consume the message reservation, a per-protocol denial that must not charge the aggregate budget, and an aggregate ceiling that must still apply;
- relay observation injection that must not create a contact, verified peer, capability, receipt, or delivery claim;
- arbitrary bytes reaching the envelope, setup, file, channel, identity-export, and contact/fingerprint parsers without panic, with verified frames re-encoding canonically.

## 4. Network privacy tests

Local tests cover codec bounds, configuration defaults, address validation, status snapshots, and direct loopback transport only.

The following require external hardware or a controlled volunteer relay and are therefore documented as pending, not claimed:

1. Two machines on the same LAN using manual addresses and optional mDNS.
2. Two machines behind separate NATs with a user-operated relay and optional AutoNAT/DCUtR.
3. A three-node relay harness that records raw relay-side bytes, searches for signed Offer/file-key sentinels, and attempts ciphertext tampering.
4. Packet capture proving no direct TCP fallback in a future fail-closed privacy mode.
5. DNS and IPv6 leak tests for a future Tor-required mode.

## 5. Fuzz smoke tests

`fuzz/` contains six real libFuzzer targets: `P2P1` envelopes, `MLS1` setup and group-control frames, `CHN1` channel frames, signed file frames, encrypted identity envelopes, and contact URI/fingerprint text. The security workflow builds them with nightly `cargo-fuzz` and runs each for a bounded 30 seconds. Locally, all six binaries also completed plain-libFuzzer 1000-input smoke runs without crashes; those local runs were not coverage-instrumented, so they do not constitute a long campaign.

A dependency-free deterministic smoke test still flips one bit at every offset of a signed `P2P1` envelope and asserts that any successfully parsed mutation fails signature verification; it also asserts that every truncated prefix is rejected. This is a regression guard, not proof of parser correctness.

Not covered by these targets: internal transport codec state machines, backup/vault import formats (no such formats exist yet), and a long sanitizer-enabled corpus-building campaign. Treat fuzzing as a bounded smoke control; CI is green, but a longer coverage-guided campaign is still required before making a broader fuzzing claim.

## 6. Dependency and supply-chain checks

Install the tools outside the repository, then run:

```bash
cargo audit --file Cargo.lock
cargo deny --locked --manifest-path Cargo.toml check
cargo audit --file fuzz/Cargo.lock
cargo deny --locked --manifest-path fuzz/Cargo.toml check
```

`deny.toml` defines advisory, license, bans, and source policy. A `security.yml` workflow runs these gates on pushes and pull requests. Locally installed `cargo-audit 0.23.0` and `cargo-deny 0.22.1` execute the same checks. After aligning `deny.toml` with cargo-deny 0.22, declaring the fuzz workspace license, moving to libp2p 0.57.1/libp2p-request-response 0.30.0, and moving to the OpenMLS 0.10.0-rc.1 provider stack, **all four local commands pass**: `cargo audit` reports zero vulnerabilities with five non-failing unmaintained warnings, and `cargo deny` ends with `advisories ok, bans ok, licenses ok, sources ok` for both lockfiles. The unmaintained warnings are `paste`, `proc-macro-error2`, `zbus_names`, `zvariant`, and `zvariant_derive`; they remain documented residual risk. GitHub Security gates run `45690333396` passed all four jobs on 2026-11-25.

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
