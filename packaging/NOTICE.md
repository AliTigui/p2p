# P2P Messenger release notice

P2P Messenger is licensed under `MIT OR Apache-2.0`. Build and run instructions are in `README.md`; detailed platform packaging instructions are in `docs/BUILDING.md`.

This application has no mandatory server, account, bootstrap list, relay, telemetry, auto-updater, browser engine, webview, JavaScript runtime, or npm dependency. Release archives are only a distribution convenience: the application does not phone home, and building from source is always supported.

By default these packages are **unsigned** and macOS packages are **not notarized**. Verify the published `SHA256SUMS` file over an authenticated channel before installing. Signing can be enabled only by the release operator with platform credentials; this repository contains no signing secrets.

Published releases include `sbom-root.spdx.json` and `sbom-fuzz.spdx.json`, generated from the locked Cargo graphs. They are source/lockfile inventories for supply-chain review, not binary composition analysis, legal license review, build provenance, or vulnerability proof. See `docs/SBOM.md`.

Integrity verification of a package does not make a file transfer safe. The desktop application configures no malware scanner, no allowed extension list, and `Retain` quarantine deletion by default. MLS group state, channels, decrypted messages, and the offline queue are memory-only and are lost on restart or lock. Schema-v4 durable control-frame digests and the vault anchor preserve only idempotent request and terminal decision outcomes across restart; they do not restore MLS group/ratchet/pending-key-package/channel state, are not a backup, and cannot detect restoration of the entire vault including the anchor.
