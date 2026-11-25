# P2P Messenger release notice

P2P Messenger is licensed under `MIT OR Apache-2.0`. Build and run instructions are in `README.md`; detailed platform packaging instructions are in `docs/BUILDING.md`.

This application has no mandatory server, account, bootstrap list, relay, telemetry, auto-updater, browser engine, webview, JavaScript runtime, or npm dependency. Release archives are only a distribution convenience: the application does not phone home, and building from source is always supported.

By default these packages are **unsigned** and macOS packages are **not notarized**. Verify the published `SHA256SUMS` file over an authenticated channel before installing. Signing can be enabled only by the release operator with platform credentials; this repository contains no signing secrets.

Integrity verification of a package does not make a file transfer safe. The desktop application configures no malware scanner, no allowed extension list, and `Retain` quarantine deletion by default. MLS group state, channels, decrypted messages, and the offline queue are memory-only and are lost on restart or lock.
