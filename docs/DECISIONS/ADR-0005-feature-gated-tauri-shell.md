# ADR-0005: Feature-gate the Tauri shell for testability

- Status: **Superseded by ADR-0006** (Tauri/React/npm removed entirely)
- Date: 2026-11-23

## Context
The development host lacks `webkit2gtk-4.1` development packages and passwordless sudo, so compiling Tauri 2 locally is impossible. The project still needs continuously runnable tests and an honest build story.

## Decision
`apps/desktop` has a Cargo feature `desktop` (not enabled by default) that pulls in `tauri` and `tauri-build`. `cargo test --workspace` verifies core logic on any host; `cargo tauri dev -f desktop` and `cargo tauri build -f desktop` build the real shell where system dependencies exist. CI installs webkit2gtk and runs the desktop build separately.

## Consequences
- A default `cargo run -p p2p-desktop` is an explicit stub that tells the user to enable the feature; it never masquerades as the full application.
- Integration with Tauri requires the feature to be passed explicitly in development and release commands.
- No security property depends on the gate; it is a build/test ergonomics decision.
