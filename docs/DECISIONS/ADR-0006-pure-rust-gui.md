# ADR-0006: Pure Rust GUI instead of Tauri/React/npm

- Status: Accepted
- Date: 2026-11-23
- Supersedes: ADR-0005

## Context
The original brief specified Tauri 2 + React + TypeScript + Vite. During Milestone 1 the user questioned why npm, TypeScript, and a browser/webview are needed and chose a pure Rust GUI instead. A React app cannot render without a DOM implementation; Tauri provides one via the OS webview. A pure-Rust toolkit removes the webview, JavaScript toolchain, and npm entirely.

## Decision
Use **egui 0.37** for widget descriptions and **eframe 0.37** for native OS windows. There is no React, TypeScript, Node.js, npm, Vite, Tailwind, webview, or browser in the application or build.

Feature layout:
- `gui` (optional dep `egui`): compiles all widget/model code without display libraries.
- `native` (implies `gui`, adds `eframe`): opens the OS window with the glow renderer.
- Default features: none, so core tests run anywhere.

## Consequences
- Single language and toolchain: Rust only. `cargo test`, `cargo check --features gui`, and `cargo build --features native` are the complete verification path.
- The GUI is immediate-mode. Long-lived state lives in Rust structs; rendering is a pure projection, which fits the "UI never blocks / never owns truth" rule.
- Styling is Rust code instead of Tailwind/CSS. Visual polish comes from egui visuals and custom layout, not a web stylesheet.
- The user explicitly accepted changing the original technology table; this ADR records that conflict with the brief and the decentralized alternative chosen.
- Security architecture is unchanged: still no mandatory centralized servers, still local identity/data, still libp2p + MLS as designed.
