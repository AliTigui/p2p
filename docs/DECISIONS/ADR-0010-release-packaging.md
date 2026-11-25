# ADR-0010: Source-first cross-platform release packaging

- Status: Accepted
- Date: 2026-11-24
- Milestone: 11 — final application / cross-platform builds

## Context

Milestones 1–10 delivered a working pure Rust native desktop application. Milestone 11 needs distributable artifacts for Linux, Windows, and macOS without adding runtime dependencies, a webview, a package-manager JavaScript toolchain, a mandatory update service, or centralized application infrastructure.

The application has strong privacy constraints: no plaintext sensitive state on disk, no mandatory centralized infrastructure, and no fake security/connection/status claims. Release engineering must not weaken those properties or imply that an unsigned package is signed, notarized, or malware-scanned.

## Decision

1. Keep source builds as the primary distribution path. `Cargo.lock` is committed and release builds use `--locked`.
2. Use native GitHub-hosted runners for the release matrix: Linux x86_64, Windows x86_64 MSVC, macOS x86_64, and macOS arm64. No cross-compiler or web technology is introduced.
3. Produce portable archives plus one native installer per desktop platform:
   - Linux: `.tar.gz` and `.deb` built with `dpkg-deb`.
   - Windows: `.zip` and `.msi` built with WiX Toolset 4+ (`candle.exe`/`light.exe`, `-arch x64`).
   - macOS: `.app` inside `.tar.gz` and `.dmg` built with `hdiutil`.
4. Each package includes `README.md` and a short `NOTICE.md` that states the license, absence of centralized runtime services, default unsigned status, and memory-only MLS/chat state.
5. Tagged releases upload all artifacts, a single `SHA256SUMS` manifest, and generated release notes. Checksums are verified in CI before publishing.
6. Signing is optional and operator-controlled through `WINDOWS_SIGNING_THUMBPRINT` or `MACOS_SIGNING_IDENTITY`. No secret or certificate is committed. macOS notarization is out of scope for this milestone.
7. No auto-updater, telemetry, phone-home endpoint, account service, discovery service, relay, or developer-operated package feed is added. GitHub Releases are only an optional download host.
8. Do not claim bit-for-bit reproducibility. Locked dependency resolution is guaranteed; build timestamp/toolchain differences remain.

## Consequences

- Users receive conventional platform artifacts and can independently build from source.
- Windows MSI manufacturing requires WiX 4+; the current Windows CI image provides it through `WIX` and rejects the WiX 3.x `Package/@Win64` attribute. macOS signing/notarization requires platform credentials not present in the repository.
- Unsigned macOS builds may be blocked by Gatekeeper unless the user explicitly allows them or a release operator signs/notarizes with Apple credentials.
- Linux ARM64 and Windows ARM64 are not built by the default matrix; add appropriate runners before claiming support.
- Windows/macOS artifacts cannot be produced or visually inspected on the current headless Linux host. CI results and per-platform verification commands in `docs/BUILDING.md` are the evidence for those targets.
- No new Cargo runtime dependency, wire protocol, or local data format is added by this milestone.
