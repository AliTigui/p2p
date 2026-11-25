# Building and packaging

This document records the Milestones 11–13 build/release path for the pure Rust desktop application. The application has no npm, TypeScript, browser, webview, or Tauri layer. `Cargo.lock` is committed and source verification and release builds use `--locked`, so dependency resolution is fixed; timestamps and toolchains can still differ, so artifacts are **not** claimed to be bit-for-bit reproducible. M13 adds optional networking features that are off/empty by default and do not change this packaging path.

## Toolchain

- Workspace `rust-version`: **1.95** (retained from the earlier egui/eframe 0.37 baseline; not lowered during the dependency refresh).
- Build with `cargo build --locked --release -p p2p-desktop --features native`.
- The `gui` feature describes widgets without display libraries; `native` adds `eframe` and the optional native-only `rfd` save dialog.

## Source verification

Run these before packaging:

```bash
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets
cargo test --locked --workspace -- --test-threads=1
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo check --locked -p p2p-desktop --features gui
cargo check --locked -p p2p-desktop --features native
cargo clippy --locked -p p2p-desktop --features gui -- -D warnings
cargo clippy --locked -p p2p-desktop --features native -- -D warnings
cargo build --locked -p p2p-desktop --features native
```

The serialized test command avoids a known transient connection-limit test race under unsynchronized parallel execution.

## Linux (x86_64)

Build dependencies:

```bash
sudo apt-get update
sudo apt-get install -y pkg-config libx11-dev libxkbcommon-dev \
  libwayland-dev libxcb1-dev libxrandr-dev libxinerama-dev \
  libxcursor-dev libxi-dev libgl1-mesa-dev libfontconfig1-dev
```

Build and package:

```bash
cargo build --locked --release -p p2p-desktop --features native \
  --target x86_64-unknown-linux-gnu
bash packaging/linux/package.sh \
  target/x86_64-unknown-linux-gnu/release/p2p-desktop \
  "$(awk -F '"' '/^\[workspace\.package\]/{w=1;next} /^\[/{w=0} w && /^version[[:space:]]*=/{print $2;exit}' Cargo.toml)" \
  x86_64 dist
```

Artifacts:

- `p2p-messenger-<version>-linux-x86_64.tar.gz`: portable binary, `README.md`, and `NOTICE.md`.
- `p2p-messenger-<version>-linux-x86_64.deb`: installs the binary to `/usr/bin/p2p-desktop` and a freedesktop launcher entry.

Inspect before publishing:

```bash
dpkg-deb --contents dist/p2p-messenger-*-linux-x86_64.deb
dpkg-deb --info dist/p2p-messenger-*-linux-x86_64.deb
tar -tzf dist/p2p-messenger-*-linux-x86_64.tar.gz
cd dist
sha256sum -c p2p-messenger-*-linux-x86_64.tar.gz.sha256
sha256sum -c p2p-messenger-*-linux-x86_64.deb.sha256
cd ..
```

The per-artifact `.sha256` sidecars contain bare filenames, so those `sha256sum -c` checks must run from `dist/`. The CI `SHA256SUMS` bundle uses a different layout and is checked from the artifact root as shown below.

## Windows (x86_64)

Requirements: Rust MSVC target, Visual Studio C++ build tools, and **WiX Toolset 3.14+** with `candle.exe`/`light.exe`. GitHub-hosted `windows-latest` runners provide WiX via the `WIX` environment variable; local builders must set it to the WiX install directory. The script passes `-arch x64` so the MSI template is x64; `Package/@Win64` is not a valid schema attribute and is not used.

```powershell
cargo build --locked --release -p p2p-desktop --features native --target x86_64-pc-windows-msvc
./packaging/windows/package.ps1 `
  -Binary "target/x86_64-pc-windows-msvc/release/p2p-desktop.exe" `
  -OutDir dist
```

Artifacts:

- `p2p-messenger-<version>-windows-x86_64.zip`: portable executable, `README.md`, and `NOTICE.md`.
- `p2p-messenger-<version>-windows-x86_64.msi`: per-machine x64 installer with a Start Menu shortcut.

Inspect the ZIP with `Expand-Archive` or any archive viewer. The MSI is built by `candle.exe`/`light.exe` from `packaging/windows/p2p-messenger.wxs` with fixed upgrade and component GUIDs.

## macOS (Intel and Apple Silicon)

Requirements: Xcode Command Line Tools and the matching Rust target. Build on native runners; the workflow uses `macos-15-intel` for x86_64 and `macos-latest` for arm64.

```bash
cargo build --locked --release -p p2p-desktop --features native \
  --target x86_64-apple-darwin   # or aarch64-apple-darwin on Apple Silicon
bash packaging/macos/package.sh \
  target/x86_64-apple-darwin/release/p2p-desktop \
  "$(awk -F '"' '/^\[workspace\.package\]/{w=1;next} /^\[/{w=0} w && /^version[[:space:]]*=/{print $2;exit}' Cargo.toml)" \
  x86_64 dist
```

Artifacts:

- `p2p-messenger-<version>-macos-<arch>.dmg`: drag-to-install disk image containing the app bundle, `README.md`, and `NOTICE.md`.
- `p2p-messenger-<version>-macos-<arch>.tar.gz`: portable app bundle archive.

Inspect with:

```bash
hdiutil verify dist/p2p-messenger-*-macos-*.dmg
tar -tzf dist/p2p-messenger-*-macos-*.tar.gz
```

The bundle is unsigned and not notarized unless the builder sets `MACOS_SIGNING_IDENTITY` to an installed Developer ID Application identity. The script does not add a notarization step; release operators must do that with their own Apple credentials if required.

## CI and tagged releases

`.github/workflows/build.yml` builds and packages all four targets on every push to `main`, every pull request, and every `v*` tag. Each build job uploads its `dist/` contents as a separate artifact. On a `v*` tag, a publish job downloads all artifacts, adds `packaging/NOTICE.md`, creates `SHA256SUMS`, verifies it locally with `sha256sum -c`, and attaches all files to the GitHub Release. External action refs in this workflow and the CI/security workflows are pinned to commit SHAs; see `SECURITY_TESTS.md` for the resolved mapping and its limits.

Verify a published artifact with:

```bash
sha256sum -c SHA256SUMS
```

GitHub Releases are an optional download convenience only. The application has no update checker, telemetry, account service, discovery service, relay, or developer-operated infrastructure. Users can build from source without contacting any release service.

## Signing and trust

- Packages are **unsigned** by default. macOS DMGs are **not notarized** by default.
- `WINDOWS_SIGNING_THUMBPRINT` may be set to sign the EXE and MSI with a locally installed certificate store entry. No certificate or password is stored in this repository.
- `MACOS_SIGNING_IDENTITY` may be set to sign the app bundle with a locally installed Developer ID Application identity.
- Checksums authenticate artifacts against the release channel used to obtain them; they do not establish developer identity without an authenticated channel or signature.
- A package checksum and an integrity-verified file transfer are not malware-scan results. The default desktop configuration has no scanner and no allowed extensions.

## Current validation limits

This host is Linux-only and headless. Linux source builds, native compile/link, packaging scripts, archive contents, and checksum verification can be checked here. The 2026-11-25 GitHub run built all four targets; downloaded TAR/ZIP/deb/DMG sidecars verified 8/8 here, archive contents and MSI x64 metadata were inspected, but MSI/DMG installation, certificate signing, notarization, and visual GUI inspection still require the corresponding platform hosts and are not claimed as locally verified.
