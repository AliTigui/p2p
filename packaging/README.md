# Packaging scripts

These scripts build distributable artifacts from a native `p2p-desktop` binary. They add no Cargo dependency and no runtime service.

- `linux/package.sh`: portable `.tar.gz` and Debian `.deb` using `dpkg-deb`.
- `windows/package.ps1`: portable `.zip` and WiX 3.14+ `.msi`; requires the `WIX` environment variable and `candle.exe`/`light.exe` in its `bin` directory.
- `macos/package.sh`: `.app`, portable `.tar.gz`, and `.dmg` using `hdiutil`; optional `MACOS_SIGNING_IDENTITY`.
- `NOTICE.md`: included in every package with license, unsigned-status, and no-central-infrastructure notes.

See [docs/BUILDING.md](../docs/BUILDING.md) for exact commands, artifact names, verification, and platform limitations. The release matrix is defined in `.github/workflows/build.yml`.
