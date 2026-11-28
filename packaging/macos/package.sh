#!/usr/bin/env bash
# Build an unsigned-by-default macOS .app bundle, .dmg, and portable tarball.
# Set MACOS_SIGNING_IDENTITY to a Developer ID Application identity to sign the
# bundle; notarization is intentionally not performed by this script.
# Usage: package.sh <binary> [version] [x86_64|aarch64] [out-dir]
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../common.sh"

binary="${1:-}"
version="${2:-$(p2p_workspace_version)}"
arch="${3:-$(uname -m)}"
out_dir="${4:-$P2P_REPO_ROOT/dist}"

if [[ -z "$binary" ]]; then
    echo "Usage: $0 <binary> [version] [arch] [out-dir]" >&2
    exit 2
fi

if [[ ! "$version" =~ ^[0-9A-Za-z.+_-]+$ ]]; then
    echo "Invalid version string: $version" >&2
    exit 2
fi

case "$arch" in
    x86_64 | amd64) asset_arch="x86_64" ;;
    aarch64 | arm64) asset_arch="aarch64" ;;
    *)
        echo "Unsupported macOS architecture: $arch" >&2
        exit 2
        ;;
esac

p2p_require_file "$binary"
p2p_require_file "$P2P_REPO_ROOT/packaging/NOTICE.md"
p2p_require_file "$P2P_REPO_ROOT/packaging/macos/Info.plist.template"
p2p_require_command hdiutil
p2p_require_command shasum

mkdir -p "$out_dir"
stage="$(mktemp -d "${TMPDIR:-/tmp}/p2p-macos-package.XXXXXX")"
trap 'rm -rf "$stage"' EXIT

app_path="$stage/P2P Messenger.app"
mkdir -p "$app_path/Contents/MacOS" "$app_path/Contents/Resources"
install -m 0755 "$binary" "$app_path/Contents/MacOS/p2p-desktop"
install -m 0644 "$P2P_REPO_ROOT/packaging/NOTICE.md" "$stage/NOTICE.md"
sed "s/__VERSION__/$version/g" \
    "$P2P_REPO_ROOT/packaging/macos/Info.plist.template" > "$app_path/Contents/Info.plist"

if [[ -n "${MACOS_SIGNING_IDENTITY:-}" ]]; then
    p2p_require_command codesign
    codesign --force --options runtime --timestamp \
        --sign "$MACOS_SIGNING_IDENTITY" "$app_path"
    echo "Signed app bundle with: $MACOS_SIGNING_IDENTITY"
else
    echo "No MACOS_SIGNING_IDENTITY set: producing an unsigned app bundle and DMG."
fi

base="p2p-messenger-${version}-macos-${asset_arch}"
dmg_path="$out_dir/$base.dmg"
tar_path="$out_dir/$base.tar.gz"

hdiutil create -volname "P2P Messenger" -srcfolder "$stage" -ov -format UDZO "$dmg_path"
tar -C "$stage" -czf "$tar_path" .

(
    cd "$out_dir"
    shasum -a 256 "$(basename "$dmg_path")" > "$(basename "$dmg_path").sha256"
    shasum -a 256 "$(basename "$tar_path")" > "$(basename "$tar_path").sha256"
)

echo "Created: $dmg_path"
echo "Created: $tar_path"
