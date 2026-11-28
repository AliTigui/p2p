#!/usr/bin/env bash
# Build a Linux portable tarball and Debian package from a native binary.
# Usage: package.sh <binary> [version] [x86_64|amd64|aarch64|arm64] [out-dir]
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../common.sh"

binary="${1:-}"
version="${2:-$(p2p_workspace_version)}"
arch="${3:-x86_64}"
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
    x86_64 | amd64)
        asset_arch="x86_64"
        deb_arch="amd64"
        ;;
    aarch64 | arm64)
        asset_arch="aarch64"
        deb_arch="arm64"
        ;;
    *)
        echo "Unsupported Linux architecture: $arch" >&2
        exit 2
        ;;
esac

p2p_require_file "$binary"
p2p_require_file "$P2P_REPO_ROOT/packaging/NOTICE.md"
p2p_require_file "$P2P_REPO_ROOT/packaging/linux/control"
p2p_require_file "$P2P_REPO_ROOT/packaging/desktop/p2p-messenger.desktop"
p2p_require_command dpkg-deb
p2p_require_command tar

mkdir -p "$out_dir"
stage="$(mktemp -d "${TMPDIR:-/tmp}/p2p-linux-package.XXXXXX")"
trap 'rm -rf "$stage"' EXIT

mkdir -p "$stage/portable" "$stage/deb/DEBIAN" \
    "$stage/deb/usr/bin" "$stage/deb/usr/share/applications" \
    "$stage/deb/usr/share/doc/p2p-messenger"

install -m 0755 "$binary" "$stage/portable/p2p-desktop"
install -m 0755 "$binary" "$stage/deb/usr/bin/p2p-desktop"
install -m 0644 "$P2P_REPO_ROOT/packaging/NOTICE.md" "$stage/portable/NOTICE.md"
install -m 0644 "$P2P_REPO_ROOT/packaging/desktop/p2p-messenger.desktop" \
    "$stage/deb/usr/share/applications/p2p-messenger.desktop"
install -m 0644 "$P2P_REPO_ROOT/packaging/NOTICE.md" "$stage/deb/usr/share/doc/p2p-messenger/NOTICE.md"

sed \
    -e "s/^Version: .*/Version: $version/" \
    -e "s/^Architecture: .*/Architecture: $deb_arch/" \
    "$P2P_REPO_ROOT/packaging/linux/control" > "$stage/deb/DEBIAN/control"

base="p2p-messenger-${version}-linux-${asset_arch}"
deb_path="$out_dir/$base.deb"
tar_path="$out_dir/$base.tar.gz"

dpkg-deb --root-owner-group --build "$stage/deb" "$deb_path"
tar -C "$stage/portable" -czf "$tar_path" .

(
    cd "$out_dir"
    sha256sum "$(basename "$deb_path")" > "$(basename "$deb_path").sha256"
    sha256sum "$(basename "$tar_path")" > "$(basename "$tar_path").sha256"
)

echo "Created: $deb_path"
echo "Created: $tar_path"
