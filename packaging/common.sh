#!/usr/bin/env bash
# Shared helpers for Unix packaging scripts. No secret values are read here.
set -euo pipefail

P2P_REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

p2p_workspace_version() {
    awk -F '"' '
        /^\[workspace\.package\]/ { in_workspace = 1; next }
        /^\[/ { in_workspace = 0 }
        in_workspace && /^version[[:space:]]*=/ { print $2; exit }
    ' "$P2P_REPO_ROOT/Cargo.toml"
}

p2p_require_file() {
    local path="$1"
    if [[ ! -f "$path" ]]; then
        echo "Missing required file: $path" >&2
        exit 1
    fi
}

p2p_require_command() {
    local command_name="$1"
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "Required command not found: $command_name" >&2
        exit 1
    fi
}
