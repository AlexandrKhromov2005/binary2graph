#!/usr/bin/env bash
# Builds binary2graph in release mode and puts it on PATH.
set -euo pipefail

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
bin_dir="${CARGO_INSTALL_ROOT:-${CARGO_HOME:-$HOME/.cargo}}/bin"

if ! command -v cargo >/dev/null 2>&1; then
    echo "can't find cargo, install rust first" >&2
    exit 1
fi

cargo install --path "$repo_dir" --force

case ":$PATH:" in
    *":$bin_dir:"*) ;;
    *)
        case "${SHELL##*/}" in
            zsh) rc="$HOME/.zshrc" ;;
            bash) rc="$HOME/.bashrc" ;;
            *) rc="$HOME/.profile" ;;
        esac
        line="export PATH=\"$bin_dir:\$PATH\""
        if ! grep -qsF -- "$line" "$rc"; then
            printf '\n%s\n' "$line" >>"$rc"
            echo "added $bin_dir to PATH in $rc"
        fi
        echo "open a new shell or run: source $rc"
        ;;
esac

echo "installed $("$bin_dir/binary2graph" --version) to $bin_dir"
