#!/usr/bin/env bash
# Compile the C consumer against this source tree's release library and header.
set -euo pipefail
cd "$(dirname "$0")/../rust"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target}"
cargo build --locked -p chur-ffi --release

work=$(mktemp -d "${TMPDIR:-/tmp}/chur-abi.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
libs=(-lpthread -ldl -lm)
if [[ $(uname -s) == Darwin ]]; then
    libs+=(-framework Security -framework CoreFoundation)
fi
cc -Wall -Wextra -Werror -I crates/chur-ffi/include \
    crates/chur-ffi/tests/handshake.c "$CARGO_TARGET_DIR/release/libchur_ffi.a" \
    "${libs[@]}" -o "$work/handshake"
(cd "$work" && ./handshake)
