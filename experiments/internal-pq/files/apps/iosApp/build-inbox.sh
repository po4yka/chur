#!/bin/sh
# Build the Rust archive for the Share Extension or the Swift host tests.
set -eu
app_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$app_dir/../../rust"
export CARGO_TARGET_DIR="$app_dir/.build/inbox-native"
case "${1:-host}" in
  host) triple= ;;
  iphoneos) triple=aarch64-apple-ios ;;
  iphonesimulator) triple=aarch64-apple-ios-sim ;;
  *) echo "Unknown Apple platform: $1" >&2; exit 1 ;;
esac
profile=debug
set -- build --locked -p chur-ffi --lib --no-default-features
if [ -n "$triple" ]; then
  set -- "$@" --target "$triple"
  if [ "$CONFIGURATION" = Release ]; then
    profile=release
    set -- "$@" --release
  fi
fi
cargo "$@" >&2
printf '%s\n' "$CARGO_TARGET_DIR/${triple:+$triple/}$profile/libchur_ffi.a"
