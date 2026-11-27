#!/usr/bin/env bash
# Build the internal mobile variant in its own source and output tree.
set -euo pipefail

if [[ $# != 2 ]]; then
    echo "usage: $0 prepare|test|android|ios NEW_DIRECTORY" >&2
    exit 2
fi
case "$1" in prepare|test|android|ios) ;; *) echo "unknown internal build: $1" >&2; exit 2 ;; esac
root=$(cd "$(dirname "$0")/.." && pwd)
mkdir -- "$2"
cd "$2"
destination=$(pwd -P)

# Copy the current contents of indexed files. Exclude local signing keys, SDK settings
# and build outputs. No branch, remote, patch base commit or history is required.
# Each profile gets its own Kotlin, Xcode and Cargo outputs.
git -C "$root" ls-files --cached -z | tar -C "$root" -cf - --null -T - | tar -xf -
overlay=experiments/internal-pq
# Prevent git apply from discovering the outer checkout when building below build/.
GIT_CEILING_DIRECTORIES=$(dirname "$destination")
export GIT_CEILING_DIRECTORIES
for part in rust shared apps test-vectors isolation; do
    git apply --whitespace=error "$overlay/$part.patch"
done
# A new file in the base with the same name requires an explicit port.
while IFS= read -r -d '' file; do
    path=${file#"$overlay/files/"}
    if [[ -e "$path" || -L "$path" ]]; then
        echo "internal profile file conflicts with base: $path" >&2
        exit 1
    fi
    mkdir -p "$(dirname "$path")"
    cp -p "$file" "$path"
done < <(find "$overlay/files" -type f -print0)

case "$1" in
    prepare) printf 'Internal PQ sources: %s\n' "$destination" ;;
    test)
        cd rust
        export CARGO_TARGET_DIR="$destination/rust/target"
        cargo test --locked --workspace
        ../scripts/check-c-abi.sh
        cargo run --locked -p chur-cli -- vectors verify --dir ../test-vectors/v1
        ;;
    android) ./gradlew --no-daemon :apps:androidApp:assembleDebug ;;
    ios)
        xcodebuild -project apps/iosApp/Chur.xcodeproj -scheme Chur -configuration Debug \
            -destination 'generic/platform=iOS Simulator' -derivedDataPath "$destination/build/xcode" \
            CODE_SIGNING_ALLOWED=YES CODE_SIGNING_REQUIRED=YES CODE_SIGN_IDENTITY=- build-for-testing
        ;;
esac
