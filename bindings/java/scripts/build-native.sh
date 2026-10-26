#!/bin/sh
# Build the lean-pq shared library for one platform bundled in the Java jar and stage it as
# NATIVE_DIR/PLATFORM/<library>, the layout `-PleanPqNativeDir=NATIVE_DIR` expects.
#   linux-x86_64, linux-aarch64: cargo-zigbuild against glibc 2.17 (needs Zig and cargo-zigbuild)
#   macos-universal:             x86_64 + arm64 slices joined with lipo (needs a macOS host)
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 linux-x86_64|linux-aarch64|macos-universal NATIVE_DIR" >&2
    exit 64
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/../../.." && pwd)
manifest="$repo_dir/bindings/native/Cargo.toml"
target_dir=${CARGO_TARGET_DIR:-"$repo_dir/target"}
platform=$1
out_dir="$2/$platform"

# Rust target triples without the glibc suffix, so .cargo/config.toml's per-target rustflags apply.
case "$platform" in
    linux-x86_64) rust_target=x86_64-unknown-linux-gnu ;;
    linux-aarch64) rust_target=aarch64-unknown-linux-gnu ;;
    macos-universal) rust_target= ;;
    *)
        echo "unsupported platform: $platform" >&2
        exit 64
        ;;
esac

mkdir -p "$out_dir"
if [ -n "$rust_target" ]; then
    cargo zigbuild --manifest-path "$manifest" --release --target "$rust_target.2.17"
    install -m 0644 "$target_dir/$rust_target/release/liblean_pq_native.so" "$out_dir/liblean_pq_native.so"
    newest=$(objdump -T "$out_dir/liblean_pq_native.so" | grep -o 'GLIBC_[0-9.]*' | sed 's/^GLIBC_//' | sort -uV | tail -n 1)
    if [ "$(printf '%s\n2.17\n' "$newest" | sort -V | tail -n 1)" != 2.17 ]; then
        echo "liblean_pq_native.so needs GLIBC_$newest, above the 2.17 baseline" >&2
        exit 1
    fi
    echo "newest glibc symbol version: GLIBC_$newest"
else
    for target in x86_64-apple-darwin aarch64-apple-darwin; do
        cargo build --manifest-path "$manifest" --release --target "$target"
    done
    lipo -create -output "$out_dir/liblean_pq_native.dylib" \
        "$target_dir/x86_64-apple-darwin/release/liblean_pq_native.dylib" \
        "$target_dir/aarch64-apple-darwin/release/liblean_pq_native.dylib"
    lipo "$out_dir/liblean_pq_native.dylib" -verify_arch x86_64 arm64
fi
echo "staged $(ls "$out_dir")"
