#!/usr/bin/env bash
set -euo pipefail

# Reproducible external TLS dependency. No sudo or system installation.
repo_root="$(cd "$(dirname "$0")/.." && pwd)"
deps_dir="$repo_root/build/deps"
version=3.5.9
archive_sha=796831ec533bf41998eaaee9d632d921b8a69f57394fa4086ff01a941113d26d
archive="${1:-$deps_dir/openssl-$version-source.tar.gz}"
source_dir="$deps_dir/openssl-$version-source"
install_dir="$deps_dir/openssl-$version"
mkdir -p "$deps_dir"
if [[ ! -f "$archive" ]]; then
  curl --fail --location --connect-timeout 15 --max-time 180 \
    "https://codeload.github.com/openssl/openssl/tar.gz/refs/tags/openssl-$version" -o "$archive"
fi
printf '%s  %s\n' "$archive_sha" "$archive" | sha256sum --check --status
if [[ ! -d "$source_dir" ]]; then
  mkdir -p "$source_dir"
  tar -xzf "$archive" --strip-components=1 -C "$source_dir"
fi
cd "$source_dir"
./Configure linux-aarch64 no-shared no-tests --prefix="$install_dir" --libdir=lib
make -j"${QUIC_BUILD_JOBS:-2}" build_libs
make install_dev
printf 'OpenSSL %s installed at %s\n' "$version" "$install_dir"
