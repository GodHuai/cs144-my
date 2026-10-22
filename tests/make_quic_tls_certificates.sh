#!/usr/bin/env bash
set -euo pipefail
openssl_bin="$1"
cert_dir="$2"
mkdir -p "$cert_dir"
# The build fixture runs this check even in an unchanged incremental build.
# Refresh both identities before expiry, preserving quick no-op builds.
if [[ -f "$cert_dir/server.key" && -f "$cert_dir/other.key" ]] \
  && "$openssl_bin" x509 -in "$cert_dir/server.pem" -checkend 86400 -noout >/dev/null 2>&1 \
  && "$openssl_bin" x509 -in "$cert_dir/other.pem" -checkend 86400 -noout >/dev/null 2>&1; then
  exit 0
fi
umask 077
"$openssl_bin" req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$cert_dir/server.key" -out "$cert_dir/server.pem" -days 30 \
  -subj /CN=localhost -addext subjectAltName=DNS:localhost \
  -addext basicConstraints=critical,CA:TRUE >/dev/null 2>&1
"$openssl_bin" req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$cert_dir/other.key" -out "$cert_dir/other.pem" -days 30 \
  -subj /CN=other -addext basicConstraints=critical,CA:TRUE >/dev/null 2>&1
