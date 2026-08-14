#!/usr/bin/env bash
set -euo pipefail

bridge_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
output_dir=${1:-"$bridge_dir/dist"}
mkdir -p -- "$output_dir"
output_dir=$(cd -- "$output_dir" && pwd)

for arch in amd64 arm64; do
    release_tmp=$(mktemp -d "${TMPDIR:-/tmp}/whmcs-dns-bridge.XXXXXX")
    install_dir="$release_tmp/whmcs-dns-bridge"
    mkdir -p -- "$install_dir"
    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go -C "$bridge_dir" build -trimpath -ldflags='-s -w -buildid=' \
        -o "$install_dir/whmcs-dns-bridge" .
    cp -a -- \
        "$bridge_dir/cpanel" \
        "$bridge_dir/install.sh" \
        "$bridge_dir/uninstall.sh" \
        "$bridge_dir/whmcs-dns-bridge.json.example" \
        "$bridge_dir/whmcs-dns-bridge.service" \
        "$install_dir/"
    tar -C "$release_tmp" -czf "$output_dir/whmcs-dns-bridge-linux-$arch.tar.gz" whmcs-dns-bridge
    rm -rf -- "$release_tmp"
done
