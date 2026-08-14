#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Run this installer as root." >&2
    exit 1
fi

source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
install -m 0755 "$source_dir/whmcs-dns-bridge" /usr/local/sbin/whmcs-dns-bridge
if [[ ! -e /usr/local/sbin/whmcs-dns-bridge.json ]]; then
    install -m 0600 "$source_dir/whmcs-dns-bridge.json.example" /usr/local/sbin/whmcs-dns-bridge.json
fi
install -D -m 0644 "$source_dir/whmcs-dns-bridge.service" /etc/systemd/system/whmcs-dns-bridge.service
install -D -m 0644 "$source_dir/cpanel/Cpanel/NameServer/Remote/WHMCSDNS.pm" \
    /usr/local/cpanel/Cpanel/NameServer/Remote/WHMCSDNS.pm
install -D -m 0644 "$source_dir/cpanel/Cpanel/NameServer/Setup/Remote/WHMCSDNS.pm" \
    /usr/local/cpanel/Cpanel/NameServer/Setup/Remote/WHMCSDNS.pm

systemctl daemon-reload
systemctl enable whmcs-dns-bridge.service

echo "Installed. Edit /usr/local/sbin/whmcs-dns-bridge.json, start the service, then add the WHMCS-DNS backend in WHM's DNS Cluster page."
