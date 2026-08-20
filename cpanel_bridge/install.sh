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

cluster_dir=/var/cpanel/cluster/root/config
install -d -m 0700 "$cluster_dir"
printf '%s\n' \
    '#version 2.0' \
    'user=root' \
    'host=whmcs-dns-bridge' \
    'pass=local-socket' \
    'module=WHMCSDNS' \
    'debug=off' \
    >"$cluster_dir/whmcs-dns-bridge"
printf 'write-only' >"$cluster_dir/whmcs-dns-bridge-dnsrole"
chmod 0600 "$cluster_dir/whmcs-dns-bridge" "$cluster_dir/whmcs-dns-bridge-dnsrole"
touch /var/cpanel/useclusteringdns

systemctl daemon-reload
systemctl enable whmcs-dns-bridge.service

echo "Installed the WHMCS-DNS backend with the Write-only role. Edit /usr/local/sbin/whmcs-dns-bridge.json, then start the service."
