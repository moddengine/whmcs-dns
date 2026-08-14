#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Run this uninstaller as root." >&2
    exit 1
fi

systemctl disable --now whmcs-dns-bridge.service || true
rm -f /etc/systemd/system/whmcs-dns-bridge.service \
    /usr/local/sbin/whmcs-dns-bridge \
    /usr/local/cpanel/Cpanel/NameServer/Remote/WHMCSDNS.pm \
    /usr/local/cpanel/Cpanel/NameServer/Setup/Remote/WHMCSDNS.pm
systemctl daemon-reload

echo "Removed the bridge. Configuration and queued/dead-letter jobs were retained."
