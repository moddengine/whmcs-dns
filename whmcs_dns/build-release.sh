#!/usr/bin/env bash
set -euo pipefail

module_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
output_dir=${1:-"$module_dir/dist"}
mkdir -p -- "$output_dir"
output_dir=$(cd -- "$output_dir" && pwd)

# This is PHP code, not a shell expression.
# shellcheck disable=SC2016
version=$(php -r '$m=json_decode(file_get_contents($argv[1]), true, flags: JSON_THROW_ON_ERROR); echo $m["version"];' "$module_dir/whmcs.json")
release_tmp=$(mktemp -d "${TMPDIR:-/tmp}/whmcs-dns-release.XXXXXX")
trap 'rm -rf -- "$release_tmp"' EXIT

install_dir="$release_tmp/whmcs_dns"
mkdir -p -- "$install_dir"
cp -a -- \
    "$module_dir/api-keys.php" \
    "$module_dir/composer.json" \
    "$module_dir/composer.lock" \
    "$module_dir/connect-website.php" \
    "$module_dir/connect-website-handler.php" \
    "$module_dir/cpanel-sync.php" \
    "$module_dir/cpanel-sync-handler.php" \
    "$module_dir/dns.php" \
    "$module_dir/dns-handler.php" \
    "$module_dir/hooks.php" \
    "$module_dir/openapi-dns-api.yaml" \
    "$module_dir/permissions.php" \
    "$module_dir/templates" \
    "$module_dir/whmcs.json" \
    "$module_dir/whmcs_dns.php" \
    "$install_dir/"

composer install \
    --working-dir="$install_dir" \
    --no-dev \
    --no-interaction \
    --optimize-autoloader
composer check-platform-reqs --working-dir="$install_dir" --no-dev

test -f "$install_dir/vendor/autoload.php"
test -d "$install_dir/vendor/namingo/plexdns"

archive_name="whmcs-dns-$version.zip"
(cd -- "$release_tmp" && zip -qr "$archive_name" whmcs_dns)
mv -f -- "$release_tmp/$archive_name" "$output_dir/$archive_name"

echo "$output_dir/$archive_name"
