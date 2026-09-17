#!/usr/bin/env bash
set -euo pipefail

module_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
output_dir=${1:-"$module_dir/dist"}
mkdir -p -- "$output_dir"
output_dir=$(cd -- "$output_dir" && pwd)

# This is PHP code, not a shell expression.
# shellcheck disable=SC2016
version=${2:-$(php -r '$m=json_decode(file_get_contents($argv[1]), true, flags: JSON_THROW_ON_ERROR); echo $m["version"];' "$module_dir/whmcs.json")}
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "invalid release version: $version" >&2; exit 1; }
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

# This is PHP code, not a shell expression.
# shellcheck disable=SC2016
php -r '$p=$argv[1]; $m=json_decode(file_get_contents($p), true, flags: JSON_THROW_ON_ERROR); $m["version"]=$argv[2]; file_put_contents($p, json_encode($m, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR).PHP_EOL);' "$install_dir/whmcs.json" "$version"
sed -Ei "s/'version'[[:space:]]*=>[[:space:]]*'[0-9]+\.[0-9]+\.[0-9]+'/'version' => '$version'/" "$install_dir/whmcs_dns.php"

composer install \
    --working-dir="$install_dir" \
    --no-dev \
    --no-interaction \
    --optimize-autoloader
composer check-platform-reqs --working-dir="$install_dir" --no-dev

test -f "$install_dir/vendor/autoload.php"
test -d "$install_dir/vendor/namingo/plexdns"

"$module_dir/vendor/bin/whmcs-plugin-manifest" "$install_dir" \
    --repository moddengine/whmcs-dns \
    --whmcs-max-exclusive 10.0.0

archive_name="whmcs-dns-$version.zip"
(cd -- "$release_tmp" && zip -qr "$archive_name" whmcs_dns)
mv -f -- "$release_tmp/$archive_name" "$output_dir/$archive_name"

echo "$output_dir/$archive_name"
