<?php

declare(strict_types=1);

if (!defined('WHMCS')) {
    die('This file cannot be accessed directly');
}

use WHMCS\Database\Capsule;
use Psr\Http\Message\ServerRequestInterface;

define('WHMCSDNS_TABLE_API_KEYS', 'whmcs_dns_api_keys');

function whmcs_dns_create_api_key_table(): void
{
    if (Capsule::schema()->hasTable(WHMCSDNS_TABLE_API_KEYS)) {
        return;
    }

    Capsule::schema()->create(WHMCSDNS_TABLE_API_KEYS, function ($table) {
        /** @var \Illuminate\Database\Schema\Blueprint $table */
        $table->bigIncrements('id');
        $table->string('key_id', 32)->unique();
        $table->string('key_hash', 255);
        $table->string('name', 255);
        $table->text('scopes');
        $table->text('domains');
        $table->bigInteger('expires_at')->unsigned()->default(0)->index();
        $table->dateTime('created_at')->useCurrent();
    });
}

/** @return array<int, string> */
function whmcs_dns_api_scopes(mixed $scopes): array
{
    if (!is_array($scopes)) {
        throw new InvalidArgumentException('At least one API scope is required.');
    }
    $allowed = ['dns_read', 'dns_write', 'dns_admin', 'auth_admin'];
    $scopes = array_values(array_unique(array_map(
        static fn (mixed $scope): string => is_string($scope) ? trim($scope) : '',
        $scopes
    )));
    if ($scopes === [] || in_array('', $scopes, true) || array_diff($scopes, $allowed) !== []) {
        throw new InvalidArgumentException('Invalid API scopes.');
    }
    sort($scopes);
    return $scopes;
}

/** @return array<int, string> */
function whmcs_dns_api_domains(mixed $domains): array
{
    $domains = is_string($domains) ? preg_split('/[\r\n,]+/', $domains) : $domains;
    if (!is_array($domains)) {
        throw new InvalidArgumentException('At least one API domain is required.');
    }
    $domains = array_values(array_unique(array_filter(array_map(
        static fn (mixed $domain): string => is_string($domain)
            ? whmcs_dns_normalize_hostname($domain)
            : '',
        $domains
    ), static fn (string $domain): bool => $domain !== '')));
    if ($domains === ['*']) {
        return $domains;
    }
    if ($domains === [] || in_array('*', $domains, true)) {
        throw new InvalidArgumentException('Use either * or a list of API domains.');
    }
    foreach ($domains as $domain) {
        if (filter_var($domain, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false) {
            throw new InvalidArgumentException("Invalid API domain: {$domain}.");
        }
    }
    sort($domains);
    return $domains;
}

/** @return array{key_id: string, key: string, key_hash: string} */
function whmcs_dns_generate_api_key(): array
{
    $keyId = 'WDNS_' . bin2hex(random_bytes(8));
    $secret = bin2hex(random_bytes(32));
    return [
        'key_id' => $keyId,
        'key' => $keyId . '_' . $secret,
        'key_hash' => password_hash($secret, PASSWORD_DEFAULT),
    ];
}

function whmcs_dns_presented_api_key(string $authorization, string $authKey): ?string
{
    $authKey = trim($authKey);
    $bearer = '';
    if (trim($authorization) !== '') {
        if (preg_match('/^Bearer\s+(\S+)$/iD', trim($authorization), $matches) !== 1) {
            return null;
        }
        $bearer = $matches[1];
    }
    if ($authKey !== '' && $bearer !== '' && !hash_equals($authKey, $bearer)) {
        return null;
    }
    return $authKey !== '' ? $authKey : ($bearer !== '' ? $bearer : null);
}

/** @return array{id: int, key_id: string, scopes: array<int, string>, domains: array<int, string>}|null */
function whmcs_dns_authenticate_api_key(ServerRequestInterface $request): ?array
{
    $key = whmcs_dns_presented_api_key(
        $request->getHeaderLine('Authorization'),
        $request->getHeaderLine('Auth-Key')
    );
    if ($key === null || preg_match('/^(WDNS_[a-f0-9]{16})_([a-f0-9]{64})$/D', $key, $matches) !== 1) {
        return null;
    }
    $row = Capsule::table(WHMCSDNS_TABLE_API_KEYS)->where('key_id', $matches[1])->first();
    if (!$row || ((int) $row->expires_at !== 0 && (int) $row->expires_at <= time())
        || !password_verify($matches[2], (string) $row->key_hash)) {
        return null;
    }
    try {
        $scopes = whmcs_dns_api_scopes(json_decode((string) $row->scopes, true, 8, JSON_THROW_ON_ERROR));
        $domains = whmcs_dns_api_domains(json_decode((string) $row->domains, true, 8, JSON_THROW_ON_ERROR));
    } catch (JsonException | InvalidArgumentException) {
        return null;
    }
    return ['id' => (int) $row->id, 'key_id' => (string) $row->key_id, 'scopes' => $scopes, 'domains' => $domains];
}

/** @param array{scopes: array<int, string>, domains: array<int, string>} $credential */
function whmcs_dns_api_key_allows(array $credential, string $scope, string $zone): bool
{
    return in_array($scope, $credential['scopes'], true)
        && (in_array('*', $credential['domains'], true)
            || in_array(whmcs_dns_normalize_hostname($zone), $credential['domains'], true));
}

function whmcs_dns_cleanup_expired_api_keys(int $now = 0): int
{
    if (!Capsule::schema()->hasTable(WHMCSDNS_TABLE_API_KEYS)) {
        return 0;
    }
    $cutoff = ($now ?: time()) - 14 * 86400;
    return Capsule::table(WHMCSDNS_TABLE_API_KEYS)
        ->where('expires_at', '>', 0)
        ->where('expires_at', '<=', $cutoff)
        ->delete();
}

function whmcs_dns_api_expiry(mixed $value): int
{
    if (!is_string($value) || trim($value) === '') {
        return 0;
    }
    $date = DateTimeImmutable::createFromFormat('!Y-m-d\TH:i', trim($value));
    $errors = DateTimeImmutable::getLastErrors();
    if (!$date || ($errors !== false && ($errors['warning_count'] > 0 || $errors['error_count'] > 0))
        || $date->getTimestamp() <= time()) {
        throw new InvalidArgumentException('API key expiry must be a valid future date and time.');
    }
    return $date->getTimestamp();
}

function whmcs_dns_admin_handle_api_keys(): void
{
    $action = (string) ($_POST['action'] ?? '');
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST'
        || !in_array($action, ['create_api_key', 'revoke_api_key'], true)) {
        return;
    }

    try {
        check_token('WHMCS.admin.default');
        if ($action === 'create_api_key') {
            $name = trim((string) ($_POST['name'] ?? ''));
            if ($name === '' || strlen($name) > 255) {
                throw new InvalidArgumentException('API key name must contain between 1 and 255 characters.');
            }
            $scopes = whmcs_dns_api_scopes($_POST['scopes'] ?? null);
            $domains = whmcs_dns_api_domains($_POST['domains'] ?? null);
            $expiresAt = whmcs_dns_api_expiry($_POST['expires_at'] ?? null);
            do {
                $generated = whmcs_dns_generate_api_key();
            } while (Capsule::table(WHMCSDNS_TABLE_API_KEYS)->where('key_id', $generated['key_id'])->exists());
            Capsule::table(WHMCSDNS_TABLE_API_KEYS)->insert([
                'key_id' => $generated['key_id'],
                'key_hash' => $generated['key_hash'],
                'name' => $name,
                'scopes' => json_encode($scopes, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR),
                'domains' => json_encode($domains, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR),
                'expires_at' => $expiresAt,
                'created_at' => date('Y-m-d H:i:s'),
            ]);
            $_SESSION['whmcs_dns_new_api_key'] = [
                'key_id' => $generated['key_id'],
                'key' => $generated['key'],
            ];
            logActivity("WHMCS DNS admin: Created API key {$generated['key_id']} ({$name}).");
        } else {
            $id = filter_var($_POST['key_id'] ?? null, FILTER_VALIDATE_INT, [
                'options' => ['min_range' => 1],
            ]);
            $row = $id === false ? null : Capsule::table(WHMCSDNS_TABLE_API_KEYS)->where('id', $id)->first();
            if (!$row) {
                throw new InvalidArgumentException('API key not found.');
            }
            Capsule::table(WHMCSDNS_TABLE_API_KEYS)->where('id', $id)->delete();
            logActivity("WHMCS DNS admin: Revoked API key {$row->key_id} ({$row->name}).");
        }
        redir('module=whmcs_dns', 'addonmodules.php');
    } catch (Throwable $e) {
        logModuleCall('whmcs_dns', 'manage_api_key', [], null, $e->getMessage());
        redir('module=whmcs_dns&dns_error=' . urlencode($e->getMessage()), 'addonmodules.php');
    }
}

function whmcs_dns_admin_api_keys_output(string $moduleLink, callable $escape, string $token): void
{
    $newApiKey = $_SESSION['whmcs_dns_new_api_key'] ?? null;
    unset($_SESSION['whmcs_dns_new_api_key']);

    echo '<details' . (is_array($newApiKey) ? ' open' : '') . '><summary><strong>Automation API Keys</strong></summary>';
    echo '<p>Keys are shown once. Scopes are independent and domain access is limited to the listed managed apexes.</p>';
    if (is_array($newApiKey) && isset($newApiKey['key_id'], $newApiKey['key'])) {
        echo '<div class="alert alert-warning"><strong>' . $escape($newApiKey['key_id'])
            . ' (copy now):</strong><br><code style="user-select:all">'
            . $escape($newApiKey['key']) . '</code></div>';
    }
    echo '<form method="post" action="' . $escape($moduleLink) . '" class="form-inline" style="margin-bottom:20px">'
        . '<input type="hidden" name="token" value="' . $escape($token) . '">'
        . '<input type="hidden" name="action" value="create_api_key">'
        . '<div class="form-group" style="margin:0 12px 8px 0"><label>Name<br>'
        . '<input class="form-control" type="text" name="name" maxlength="255" required></label></div>'
        . '<div class="form-group" style="margin:0 12px 8px 0"><label>Domains (one per line or *)<br>'
        . '<textarea class="form-control" name="domains" rows="2" required></textarea></label></div>'
        . '<div class="form-group" style="margin:0 12px 8px 0"><label>Expiry (optional)<br>'
        . '<input class="form-control" type="datetime-local" name="expires_at"></label></div>'
        . '<div class="form-group" style="margin:0 12px 8px 0"><strong>Scopes</strong><br>';
    foreach (['dns_read' => 'DNS read', 'dns_write' => 'DNS write', 'dns_admin' => 'DNS admin', 'auth_admin' => 'Auth admin'] as $scope => $label) {
        echo '<label class="checkbox-inline"><input type="checkbox" name="scopes[]" value="'
            . $escape($scope) . '"> ' . $escape($label) . '</label>';
    }
    echo '</div><button class="btn btn-primary" type="submit">Create key</button></form>';

    $keys = Capsule::table(WHMCSDNS_TABLE_API_KEYS)->orderBy('id', 'desc')->get();
    echo '<div class="table-responsive"><table class="table table-striped table-bordered"><thead><tr>'
        . '<th>Key ID</th><th>Name</th><th>Scopes</th><th>Domains</th><th>Expiry</th><th>Action</th>'
        . '</tr></thead><tbody>';
    foreach ($keys as $key) {
        $expiresAt = (int) $key->expires_at;
        $expired = $expiresAt !== 0 && $expiresAt <= time();
        echo '<tr><td><code>' . $escape($key->key_id) . '</code></td><td>' . $escape($key->name)
            . '</td><td>' . $escape(implode(', ', whmcs_dns_api_scopes(json_decode((string) $key->scopes, true))))
            . '</td><td>' . $escape(implode(', ', whmcs_dns_api_domains(json_decode((string) $key->domains, true))))
            . '</td><td>' . ($expiresAt === 0 ? 'Never' : $escape(date('Y-m-d H:i', $expiresAt))
                . ($expired ? ' <span class="label label-danger">Expired</span>' : ''))
            . '</td><td><form method="post" action="' . $escape($moduleLink)
            . '" onsubmit="return confirm(&quot;Revoke this API key immediately?&quot;)">'
            . '<input type="hidden" name="token" value="' . $escape($token) . '">'
            . '<input type="hidden" name="action" value="revoke_api_key">'
            . '<input type="hidden" name="key_id" value="' . (int) $key->id . '">'
            . '<button class="btn btn-danger btn-xs" type="submit">Revoke</button></form></td></tr>';
    }
    if ($keys->isEmpty()) {
        echo '<tr><td colspan="6">No API keys configured.</td></tr>';
    }
    echo '</tbody></table></div></details>';
}
