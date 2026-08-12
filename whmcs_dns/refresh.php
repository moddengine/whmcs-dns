<?php

declare(strict_types=1);

use WHMCS\Module\Addon\Setting;

require dirname(__DIR__, 3) . '/init.php';
require_once __DIR__ . '/whmcs_dns.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

/** @param array<string, mixed> $body */
function whmcs_dns_refresh_response(int $status, array $body): never
{
    http_response_code($status);
    echo json_encode($body, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    header('Allow: POST');
    whmcs_dns_refresh_response(405, ['error' => 'Method not allowed.']);
}

$authorization = (string) ($_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '');
$tokenHash = (string) (Setting::getSettingValueForModule('whmcs_dns', 'refresh_api_token_hash') ?? '');
if (!whmcs_dns_api_token_valid($authorization, $tokenHash)) {
    whmcs_dns_refresh_response(401, ['error' => 'Unauthorized.']);
}

try {
    $rawBody = file_get_contents('php://input');
    if ($rawBody === false || strlen($rawBody) > 8192) {
        throw new InvalidArgumentException('Invalid request body.');
    }

    $body = json_decode($rawBody, true, 16, JSON_THROW_ON_ERROR);
    if (!is_array($body) || !is_string($body['domain'] ?? null)) {
        throw new InvalidArgumentException('JSON field "domain" is required.');
    }

    $provider = Setting::getSettingValueForModule('whmcs_dns', 'provider');
    $apiKey = Setting::getSettingValueForModule('whmcs_dns', 'apikey');
    if ($provider !== 'Bunny' || !$apiKey) {
        throw new RuntimeException('Bunny DNS is not configured.');
    }

    $domain = strtolower(rtrim(trim($body['domain']), '.'));
    $count = whmcs_dns_refresh_bunny_zone($domain, $apiKey);
    whmcs_dns_refresh_response(200, ['domain' => $domain, 'records' => $count]);
} catch (JsonException | InvalidArgumentException $e) {
    whmcs_dns_refresh_response(400, ['error' => $e->getMessage()]);
} catch (Throwable $e) {
    logModuleCall('whmcs_dns', 'refresh_zone', [], null, $e->getMessage());
    whmcs_dns_refresh_response(502, ['error' => 'Zone refresh failed.']);
}
