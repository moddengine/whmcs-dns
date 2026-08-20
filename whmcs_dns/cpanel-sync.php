<?php

declare(strict_types=1);

use WHMCS\Module\Addon\Setting;

require dirname(__DIR__, 3) . '/init.php';
require_once __DIR__ . '/whmcs_dns.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

/** @param array<string, string> $body */
function whmcs_dns_cpanel_response(int $status, array $body): never
{
    http_response_code($status);
    echo json_encode($body, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    header('Allow: POST');
    whmcs_dns_cpanel_response(405, ['status' => 'error', 'error' => 'Method not allowed.']);
}

$authorization = (string) ($_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '');
$tokenHash = (string) (Setting::getSettingValueForModule('whmcs_dns', 'cpanel_sync_api_token_hash') ?? '');
if (!whmcs_dns_api_token_valid($authorization, $tokenHash, (string) ($_SERVER['HTTP_AUTH_KEY'] ?? ''))) {
    whmcs_dns_cpanel_response(401, ['status' => 'error', 'error' => 'Unauthorized.']);
}

$request = [];
try {
    $rawBody = file_get_contents('php://input');
    if ($rawBody === false) {
        throw new InvalidArgumentException('Invalid request body.');
    }
    $request = whmcs_dns_cpanel_request($rawBody);
    whmcs_dns_cpanel_response(200, whmcs_dns_sync_cpanel_record($request));
} catch (JsonException | InvalidArgumentException $e) {
    whmcs_dns_cpanel_response(400, ['status' => 'error', 'error' => $e->getMessage()]);
} catch (UnexpectedValueException $e) {
    whmcs_dns_cpanel_response($e->getCode() ?: 409, ['status' => 'error', 'error' => $e->getMessage()]);
} catch (Throwable $e) {
    logModuleCall(
        'whmcs_dns',
        'cpanel_sync',
        ['server_id' => $request['server_id'] ?? null, 'domain' => $request['domain'] ?? null],
        null,
        $e->getMessage()
    );
    whmcs_dns_cpanel_response(502, ['status' => 'error', 'error' => 'cPanel DNS synchronization failed.']);
}
