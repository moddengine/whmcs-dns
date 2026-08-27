<?php

declare(strict_types=1);

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

$credential = whmcs_dns_request_api_key();
if ($credential === null) {
    whmcs_dns_cpanel_response(401, ['status' => 'error', 'error' => 'Unauthorized.']);
}

$request = [];
try {
    $rawBody = file_get_contents('php://input');
    if ($rawBody === false) {
        throw new InvalidArgumentException('Invalid request body.');
    }
    $request = whmcs_dns_cpanel_request($rawBody);
    $context = whmcs_dns_cpanel_record_context(
        $request['server_id'],
        $request['cpanel_user'],
        $request['domain']
    );
    if (!whmcs_dns_api_key_allows($credential, 'dns_write', $context['zone'])
        || !whmcs_dns_api_key_allows($credential, 'dns_admin', $context['zone'])) {
        whmcs_dns_cpanel_response(403, ['status' => 'error', 'error' => 'Forbidden.']);
    }
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
