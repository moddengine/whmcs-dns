<?php

declare(strict_types=1);

if (!defined('WHMCS')) {
    die('This file cannot be accessed directly');
}

require_once __DIR__ . '/dns-handler.php';

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

function whmcs_dns_handle_cpanel_sync_request(ServerRequestInterface $request): ResponseInterface
{
    if (strtoupper($request->getMethod()) !== 'POST') {
        return whmcs_dns_http_result(
            405,
            ['status' => 'error', 'error' => 'Method not allowed.'],
            ['Allow' => 'POST']
        );
    }

    $credential = whmcs_dns_authenticate_api_key($request);
    if ($credential === null) {
        return whmcs_dns_http_result(401, ['status' => 'error', 'error' => 'Unauthorized.']);
    }

    $body = [];
    try {
        $body = whmcs_dns_cpanel_request((string) $request->getBody());
        $context = whmcs_dns_cpanel_record_context(
            $body['server_id'],
            $body['cpanel_user'],
            $body['domain']
        );
        if (!whmcs_dns_api_key_allows($credential, 'dns_write', $context['zone'])
            || !whmcs_dns_api_key_allows($credential, 'dns_admin', $context['zone'])) {
            return whmcs_dns_http_result(403, ['status' => 'error', 'error' => 'Forbidden.']);
        }
        return whmcs_dns_http_result(200, whmcs_dns_sync_cpanel_record($body));
    } catch (JsonException | InvalidArgumentException $e) {
        return whmcs_dns_http_result(400, ['status' => 'error', 'error' => $e->getMessage()]);
    } catch (UnexpectedValueException $e) {
        return whmcs_dns_http_result(
            $e->getCode() ?: 409,
            ['status' => 'error', 'error' => $e->getMessage()]
        );
    } catch (Throwable $e) {
        logModuleCall(
            'whmcs_dns',
            'cpanel_sync',
            ['server_id' => $body['server_id'] ?? null, 'domain' => $body['domain'] ?? null],
            null,
            $e->getMessage()
        );
        return whmcs_dns_http_result(
            502,
            ['status' => 'error', 'error' => 'cPanel DNS synchronization failed.']
        );
    }
}
