<?php

declare(strict_types=1);

require dirname(__DIR__, 3) . '/init.php';
require_once __DIR__ . '/whmcs_dns.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

/** @param array<string, mixed>|null $body */
function whmcs_dns_http_response(int $status, ?array $body = null): never
{
    http_response_code($status);
    if ($body !== null) {
        echo json_encode($body, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    }
    exit;
}

function whmcs_dns_http_error(int $status, string $error, string $message): never
{
    whmcs_dns_http_response($status, ['error' => $error, 'message' => $message]);
}

$path = (string) ($_SERVER['PATH_INFO'] ?? '');
if ($path === '') {
    $requestPath = (string) (parse_url((string) ($_SERVER['REQUEST_URI'] ?? ''), PHP_URL_PATH) ?? '');
    $offset = strpos($requestPath, '/dns.php');
    $path = $offset === false ? '' : substr($requestPath, $offset + strlen('/dns.php'));
}
$segments = array_values(array_filter(explode('/', trim($path, '/')), static fn (string $part): bool => $part !== ''));
$segments = array_map('rawurldecode', $segments);
if (array_filter($segments, static fn (string $part): bool => str_contains($part, '/')) !== []) {
    whmcs_dns_http_error(404, 'not_found', 'API route not found.');
}

$route = null;
if (count($segments) === 3 && $segments[0] === 'record') {
    $route = ['kind' => 'record', 'fqdn' => $segments[1], 'type' => strtoupper($segments[2])];
} elseif (count($segments) === 2 && $segments[0] === 'sync') {
    $route = ['kind' => 'sync', 'fqdn' => $segments[1]];
}
if ($route === null) {
    whmcs_dns_http_error(404, 'not_found', 'API route not found.');
}

$method = strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? ''));
$allowed = $route['kind'] === 'record' ? ['GET', 'PUT', 'DELETE'] : ['POST'];
if (!in_array($method, $allowed, true)) {
    header('Allow: ' . implode(', ', $allowed));
    whmcs_dns_http_error(405, 'method_not_allowed', 'Method not allowed.');
}

$credential = whmcs_dns_request_api_key();
if ($credential === null) {
    whmcs_dns_http_error(401, 'unauthorized', 'Invalid or missing API token.');
}

try {
    $context = whmcs_dns_api_zone_context($route['fqdn']);
    $scope = $route['kind'] === 'sync' ? 'dns_admin' : ($method === 'GET' ? 'dns_read' : 'dns_write');
    if (!whmcs_dns_api_key_allows($credential, $scope, $context['domain'])) {
        whmcs_dns_http_error(403, 'forbidden', 'This DNS name cannot be managed by this API credential.');
    }

    if ($route['kind'] === 'sync') {
        if ($context['provider'] !== 'Bunny') {
            throw new RuntimeException('DNS provider synchronization is not supported.');
        }
        whmcs_dns_refresh_bunny_zone($context['domain'], (string) $context['config']['apikey']);
        whmcs_dns_http_response(204);
    }

    if (!in_array($route['type'], whmcs_dns_api_record_types(), true)) {
        throw new InvalidArgumentException('Unsupported DNS record type.');
    }
    if ($method === 'GET') {
        $rrset = whmcs_dns_api_get_rrset($context, $route['fqdn'], $route['type']);
        if ($rrset === null) {
            whmcs_dns_http_error(404, 'record_not_found', 'DNS record set was not found.');
        }
        whmcs_dns_http_response(200, $rrset);
    }
    if ($method === 'DELETE') {
        whmcs_dns_api_delete_rrset($context, $route['fqdn'], $route['type']);
        whmcs_dns_http_response(204);
    }

    $rawBody = file_get_contents('php://input');
    if ($rawBody === false || strlen($rawBody) > 65536) {
        throw new InvalidArgumentException('Invalid request body.');
    }
    $body = json_decode($rawBody, true, 16, JSON_THROW_ON_ERROR);
    if (!is_array($body) || array_diff(array_keys($body), ['ttl', 'values']) !== []
        || !array_key_exists('values', $body) || !is_array($body['values'])) {
        throw new InvalidArgumentException('A JSON object containing values is required.');
    }
    $ttl = filter_var($body['ttl'] ?? 300, FILTER_VALIDATE_INT, [
        'options' => ['min_range' => 1, 'max_range' => 2147483647],
    ]);
    if ($ttl === false) {
        throw new InvalidArgumentException('TTL must be a positive integer.');
    }
    $result = whmcs_dns_api_put_rrset($context, $route['fqdn'], $route['type'], (int) $ttl, $body['values']);
    whmcs_dns_http_response($result['created'] ? 201 : 200, $result['rrset']);
} catch (JsonException | InvalidArgumentException $e) {
    whmcs_dns_http_error(400, 'invalid_record', $e->getMessage());
} catch (UnexpectedValueException $e) {
    if ($e->getCode() === 403) {
        whmcs_dns_http_error(403, 'forbidden', 'This DNS name cannot be managed by this API credential.');
    }
    whmcs_dns_http_error(400, 'invalid_record', $e->getMessage());
} catch (Throwable $e) {
    logModuleCall('whmcs_dns', 'dns_api', [
        'method' => $method,
        'route' => $path,
        'key_id' => $credential['key_id'],
    ], null, $e->getMessage());
    whmcs_dns_http_error(500, 'provider_error', 'Unable to update DNS provider.');
}
