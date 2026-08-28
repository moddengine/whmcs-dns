<?php

declare(strict_types=1);

if (!defined('WHMCS')) {
    die('This file cannot be accessed directly');
}

use GuzzleHttp\Psr7\Response;
use PlexDNS\Service as PlexService;
use PlexDNS\UnsupportedProviderException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use WHMCS\Database\Capsule;

/**
 * @param array<string, mixed>|null $body
 * @param array<string, string> $headers
 */
function whmcs_dns_http_result(int $status, ?array $body = null, array $headers = []): ResponseInterface
{
    return new Response(
        $status,
        ['Content-Type' => 'application/json; charset=utf-8', 'Cache-Control' => 'no-store'] + $headers,
        $body === null ? null : json_encode($body, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)
    );
}

function whmcs_dns_emit_http_response(ResponseInterface $response): void
{
    http_response_code($response->getStatusCode());
    foreach ($response->getHeaders() as $name => $values) {
        header($name . ': ' . implode(', ', $values));
    }
    echo $response->getBody();
}

function whmcs_dns_http_path(string $pathInfo, string $requestUri): string
{
    if ($pathInfo !== '') {
        return $pathInfo;
    }
    $path = (string) (parse_url($requestUri, PHP_URL_PATH) ?? '');
    $offset = strpos($path, '/dns.php');
    return $offset === false ? '' : substr($path, $offset + strlen('/dns.php'));
}

function whmcs_dns_handle_http_request(ServerRequestInterface $request): ResponseInterface
{
    $server = $request->getServerParams();
    $path = whmcs_dns_http_path((string) ($server['PATH_INFO'] ?? ''), $request->getUri()->getPath());
    $segments = array_values(array_filter(
        explode('/', trim($path, '/')),
        static fn (string $part): bool => $part !== ''
    ));
    $segments = array_map('rawurldecode', $segments);
    if (array_filter($segments, static fn (string $part): bool => str_contains($part, '/')) !== []) {
        return whmcs_dns_http_result(404, ['error' => 'not_found', 'message' => 'API route not found.']);
    }

    $route = null;
    if (count($segments) === 3 && $segments[0] === 'record') {
        $route = ['kind' => 'record', 'fqdn' => $segments[1], 'type' => strtoupper($segments[2])];
    } elseif (count($segments) === 2 && $segments[0] === 'sync') {
        $route = ['kind' => 'sync', 'fqdn' => $segments[1]];
    }
    if ($route === null) {
        return whmcs_dns_http_result(404, ['error' => 'not_found', 'message' => 'API route not found.']);
    }

    $method = strtoupper($request->getMethod());
    $allowed = $route['kind'] === 'record' ? ['GET', 'PUT', 'DELETE'] : ['POST'];
    if (!in_array($method, $allowed, true)) {
        return whmcs_dns_http_result(
            405,
            ['error' => 'method_not_allowed', 'message' => 'Method not allowed.'],
            ['Allow' => implode(', ', $allowed)]
        );
    }

    $credential = whmcs_dns_authenticate_api_key($request);
    if ($credential === null) {
        return whmcs_dns_http_result(401, ['error' => 'unauthorized', 'message' => 'Invalid or missing API token.']);
    }

    try {
        $context = whmcs_dns_api_zone_context($route['fqdn']);
        $scope = $route['kind'] === 'sync' ? 'dns_admin' : ($method === 'GET' ? 'dns_read' : 'dns_write');
        if (!whmcs_dns_api_key_allows($credential, $scope, $context['domain'])) {
            return whmcs_dns_http_result(403, [
                'error' => 'forbidden',
                'message' => 'This DNS name cannot be managed by this API credential.',
            ]);
        }

        if ($route['kind'] === 'sync') {
            (new PlexService(Capsule::connection()->getPdo()))->sync($context['config']);
            return whmcs_dns_http_result(204);
        }

        if (!in_array($route['type'], whmcs_dns_api_record_types(), true)) {
            throw new InvalidArgumentException('Unsupported DNS record type.');
        }
        if ($method === 'GET') {
            $rrset = whmcs_dns_api_get_rrset($context, $route['fqdn'], $route['type']);
            return $rrset === null
                ? whmcs_dns_http_result(404, ['error' => 'record_not_found', 'message' => 'DNS record set was not found.'])
                : whmcs_dns_http_result(200, $rrset);
        }
        if ($method === 'DELETE') {
            whmcs_dns_api_delete_rrset($context, $route['fqdn'], $route['type']);
            return whmcs_dns_http_result(204);
        }

        $rawBody = (string) $request->getBody();
        if (strlen($rawBody) > 65536) {
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
        $result = whmcs_dns_api_put_rrset(
            $context,
            $route['fqdn'],
            $route['type'],
            (int) $ttl,
            $body['values']
        );
        return whmcs_dns_http_result($result['created'] ? 201 : 200, $result['rrset']);
    } catch (JsonException | InvalidArgumentException $e) {
        return whmcs_dns_http_result(400, ['error' => 'invalid_record', 'message' => $e->getMessage()]);
    } catch (UnexpectedValueException $e) {
        return whmcs_dns_http_result(
            $e->getCode() === 403 ? 403 : 400,
            $e->getCode() === 403
                ? ['error' => 'forbidden', 'message' => 'This DNS name cannot be managed by this API credential.']
                : ['error' => 'invalid_record', 'message' => $e->getMessage()]
        );
    } catch (UnsupportedProviderException) {
        return whmcs_dns_http_result(501, [
            'error' => 'unsupported_provider',
            'message' => 'DNS provider synchronization is not supported.',
        ]);
    } catch (Throwable $e) {
        logModuleCall('whmcs_dns', 'dns_api', [
            'method' => $method,
            'route' => $path,
            'key_id' => $credential['key_id'],
        ], null, $e->getMessage());
        return whmcs_dns_http_result(500, [
            'error' => 'provider_error',
            'message' => 'Unable to update DNS provider.',
        ]);
    }
}
