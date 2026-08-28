<?php

declare(strict_types=1);

if (!defined('WHMCS')) {
    die('This file cannot be accessed directly');
}

require_once __DIR__ . '/dns-handler.php';

use PlexDNS\Providers\Bunny as BunnyProvider;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use WHMCS\Database\Capsule;
use WHMCS\Module\Addon\Setting;

function whmcs_dns_handle_connect_website_request(ServerRequestInterface $request): ResponseInterface
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

    $domain = '';
    try {
        $body = whmcs_dns_website_request((string) $request->getBody());
        $domain = $body['domain'];
        $ipv4 = $body['ipv4'];
        if (!whmcs_dns_api_key_allows($credential, 'dns_write', $domain)) {
            return whmcs_dns_http_result(403, ['status' => 'error', 'error' => 'Forbidden.']);
        }

        $domains = Capsule::table('tbldomains')
            ->select('userid', 'domain')
            ->where('domain', $domain)
            ->where('status', 'Active')
            ->get()
            ->filter(fn ($row): bool => whmcs_dns_normalize_hostname((string) $row->domain) === $domain)
            ->values();
        if ($domains->count() !== 1) {
            return whmcs_dns_http_result(
                404,
                ['status' => 'error', 'error' => 'An exact active WHMCS domain is required.']
            );
        }
        $clientId = (int) $domains->first()->userid;

        $zone = Capsule::table(WHMCSDNS_TABLE_ZONES)->where('domain_name', $domain)->first();
        if (!$zone) {
            throw new UnexpectedValueException('DNS is not enabled for this domain.', 404);
        }
        if ((int) $zone->client_id !== $clientId) {
            throw new UnexpectedValueException('The local zone belongs to another WHMCS client.', 409);
        }

        if (Setting::getSettingValueForModule('whmcs_dns', 'provider') !== 'Bunny') {
            throw new RuntimeException('Bunny DNS is not configured.');
        }
        $apiKey = (string) (Setting::getSettingValueForModule('whmcs_dns', 'apikey') ?? '');
        if ($apiKey === '') {
            throw new RuntimeException('Bunny DNS is not configured.');
        }

        $zoneId = (string) $zone->zoneId;
        $records = Capsule::table(WHMCSDNS_TABLE_RECORDS)->where('domain_id', $zone->id)->get()->map(
            fn ($record): array => (array) $record
        )->toArray();
        $provider = new BunnyProvider(['apikey' => $apiKey, 'domain_name' => $domain, 'zone_id' => $zoneId]);
        whmcs_dns_reconcile_bunny_website($provider, $clientId, $domain, $ipv4, $records);

        return whmcs_dns_http_result(200, ['status' => 'ok', 'error' => '']);
    } catch (JsonException | InvalidArgumentException $e) {
        return whmcs_dns_http_result(400, ['status' => 'error', 'error' => $e->getMessage()]);
    } catch (UnexpectedValueException $e) {
        return whmcs_dns_http_result(
            $e->getCode() ?: 409,
            ['status' => 'error', 'error' => $e->getMessage()]
        );
    } catch (Throwable $e) {
        logModuleCall('whmcs_dns', 'connect_website', ['domain' => $domain], null, $e->getMessage());
        return whmcs_dns_http_result(
            502,
            ['status' => 'error', 'error' => 'Website DNS reconciliation failed.']
        );
    }
}
