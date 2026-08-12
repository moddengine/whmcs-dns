<?php

declare(strict_types=1);

use WHMCS\Database\Capsule;
use WHMCS\Module\Addon\Setting;
use PlexDNS\Providers\Bunny as BunnyProvider;

require dirname(__DIR__, 3) . '/init.php';
require_once __DIR__ . '/whmcs_dns.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

/** @param array<string, string> $body */
function whmcs_dns_connect_website_response(int $status, array $body): never
{
    http_response_code($status);
    echo json_encode($body, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    header('Allow: POST');
    whmcs_dns_connect_website_response(405, ['status' => 'error', 'error' => 'Method not allowed.']);
}

$authorization = (string) ($_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '');
$tokenHash = (string) (Setting::getSettingValueForModule('whmcs_dns', 'connect_website_api_token_hash') ?? '');
if (!whmcs_dns_api_token_valid($authorization, $tokenHash)) {
    whmcs_dns_connect_website_response(401, ['status' => 'error', 'error' => 'Unauthorized.']);
}

$domain = '';
$apiKey = '';
try {
    $rawBody = file_get_contents('php://input');
    if ($rawBody === false || strlen($rawBody) > 8192) {
        throw new InvalidArgumentException('Invalid request body.');
    }
    $request = whmcs_dns_website_request($rawBody);
    $domain = $request['domain'];
    $ipv4 = $request['ipv4'];

    $domains = Capsule::table('tbldomains')
        ->select('userid', 'domain')
        ->where('domain', $domain)
        ->where('status', 'Active')
        ->get()
        ->filter(fn ($row): bool => whmcs_dns_normalize_hostname((string) $row->domain) === $domain)
        ->values();
    if ($domains->count() !== 1) {
        whmcs_dns_connect_website_response(404, ['status' => 'error', 'error' => 'An exact active WHMCS domain is required.']);
    }
    $clientId = (int) $domains->first()->userid;

    if (Setting::getSettingValueForModule('whmcs_dns', 'provider') !== 'Bunny') {
        throw new RuntimeException('Bunny DNS is not configured.');
    }
    $apiKey = (string) (Setting::getSettingValueForModule('whmcs_dns', 'apikey') ?? '');
    if ($apiKey === '') {
        throw new RuntimeException('Bunny DNS is not configured.');
    }

    $zone = Capsule::table(WHMCSDNS_TABLE_ZONES)->where('domain_name', $domain)->first();
    if ($zone && (int) $zone->client_id !== $clientId) {
        throw new UnexpectedValueException('The local zone belongs to another WHMCS client.', 409);
    }

    $locator = new BunnyProvider(['apikey' => $apiKey]);
    $remoteZones = array_values(array_filter(
        $locator->listDomains(),
        fn ($remote): bool => is_array($remote)
            && whmcs_dns_normalize_hostname((string) ($remote['domain'] ?? '')) === $domain
    ));
    if (count($remoteZones) > 1) {
        throw new UnexpectedValueException('Multiple exact Bunny zones were found.', 409);
    }
    if ($remoteZones === []) {
        $created = $locator->createDomain($domain);
        if (!is_array($created) || !is_numeric($created['Id'] ?? null)) {
            throw new RuntimeException('Bunny did not return the new zone ID.');
        }
        $zoneId = (string) $created['Id'];
    } elseif (!is_numeric($remoteZones[0]['id'] ?? null)) {
        throw new RuntimeException('Bunny returned an invalid zone ID.');
    } else {
        $zoneId = (string) $remoteZones[0]['id'];
    }

    $config = json_encode(['provider' => 'Bunny'], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    $now = date('Y-m-d H:i:s');
    if ($zone) {
        Capsule::table(WHMCSDNS_TABLE_ZONES)->where('id', $zone->id)->update([
            'client_id' => $clientId, 'zoneId' => $zoneId, 'config' => $config, 'updated_at' => $now,
        ]);
    } else {
        Capsule::table(WHMCSDNS_TABLE_ZONES)->insert([
            'client_id' => $clientId, 'domain_name' => $domain, 'zoneId' => $zoneId, 'config' => $config,
            'created_at' => $now, 'updated_at' => $now,
        ]);
    }

    whmcs_dns_refresh_bunny_zone($domain, $apiKey);
    $zone = Capsule::table(WHMCSDNS_TABLE_ZONES)->where('domain_name', $domain)->first();
    $records = Capsule::table(WHMCSDNS_TABLE_RECORDS)->where('domain_id', $zone->id)->get()->map(
        fn ($record): array => (array) $record
    )->toArray();
    $provider = new BunnyProvider(['apikey' => $apiKey, 'domain_name' => $domain, 'zone_id' => $zoneId]);
    whmcs_dns_reconcile_bunny_website($provider, $clientId, $domain, $ipv4, $records);
    whmcs_dns_refresh_bunny_zone($domain, $apiKey);

    whmcs_dns_connect_website_response(200, ['status' => 'ok', 'error' => '']);
} catch (JsonException | InvalidArgumentException $e) {
    whmcs_dns_connect_website_response(400, ['status' => 'error', 'error' => $e->getMessage()]);
} catch (UnexpectedValueException $e) {
    whmcs_dns_connect_website_response($e->getCode() ?: 409, ['status' => 'error', 'error' => $e->getMessage()]);
} catch (Throwable $e) {
    if ($domain !== '' && $apiKey !== '') {
        try {
            whmcs_dns_refresh_bunny_zone($domain, $apiKey);
        } catch (Throwable) {
        }
    }
    logModuleCall('whmcs_dns', 'connect_website', ['domain' => $domain], null, $e->getMessage());
    whmcs_dns_connect_website_response(502, ['status' => 'error', 'error' => 'Website DNS reconciliation failed.']);
}
