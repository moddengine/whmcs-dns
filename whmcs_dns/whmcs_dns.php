<?php
/**
 * WHMCS-DNS module
 *
 * Written in 2025-2026 by Taras Kondratyuk (https://namingo.org)
 *
 * @license MIT
 * @see https://opensource.org/licenses/MIT
 */

if (!defined("WHMCS")) {
    die("This file cannot be accessed directly");
}

use WHMCS\Database\Capsule;
use WHMCS\Module\Addon\Setting;
use PlexDNS\Service as PlexService;
use PlexDNS\UnsupportedProviderException;
use PlexDNS\Providers\Bunny as BunnyProvider;

define('WHMCSDNS_TABLE_ZONES', 'zones');
define('WHMCSDNS_TABLE_RECORDS', 'records');
define('WHMCSDNS_TABLE_RATE_LIMITS', 'whmcs_dns_rate_limits');
define('WHMCSDNS_MUTATION_LIMIT', 30);
define('WHMCSDNS_MUTATION_WINDOW', 60);
define('WHMCSDNS_INTEGRATION_API_VERSION', 1);

$autoload = __DIR__ . '/vendor/autoload.php';
if (file_exists($autoload)) {
    require_once $autoload;
}
require_once __DIR__ . '/permissions.php';
require_once __DIR__ . '/api-keys.php';

/**
 * Addon module config
 *
 * @return array<string, mixed>
 */
function whmcs_dns_config(): array
{
    return [
        'name'        => 'DNS Hosting',
        'description' => 'DNS management addon enabling zone and record control via external providers',
        'author'      => 'Namingo',
        'language'    => 'english',
        'version'     => '3.1.2',
        'fields'      => [
            'provider' => [
                'FriendlyName' => 'Provider',
                'Type'         => 'dropdown',
                'Options'      => [
                    'AnycastDNS'    => 'AnycastDNS',
                    'Bind'     => 'Bind',
                    'Bunny'     => 'Bunny',
                    'Cloudflare' => 'Cloudflare',
                    'ClouDNS'    => 'ClouDNS',
                    'Desec'     => 'Desec',
                    'DNSimple' => 'DNSimple',
                    'Hetzner'    => 'Hetzner',
                    'PowerDNS'     => 'PowerDNS',
                    'Vultr' => 'Vultr',
                ],
                'Default'      => 'Vultr',
                'Description'  => 'Select your DNS provider from the list. Ensure you have an account with the chosen service.',
            ],
            'apikey' => [
                'FriendlyName' => 'API Key',
                'Type'         => 'password',
                'Size'         => '50',
                'Default'      => '',
                'Description'  => "Enter your DNS provider's API key. Keep it confidential and ensure it's valid for requests.",
            ],

            'apply_custom_nameservers' => [
                'FriendlyName' => 'Apply Custom Nameservers',
                'Type'         => 'yesno',
                'Description'  => 'Configure new Bunny DNS zones to use NS1 and NS2 below.',
            ],

            'manage_dns_button_location' => [
                'FriendlyName' => 'Show Manage DNS Button On',
                'Type'         => 'dropdown',
                'Options'      => [
                    'domain'  => 'Domains',
                    'service' => 'All Products/Services',
                    'both'    => 'Both',
                ],
                'Default'      => 'both',
                'Description'  => 'Choose where the button appears in both the client and admin areas.',
            ],

            'soa_email' => [
                'FriendlyName' => 'SOA Email',
                'Type'         => 'text',
                'Size'         => '50',
                'Default'      => '',
                'Description'  => 'Email address for the responsible person of this DNS zone (used in SOA).',
            ],

            'bind_powerdns_api_ip' => [
                'FriendlyName' => 'BIND/PowerDNS API IP',
                'Type'         => 'text',
                'Size'         => '50',
                'Default'      => '127.0.0.1',
                'Description'  => 'IP address of your BIND/PowerDNS server where the API is accessible.',
            ],

            'ns1' => [
                'FriendlyName' => 'NS1',
                'Type'         => 'text',
                'Size'         => '50',
                'Default'      => '',
                'Description'  => 'Nameserver 1 for your DNS zone.',
            ],
            'ns2' => [
                'FriendlyName' => 'NS2',
                'Type'         => 'text',
                'Size'         => '50',
                'Default'      => '',
                'Description'  => 'Nameserver 2 for your DNS zone.',
            ],
            'ns3' => [
                'FriendlyName' => 'NS3',
                'Type'         => 'text',
                'Size'         => '50',
                'Default'      => '',
                'Description'  => 'Nameserver 3 for your DNS zone (optional).',
            ],
            'ns4' => [
                'FriendlyName' => 'NS4',
                'Type'         => 'text',
                'Size'         => '50',
                'Default'      => '',
                'Description'  => 'Nameserver 4 for your DNS zone (optional).',
            ],
            'ns5' => [
                'FriendlyName' => 'NS5',
                'Type'         => 'text',
                'Size'         => '50',
                'Default'      => '',
                'Description'  => 'Nameserver 5 for your DNS zone (optional).',
            ],
        ],
    ];
}

function whmcs_dns_create_rate_limit_table(): void
{
    if (!Capsule::schema()->hasTable(WHMCSDNS_TABLE_RATE_LIMITS)) {
        Capsule::schema()->create(WHMCSDNS_TABLE_RATE_LIMITS, function ($table) {
            /** @var \Illuminate\Database\Schema\Blueprint $table */
            $table->bigInteger('client_id')->unsigned()->unique();
            $table->integer('window_started_at');
            $table->integer('attempts');
        });
    }
}

function whmcs_dns_add_srv_columns(): void
{
    if (!Capsule::schema()->hasTable(WHMCSDNS_TABLE_RECORDS)) {
        return;
    }

    foreach (['weight', 'port'] as $column) {
        if (!Capsule::schema()->hasColumn(WHMCSDNS_TABLE_RECORDS, $column)) {
            Capsule::schema()->table(WHMCSDNS_TABLE_RECORDS, function ($table) use ($column) {
                /** @var \Illuminate\Database\Schema\Blueprint $table */
                $table->integer($column)->nullable();
            });
        }
    }
}

function whmcs_dns_srv_number(mixed $value, string $field): int
{
    $number = filter_var($value, FILTER_VALIDATE_INT, [
        'options' => ['min_range' => 0, 'max_range' => 65535],
    ]);

    if ($number === false) {
        throw new InvalidArgumentException("SRV {$field} must be between 0 and 65535.");
    }

    return $number;
}

/** @return array{CustomNameserversEnabled: true, Nameserver1: string, Nameserver2: string} */
function whmcs_dns_bunny_nameserver_payload(string $ns1, string $ns2): array
{
    $ns1 = strtolower(rtrim(trim($ns1), '.'));
    $ns2 = strtolower(rtrim(trim($ns2), '.'));

    foreach (['NS1' => $ns1, 'NS2' => $ns2] as $label => $hostname) {
        if ($hostname === '' || filter_var($hostname, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false) {
            throw new InvalidArgumentException("{$label} must be a valid nameserver hostname.");
        }
    }
    if ($ns1 === $ns2) {
        throw new InvalidArgumentException('NS1 and NS2 must be different hostnames.');
    }

    return [
        'CustomNameserversEnabled' => true,
        'Nameserver1' => $ns1,
        'Nameserver2' => $ns2,
    ];
}

function whmcs_dns_apply_bunny_nameservers(string $apiKey, string $zoneId, string $ns1, string $ns2): void
{
    if (!ctype_digit($zoneId) || (int) $zoneId < 1) {
        throw new RuntimeException('Bunny zone ID is missing or invalid.');
    }

    $payload = json_encode(
        whmcs_dns_bunny_nameserver_payload($ns1, $ns2),
        JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR
    );
    $curl = curl_init('https://api.bunny.net/dnszone/' . $zoneId);
    if ($curl === false) {
        throw new RuntimeException('Could not initialize the Bunny nameserver request.');
    }

    curl_setopt_array($curl, [
        CURLOPT_CUSTOMREQUEST => 'POST',
        CURLOPT_POSTFIELDS => $payload,
        CURLOPT_HTTPHEADER => ['AccessKey: ' . $apiKey, 'Content-Type: application/json'],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_TIMEOUT => 30,
    ]);
    $response = curl_exec($curl);
    $status = (int) curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
    $error = curl_error($curl);
    curl_close($curl);

    if ($response === false) {
        throw new RuntimeException('Bunny nameserver request failed: ' . $error);
    }
    if ($status < 200 || $status >= 300) {
        throw new RuntimeException("Bunny rejected the custom nameservers (HTTP {$status}).");
    }
}

function whmcs_dns_bunny_zone_note(string $domainName, string $zoneFile): string
{
    if (trim($zoneFile) === '') {
        throw new RuntimeException('Bunny returned an empty zone export; the zone was not deleted.');
    }

    $note = "DNS ZONE for {$domainName}\n"
        . 'Exported from Bunny before deletion at ' . gmdate('c') . "\n\n"
        . $zoneFile;
    if (strlen($note) > 60000) {
        throw new RuntimeException('The zone export is too large for a WHMCS client note; the zone was not deleted.');
    }

    return $note;
}

/** @param array<int, mixed> $records */
function whmcs_dns_bunny_empty_export_is_expected(array $records): bool
{
    foreach ($records as $record) {
        if (!is_array($record) || (int) ($record['Type'] ?? -1) !== 5) {
            return false;
        }
    }

    return true;
}

function whmcs_dns_save_bunny_zone_note(
    int $clientId,
    string $domainName,
    string $apiKey,
    string $zoneId
): void {
    $provider = new BunnyProvider([
        'apikey' => $apiKey,
        'domain_name' => $domainName,
        'zone_id' => $zoneId,
    ]);
    $zoneFile = (string) $provider->exportDomainAsZonefile($domainName);
    if (trim($zoneFile) === '' && whmcs_dns_bunny_empty_export_is_expected(
        $provider->retrieveAllRRsets($domainName)
    )) {
        return;
    }

    /** @var array<string, mixed> $result */
    $result = localAPI('AddClientNote', [
        'userid' => $clientId,
        'notes' => whmcs_dns_bunny_zone_note($domainName, $zoneFile),
        'sticky' => false,
    ]);
    if (($result['result'] ?? null) !== 'success') {
        throw new RuntimeException('Could not save the DNS zone export to the client notes; the zone was not deleted.');
    }
}

function whmcs_dns_public_ipv4(string $address): bool
{
    if (filter_var(
        $address,
        FILTER_VALIDATE_IP,
        FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
    ) === false) {
        return false;
    }

    $ip = (int) sprintf('%u', ip2long($address));
    foreach ([
        ['100.64.0.0', 10], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24],
        ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24],
    ] as [$network, $prefix]) {
        $mask = (0xffffffff << (32 - $prefix)) & 0xffffffff;
        if (($ip & $mask) === (((int) sprintf('%u', ip2long($network))) & $mask)) {
            return false;
        }
    }

    return true;
}

/** @return array{domain: string, ipv4: string} */
function whmcs_dns_website_request(string $rawBody): array
{
    if (strlen($rawBody) > 8192) {
        throw new InvalidArgumentException('Invalid request body.');
    }
    $body = json_decode($rawBody, true, 16, JSON_THROW_ON_ERROR);
    if (!is_array($body) || !is_string($body['domain'] ?? null) || !is_string($body['ipv4'] ?? null)) {
        throw new InvalidArgumentException('JSON fields "domain" and "ipv4" are required.');
    }

    $domain = whmcs_dns_normalize_hostname($body['domain']);
    if ($domain === '' || filter_var($domain, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false) {
        throw new InvalidArgumentException('A valid domain is required.');
    }
    $ipv4 = trim($body['ipv4']);
    if (!whmcs_dns_public_ipv4($ipv4)) {
        throw new InvalidArgumentException('A valid public IPv4 address is required.');
    }

    return ['domain' => $domain, 'ipv4' => $ipv4];
}

/** @return array{server_id: int, cpanel_user: string, domain: string, type: string, value: string} */
function whmcs_dns_cpanel_request(string $rawBody): array
{
    if (strlen($rawBody) > 16384) {
        throw new InvalidArgumentException('Invalid request body.');
    }

    $body = json_decode($rawBody, true, 8, JSON_THROW_ON_ERROR);
    if (!is_array($body)) {
        throw new InvalidArgumentException('A JSON object is required.');
    }

    $serverId = filter_var($body['server_id'] ?? null, FILTER_VALIDATE_INT, [
        'options' => ['min_range' => 1],
    ]);
    $user = strtolower(trim(is_string($body['cpanel_user'] ?? null) ? $body['cpanel_user'] : ''));
    $domain = whmcs_dns_normalize_hostname(is_string($body['domain'] ?? null) ? $body['domain'] : '');
    $type = strtoupper(trim(is_string($body['type'] ?? null) ? $body['type'] : ''));
    $value = trim(is_string($body['value'] ?? null) ? $body['value'] : '');

    if ($serverId === false) {
        throw new InvalidArgumentException('A valid server_id is required.');
    }
    if ($user !== '' && !preg_match('/^[a-z][a-z0-9_]{0,15}$/', $user)) {
        throw new InvalidArgumentException('A valid cPanel username is required.');
    }
    $validDomain = filter_var($domain, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) !== false;
    if ($type === 'TXT') {
        $validDomain = preg_match(
            '/^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/D',
            $domain
        ) === 1;
    }
    if (!$validDomain) {
        throw new InvalidArgumentException('A valid record domain is required.');
    }
    if (!in_array($type, ['A', 'TXT'], true)) {
        throw new InvalidArgumentException('Only A and TXT records are accepted.');
    }
    if ($type === 'A' && filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
        throw new InvalidArgumentException('A valid IPv4 value is required.');
    }
    if ($type === 'TXT' && ($value === '' || strlen($value) > 4096)) {
        throw new InvalidArgumentException('TXT values must contain between 1 and 4096 bytes.');
    }

    return [
        'server_id' => (int) $serverId,
        'cpanel_user' => $user,
        'domain' => $domain,
        'type' => $type,
        'value' => $value,
    ];
}

function whmcs_dns_hostname_in_zone(string $hostname, string $zone): bool
{
    return $hostname === $zone || str_ends_with($hostname, '.' . $zone);
}

function whmcs_dns_provider_record_value(string $provider, string $type, string $value): string
{
    if ($type !== 'TXT' || $provider === 'Bunny') {
        return $value;
    }

    $value = trim($value);
    return $value !== '' && $value[0] === '"' && str_ends_with($value, '"')
        ? $value
        : '"' . str_replace('"', '\"', $value) . '"';
}

/** @return array<int, string> */
function whmcs_dns_api_record_types(): array
{
    return ['A', 'AAAA', 'CAA', 'CNAME', 'MX', 'NS', 'PTR', 'SRV', 'TXT'];
}

function whmcs_dns_api_fqdn(string $fqdn): string
{
    $fqdn = whmcs_dns_normalize_hostname($fqdn);
    if (strlen($fqdn) > 253 || preg_match(
        '/^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/D',
        $fqdn
    ) !== 1) {
        throw new InvalidArgumentException('A valid fully-qualified DNS name is required.');
    }
    return $fqdn;
}

/** @return array{zone: object, domain: string, client_id: int, provider: string, config: array<string, mixed>} */
function whmcs_dns_api_zone_context(string $fqdn): array
{
    $fqdn = whmcs_dns_api_fqdn($fqdn);
    $labels = explode('.', $fqdn);
    $candidates = [];
    for ($index = 0, $count = count($labels) - 1; $index < $count; $index++) {
        $candidates[] = implode('.', array_slice($labels, $index));
    }
    $zones = Capsule::table(WHMCSDNS_TABLE_ZONES)->whereIn('domain_name', $candidates)->get()->all();
    usort($zones, static fn (object $left, object $right): int =>
        strlen((string) $right->domain_name) <=> strlen((string) $left->domain_name));
    $zone = $zones[0] ?? null;
    if (!$zone) {
        throw new UnexpectedValueException('This DNS name is not in a managed zone.', 403);
    }
    $domain = whmcs_dns_normalize_hostname((string) $zone->domain_name);
    $config = whmcs_dns_provider_record_config($domain);
    $stored = json_decode((string) $zone->config, true);
    $provider = is_array($stored) ? (string) ($stored['provider'] ?? '') : '';
    if ($provider === '' || $provider !== ($config['provider'] ?? null)) {
        throw new RuntimeException('The DNS zone provider does not match the configured provider.');
    }
    return [
        'zone' => $zone,
        'domain' => $domain,
        'client_id' => (int) $zone->client_id,
        'provider' => $provider,
        'config' => $config,
    ];
}

function whmcs_dns_api_relative_name(string $fqdn, string $zone): string
{
    return $fqdn === $zone ? '' : substr($fqdn, 0, -strlen('.' . $zone));
}

/** @return array{name: string, type: string, value: string, ttl: int, priority: int|null, weight: int|null, port: int|null} */
function whmcs_dns_api_record(string $fqdn, string $zone, string $type, int $ttl, string $value): array
{
    $type = strtoupper(trim($type));
    if (!in_array($type, whmcs_dns_api_record_types(), true)) {
        throw new InvalidArgumentException('Unsupported DNS record type.');
    }
    $record = [
        'name' => whmcs_dns_api_relative_name(whmcs_dns_api_fqdn($fqdn), $zone),
        'type' => $type,
        'value' => trim($value),
        'ttl' => $ttl,
        'priority' => null,
        'weight' => null,
        'port' => null,
    ];
    if ($type === 'MX') {
        if (preg_match('/^([0-9]{1,5})\s+(\S+)$/D', trim($value), $matches) !== 1) {
            throw new InvalidArgumentException('MX values must contain "priority hostname".');
        }
        $record['priority'] = (int) $matches[1];
        $record['value'] = $matches[2];
    } elseif ($type === 'SRV') {
        if (preg_match('/^([0-9]{1,5})\s+([0-9]{1,5})\s+([0-9]{1,5})\s+(\S+)$/D', trim($value), $matches) !== 1) {
            throw new InvalidArgumentException('SRV values must contain "priority weight port target".');
        }
        $record['priority'] = (int) $matches[1];
        $record['weight'] = (int) $matches[2];
        $record['port'] = (int) $matches[3];
        $record['value'] = $matches[4];
    }
    return whmcs_dns_integration_record($record, $zone);
}

/** @param array<string, mixed> $record */
function whmcs_dns_api_record_value(array $record): string
{
    if ($record['type'] === 'MX') {
        return (int) $record['priority'] . ' ' . (string) $record['value'];
    }
    if ($record['type'] === 'SRV') {
        return (int) $record['priority'] . ' ' . (int) $record['weight'] . ' '
            . (int) $record['port'] . ' ' . (string) $record['value'];
    }
    return (string) $record['value'];
}

/**
 * @param array{zone: object, domain: string} $context
 * @return array<int, array{row: object, record: array<string, mixed>}>
 */
function whmcs_dns_api_rrset_rows(array $context, string $fqdn, string $type): array
{
    $fqdn = whmcs_dns_api_fqdn($fqdn);
    $type = strtoupper($type);
    $name = whmcs_dns_api_relative_name($fqdn, $context['domain']);
    $matches = [];
    foreach (Capsule::table(WHMCSDNS_TABLE_RECORDS)
        ->where('domain_id', $context['zone']->id)
        ->where('type', $type)
        ->get() as $row) {
        $record = whmcs_dns_integration_record([
            'name' => (string) $row->host,
            'type' => $type,
            'value' => (string) $row->value,
            'ttl' => $row->ttl ?? 300,
            'priority' => $row->priority ?? ($type === 'MX' ? 0 : null),
            'weight' => $row->weight,
            'port' => $row->port,
        ], $context['domain']);
        if ($record['name'] === $name) {
            $matches[] = ['row' => $row, 'record' => $record];
        }
    }
    return $matches;
}

/**
 * @param array{domain: string, zone: object} $context
 * @return array{fqdn: string, type: string, ttl: int, values: array<int, string>}|null
 */
function whmcs_dns_api_get_rrset(array $context, string $fqdn, string $type): ?array
{
    $fqdn = whmcs_dns_api_fqdn($fqdn);
    $type = strtoupper($type);
    if (!in_array($type, whmcs_dns_api_record_types(), true)) {
        throw new InvalidArgumentException('Unsupported DNS record type.');
    }
    $rows = whmcs_dns_api_rrset_rows($context, $fqdn, $type);
    if ($rows === []) {
        return null;
    }
    $values = array_values(array_unique(array_map(
        static fn (array $item): string => whmcs_dns_api_record_value($item['record']),
        $rows
    )));
    sort($values);
    return ['fqdn' => $fqdn, 'type' => $type, 'ttl' => (int) $rows[0]['record']['ttl'], 'values' => $values];
}

/**
 * @param array{config: array<string, mixed>, provider: string} $context
 * @param array<int, array{row: object, record: array<string, mixed>}> $rows
 */
function whmcs_dns_api_delete_rrset_rows(array $context, array $rows, PlexService $plex): void
{
    foreach ($rows as $item) {
        $record = $item['record'];
        $plex->delRecord($context['config'] + [
            'record_id' => (int) $item['row']->id,
            'record_name' => $record['name'],
            'record_type' => $record['type'],
            'record_value' => whmcs_dns_provider_record_value(
                $context['provider'],
                (string) $record['type'],
                (string) $record['value']
            ),
        ]);
    }
}

/**
 * @param array{zone: object, domain: string, provider: string, config: array<string, mixed>} $context
 * @param array<int, mixed> $values
 * @return array{created: bool, rrset: array{fqdn: string, type: string, ttl: int, values: array<int, string>}}
 */
function whmcs_dns_api_put_rrset(array $context, string $fqdn, string $type, int $ttl, array $values): array
{
    $fqdn = whmcs_dns_api_fqdn($fqdn);
    $type = strtoupper($type);
    if ($values === [] || !array_is_list($values)) {
        throw new InvalidArgumentException('At least one DNS record value is required.');
    }
    $records = [];
    $seen = [];
    foreach ($values as $value) {
        if (!is_string($value)) {
            throw new InvalidArgumentException('Every DNS record value must be a string.');
        }
        $record = whmcs_dns_api_record($fqdn, $context['domain'], $type, $ttl, $value);
        $wireValue = whmcs_dns_api_record_value($record);
        $key = strlen($wireValue) . ':' . $wireValue;
        if (isset($seen[$key])) {
            throw new InvalidArgumentException('DNS record values must be unique.');
        }
        $seen[$key] = true;
        $records[] = $record;
    }
    if ($type === 'CNAME' && count($records) !== 1) {
        throw new InvalidArgumentException('A CNAME RRset must contain exactly one value.');
    }

    $name = whmcs_dns_api_relative_name($fqdn, $context['domain']);
    foreach (Capsule::table(WHMCSDNS_TABLE_RECORDS)->where('domain_id', $context['zone']->id)->get() as $row) {
        $rowType = strtoupper((string) $row->type);
        if ($rowType === $type) {
            continue;
        }
        $rowName = whmcs_dns_integration_record([
            'name' => (string) $row->host,
            'type' => $rowType,
            'value' => (string) $row->value,
            'ttl' => $row->ttl ?? 300,
            'priority' => $row->priority ?? ($rowType === 'MX' ? 0 : null),
            'weight' => $row->weight,
            'port' => $row->port,
        ], $context['domain'])['name'];
        if ($rowName === $name && ($type === 'CNAME' || $rowType === 'CNAME')) {
            throw new UnexpectedValueException('A CNAME cannot coexist with another record at the same name.', 409);
        }
    }

    $existing = whmcs_dns_api_rrset_rows($context, $fqdn, $type);
    $plex = new PlexService(Capsule::connection()->getPdo());
    whmcs_dns_api_delete_rrset_rows($context, $existing, $plex);
    foreach ($records as $record) {
        $plex->addRecord($context['config'] + [
            'record_name' => $record['name'],
            'record_type' => $record['type'],
            'record_value' => whmcs_dns_provider_record_value(
                $context['provider'],
                (string) $record['type'],
                (string) $record['value']
            ),
            'record_ttl' => $record['ttl'],
            'record_priority' => $record['priority'],
            'record_weight' => $record['weight'],
            'record_port' => $record['port'],
        ]);
    }
    $wireValues = array_map('whmcs_dns_api_record_value', $records);
    sort($wireValues);
    return [
        'created' => $existing === [],
        'rrset' => ['fqdn' => $fqdn, 'type' => $type, 'ttl' => $ttl, 'values' => $wireValues],
    ];
}

/** @param array{zone: object, domain: string, provider: string, config: array<string, mixed>} $context */
function whmcs_dns_api_delete_rrset(array $context, string $fqdn, string $type): void
{
    $rows = whmcs_dns_api_rrset_rows($context, $fqdn, strtoupper($type));
    if ($rows !== []) {
        whmcs_dns_api_delete_rrset_rows($context, $rows, new PlexService(Capsule::connection()->getPdo()));
    }
}

/**
 * @param array<int, array{client_id: int, domain: string, status: string}> $sources
 * @param array<int, array{client_id: int, domain: string}> $zones
 * @return array{client_id: int, zone: string}
 */
function whmcs_dns_cpanel_relaxed_context(array $sources, array $zones, string $domain): array
{
    $matches = [];
    foreach ($sources as $source) {
        $zone = whmcs_dns_normalize_hostname($source['domain']);
        if (!in_array($source['status'], ['Active', 'Pending'], true) || $zone === ''
            || !whmcs_dns_hostname_in_zone($domain, $zone)) {
            continue;
        }
        $matches[] = ['client_id' => $source['client_id'], 'zone' => $zone];
    }
    if ($matches === []) {
        throw new UnexpectedValueException('The DNS record does not map to an eligible WHMCS domain.', 409);
    }

    $length = max(array_map(static fn (array $match): int => strlen($match['zone']), $matches));
    $matches = array_values(array_filter(
        $matches,
        static fn (array $match): bool => strlen($match['zone']) === $length
    ));
    $clientIds = array_values(array_unique(array_column($matches, 'client_id')));
    if (count($clientIds) !== 1) {
        throw new UnexpectedValueException('The DNS record maps to multiple WHMCS customers.', 409);
    }

    $clientId = (int) $clientIds[0];
    $managed = [];
    foreach ($zones as $zone) {
        $zoneName = whmcs_dns_normalize_hostname($zone['domain']);
        if ($zoneName === '' || !whmcs_dns_hostname_in_zone($domain, $zoneName)) {
            continue;
        }
        if ($zone['client_id'] !== $clientId) {
            throw new UnexpectedValueException('The local DNS zone belongs to another WHMCS client.', 409);
        }
        $managed[$zoneName] = $zoneName;
    }

    $candidates = $managed !== [] ? array_values($managed) : [$matches[0]['zone']];
    usort($candidates, static fn (string $left, string $right): int => strlen($right) <=> strlen($left));
    return ['client_id' => $clientId, 'zone' => $candidates[0]];
}

/** @return array{client_id: int, zone: string} */
function whmcs_dns_cpanel_record_context(int $serverId, string $user, string $domain): array
{
    if ($user === '') {
        $apex = whmcs_dns_registrable_domain($domain, true);
        if ($apex === null) {
            throw new UnexpectedValueException('The DNS record does not have a registrable domain.', 409);
        }
        $sources = Capsule::table('tbldomains')
            ->select('userid', 'domain', 'status')
            ->whereIn('status', ['Active', 'Pending'])
            ->where('domain', $apex)
            ->get()
            ->map(static fn ($item): array => [
                'client_id' => (int) $item->userid,
                'domain' => whmcs_dns_normalize_hostname((string) $item->domain),
                'status' => (string) $item->status,
            ])
            ->toArray();

        foreach (Capsule::table('tblhosting')
            ->select('userid', 'domain', 'domainstatus')
            ->whereIn('domainstatus', ['Active', 'Pending'])
            ->where(static function ($query) use ($apex): void {
                $query->where('domain', $apex)->orWhere('domain', 'like', '%.' . $apex);
            })
            ->get() as $service) {
            $serviceApex = whmcs_dns_registrable_domain((string) $service->domain);
            if ($serviceApex !== null) {
                $sources[] = [
                    'client_id' => (int) $service->userid,
                    'domain' => $serviceApex,
                    'status' => (string) $service->domainstatus,
                ];
            }
        }

        $zoneNames = [];
        for ($name = $domain; whmcs_dns_hostname_in_zone($name, $apex); $name = substr($name, strpos($name, '.') + 1)) {
            $zoneNames[] = $name;
            if ($name === $apex) {
                break;
            }
        }
        $zones = Capsule::table(WHMCSDNS_TABLE_ZONES)
            ->select('client_id', 'domain_name')
            ->whereIn('domain_name', $zoneNames)
            ->get()
            ->map(static fn ($zone): array => [
                'client_id' => (int) $zone->client_id,
                'domain' => whmcs_dns_normalize_hostname((string) $zone->domain_name),
            ])
            ->toArray();
        return whmcs_dns_cpanel_relaxed_context($sources, $zones, $domain);
    }

    $services = Capsule::table('tblhosting')
        ->select('userid', 'domain')
        ->where('server', $serverId)
        ->where('username', $user)
        ->where('domainstatus', 'Active')
        ->where('domain', '<>', '')
        ->get();

    $clientIds = [];
    $apexes = [];
    foreach ($services as $service) {
        $apex = whmcs_dns_registrable_domain((string) $service->domain);
        if ($apex === null || !whmcs_dns_hostname_in_zone($domain, $apex)) {
            continue;
        }
        $clientId = (int) $service->userid;
        $clientIds[$clientId] = $clientId;
        $apexes[$apex] = $apex;
    }
    if (count($clientIds) !== 1 || $apexes === []) {
        throw new UnexpectedValueException('The cPanel account does not map to one active WHMCS customer.', 409);
    }

    $clientId = array_values($clientIds)[0];
    $zones = Capsule::table(WHMCSDNS_TABLE_ZONES)
        ->select('domain_name')
        ->where('client_id', $clientId)
        ->get()
        ->map(static fn ($zone): string => whmcs_dns_normalize_hostname((string) $zone->domain_name))
        ->filter(static fn (string $zone): bool => $zone !== '' && whmcs_dns_hostname_in_zone($domain, $zone))
        ->values()
        ->toArray();

    $candidates = $zones !== [] ? $zones : array_values($apexes);
    usort($candidates, static fn (string $left, string $right): int => strlen($right) <=> strlen($left));
    return ['client_id' => $clientId, 'zone' => $candidates[0]];
}

/** @return array<string, mixed> */
function whmcs_dns_provider_record_config(string $domainName): array
{
    $provider = (string) (Setting::getSettingValueForModule('whmcs_dns', 'provider') ?? '');
    $apiKey = (string) (Setting::getSettingValueForModule('whmcs_dns', 'apikey') ?? '');
    if ($provider === '' || $apiKey === '') {
        throw new RuntimeException('DNS provider is not configured.');
    }

    $config = ['domain_name' => $domainName, 'provider' => $provider, 'apikey' => $apiKey];
    if ($provider === 'PowerDNS') {
        $config['powerdnsip'] = Setting::getSettingValueForModule('whmcs_dns', 'bind_powerdns_api_ip');
    } elseif ($provider === 'Bind') {
        $config['bindip'] = Setting::getSettingValueForModule('whmcs_dns', 'bind_powerdns_api_ip');
    }
    if (in_array($provider, ['PowerDNS', 'Bind'], true)) {
        for ($i = 1; $i <= 5; $i++) {
            $value = (string) (Setting::getSettingValueForModule('whmcs_dns', 'ns' . $i) ?? '');
            if ($value !== '') {
                $config['ns' . $i] = $value;
            }
        }
    }
    return $config;
}

/**
 * @param array<int, mixed> $zones
 * @return array{id: string, domain: string}|null
 */
function whmcs_dns_find_bunny_zone(array $zones, string $domainName): ?array
{
    $domainName = whmcs_dns_normalize_hostname($domainName);
    $matches = [];
    foreach ($zones as $zone) {
        if (!is_array($zone)
            || whmcs_dns_normalize_hostname((string) ($zone['domain'] ?? '')) !== $domainName) {
            continue;
        }
        if (!is_numeric($zone['id'] ?? null)) {
            throw new RuntimeException('Bunny returned an invalid zone ID.');
        }
        $matches[] = ['id' => (string) $zone['id'], 'domain' => $domainName];
    }
    if (count($matches) > 1) {
        throw new UnexpectedValueException('Multiple exact Bunny zones were found.', 409);
    }
    return $matches[0] ?? null;
}

/** @param array<string, mixed> $config */
function whmcs_dns_enable_domain(int $clientId, array $config): bool
{
    $domainName = whmcs_dns_normalize_hostname((string) ($config['domain_name'] ?? ''));
    $providerName = (string) ($config['provider'] ?? '');
    if ($clientId <= 0 || $providerName === ''
        || filter_var($domainName, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false) {
        throw new InvalidArgumentException('A client, domain, and DNS provider are required.');
    }
    $config['domain_name'] = $domainName;

    $zone = Capsule::table(WHMCSDNS_TABLE_ZONES)->where('domain_name', $domainName)->first();
    if ($zone) {
        if ((int) $zone->client_id !== $clientId) {
            throw new UnexpectedValueException('The local zone belongs to another WHMCS client.', 409);
        }
        return false;
    }

    $plex = new PlexService(Capsule::connection()->getPdo());
    $created = true;
    if ($providerName === 'Bunny') {
        $remote = whmcs_dns_find_bunny_zone(
            (new BunnyProvider(['apikey' => (string) ($config['apikey'] ?? '')]))->listDomains(),
            $domainName
        );
        if ($remote !== null) {
            $now = date('Y-m-d H:i:s');
            Capsule::table(WHMCSDNS_TABLE_ZONES)->insert([
                'client_id' => $clientId,
                'domain_name' => $domainName,
                'zoneId' => $remote['id'],
                'config' => json_encode(['provider' => 'Bunny'], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR),
                'created_at' => $now,
                'updated_at' => $now,
            ]);
            $created = false;
        }
    }

    if ($created) {
        $plex->createDomain([
            'client_id' => $clientId,
            'config' => json_encode($config, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR),
        ]);
    }
    if (!Capsule::table(WHMCSDNS_TABLE_ZONES)->where('domain_name', $domainName)->first()) {
        throw new RuntimeException('The provider zone was created without a local zone mapping.');
    }
    try {
        $plex->sync($config);
    } catch (UnsupportedProviderException) {
        // A provider may support creating zones without supporting cache imports.
    }
    return $created;
}

/**
 * @param array{server_id: int, cpanel_user: string, domain: string, type: string, value: string} $request
 * @return array{status: string, action: string, zone: string}
 */
function whmcs_dns_sync_cpanel_record(array $request): array
{
    $context = whmcs_dns_cpanel_record_context(
        $request['server_id'],
        $request['cpanel_user'],
        $request['domain']
    );
    $zoneName = $context['zone'];
    $relativeName = $request['domain'] === $zoneName
        ? ''
        : substr($request['domain'], 0, -strlen('.' . $zoneName));
    if ($request['type'] === 'TXT' && !str_ends_with($relativeName, '._domainkey')) {
        throw new InvalidArgumentException('Only DKIM TXT records are accepted.');
    }

    $config = whmcs_dns_provider_record_config($zoneName);
    $pdo = Capsule::connection()->getPdo();
    $plex = new PlexService($pdo);
    $zone = Capsule::table(WHMCSDNS_TABLE_ZONES)
        ->where('domain_name', $zoneName)
        ->where('client_id', $context['client_id'])
        ->first();
    if (!$zone) {
        whmcs_dns_enable_domain($context['client_id'], $config);
        $zone = Capsule::table(WHMCSDNS_TABLE_ZONES)
            ->where('domain_name', $zoneName)
            ->where('client_id', $context['client_id'])
            ->first();
        if (!$zone) {
            throw new RuntimeException('The provider zone was created without a local zone mapping.');
        }
    }

    $records = Capsule::table(WHMCSDNS_TABLE_RECORDS)
        ->where('domain_id', $zone->id)
        ->where('type', $request['type'])
        ->where('host', $relativeName)
        ->get();
    if ($records->count() > 1) {
        throw new UnexpectedValueException('The target RRset contains multiple records.', 409);
    }

    $value = whmcs_dns_provider_record_value(
        (string) ($config['provider'] ?? ''),
        $request['type'],
        $request['value']
    );
    $record = $records->first();
    if ($record && (string) $record->value === $value) {
        return ['status' => 'ok', 'action' => 'unchanged', 'zone' => $zoneName];
    }

    $recordConfig = $config + [
        'record_name' => $relativeName,
        'record_type' => $request['type'],
        'record_value' => $value,
        'record_ttl' => $record && $record->ttl !== null ? (int) $record->ttl : 3600,
        'record_priority' => null,
        'record_weight' => null,
        'record_port' => null,
    ];
    if (!$record) {
        $plex->addRecord($recordConfig);
        return ['status' => 'ok', 'action' => 'created', 'zone' => $zoneName];
    }

    $plex->updateRecord($recordConfig + [
        'record_id' => (int) $record->id,
        'old_value' => (string) $record->value,
    ]);
    return ['status' => 'ok', 'action' => 'updated', 'zone' => $zoneName];
}

/**
 * @param array<int, array<string, int|string|null>> $records
 * @return array{delete: array<int, array<string, int|string|null>>, create_apex: bool, create_www: bool}
 */
function whmcs_dns_website_record_plan(array $records, string $domainName, string $ipv4): array
{
    $domainName = whmcs_dns_normalize_hostname($domainName);
    $delete = [];
    $apexKept = false;
    $wwwKept = false;

    foreach ($records as $record) {
        $host = strtolower(rtrim(trim((string) ($record['host'] ?? '')), '.'));
        $type = strtoupper((string) ($record['type'] ?? ''));
        $value = strtolower(rtrim(trim((string) ($record['value'] ?? '')), '.'));
        $isApex = in_array($host, ['', '@', $domainName], true);
        $isWww = in_array($host, ['www', 'www.' . $domainName], true);

        if ($isApex && in_array($type, ['A', 'CNAME', 'RDR'], true)) {
            if ($type === 'A' && $value === $ipv4 && !$apexKept) {
                $apexKept = true;
            } else {
                $delete[] = $record;
            }
            continue;
        }

        if (!$isWww) {
            continue;
        }
        if (!in_array($type, ['A', 'AAAA', 'CNAME', 'RDR'], true)) {
            throw new UnexpectedValueException("The unmanaged {$type} record at www prevents a CNAME.", 409);
        }
        if ($type === 'CNAME' && $value === $domainName && !$wwwKept) {
            $wwwKept = true;
        } else {
            $delete[] = $record;
        }
    }

    return ['delete' => $delete, 'create_apex' => !$apexKept, 'create_www' => !$wwwKept];
}

/** @param array<int, array<string, int|string|null>> $records */
function whmcs_dns_website_replacement_note(string $domainName, array $records): string
{
    $lines = ["Website DNS reconciliation for {$domainName} at " . gmdate('c'), 'Deleted/replaced records:'];
    foreach ($records as $record) {
        $host = (string) ($record['host'] ?? '');
        $lines[] = sprintf(
            '%s %s %s (Bunny ID %s)',
            strtoupper((string) ($record['type'] ?? '')),
            $host === '' ? '@' : $host,
            (string) ($record['value'] ?? ''),
            (string) ($record['recordId'] ?? '')
        );
    }
    $note = implode("\n", $lines);
    if (strlen($note) > 60000) {
        throw new RuntimeException('The replacement list is too large for a WHMCS client note.');
    }
    return $note;
}

/** @param array<int, array<string, int|string|null>> $records */
function whmcs_dns_reconcile_bunny_website(
    BunnyProvider $provider,
    int $clientId,
    string $domainName,
    string $ipv4,
    array $records
): void {
    $plan = whmcs_dns_website_record_plan($records, $domainName, $ipv4);

    if ($plan['delete'] !== []) {
        $result = localAPI('AddClientNote', [
            'userid' => $clientId,
            'notes' => whmcs_dns_website_replacement_note($domainName, $plan['delete']),
            'sticky' => false,
        ]);
        if (($result['result'] ?? null) !== 'success') {
            throw new RuntimeException('Could not save replaced DNS records to the client notes.');
        }
    }

    foreach ($plan['delete'] as $record) {
        $provider->deleteRRset(
            $domainName,
            (string) ($record['host'] ?? ''),
            (string) ($record['type'] ?? ''),
            (string) ($record['value'] ?? ''),
            $record['recordId'] ?? null
        );
    }
    if ($plan['create_apex']) {
        $provider->createRRset($domainName, ['subname' => '', 'type' => 'A', 'ttl' => 300, 'records' => [$ipv4]]);
    }
    if ($plan['create_www']) {
        $provider->createRRset($domainName, ['subname' => 'www', 'type' => 'CNAME', 'ttl' => 300, 'records' => [$domainName]]);
    }
}

function whmcs_dns_domain_status_allowed(string $status): bool
{
    return $status === 'Active';
}

/**
 * @param array<int, array{id: int|string, domain: string}> $bunnyZones
 * @param array<int, array{id: int, client_id: int, domain: string, zone_id: string}> $localZones
 * @param array<int, array{client_id: int, domain: string, id: int, kind: string, name: string, status: string}> $sources
 * @return array<int, array<string, mixed>>
 */
function whmcs_dns_reconciliation_rows(array $bunnyZones, array $localZones, array $sources): array
{
    $rows = [];
    $row = static fn (string $domain): array => [
        'domain' => $domain,
        'bunny' => null,
        'local' => null,
        'sources' => [],
        'active_sources' => [],
        'eligible_client_ids' => [],
        'status' => '',
    ];

    foreach ($bunnyZones as $zone) {
        $domain = whmcs_dns_normalize_hostname($zone['domain']);
        if ($domain === '') {
            continue;
        }
        $rows[$domain] ??= $row($domain);
        $rows[$domain]['bunny'] = ['id' => (string) $zone['id']];
    }

    foreach ($localZones as $zone) {
        $domain = whmcs_dns_normalize_hostname($zone['domain']);
        if ($domain === '') {
            continue;
        }
        $rows[$domain] ??= $row($domain);
        $rows[$domain]['local'] = $zone;
    }

    foreach ($sources as $source) {
        $domain = whmcs_dns_normalize_hostname($source['domain']);
        if ($domain === '') {
            continue;
        }
        $rows[$domain] ??= $row($domain);
        $rows[$domain]['sources'][] = $source;
        if (whmcs_dns_domain_status_allowed($source['status'])) {
            $rows[$domain]['active_sources'][] = $source;
            $rows[$domain]['eligible_client_ids'][(int) $source['client_id']] = (int) $source['client_id'];
        }
    }

    foreach ($rows as $domain => &$item) {
        usort($item['sources'], static function (array $left, array $right): int {
            $active = (int) whmcs_dns_domain_status_allowed($right['status'])
                <=> (int) whmcs_dns_domain_status_allowed($left['status']);
            return $active ?: [$left['name'], $left['id']] <=> [$right['name'], $right['id']];
        });
        $item['eligible_client_ids'] = array_values($item['eligible_client_ids']);
        $hasActive = $item['active_sources'] !== [];
        $hasBunny = $item['bunny'] !== null;
        $hasLocal = $item['local'] !== null;

        if (count($item['eligible_client_ids']) > 1) {
            $item['status'] = 'conflict';
        } elseif ($hasActive && !$hasBunny) {
            $item['status'] = 'missing';
        } elseif ($hasActive) {
            $clientId = $item['eligible_client_ids'][0];
            $item['status'] = !$hasLocal
                || (int) $item['local']['client_id'] !== $clientId
                || (string) $item['local']['zone_id'] !== (string) $item['bunny']['id']
                ? 'repair'
                : 'in_sync';
        } elseif ($hasBunny) {
            $item['status'] = $item['sources'] === [] ? 'orphan' : 'inactive';
        } elseif ($hasLocal) {
            $item['status'] = 'stale_local';
        } else {
            unset($rows[$domain]);
        }
    }
    unset($item);

    ksort($rows, SORT_NATURAL | SORT_FLAG_CASE);
    return array_values($rows);
}

function whmcs_dns_rate_limit_reached(int $attempts): bool
{
    return $attempts >= WHMCSDNS_MUTATION_LIMIT;
}

function whmcs_dns_enforce_mutation_limit(int $clientId): void
{
    $now = time();

    Capsule::table(WHMCSDNS_TABLE_RATE_LIMITS)->insertOrIgnore([
        'client_id' => $clientId,
        'window_started_at' => 0,
        'attempts' => 0,
    ]);

    Capsule::connection()->transaction(function () use ($clientId, $now): void {
        $query = Capsule::table(WHMCSDNS_TABLE_RATE_LIMITS)->where('client_id', $clientId);
        $limit = $query->lockForUpdate()->first();

        if (!$limit) {
            throw new RuntimeException('DNS rate limit is unavailable.');
        }

        $windowStartedAt = (int) $limit->window_started_at;
        if ($now < $windowStartedAt || $now - $windowStartedAt >= WHMCSDNS_MUTATION_WINDOW) {
            $query->update(['window_started_at' => $now, 'attempts' => 1]);
            return;
        }

        if (whmcs_dns_rate_limit_reached((int) $limit->attempts)) {
            throw new RuntimeException('Too many DNS changes. Please wait a minute and try again.');
        }

        $query->increment('attempts');
    });
}

/**
 * Normalize a record crossing the local addon integration boundary.
 *
 * @param array<string, mixed> $record
 * @return array{name: string, type: string, value: string, ttl: int, priority: int|null, weight: int|null, port: int|null}
 */
function whmcs_dns_integration_record(array $record, string $domainName): array
{
    $domainName = whmcs_dns_normalize_hostname($domainName);
    $name = whmcs_dns_normalize_hostname(is_string($record['name'] ?? null) ? $record['name'] : '');
    if ($name === '@' || $name === $domainName) {
        $name = '';
    } elseif (str_ends_with($name, '.' . $domainName)) {
        $name = substr($name, 0, -strlen('.' . $domainName));
    }

    $fqdn = $name === '' ? $domainName : $name . '.' . $domainName;
    if ($domainName === '' || strlen($fqdn) > 253 || preg_match(
        '/^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/D',
        $fqdn
    ) !== 1) {
        throw new InvalidArgumentException('A valid DNS record name is required.');
    }

    $type = strtoupper(trim(is_string($record['type'] ?? null) ? $record['type'] : ''));
    if (!in_array($type, ['A', 'AAAA', 'CAA', 'CNAME', 'HTTPS', 'MX', 'NS', 'PTR', 'RDR', 'SRV', 'SVCB', 'TLSA', 'TXT'], true)) {
        throw new InvalidArgumentException('Unsupported DNS record type.');
    }

    $value = trim(is_string($record['value'] ?? null) ? $record['value'] : '');
    if ($type === 'SRV' && preg_match('/^([0-9]{1,5})\s+([0-9]{1,5})\s+(\S+)$/D', $value, $matches) === 1) {
        $record['weight'] = (int) $matches[1];
        $record['port'] = (int) $matches[2];
        $value = $matches[3];
    }
    if ($type === 'TXT' && strlen($value) >= 2 && $value[0] === '"' && str_ends_with($value, '"')) {
        $value = substr($value, 1, -1);
    }
    if ($value === '' || strlen($value) > 4096) {
        throw new InvalidArgumentException('A DNS record value between 1 and 4096 bytes is required.');
    }
    if (in_array($type, ['CNAME', 'MX', 'NS', 'PTR', 'SRV'], true)) {
        $value = strtolower(rtrim($value, '.'));
        if (!str_contains($value, '.')
            || filter_var($value, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false) {
            throw new InvalidArgumentException("{$type} records require a valid hostname value.");
        }
    } elseif ($type === 'A' && filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
        throw new InvalidArgumentException('A records require a valid IPv4 value.');
    } elseif ($type === 'AAAA' && filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false) {
        throw new InvalidArgumentException('AAAA records require a valid IPv6 value.');
    }

    $ttl = filter_var($record['ttl'] ?? null, FILTER_VALIDATE_INT, [
        'options' => ['min_range' => 1, 'max_range' => 2147483647],
    ]);
    if ($ttl === false) {
        throw new InvalidArgumentException('DNS record TTL must be a positive integer.');
    }

    $priority = $weight = $port = null;
    if (in_array($type, ['MX', 'SRV'], true)) {
        $priority = filter_var($record['priority'] ?? null, FILTER_VALIDATE_INT, [
            'options' => ['min_range' => 0, 'max_range' => 65535],
        ]);
        if ($priority === false) {
            throw new InvalidArgumentException('DNS record priority must be between 0 and 65535.');
        }
    }
    if ($type === 'SRV') {
        $weight = whmcs_dns_srv_number($record['weight'] ?? null, 'weight');
        $port = whmcs_dns_srv_number($record['port'] ?? null, 'port');
    }
    return [
        'name' => $name,
        'type' => $type,
        'value' => $value,
        'ttl' => (int) $ttl,
        'priority' => $priority,
        'weight' => $weight,
        'port' => $port,
    ];
}

/** @param array<string, mixed> $record */
function whmcs_dns_integration_record_key(array $record): string
{
    return json_encode(array_values($record), JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
}

/**
 * @param array<int, mixed> $current
 * @param array<int, mixed> $delete
 * @param array<int, mixed> $upsert
 * @return array{delete_indexes: array<int, int>, upsert: array<int, array<string, mixed>>}
 */
function whmcs_dns_integration_plan(array $current, array $delete, array $upsert, string $domainName): array
{
    foreach (array_merge($current, $delete, $upsert) as $record) {
        if (!is_array($record)) {
            throw new InvalidArgumentException('Every DNS record must be an object-like array.');
        }
    }
    $current = array_map(
        static fn (array $record): array => whmcs_dns_integration_record($record, $domainName),
        $current
    );
    $delete = array_map(
        static fn (array $record): array => whmcs_dns_integration_record($record, $domainName),
        $delete
    );
    $upsert = array_map(
        static fn (array $record): array => whmcs_dns_integration_record($record, $domainName),
        $upsert
    );

    $deleteKeys = array_fill_keys(array_map('whmcs_dns_integration_record_key', $delete), true);
    $deleteIndexes = [];
    $remaining = [];
    foreach ($current as $index => $record) {
        $key = whmcs_dns_integration_record_key($record);
        if (isset($deleteKeys[$key])) {
            $deleteIndexes[] = $index;
        } else {
            $remaining[$key] = true;
        }
    }

    $create = [];
    foreach ($upsert as $record) {
        $key = whmcs_dns_integration_record_key($record);
        if (!isset($remaining[$key])) {
            $create[$key] = $record;
            $remaining[$key] = true;
        }
    }

    $postChange = [];
    foreach ($current as $index => $record) {
        if (!in_array($index, $deleteIndexes, true)) {
            $postChange[] = $record;
        }
    }
    array_push($postChange, ...array_values($create));
    $typesByName = [];
    foreach ($postChange as $record) {
        $type = (string) $record['type'];
        $typesByName[$record['name']][$type] = ($typesByName[$record['name']][$type] ?? 0) + 1;
    }
    foreach ($typesByName as $types) {
        if (($types['CNAME'] ?? 0) > 1 || (isset($types['CNAME']) && count($types) > 1)) {
            throw new UnexpectedValueException('A CNAME cannot coexist with another record at the same name.', 409);
        }
    }

    return ['delete_indexes' => $deleteIndexes, 'upsert' => array_values($create)];
}

/** @param array<int, array<string, mixed>> $records */
function whmcs_dns_integration_replacement_note(string $operation, string $domainName, array $records): string
{
    $lines = [
        "DNS integration {$operation} for {$domainName} at " . gmdate('c'),
        'Deleted/replaced records:',
    ];
    foreach ($records as $record) {
        $lines[] = sprintf(
            '%s %s %s TTL %d%s',
            (string) $record['type'],
            $record['name'] === '' ? '@' : (string) $record['name'],
            (string) $record['value'],
            (int) $record['ttl'],
            $record['priority'] === null ? '' : ' priority ' . (int) $record['priority']
        );
    }
    $note = implode("\n", $lines);
    if (strlen($note) > 60000) {
        throw new RuntimeException('The DNS replacement list is too large for a WHMCS client note.');
    }
    return $note;
}

/** @param array<int, array<string, mixed>> $records */
function whmcs_dns_integration_save_replacement_note(
    int $clientId,
    string $operation,
    string $domainName,
    array $records
): void {
    $result = localAPI('AddClientNote', [
        'userid' => $clientId,
        'notes' => whmcs_dns_integration_replacement_note($operation, $domainName, $records),
        'sticky' => false,
    ]);
    if (($result['result'] ?? null) !== 'success') {
        throw new RuntimeException('Could not save replaced DNS records to the client notes.');
    }
}

/** @return array{zone: object, domain: string, provider: string, config: array<string, mixed>} */
function whmcs_dns_integration_context(int $clientId, string $domainName): array
{
    $domainName = whmcs_dns_normalize_hostname($domainName);
    if ($clientId <= 0 || filter_var($domainName, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false) {
        throw new InvalidArgumentException('A valid client and domain are required.');
    }
    $zone = Capsule::table(WHMCSDNS_TABLE_ZONES)->where('domain_name', $domainName)->first();
    if (!$zone) {
        throw new UnexpectedValueException('DNS is not enabled for this domain.', 404);
    }
    if ((int) $zone->client_id !== $clientId) {
        throw new UnexpectedValueException('The DNS zone belongs to another WHMCS client.', 403);
    }

    $zoneConfig = json_decode((string) $zone->config, true);
    $provider = is_array($zoneConfig) ? (string) ($zoneConfig['provider'] ?? '') : '';
    $config = whmcs_dns_provider_record_config($domainName);
    if ($provider === '' || $provider !== ($config['provider'] ?? null)) {
        throw new RuntimeException('The DNS zone provider does not match the configured provider.');
    }
    return ['zone' => $zone, 'domain' => $domainName, 'provider' => $provider, 'config' => $config];
}

/** @return array{enabled: bool, domain: string, client_id: int, provider: string|null} */
function whmcs_dns_integration_status(int $clientId, string $domainName): array
{
    $domainName = whmcs_dns_normalize_hostname($domainName);
    if ($clientId <= 0 || filter_var($domainName, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false) {
        throw new InvalidArgumentException('A valid client and domain are required.');
    }
    $zone = Capsule::table(WHMCSDNS_TABLE_ZONES)->where('domain_name', $domainName)->first();
    if (!$zone) {
        return ['enabled' => false, 'domain' => $domainName, 'client_id' => $clientId, 'provider' => null];
    }
    if ((int) $zone->client_id !== $clientId) {
        throw new UnexpectedValueException('The DNS zone belongs to another WHMCS client.', 403);
    }
    $config = json_decode((string) $zone->config, true);
    return [
        'enabled' => true,
        'domain' => $domainName,
        'client_id' => $clientId,
        'provider' => is_array($config) && is_string($config['provider'] ?? null) ? $config['provider'] : null,
    ];
}

/** @return array<int, array{name: string, type: string, value: string, ttl: int, priority: int|null, weight: int|null, port: int|null}> */
function whmcs_dns_integration_list_records(int $clientId, string $domainName): array
{
    $context = whmcs_dns_integration_context($clientId, $domainName);

    $rows = Capsule::table(WHMCSDNS_TABLE_RECORDS)
        ->where('domain_id', $context['zone']->id)
        ->get();
    $records = [];
    foreach ($rows as $row) {
        $type = strtoupper((string) $row->type);
        $records[] = whmcs_dns_integration_record([
            'name' => (string) $row->host,
            'type' => $type,
            'value' => (string) $row->value,
            'ttl' => $row->ttl ?? 3600,
            'priority' => $row->priority ?? ($type === 'MX' ? 0 : null),
            'weight' => $row->weight,
            'port' => $row->port,
        ], $context['domain']);
    }
    return $records;
}

/**
 * @param array<int, mixed> $delete
 * @param array<int, mixed> $upsert
 * @return array{deleted_count: int, created_count: int}
 */
function whmcs_dns_integration_apply_records(
    int $clientId,
    string $domainName,
    array $delete,
    array $upsert,
    string $operation
): array {
    $operation = trim($operation);
    if ($operation === '' || strlen($operation) > 100 || preg_match('/^[a-z0-9 _-]+$/iD', $operation) !== 1) {
        throw new InvalidArgumentException('A valid DNS operation label is required.');
    }
    foreach (array_merge($delete, $upsert) as $record) {
        if (!is_array($record)) {
            throw new InvalidArgumentException('Every DNS record must be an object-like array.');
        }
    }
    foreach ($upsert as $record) {
        if (!in_array(strtoupper((string) ($record['type'] ?? '')), ['MX', 'TXT', 'CNAME'], true)) {
            throw new InvalidArgumentException('Only MX, TXT, and CNAME records may be added through the integration API.');
        }
    }
    $context = whmcs_dns_integration_context($clientId, $domainName);
    if ($upsert !== [] && !whmcs_dns_client_can_manage_domain_name($clientId, $context['domain'])) {
        throw new UnexpectedValueException('The WHMCS client does not have an active service for this domain.', 403);
    }

    $rows = Capsule::table(WHMCSDNS_TABLE_RECORDS)
        ->where('domain_id', $context['zone']->id)
        ->get()
        ->all();
    $current = [];
    foreach ($rows as $row) {
        $type = strtoupper((string) $row->type);
        $current[] = whmcs_dns_integration_record([
            'name' => (string) $row->host,
            'type' => $type,
            'value' => (string) $row->value,
            'ttl' => $row->ttl ?? 3600,
            'priority' => $row->priority ?? ($type === 'MX' ? 0 : null),
            'weight' => $row->weight,
            'port' => $row->port,
        ], $context['domain']);
    }
    $plan = whmcs_dns_integration_plan($current, $delete, $upsert, $context['domain']);
    if ($plan['delete_indexes'] === [] && $plan['upsert'] === []) {
        return ['deleted_count' => 0, 'created_count' => 0];
    }
    whmcs_dns_enforce_mutation_limit($clientId);

    $deleted = array_map(static fn (int $index): array => $current[$index], $plan['delete_indexes']);
    if ($deleted !== []) {
        whmcs_dns_integration_save_replacement_note($clientId, $operation, $context['domain'], $deleted);
    }

    $plex = new PlexService(Capsule::connection()->getPdo());
    foreach ($plan['delete_indexes'] as $index) {
        $record = $current[$index];
        $plex->delRecord($context['config'] + [
            'record_id' => (int) $rows[$index]->id,
            'record_name' => $record['name'],
            'record_type' => $record['type'],
            'record_value' => whmcs_dns_provider_record_value(
                $context['provider'],
                (string) $record['type'],
                (string) $record['value']
            ),
            'record_ttl' => $record['ttl'],
        ]);
    }
    foreach ($plan['upsert'] as $record) {
        $plex->addRecord($context['config'] + [
            'record_name' => $record['name'],
            'record_type' => $record['type'],
            'record_value' => whmcs_dns_provider_record_value(
                $context['provider'],
                (string) $record['type'],
                (string) $record['value']
            ),
            'record_ttl' => $record['ttl'],
            'record_priority' => $record['priority'],
            'record_weight' => null,
            'record_port' => null,
        ]);
    }

    return ['deleted_count' => count($plan['delete_indexes']), 'created_count' => count($plan['upsert'])];
}

/**
 * Create DB tables
 *
 * @return array<string, string>
 */
function whmcs_dns_activate(): array
{
    try {
        whmcs_dns_create_rate_limit_table();
        whmcs_dns_create_api_key_table();

        if (!Capsule::schema()->hasTable(WHMCSDNS_TABLE_ZONES)) {
            Capsule::schema()->create(WHMCSDNS_TABLE_ZONES, function ($table) {
                /** @var \Illuminate\Database\Schema\Blueprint $table */
                $table->bigIncrements('id');
                $table->bigInteger('client_id')->unsigned()->index();
                $table->string('domain_name', 75)->nullable()->unique();
                $table->string('provider_id', 11)->nullable();
                $table->string('zoneId', 100)->nullable();
                $table->text('config');
                $table->dateTime('created_at')->useCurrent();
                $table->dateTime('updated_at')->useCurrent()->useCurrentOnUpdate();
            });
        }

        if (!Capsule::schema()->hasTable(WHMCSDNS_TABLE_RECORDS)) {
            Capsule::schema()->create(WHMCSDNS_TABLE_RECORDS, function ($table) {
                /** @var \Illuminate\Database\Schema\Blueprint $table */
                $table->bigIncrements('id');
                $table->bigInteger('domain_id')->unsigned()->index();
                $table->string('recordId', 100)->nullable();
                $table->string('type', 10);
                $table->string('host', 255);
                $table->text('value');
                $table->integer('ttl')->nullable();
                $table->integer('priority')->nullable();
                $table->integer('weight')->nullable();
                $table->integer('port')->nullable();
                $table->dateTime('created_at')->useCurrent();
                $table->dateTime('updated_at')->useCurrent()->useCurrentOnUpdate();

                // Foreign keys are optional in many WHMCS installs; enable only if you know your DB config allows it.
                // $table->foreign('domain_id')->references('id')->on(WHMCSDNS_TABLE_ZONES)->onDelete('cascade');
            });
        }

        return ['status' => 'success', 'description' => 'WHMCS-DNS addon activated.'];
    } catch (Throwable $e) {
        return ['status' => 'error', 'description' => 'Activation failed: ' . $e->getMessage()];
    }
}

/**
 * Drop tables
 *
 * @return array<string, string>
 */
function whmcs_dns_deactivate(): array
{
    try {
        if (Capsule::schema()->hasTable(WHMCSDNS_TABLE_API_KEYS)) {
            Capsule::schema()->drop(WHMCSDNS_TABLE_API_KEYS);
        }
        if (Capsule::schema()->hasTable(WHMCSDNS_TABLE_RATE_LIMITS)) {
            Capsule::schema()->drop(WHMCSDNS_TABLE_RATE_LIMITS);
        }
        if (Capsule::schema()->hasTable(WHMCSDNS_TABLE_RECORDS)) {
            Capsule::schema()->drop(WHMCSDNS_TABLE_RECORDS);
        }
        if (Capsule::schema()->hasTable(WHMCSDNS_TABLE_ZONES)) {
            Capsule::schema()->drop(WHMCSDNS_TABLE_ZONES);
        }

        return ['status' => 'success', 'description' => 'WHMCS-DNS addon deactivated.'];
    } catch (Throwable $e) {
        return ['status' => 'error', 'description' => 'Deactivation failed: ' . $e->getMessage()];
    }
}

/** @param array<string, mixed> $vars */
function whmcs_dns_upgrade(array $vars): void
{
    whmcs_dns_create_rate_limit_table();
    whmcs_dns_create_api_key_table();
    whmcs_dns_add_srv_columns();
    Capsule::table('tbladdonmodules')
        ->where('module', 'whmcs_dns')
        ->whereIn('setting', [
            'refresh_api_token_hash',
            'connect_website_api_token_hash',
            'cpanel_sync_api_token_hash',
        ])
        ->delete();
}

/** @return array<int, array<string, mixed>> */
function whmcs_dns_admin_reconciliation(string $apiKey): array
{
    $provider = new BunnyProvider(['apikey' => $apiKey]);
    $bunnyZones = [];
    foreach ($provider->listDomains() as $zone) {
        if (!is_array($zone) || !is_numeric($zone['id'] ?? null) || !is_string($zone['domain'] ?? null)) {
            throw new RuntimeException('Bunny returned an invalid DNS zone.');
        }
        $bunnyZones[] = ['id' => (string) $zone['id'], 'domain' => $zone['domain']];
    }

    $localZones = Capsule::table(WHMCSDNS_TABLE_ZONES)
        ->select('id', 'client_id', 'domain_name', 'zoneId')
        ->get()
        ->map(static fn ($zone): array => [
            'id' => (int) $zone->id,
            'client_id' => (int) $zone->client_id,
            'domain' => (string) $zone->domain_name,
            'zone_id' => (string) ($zone->zoneId ?? ''),
        ])
        ->toArray();

    $sources = Capsule::table('tbldomains')
        ->select('id', 'userid', 'domain', 'status')
        ->where('domain', '<>', '')
        ->get()
        ->map(static fn ($domain): array => [
            'client_id' => (int) $domain->userid,
            'domain' => whmcs_dns_normalize_hostname((string) $domain->domain),
            'id' => (int) $domain->id,
            'kind' => 'domain',
            'name' => whmcs_dns_normalize_hostname((string) $domain->domain),
            'status' => (string) $domain->status,
        ])
        ->toArray();

    // ponytail: scan service hostnames here; add a stored apex only if this admin page becomes measurably slow.
    foreach (Capsule::table('tblhosting')
        ->select('id', 'userid', 'domain', 'domainstatus')
        ->where('domain', '<>', '')
        ->get() as $service) {
        $apex = whmcs_dns_registrable_domain((string) $service->domain);
        if ($apex === null) {
            continue;
        }
        $sources[] = [
            'client_id' => (int) $service->userid,
            'domain' => $apex,
            'id' => (int) $service->id,
            'kind' => 'service',
            'name' => whmcs_dns_normalize_hostname((string) $service->domain),
            'status' => (string) $service->domainstatus,
        ];
    }

    return whmcs_dns_reconciliation_rows($bunnyZones, $localZones, $sources);
}

/**
 * @param array<int, array<string, mixed>> $rows
 * @return array<string, mixed>
 */
function whmcs_dns_admin_find_row(array $rows, string $domainName): array
{
    foreach ($rows as $row) {
        if ($row['domain'] === $domainName) {
            return $row;
        }
    }
    throw new InvalidArgumentException('The selected reconciliation row no longer exists.');
}

/** @param array<string, mixed> $row */
function whmcs_dns_admin_repair(array $row, int $clientId, string $apiKey): int
{
    if ($row['bunny'] === null || $row['active_sources'] === [] || $row['status'] === 'conflict'
        || !in_array($clientId, $row['eligible_client_ids'], true)) {
        throw new InvalidArgumentException('This customer is not eligible to own the zone.');
    }

    $domainName = (string) $row['domain'];
    $now = date('Y-m-d H:i:s');
    $values = [
        'client_id' => $clientId,
        'zoneId' => (string) $row['bunny']['id'],
        'config' => json_encode(['provider' => 'Bunny'], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR),
        'updated_at' => $now,
    ];
    $zone = Capsule::table(WHMCSDNS_TABLE_ZONES)->where('domain_name', $domainName)->first();
    if ($zone) {
        Capsule::table(WHMCSDNS_TABLE_ZONES)->where('id', $zone->id)->update($values);
    } else {
        Capsule::table(WHMCSDNS_TABLE_ZONES)->insert($values + [
            'domain_name' => $domainName,
            'created_at' => $now,
        ]);
    }

    return (new PlexService(Capsule::connection()->getPdo()))->sync([
        'domain_name' => $domainName,
        'provider' => 'Bunny',
        'apikey' => $apiKey,
    ]);
}

/** @param array<string, mixed> $row */
function whmcs_dns_admin_enable(array $row, string $apiKey): int
{
    if ($row['status'] !== 'missing' || count($row['eligible_client_ids']) !== 1) {
        throw new InvalidArgumentException('This zone is not eligible to be enabled.');
    }

    $domainName = (string) $row['domain'];
    $clientId = (int) $row['eligible_client_ids'][0];
    whmcs_dns_enable_domain($clientId, [
        'domain_name' => $domainName,
        'provider' => 'Bunny',
        'apikey' => $apiKey,
    ]);

    $zone = Capsule::table(WHMCSDNS_TABLE_ZONES)->where('domain_name', $domainName)->first();
    return $zone
        ? Capsule::table(WHMCSDNS_TABLE_RECORDS)->where('domain_id', $zone->id)->count()
        : 0;
}

/** @param array<string, mixed> $row */
function whmcs_dns_admin_disable(array $row, string $apiKey): void
{
    $domainName = (string) $row['domain'];
    if ($row['bunny'] === null && $row['local'] === null) {
        throw new InvalidArgumentException('There is no zone state to remove.');
    }

    if ($row['bunny'] !== null) {
        $noteClientId = (int) ($row['local']['client_id'] ?? $row['sources'][0]['client_id'] ?? 0);
        if ($noteClientId > 0) {
            whmcs_dns_save_bunny_zone_note(
                $noteClientId,
                $domainName,
                $apiKey,
                (string) $row['bunny']['id']
            );
        }
        (new BunnyProvider([
            'apikey' => $apiKey,
            'domain_name' => $domainName,
            'zone_id' => (string) $row['bunny']['id'],
        ]))->deleteDomain($domainName);
    }

    if ($row['local'] !== null) {
        Capsule::connection()->transaction(function () use ($row): void {
            Capsule::table(WHMCSDNS_TABLE_RECORDS)->where('domain_id', $row['local']['id'])->delete();
            Capsule::table(WHMCSDNS_TABLE_ZONES)->where('id', $row['local']['id'])->delete();
        });
    }
}

/** @param array<string, mixed> $vars */
function whmcs_dns_output(array $vars): void
{
    $moduleLink = (string) ($vars['modulelink'] ?? 'addonmodules.php?module=whmcs_dns');
    $providerName = (string) ($vars['provider'] ?? '');
    $apiKey = (string) ($vars['apikey'] ?? '');
    $escape = static fn (mixed $value): string => htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
    $notice = isset($_GET['dns_notice']) ? ['type' => 'success', 'text' => (string) $_GET['dns_notice']] : null;
    if (isset($_GET['dns_error'])) {
        $notice = ['type' => 'danger', 'text' => (string) $_GET['dns_error']];
    }

    if (($_GET['dns_action'] ?? '') === 'manage') {
        try {
            $itemId = filter_var($_GET['item_id'] ?? null, FILTER_VALIDATE_INT, [
                'options' => ['min_range' => 1],
            ]);
            $itemType = (string) ($_GET['item_type'] ?? '');
            if ($itemId === false) {
                throw new InvalidArgumentException('Invalid Manage DNS link.');
            }
            $context = whmcs_dns_admin_item_context($itemType, (int) $itemId);
            if ($context === null) {
                throw new InvalidArgumentException('This item is not active or does not have a valid domain.');
            }

            $sso = localAPI('CreateSsoToken', [
                'client_id' => $context['client_id'],
                'destination' => 'sso:custom_redirect',
                'sso_redirect_path' => 'index.php?m=whmcs_dns&domain=' . urlencode($context['domain_name']),
            ]);
            $redirectUrl = (string) ($sso['redirect_url'] ?? '');
            if (($sso['result'] ?? '') !== 'success'
                || filter_var($redirectUrl, FILTER_VALIDATE_URL) === false) {
                throw new RuntimeException((string) ($sso['message'] ?? 'WHMCS could not create the client login.'));
            }

            logActivity('WHMCS DNS admin: Generated client login for '
                . $context['domain_name'] . ' (customer #' . $context['client_id'] . ').');
            header('Location: ' . $redirectUrl);
            exit;
        } catch (Throwable $e) {
            logModuleCall('whmcs_dns', 'admin_manage_dns', [
                'item_type' => (string) ($_GET['item_type'] ?? ''),
                'item_id' => (string) ($_GET['item_id'] ?? ''),
            ], null, $e->getMessage());
            $notice = ['type' => 'danger', 'text' => $e->getMessage()];
        }
    }

    whmcs_dns_admin_handle_api_keys();
    $token = generate_token('plain');
    whmcs_dns_admin_api_keys_output($moduleLink, $escape, $token);
    if ($notice !== null) {
        echo '<div class="alert alert-' . $escape($notice['type']) . '">' . $escape($notice['text']) . '</div>';
        $notice = null;
    }

    if ($providerName !== 'Bunny' || $apiKey === '') {
        echo '<div class="alert alert-danger">Bunny DNS must be configured before reconciliation is available.</div>';
        return;
    }

    try {
        $rows = whmcs_dns_admin_reconciliation($apiKey);
        if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
            check_token('WHMCS.admin.default');
            $action = (string) ($_POST['action'] ?? '');
            $domainName = whmcs_dns_normalize_hostname((string) ($_POST['domain_name'] ?? ''));
            $row = whmcs_dns_admin_find_row($rows, $domainName);

            if ($action === 'enable') {
                $records = whmcs_dns_admin_enable($row, $apiKey);
                $message = "Enabled {$domainName}; synced {$records} records.";
            } elseif ($action === 'repair') {
                $clientId = filter_var($_POST['client_id'] ?? null, FILTER_VALIDATE_INT, [
                    'options' => ['min_range' => 1],
                ]);
                if ($clientId === false) {
                    throw new InvalidArgumentException('A valid eligible customer is required.');
                }
                $records = whmcs_dns_admin_repair($row, $clientId, $apiKey);
                $message = "Repaired {$domainName}; synced {$records} records.";
            } elseif ($action === 'disable') {
                whmcs_dns_admin_disable($row, $apiKey);
                $message = "Disabled {$domainName}.";
            } else {
                throw new InvalidArgumentException('Invalid reconciliation action.');
            }

            logActivity('WHMCS DNS admin: ' . $message);
            redir('module=whmcs_dns&dns_notice=' . urlencode($message), 'addonmodules.php');
        }
    } catch (Throwable $e) {
        logModuleCall('whmcs_dns', 'admin_reconciliation', [], null, $e->getMessage());
        if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
            redir('module=whmcs_dns&dns_error=' . urlencode($e->getMessage()), 'addonmodules.php');
        }
        $rows = [];
        $notice = ['type' => 'danger', 'text' => $e->getMessage()];
    }

    $statusLabels = [
        'in_sync' => ['In sync', 'success'],
        'missing' => ['Missing in Bunny', 'warning'],
        'repair' => ['Needs repair', 'warning'],
        'inactive' => ['Inactive WHMCS item', 'danger'],
        'orphan' => ['Orphan', 'danger'],
        'stale_local' => ['Stale local state', 'danger'],
        'conflict' => ['Ownership conflict', 'danger'],
    ];
    $counts = array_count_values(array_column($rows, 'status'));
    $clientIds = [];
    foreach ($rows as $row) {
        if ($row['local'] !== null) {
            $clientIds[] = (int) $row['local']['client_id'];
        }
        $clientIds = array_merge($clientIds, $row['eligible_client_ids']);
    }
    $clients = [];
    if ($clientIds !== []) {
        foreach (Capsule::table('tblclients')
            ->select('id', 'firstname', 'lastname', 'companyname')
            ->whereIn('id', array_values(array_unique($clientIds)))
            ->get() as $client) {
            $name = trim((string) $client->companyname);
            $clients[(int) $client->id] = $name !== ''
                ? $name
                : trim((string) $client->firstname . ' ' . (string) $client->lastname);
        }
    }

    echo '<h2>Bunny DNS Reconciliation</h2>';
    echo '<p>Compares WHMCS domains and services with Bunny zones and the addon local mapping. Actions apply to one zone only.</p>';
    echo '<p>';
    foreach ($statusLabels as $status => [$label, $class]) {
        echo '<span class="label label-' . $class . '" style="margin-right:8px">'
            . $escape($label) . ': ' . (int) ($counts[$status] ?? 0) . '</span>';
    }
    echo '</p><div class="table-responsive"><table class="table table-striped table-bordered">'
        . '<thead><tr><th>Domain</th><th>WHMCS item</th><th>Customer / local mapping</th>'
        . '<th>Bunny</th><th>Status</th><th style="min-width:250px">Actions</th></tr></thead><tbody>';

    foreach ($rows as $row) {
        [$statusLabel, $statusClass] = $statusLabels[$row['status']];
        $source = $row['sources'][0] ?? null;
        echo '<tr><td><strong>' . $escape($row['domain']) . '</strong></td><td>';
        if ($source === null) {
            echo '<span class="text-muted">No matching WHMCS item</span>';
        } else {
            $sourceUrl = $source['kind'] === 'domain'
                ? 'clientsdomains.php?id=' . (int) $source['id']
                : 'clientsservices.php?id=' . (int) $source['id'];
            if (whmcs_dns_domain_status_allowed($source['status'])) {
                echo '<span class="text-success" aria-label="Active">&#10003;</span> ';
            }
            echo '<a href="' . $escape($sourceUrl) . '">' . $escape($source['name']) . '</a>'
                . '<br><small>' . $escape(ucfirst($source['kind']) . ': ' . $source['status']) . '</small>';
        }
        echo '</td><td>';
        if ($row['local'] === null) {
            echo '<span class="text-muted">No local mapping</span>';
        } else {
            $ownerId = (int) $row['local']['client_id'];
            echo '<a href="clientssummary.php?userid=' . $ownerId . '">'
                . $escape($clients[$ownerId] ?? "Customer #{$ownerId}") . '</a>'
                . '<br><small>Local zone #' . (int) $row['local']['id']
                . ', Bunny ID ' . $escape($row['local']['zone_id'] ?: 'missing') . '</small>';
        }
        echo '</td><td>' . ($row['bunny'] === null
            ? '<span class="text-muted">Missing</span>'
            : 'Zone #' . $escape($row['bunny']['id'])) . '</td>'
            . '<td><span class="label label-' . $statusClass . '">' . $escape($statusLabel) . '</span></td><td>';

        if ($row['status'] === 'missing') {
            echo '<form method="post" action="' . $escape($moduleLink) . '" style="display:inline-block;margin-right:6px">'
                . '<input type="hidden" name="token" value="' . $escape($token) . '">'
                . '<input type="hidden" name="action" value="enable">'
                . '<input type="hidden" name="domain_name" value="' . $escape($row['domain']) . '">'
                . '<button class="btn btn-primary btn-xs" type="submit">Enable</button></form>';
        }
        if ($row['status'] === 'repair') {
            echo '<form method="post" action="' . $escape($moduleLink) . '" style="display:inline-block;margin-right:6px">'
                . '<input type="hidden" name="token" value="' . $escape($token) . '">'
                . '<input type="hidden" name="action" value="repair">'
                . '<input type="hidden" name="domain_name" value="' . $escape($row['domain']) . '">'
                . '<select name="client_id" class="form-control input-sm" style="width:auto;display:inline-block" aria-label="Eligible customer">';
            foreach ($row['eligible_client_ids'] as $clientId) {
                echo '<option value="' . (int) $clientId . '">'
                    . $escape($clients[$clientId] ?? "Customer #{$clientId}") . '</option>';
            }
            echo '</select> <button class="btn btn-warning btn-xs" type="submit">Repair owner/cache</button></form>';
        }
        if ($row['status'] !== 'conflict' && ($row['bunny'] !== null || $row['local'] !== null)) {
            $warning = $row['bunny'] !== null
                ? 'WARNING: Permanently delete the Bunny DNS zone and all records for ' . $row['domain'] . '? This cannot be undone.'
                : 'Remove stale local DNS state for ' . $row['domain'] . '?';
            echo '<form method="post" action="' . $escape($moduleLink) . '" style="display:inline-block" onsubmit="return confirm(&quot;'
                . $escape($warning) . '&quot;)">'
                . '<input type="hidden" name="token" value="' . $escape($token) . '">'
                . '<input type="hidden" name="action" value="disable">'
                . '<input type="hidden" name="domain_name" value="' . $escape($row['domain']) . '">'
                . '<button class="btn btn-danger btn-xs" type="submit">'
                . ($row['bunny'] !== null ? 'Disable / delete' : 'Clear local state') . '</button></form>';
        }
        if ($row['status'] === 'conflict') {
            echo '<span class="text-danger">No automatic action: multiple active customers claim this apex.</span>';
        }
        echo '</td></tr>';
    }
    if ($rows === []) {
        echo '<tr><td colspan="6">No DNS reconciliation rows found.</td></tr>';
    }
    echo '</tbody></table></div>';
}

/**
 * Client area page
 *
 * @param array<string, mixed> $vars
 * @return array<string, mixed>
 */
function whmcs_dns_clientarea(array $vars): array
{
    // Ensure client is logged in
    if (empty($_SESSION['uid'])) {
        return [
            'pagetitle'    => 'DNS Manager',
            'breadcrumb'   => ['index.php?m=whmcs_dns' => 'DNS Manager'],
            'templatefile' => 'clientarea',
            'requirelogin' => true,
            'vars'         => ['error' => 'Please login first.'],
        ];
    }

    $clientId = (int) $_SESSION['uid'];

    if (!whmcs_dns_can_manage_domains($clientId)) {
        return [
            'pagetitle'    => 'DNS Manager',
            'breadcrumb'   => ['index.php?m=whmcs_dns' => 'DNS Manager'],
            'templatefile' => 'clientarea',
            'requirelogin' => true,
            'vars'         => [
                'message' => ['type' => 'error', 'text' => 'You do not have permission to manage domains.'],
                'domainAvailable' => false,
                'clientDomains' => [],
                'selectedDomain' => '',
                'zone' => null,
                'records' => [],
            ],
        ];
    }

    $provider = $vars['provider'] ?? '';
    $apikey   = $vars['apikey'] ?? '';

    // List user WHMCS domains
    $clientDomains = Capsule::table('tbldomains')
        ->select('id', 'domain', 'status')
        ->where('userid', $clientId)
        ->where('status', 'Active')
        ->orderBy('domain', 'asc')
        ->get()
        ->map(function ($d) {
            return [
                'id'     => (int)$d->id,
                'domain' => (string)$d->domain,
                'status' => (string)$d->status,
            ];
        })
        ->toArray();

    $selectedDomain = whmcs_dns_normalize_hostname((string)($_REQUEST['domain'] ?? ''));
    $message = null;

    $isActiveDomain = fn (string $domainName): bool =>
        whmcs_dns_client_can_manage_domain_name($clientId, $domainName);

    $domainAvailable = $selectedDomain !== '' && $isActiveDomain($selectedDomain);
    if ($selectedDomain !== '' && !$domainAvailable) {
        $message = ['type' => 'error', 'text' => 'This domain is not active or does not belong to your account.'];
    }

    $pdo = Capsule::connection()->getPdo();
    $plex = new PlexService($pdo);

    // Helper: fetch zone
    $getZone = function (string $domainName) use ($clientId) {
        $zone = Capsule::table(WHMCSDNS_TABLE_ZONES)
            ->where('domain_name', $domainName)
            ->where('client_id', $clientId)
            ->first();
        return $zone ?: null;
    };

    // Handle actions (add / update / delete)
    if (!empty($_POST['action'])) {
        check_token(); // WHMCS client token

        $action = (string)$_POST['action'];
        $domainName = whmcs_dns_normalize_hostname((string)($_POST['domain_name'] ?? ''));
        if ($domainName === '') {
            $message = ['type' => 'error', 'text' => 'Domain is required.'];
        } else {
            if (!$isActiveDomain($domainName)) {
                $message = ['type' => 'error', 'text' => 'Domain is not active or does not belong to your account.'];
            } elseif ($provider === '') {
                $message = ['type' => 'error', 'text' => 'DNS provider is not configured.'];
            } else {
                try {
                    whmcs_dns_enforce_mutation_limit($clientId);

                    if ($action === 'enable_dns') {
                        // Create zone explicitly (no silent auto-create)
                        $zone = Capsule::table(WHMCSDNS_TABLE_ZONES)
                            ->where('domain_name', $domainName)
                            ->where('client_id', $clientId)
                            ->first();

                        $applyCustomNameservers = $provider === 'Bunny'
                            && ($vars['apply_custom_nameservers'] ?? '') === 'on';
                        if ($applyCustomNameservers) {
                            // Validate before creating a zone so bad addon configuration cannot leave an orphan.
                            whmcs_dns_bunny_nameserver_payload(
                                (string) ($vars['ns1'] ?? ''),
                                (string) ($vars['ns2'] ?? '')
                            );
                        }

                        if ($zone) {
                            $messageText = 'DNS is already enabled for this domain.';
                        } else {
                            $cfg = [
                                'domain_name' => $domainName,
                                'provider'    => $provider,
                                'apikey'      => $apikey,
                            ];

                            if ($provider === 'PowerDNS') {
                                $cfg['powerdnsip'] = $vars['bind_powerdns_api_ip'] ?? null;
                                for ($i = 1; $i <= 5; $i++) {
                                    $k = 'ns' . $i;
                                    if (!empty($vars[$k])) $cfg[$k] = $vars[$k];
                                }
                            } elseif ($provider === 'Bind') {
                                $cfg['bindip'] = $vars['bind_powerdns_api_ip'] ?? null;
                                for ($i = 1; $i <= 5; $i++) {
                                    $k = 'ns' . $i;
                                    if (!empty($vars[$k])) $cfg[$k] = $vars[$k];
                                }
                            }

                            $created = whmcs_dns_enable_domain($clientId, $cfg);
                            $zone = Capsule::table(WHMCSDNS_TABLE_ZONES)
                                ->where('domain_name', $domainName)
                                ->where('client_id', $clientId)
                                ->first();
                            $messageText = $created
                                ? 'DNS enabled. Zone created.'
                                : 'DNS enabled. Existing provider zone adopted.';
                        }

                        if ($applyCustomNameservers) {
                            if (!$zone) {
                                throw new RuntimeException('Zone was created but its local configuration is missing.');
                            }
                            whmcs_dns_apply_bunny_nameservers(
                                $apikey,
                                (string) ($zone->zoneId ?? ''),
                                (string) ($vars['ns1'] ?? ''),
                                (string) ($vars['ns2'] ?? '')
                            );
                            $messageText .= ' Custom nameservers applied.';
                        }

                        $message = ['type' => 'success', 'text' => $messageText];
                    }

                    if ($action === 'disable_dns') {
                        // Delete zone explicitly
                        $zone = Capsule::table(WHMCSDNS_TABLE_ZONES)
                            ->where('domain_name', $domainName)
                            ->where('client_id', $clientId)
                            ->first();

                        if (!$zone) {
                            $message = ['type' => 'success', 'text' => 'DNS is already disabled (zone not found).'];
                        } else {
                            $cfg = [
                                'domain_name' => $domainName,
                                'provider'    => $provider,
                                'apikey'      => $apikey,
                            ];

                            if ($provider === 'PowerDNS') {
                                $cfg['powerdnsip'] = $vars['bind_powerdns_api_ip'] ?? null;
                                for ($i = 1; $i <= 5; $i++) {
                                    $k = 'ns' . $i;
                                    if (!empty($vars[$k])) $cfg[$k] = $vars[$k];
                                }
                            } elseif ($provider === 'Bind') {
                                $cfg['bindip'] = $vars['bind_powerdns_api_ip'] ?? null;
                                for ($i = 1; $i <= 5; $i++) {
                                    $k = 'ns' . $i;
                                    if (!empty($vars[$k])) $cfg[$k] = $vars[$k];
                                }
                            }

                            if ($provider === 'Bunny') {
                                whmcs_dns_save_bunny_zone_note(
                                    $clientId,
                                    $domainName,
                                    $apikey,
                                    (string) ($zone->zoneId ?? '')
                                );
                            }

                            $plex->deleteDomain([
                                'config' => json_encode($cfg, JSON_UNESCAPED_SLASHES),
                            ]);

                            Capsule::table(WHMCSDNS_TABLE_RECORDS)->where('domain_id', $zone->id)->delete();
                            Capsule::table(WHMCSDNS_TABLE_ZONES)->where('id', $zone->id)->delete();

                            $message = ['type' => 'success', 'text' => 'DNS disabled. Zone deleted.'];
                        }
                    }

                    if ($action === 'sync_records') {
                        if (!$getZone($domainName)) {
                            throw new RuntimeException('DNS is not enabled for this domain.');
                        }

                        $count = $plex->sync(whmcs_dns_provider_record_config($domainName));
                        $message = ['type' => 'success', 'text' => "Synced {$count} records from the DNS provider."];
                    }

                    if ($action === 'add_record') {
                        $recordName  = (string)($_POST['record_name'] ?? '');
                        $recordType  = strtoupper((string)($_POST['record_type'] ?? ''));
                        $recordValue = (string)($_POST['record_value'] ?? '');
                        $ttl         = isset($_POST['record_ttl']) ? (int)$_POST['record_ttl'] : 3600;
                        $priority    = (isset($_POST['record_priority']) && $_POST['record_priority'] !== '')
                            ? (int)$_POST['record_priority'] : null;
                        $weight = null;
                        $port = null;

                        if ($recordType === '' || $recordValue === '') {
                            throw new Exception('Record type and value are required.');
                        }

                        if ($recordType === 'MX' && $priority === null) {
                            $priority = 0;
                        }

                        if ($recordType === 'SRV') {
                            $priority = whmcs_dns_srv_number($_POST['record_priority'] ?? null, 'priority');
                            $weight = whmcs_dns_srv_number($_POST['record_weight'] ?? null, 'weight');
                            $port = whmcs_dns_srv_number($_POST['record_port'] ?? null, 'port');
                        }

                        $recordValue = whmcs_dns_provider_record_value($provider, $recordType, $recordValue);

                        if (in_array($provider, ['PowerDNS'], true) && $recordType === 'CNAME') {
                            $recordValue = rtrim(trim($recordValue), '.') . '.';
                        }

                        $zone = Capsule::table(WHMCSDNS_TABLE_ZONES)
                            ->where('domain_name', $domainName)
                            ->where('client_id', $clientId)
                            ->first();
                        if (!$zone) {
                            throw new Exception('DNS is not enabled for this domain. Click "Enable DNS" first.');
                        }

                        $req = [
                            'domain_name'      => $domainName,
                            'record_name'      => $recordName,
                            'record_type'      => $recordType,
                            'record_value'     => $recordValue,
                            'record_ttl'       => $ttl,
                            'record_priority'  => $priority,
                            'record_weight'    => $weight,
                            'record_port'      => $port,
                            'provider'         => $provider,
                            'apikey'           => $apikey,
                        ];

                        if ($provider === 'PowerDNS') {
                            $req['powerdnsip'] = $vars['bind_powerdns_api_ip'] ?? null;
                            for ($i = 1; $i <= 5; $i++) {
                                $k = 'ns' . $i;
                                if (!empty($vars[$k])) $req[$k] = $vars[$k];
                            }
                        } elseif ($provider === 'Bind') {
                            $req['bindip'] = $vars['bind_powerdns_api_ip'] ?? null;
                            for ($i = 1; $i <= 5; $i++) {
                                $k = 'ns' . $i;
                                if (!empty($vars[$k])) $req[$k] = $vars[$k];
                            }
                        }

                        $plex->addRecord($req);

                        $message = ['type' => 'success', 'text' => 'Record added.'];
                    }

                    if ($action === 'update_record') {
                        $rowId      = (int)($_POST['row_id'] ?? 0);
                        $recordName  = (string)($_POST['record_name'] ?? '');
                        $recordType  = strtoupper((string)($_POST['record_type'] ?? ''));
                        $recordValue = (string)($_POST['record_value'] ?? '');
                        $ttl         = isset($_POST['record_ttl']) ? (int)$_POST['record_ttl'] : 3600;
                        $priority    = (isset($_POST['record_priority']) && $_POST['record_priority'] !== '')
                            ? (int)$_POST['record_priority'] : null;
                        $weight = null;
                        $port = null;

                        if ($rowId <= 0) {
                            throw new Exception('Invalid record row id.');
                        }
                        
                        if ($recordType === 'MX' && $priority === null) {
                            $priority = 0;
                        }

                        if ($recordType === 'SRV') {
                            $priority = whmcs_dns_srv_number($_POST['record_priority'] ?? null, 'priority');
                            $weight = whmcs_dns_srv_number($_POST['record_weight'] ?? null, 'weight');
                            $port = whmcs_dns_srv_number($_POST['record_port'] ?? null, 'port');
                        }

                        $recordValue = whmcs_dns_provider_record_value($provider, $recordType, $recordValue);

                        if (in_array($provider, ['PowerDNS'], true) && $recordType === 'CNAME') {
                            $recordValue = rtrim(trim($recordValue), '.') . '.';
                        }

                        // Resolve zone + row ownership
                        $zone = Capsule::table(WHMCSDNS_TABLE_ZONES)
                            ->where('domain_name', $domainName)
                            ->where('client_id', $clientId)
                            ->first();
                        if (!$zone) {
                            throw new Exception('Zone not found. Refresh and try again.');
                        }

                        $rec = Capsule::table(WHMCSDNS_TABLE_RECORDS)
                            ->where('id', $rowId)
                            ->where('domain_id', $zone->id)
                            ->first();
                        if (!$rec) {
                            throw new Exception('Record not found. Please refresh and try again.');
                        }

                        $oldValue = (string)($_POST['old_value'] ?? '');
                        if ($oldValue !== '' && (string)$rec->value !== $oldValue) {
                            throw new Exception('Record changed since page load. Please refresh and try again.');
                        }

                        $recordId = $rec->recordId ?? null;
                        if (empty($recordId)) {
                            throw new Exception('This record is missing provider recordId. Please delete and re-create it.');
                        }
                        
                        $zone = Capsule::table(WHMCSDNS_TABLE_ZONES)
                            ->where('domain_name', $domainName)
                            ->where('client_id', $clientId)
                            ->first();
                        if (!$zone) {
                            throw new Exception('DNS is not enabled for this domain. Click "Enable DNS" first.');
                        }

                        $req = [
                            'domain_name'      => $domainName,
                            'record_id'        => $rowId,
                            'record_name'      => $recordName,
                            'record_type'      => $recordType,
                            'record_value'     => $recordValue,
                            'old_value'        => $oldValue,
                            'record_ttl'       => $ttl,
                            'record_priority'  => $priority,
                            'record_weight'    => $weight,
                            'record_port'      => $port,
                            'provider'         => $provider,
                            'apikey'           => $apikey,
                        ];

                        if ($provider === 'PowerDNS') {
                            $req['powerdnsip'] = $vars['bind_powerdns_api_ip'] ?? null;
                            for ($i = 1; $i <= 5; $i++) {
                                $k = 'ns' . $i;
                                if (!empty($vars[$k])) $req[$k] = $vars[$k];
                            }
                        } elseif ($provider === 'Bind') {
                            $req['bindip'] = $vars['bind_powerdns_api_ip'] ?? null;
                            for ($i = 1; $i <= 5; $i++) {
                                $k = 'ns' . $i;
                                if (!empty($vars[$k])) $req[$k] = $vars[$k];
                            }
                        }

                        $plex->updateRecord($req);

                        $message = ['type' => 'success', 'text' => 'Record updated.'];
                    }

                    if ($action === 'delete_record') {
                        $rowId = (int)($_POST['row_id'] ?? 0);
                        if ($rowId <= 0) {
                            throw new Exception('Invalid record row id.');
                        }

                        $zone = Capsule::table(WHMCSDNS_TABLE_ZONES)
                            ->where('domain_name', $domainName)
                            ->where('client_id', $clientId)
                            ->first();
                        if (!$zone) {
                            throw new Exception('Zone not found. Refresh and try again.');
                        }

                        $rec = Capsule::table(WHMCSDNS_TABLE_RECORDS)
                            ->where('id', $rowId)
                            ->where('domain_id', $zone->id)
                            ->first();
                        if (!$rec) {
                            throw new Exception('Record not found. Please refresh and try again.');
                        }

                        $recordId = $rec->recordId ?? null;
                        if (empty($recordId)) {
                            throw new Exception('This record is missing provider recordId. Please delete and re-create it.');
                        }
                        
                        $zone = Capsule::table(WHMCSDNS_TABLE_ZONES)
                            ->where('domain_name', $domainName)
                            ->where('client_id', $clientId)
                            ->first();
                        if (!$zone) {
                            throw new Exception('DNS is not enabled for this domain. Click "Enable DNS" first.');
                        }

                        $req = [
                            'domain_name'      => $domainName,
                            'record_id'        => $rowId,
                            'record_name'      => (string)$rec->host,
                            'record_type'      => strtoupper((string)$rec->type),
                            'record_value'     => (string)$rec->value,
                            'provider'         => $provider,
                            'apikey'           => $apikey,
                        ];

                        if ($provider === 'PowerDNS') {
                            $req['powerdnsip'] = $vars['bind_powerdns_api_ip'] ?? null;
                            for ($i = 1; $i <= 5; $i++) {
                                $k = 'ns' . $i;
                                if (!empty($vars[$k])) $req[$k] = $vars[$k];
                            }
                        } elseif ($provider === 'Bind') {
                            $req['bindip'] = $vars['bind_powerdns_api_ip'] ?? null;
                            for ($i = 1; $i <= 5; $i++) {
                                $k = 'ns' . $i;
                                if (!empty($vars[$k])) $req[$k] = $vars[$k];
                            }
                        }

                        $plex->delRecord($req);

                        $message = ['type' => 'success', 'text' => 'Record deleted.'];
                    }
                } catch (Throwable $e) {
                    $message = ['type' => 'error', 'text' => $e->getMessage()];
                }
            }
        }

        // keep domain selected after POST
        $selectedDomain = $domainName;
        $domainAvailable = $isActiveDomain($selectedDomain);
    }

    // Fetch zone + records for selected domain
    $zoneData = null;
    $records = [];

    if ($domainAvailable) {
        $zone = Capsule::table(WHMCSDNS_TABLE_ZONES)
            ->where('domain_name', $selectedDomain)
            ->where('client_id', $clientId)
            ->first();

        if ($zone) {
            $zoneData = [
                'id'          => (int)$zone->id,
                'domain_name' => (string)$zone->domain_name,
                'created_at'  => (string)$zone->created_at,
                'updated_at'  => (string)$zone->updated_at,
                'config'      => json_decode((string)$zone->config, true),
            ];

            $records = Capsule::table(WHMCSDNS_TABLE_RECORDS)
                ->select('id', 'type', 'host', 'value', 'ttl', 'priority', 'weight', 'port', 'recordId')
                ->where('domain_id', $zone->id)
                ->orderBy('type', 'asc')
                ->orderBy('host', 'asc')
                ->get()
                ->map(function ($r) use ($selectedDomain) {
                    $type = strtoupper((string) $r->type);
                    $storedValue = (string) $r->value;
                    $record = $type === 'SRV' ? whmcs_dns_integration_record([
                        'name' => (string) $r->host,
                        'type' => $type,
                        'value' => $storedValue,
                        'ttl' => $r->ttl ?? 3600,
                        'priority' => $r->priority,
                        'weight' => $r->weight,
                        'port' => $r->port,
                    ], $selectedDomain) : null;
                    return [
                        'id'       => (int)$r->id,
                        'type'     => $type,
                        'host'     => (string)$r->host,
                        'value'    => $record['value'] ?? $storedValue,
                        'stored_value' => $storedValue,
                        'ttl'      => $r->ttl !== null ? (int)$r->ttl : null,
                        'priority' => $r->priority !== null ? (int)$r->priority : null,
                        'weight'   => $record['weight'] ?? ($r->weight !== null ? (int)$r->weight : null),
                        'port'     => $record['port'] ?? ($r->port !== null ? (int)$r->port : null),
                        'recordId' => (string)($r->recordId ?? ''),
                    ];
                })
                ->toArray();
        }
    }

    $domainCrumbs = [
        'index.php?m=whmcs_dns&domain=' . urlencode($selectedDomain) => 'DNS Manager',
    ];

    if ($selectedDomain !== '') {
        $domainId = (int) Capsule::table('tbldomains')
            ->where('userid', $clientId)
            ->where('domain', $selectedDomain)
            ->where('status', 'Active')
            ->value('id');

        if ($domainId > 0) {
            $domainCrumbs = [
                'clientarea.php?action=domains' => 'My Domains',
                'clientarea.php?action=domaindetails&id=' . $domainId => $selectedDomain,
                'index.php?m=whmcs_dns&domain=' . urlencode($selectedDomain) => 'DNS Manager',
            ];
        }
    }

    return [
        'pagetitle'    => 'DNS Manager',
        'breadcrumb' => $domainCrumbs,
        'templatefile' => 'clientarea',
        'requirelogin' => true,
        'vars'         => [
            'message'        => $message,
            'clientDomains'  => $clientDomains,
            'selectedDomain' => $selectedDomain,
            'domainAvailable' => $domainAvailable,
            'zone'           => $zoneData,
            'records'        => $records,
        ],
    ];
}
