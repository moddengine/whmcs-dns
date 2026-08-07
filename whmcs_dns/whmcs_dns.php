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
use PlexDNS\Service as PlexService;
use PlexDNS\Providers\Bunny as BunnyProvider;

define('WHMCSDNS_TABLE_ZONES', 'zones');
define('WHMCSDNS_TABLE_RECORDS', 'records');
define('WHMCSDNS_TABLE_RATE_LIMITS', 'whmcs_dns_rate_limits');
define('WHMCSDNS_MUTATION_LIMIT', 30);
define('WHMCSDNS_MUTATION_WINDOW', 60);

$autoload = __DIR__ . '/vendor/autoload.php';
if (file_exists($autoload)) {
    require_once $autoload;
}
require_once __DIR__ . '/permissions.php';

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
        'version'     => '1.0.2',
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

            'refresh_api_token_hash' => [
                'FriendlyName' => 'Refresh API Token SHA-256',
                'Type'         => 'text',
                'Size'         => '64',
                'Default'      => '',
                'Description'  => 'SHA-256 hash of the bearer token allowed to call refresh.php. Leave blank to disable the API.',
            ],

            'apply_custom_nameservers' => [
                'FriendlyName' => 'Apply Custom Nameservers',
                'Type'         => 'yesno',
                'Description'  => 'Configure new Bunny DNS zones to use NS1 and NS2 below.',
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

function whmcs_dns_refresh_token_valid(string $authorization, string $configuredHash): bool
{
    if (!preg_match('/^Bearer\s+(\S+)$/i', trim($authorization), $matches)
        || !preg_match('/^[a-f0-9]{64}$/i', $configuredHash)) {
        return false;
    }

    return hash_equals(strtolower($configuredHash), hash('sha256', $matches[1]));
}

/**
 * @param array<int, mixed> $records
 * @return array<int, array<string, int|string|null>>
 */
function whmcs_dns_normalize_bunny_records(array $records): array
{
    $types = [
        0 => 'A', 1 => 'AAAA', 2 => 'CNAME', 3 => 'TXT', 4 => 'MX', 5 => 'RDR',
        8 => 'SRV', 9 => 'CAA', 12 => 'NS', 13 => 'SVCB', 14 => 'HTTPS', 15 => 'TLSA',
    ];
    $rows = [];

    foreach ($records as $record) {
        if (!is_array($record) || !isset($record['Id'], $record['Type']) || !is_numeric($record['Id'])) {
            throw new RuntimeException('Bunny returned an invalid DNS record.');
        }

        $typeId = (int) $record['Type'];
        if (!isset($types[$typeId])) {
            throw new RuntimeException("Bunny returned unsupported record type {$typeId}.");
        }

        $rows[] = [
            'recordId' => (string) $record['Id'],
            'type' => $types[$typeId],
            'host' => (string) ($record['Name'] ?? ''),
            'value' => (string) ($record['Value'] ?? ''),
            'ttl' => isset($record['Ttl']) ? (int) $record['Ttl'] : null,
            'priority' => isset($record['Priority']) ? (int) $record['Priority'] : null,
            'weight' => isset($record['Weight']) ? (int) $record['Weight'] : null,
            'port' => isset($record['Port']) ? (int) $record['Port'] : null,
        ];
    }

    return $rows;
}

function whmcs_dns_refresh_bunny_zone(string $domainName, string $apiKey): int
{
    $domainName = strtolower(rtrim(trim($domainName), '.'));
    if ($domainName === '' || strlen($domainName) > 253) {
        throw new InvalidArgumentException('A valid domain is required.');
    }

    $zone = Capsule::table(WHMCSDNS_TABLE_ZONES)->where('domain_name', $domainName)->first();
    if (!$zone) {
        throw new InvalidArgumentException('Zone not found.');
    }

    $config = json_decode((string) $zone->config, true);
    if (!is_array($config) || ($config['provider'] ?? null) !== 'Bunny' || empty($zone->zoneId)) {
        throw new InvalidArgumentException('Zone is not a Bunny DNS zone.');
    }

    $provider = new BunnyProvider([
        'apikey' => $apiKey,
        'domain_name' => $domainName,
        'zone_id' => (string) $zone->zoneId,
    ]);
    $rows = whmcs_dns_normalize_bunny_records($provider->retrieveAllRRsets($domainName));
    $now = date('Y-m-d H:i:s');

    Capsule::connection()->transaction(function () use ($zone, $rows, $now): void {
        $lockedZone = Capsule::table(WHMCSDNS_TABLE_ZONES)->where('id', $zone->id)->lockForUpdate()->first();
        if (!$lockedZone) {
            throw new RuntimeException('Zone was removed while it was being refreshed.');
        }

        Capsule::table(WHMCSDNS_TABLE_RECORDS)->where('domain_id', $zone->id)->delete();
        foreach ($rows as $row) {
            Capsule::table(WHMCSDNS_TABLE_RECORDS)->insert($row + [
                'domain_id' => (int) $zone->id,
                'created_at' => $now,
                'updated_at' => $now,
            ]);
        }
        Capsule::table(WHMCSDNS_TABLE_ZONES)->where('id', $zone->id)->update(['updated_at' => $now]);
    });

    return count($rows);
}

function whmcs_dns_domain_status_allowed(string $status): bool
{
    return $status === 'Active';
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
 * Create DB tables
 *
 * @return array<string, string>
 */
function whmcs_dns_activate(): array
{
    try {
        whmcs_dns_create_rate_limit_table();

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
    whmcs_dns_add_srv_columns();
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

    $selectedDomain = trim((string)($_REQUEST['domain'] ?? ''));
    $message = null;

    $isActiveDomain = function (string $domainName) use ($clientId): bool {
        $status = Capsule::table('tbldomains')
            ->where('userid', $clientId)
            ->where('domain', $domainName)
            ->value('status');

        return is_string($status) && whmcs_dns_domain_status_allowed($status);
    };

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
        $domainName = trim((string)($_POST['domain_name'] ?? ''));
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

                            $domainOrder = [
                                'client_id' => $clientId,
                                'config'    => json_encode($cfg, JSON_UNESCAPED_SLASHES),
                            ];

                            $plex->createDomain($domainOrder);

                            // Ensure local row exists if PlexDNS didn't insert it itself
                            $zone = Capsule::table(WHMCSDNS_TABLE_ZONES)->where('domain_name', $domainName)->first();
                            if (!$zone) {
                                Capsule::table(WHMCSDNS_TABLE_ZONES)->insert([
                                    'client_id'   => $clientId,
                                    'domain_name' => $domainName,
                                    'config'      => $domainOrder['config'],
                                    'created_at'  => date('Y-m-d H:i:s'),
                                    'updated_at'  => date('Y-m-d H:i:s'),
                                ]);
                                $zone = Capsule::table(WHMCSDNS_TABLE_ZONES)
                                    ->where('domain_name', $domainName)
                                    ->where('client_id', $clientId)
                                    ->first();
                            }

                            $messageText = 'DNS enabled. Zone created.';
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

                        if ($recordType === 'TXT') {
                            $v = trim($recordValue);
                            if ($v === '' || $v[0] !== '"' || substr($v, -1) !== '"') {
                                $recordValue = '"' . str_replace('"', '\"', $v) . '"';
                            }
                        }

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

                        $rowId = $plex->addRecord($req);
                        Capsule::table(WHMCSDNS_TABLE_RECORDS)->where('id', $rowId)->update([
                            'weight' => $weight,
                            'port' => $port,
                        ]);

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

                        if ($recordType === 'TXT') {
                            $v = trim($recordValue);
                            if ($v === '' || $v[0] !== '"' || substr($v, -1) !== '"') {
                                $recordValue = '"' . str_replace('"', '\"', $v) . '"';
                            }
                        }

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
                        Capsule::table(WHMCSDNS_TABLE_RECORDS)->where('id', $rowId)->update([
                            'weight' => $weight,
                            'port' => $port,
                        ]);

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
                ->map(function ($r) {
                    return [
                        'id'       => (int)$r->id,
                        'type'     => (string)$r->type,
                        'host'     => (string)$r->host,
                        'value'    => (string)$r->value,
                        'ttl'      => $r->ttl !== null ? (int)$r->ttl : null,
                        'priority' => $r->priority !== null ? (int)$r->priority : null,
                        'weight'   => $r->weight !== null ? (int)$r->weight : null,
                        'port'     => $r->port !== null ? (int)$r->port : null,
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
