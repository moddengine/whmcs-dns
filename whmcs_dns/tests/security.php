<?php

define('WHMCS', true);
require dirname(__DIR__) . '/whmcs_dns.php';

/** @param array<string, mixed> $values @return array<string, string> */
function localAPI(string $command, array $values, ?string $adminUsername = null): array
{
    return ['result' => 'success'];
}

class WebsiteBunnyFake extends PlexDNS\Providers\Bunny
{
    /** @var array<int, array<string, int|string|null>> */
    public array $records;
    public bool $failWwwOnce = false;
    private int $nextId = 100;

    /** @param array<int, array<string, int|string|null>> $records */
    public function __construct(array $records)
    {
        $this->records = $records;
    }

    public function deleteRRset($domainName, $subname, $type, $value, $persistedRecordId = null)
    {
        $this->records = array_values(array_filter(
            $this->records,
            fn (array $record): bool => (string) $record['recordId'] !== (string) $persistedRecordId
        ));
        return true;
    }

    public function createRRset($domainName, $rrsetData)
    {
        if ($this->failWwwOnce && ($rrsetData['subname'] ?? null) === 'www') {
            $this->failWwwOnce = false;
            throw new RuntimeException('Injected www failure.');
        }
        $this->records[] = [
            'recordId' => (string) $this->nextId++,
            'type' => (string) $rrsetData['type'],
            'host' => (string) $rrsetData['subname'],
            'value' => (string) $rrsetData['records'][0],
            'ttl' => (int) $rrsetData['ttl'],
            'priority' => null,
            'weight' => null,
            'port' => null,
        ];
        return $this->nextId - 1;
    }
}

if (!whmcs_dns_domain_status_allowed('Active') || whmcs_dns_domain_status_allowed('Expired')) {
    throw new RuntimeException('Domain status policy failed.');
}

$reconciliation = whmcs_dns_reconciliation_rows(
    [
        ['id' => 1, 'domain' => 'ok.example'],
        ['id' => 2, 'domain' => 'repair.example'],
        ['id' => 3, 'domain' => 'inactive.example'],
        ['id' => 4, 'domain' => 'orphan.example'],
        ['id' => 5, 'domain' => 'conflict.example'],
    ],
    [
        ['id' => 1, 'client_id' => 10, 'domain' => 'ok.example', 'zone_id' => '1'],
        ['id' => 2, 'client_id' => 99, 'domain' => 'repair.example', 'zone_id' => '2'],
        ['id' => 6, 'client_id' => 10, 'domain' => 'stale.example', 'zone_id' => '6'],
    ],
    [
        ['client_id' => 10, 'domain' => 'ok.example', 'id' => 1, 'kind' => 'domain', 'name' => 'ok.example', 'status' => 'Active'],
        ['client_id' => 10, 'domain' => 'repair.example', 'id' => 2, 'kind' => 'service', 'name' => 'www.repair.example', 'status' => 'Active'],
        ['client_id' => 10, 'domain' => 'missing.example', 'id' => 3, 'kind' => 'domain', 'name' => 'missing.example', 'status' => 'Active'],
        ['client_id' => 10, 'domain' => 'inactive.example', 'id' => 4, 'kind' => 'service', 'name' => 'inactive.example', 'status' => 'Suspended'],
        ['client_id' => 10, 'domain' => 'conflict.example', 'id' => 5, 'kind' => 'service', 'name' => 'one.conflict.example', 'status' => 'Active'],
        ['client_id' => 11, 'domain' => 'conflict.example', 'id' => 6, 'kind' => 'service', 'name' => 'two.conflict.example', 'status' => 'Active'],
        ['client_id' => 10, 'domain' => 'irrelevant.example', 'id' => 7, 'kind' => 'service', 'name' => 'irrelevant.example', 'status' => 'Terminated'],
    ]
);
$statuses = array_column($reconciliation, 'status', 'domain');
if ($statuses !== [
    'conflict.example' => 'conflict',
    'inactive.example' => 'inactive',
    'missing.example' => 'missing',
    'ok.example' => 'in_sync',
    'orphan.example' => 'orphan',
    'repair.example' => 'repair',
    'stale.example' => 'stale_local',
]) {
    throw new RuntimeException('Bunny reconciliation classification failed.');
}

foreach ([
    'portal.site.com' => 'site.com',
    'staff.company.co.nz' => 'company.co.nz',
    'WWW.Example.COM.' => 'example.com',
] as $hostname => $expected) {
    if (whmcs_dns_registrable_domain($hostname) !== $expected) {
        throw new RuntimeException("Registrable domain parsing failed for {$hostname}.");
    }
}

foreach (['', 'not a domain', '192.0.2.1', 'co.nz'] as $hostname) {
    if (whmcs_dns_registrable_domain($hostname) !== null) {
        throw new RuntimeException("Invalid registrable domain accepted: {$hostname}.");
    }
}

if (whmcs_dns_rate_limit_reached(29) || !whmcs_dns_rate_limit_reached(30)) {
    throw new RuntimeException('Mutation rate limit boundary failed.');
}

if (!whmcs_dns_permission_list_allows('domains, managedomains')
    || whmcs_dns_permission_list_allows('domains,managedomains-disabled')) {
    throw new RuntimeException('Manage Domains permission policy failed.');
}

$apiToken = bin2hex(random_bytes(32));
$apiHash = password_hash($apiToken, PASSWORD_BCRYPT);
if (!str_starts_with($apiHash, '$2y$')
    || !whmcs_dns_api_token_valid('Bearer ' . $apiToken, $apiHash)
    || whmcs_dns_api_token_valid('Bearer wrong', $apiHash)
    || whmcs_dns_api_token_valid('Basic ' . $apiToken, $apiHash)) {
    throw new RuntimeException('Automation API authentication failed.');
}

foreach (['8.8.8.8', '1.1.1.1'] as $address) {
    if (!whmcs_dns_public_ipv4($address)) {
        throw new RuntimeException("Public IPv4 rejected: {$address}");
    }
}
foreach (['127.0.0.1', '10.0.0.1', '169.254.1.1', '203.0.113.10', '::1', 'invalid'] as $address) {
    if (whmcs_dns_public_ipv4($address)) {
        throw new RuntimeException("Non-public IPv4 accepted: {$address}");
    }
}

$request = whmcs_dns_website_request('{"domain":"WWW.Example.COM.","ipv4":"8.8.8.8"}');
if ($request !== ['domain' => 'www.example.com', 'ipv4' => '8.8.8.8']) {
    throw new RuntimeException('Website request normalization failed.');
}
foreach (['', '{', '{}', '{"domain":"example.com","ipv4":"10.0.0.1"}'] as $json) {
    try {
        whmcs_dns_website_request($json);
        throw new RuntimeException("Invalid website request accepted: {$json}");
    } catch (JsonException | InvalidArgumentException) {
    }
}

$plan = whmcs_dns_website_record_plan([
    ['recordId' => '1', 'type' => 'A', 'host' => '', 'value' => '8.8.8.8'],
    ['recordId' => '2', 'type' => 'A', 'host' => '@', 'value' => '8.8.8.8'],
    ['recordId' => '3', 'type' => 'CNAME', 'host' => 'www', 'value' => 'EXAMPLE.COM.'],
    ['recordId' => '4', 'type' => 'AAAA', 'host' => 'www.example.com.', 'value' => '2001:4860:4860::8888'],
    ['recordId' => '5', 'type' => 'MX', 'host' => '', 'value' => 'mail.example.com'],
    ['recordId' => '6', 'type' => 'TXT', 'host' => '_verify', 'value' => 'keep'],
    ['recordId' => '7', 'type' => 'NS', 'host' => '', 'value' => 'ns1.example.com'],
], 'example.com', '8.8.8.8');
if ($plan['create_apex'] || $plan['create_www']
    || array_column($plan['delete'], 'recordId') !== ['2', '4']) {
    throw new RuntimeException('Website record deduplication plan failed.');
}

try {
    whmcs_dns_website_record_plan([
        ['recordId' => '8', 'type' => 'TXT', 'host' => 'www', 'value' => 'managed elsewhere'],
    ], 'example.com', '8.8.8.8');
    throw new RuntimeException('Blocking unmanaged www record was accepted.');
} catch (UnexpectedValueException) {
}

$fake = new WebsiteBunnyFake([
    ['recordId' => '10', 'type' => 'A', 'host' => '', 'value' => '1.1.1.1'],
    ['recordId' => '11', 'type' => 'TXT', 'host' => '_verify', 'value' => 'keep'],
    ['recordId' => '12', 'type' => 'MX', 'host' => '', 'value' => 'mail.example.com'],
    ['recordId' => '13', 'type' => 'NS', 'host' => '', 'value' => 'ns1.example.com'],
]);
$fake->failWwwOnce = true;
try {
    whmcs_dns_reconcile_bunny_website($fake, 1, 'example.com', '8.8.8.8', $fake->records);
    throw new RuntimeException('Injected partial Bunny failure was ignored.');
} catch (RuntimeException $e) {
    if ($e->getMessage() !== 'Injected www failure.') {
        throw $e;
    }
}
whmcs_dns_reconcile_bunny_website($fake, 1, 'example.com', '8.8.8.8', $fake->records);
$retry = whmcs_dns_website_record_plan($fake->records, 'example.com', '8.8.8.8');
if ($retry['delete'] !== [] || $retry['create_apex'] || $retry['create_www']) {
    throw new RuntimeException('Identical retry did not repair partial Bunny failure.');
}
foreach (['11', '12', '13'] as $preservedId) {
    if (!in_array($preservedId, array_column($fake->records, 'recordId'), true)) {
        throw new RuntimeException("Unrelated record {$preservedId} was not preserved.");
    }
}

$records = whmcs_dns_normalize_bunny_records([[
    'Id' => 42, 'Type' => 8, 'Name' => '_sip._tcp', 'Value' => 'sip.example.com',
    'Ttl' => 300, 'Priority' => 10, 'Weight' => 20, 'Port' => 5060,
]]);
if (($records[0]['type'] ?? null) !== 'SRV' || ($records[0]['recordId'] ?? null) !== '42'
    || ($records[0]['port'] ?? null) !== 5060) {
    throw new RuntimeException('Bunny record normalization failed.');
}

$nameservers = whmcs_dns_bunny_nameserver_payload('NS1.Example.com.', 'ns2.example.com');
if ($nameservers['Nameserver1'] !== 'ns1.example.com'
    || $nameservers['Nameserver2'] !== 'ns2.example.com'
    || $nameservers['CustomNameserversEnabled'] !== true) {
    throw new RuntimeException('Bunny custom nameserver payload failed.');
}

try {
    whmcs_dns_bunny_nameserver_payload('same.example.com', 'same.example.com');
    throw new RuntimeException('Duplicate custom nameservers were accepted.');
} catch (InvalidArgumentException) {
}

$zoneNote = whmcs_dns_bunny_zone_note('abc.com', "abc.com. 300 IN A 192.0.2.1\n");
if (!str_starts_with($zoneNote, 'DNS ZONE for abc.com')
    || !str_contains($zoneNote, 'abc.com. 300 IN A 192.0.2.1')) {
    throw new RuntimeException('Bunny zone client note failed.');
}

try {
    whmcs_dns_bunny_zone_note('abc.com', '');
    throw new RuntimeException('Empty Bunny zone export was accepted.');
} catch (RuntimeException $e) {
    if (!str_contains($e->getMessage(), 'empty zone export')) {
        throw $e;
    }
}

if (!whmcs_dns_bunny_empty_export_is_expected([])
    || !whmcs_dns_bunny_empty_export_is_expected([['type' => 'RDR']])
    || whmcs_dns_bunny_empty_export_is_expected([['type' => 'A']])) {
    throw new RuntimeException('Bunny empty zone export record policy failed.');
}

if (whmcs_dns_srv_number('0', 'weight') !== 0 || whmcs_dns_srv_number('65535', 'port') !== 65535) {
    throw new RuntimeException('SRV field boundary failed.');
}

try {
    whmcs_dns_srv_number('65536', 'port');
    throw new RuntimeException('Invalid SRV field was accepted.');
} catch (InvalidArgumentException) {
}

$template = file_get_contents(dirname(__DIR__) . '/templates/clientarea.tpl');
if ($template === false || substr_count($template, '<form') !== substr_count($template, 'name="token"')) {
    throw new RuntimeException('Every POST form must submit a WHMCS token.');
}

if (!str_contains($template, 'name="action" value="sync_records"')
    || !str_contains($template, 'Sync Records')) {
    throw new RuntimeException('Bunny record sync control is missing.');
}

foreach (['record_priority', 'record_weight', 'record_port'] as $field) {
    if (!str_contains($template, 'name="' . $field . '"')) {
        throw new RuntimeException("Missing SRV {$field} field.");
    }
}

$module = file_get_contents(dirname(__DIR__) . '/whmcs_dns.php');
if ($module === false
    || !str_contains($module, "check_token('WHMCS.admin.default')")
    || !str_contains($module, 'Permanently delete the Bunny DNS zone')
    || str_contains($module, 'name="zones[]"')) {
    throw new RuntimeException('Admin reconciliation mutation controls failed.');
}

echo "Security checks passed.\n";
