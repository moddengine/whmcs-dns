<?php

define('WHMCS', true);
require dirname(__DIR__) . '/whmcs_dns.php';

$GLOBALS['localApiResult'] = 'success';

/** @param array<string, mixed> $values @return array<string, string> */
function localAPI(string $command, array $values, ?string $adminUsername = null): array
{
    global $localApiResult;
    return ['result' => $localApiResult];
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

$existingBunnyZone = whmcs_dns_find_bunny_zone([
    ['id' => 42, 'domain' => 'unrelated.example'],
    ['id' => 84, 'domain' => 'EXAMPLE.COM.'],
], 'example.com');
if ($existingBunnyZone !== ['id' => '84', 'domain' => 'example.com']
    || whmcs_dns_find_bunny_zone([], 'example.com') !== null) {
    throw new RuntimeException('Existing Bunny zone lookup failed.');
}
try {
    whmcs_dns_find_bunny_zone([
        ['id' => 1, 'domain' => 'example.com'],
        ['id' => 2, 'domain' => 'EXAMPLE.COM.'],
    ], 'example.com');
    throw new RuntimeException('Duplicate exact Bunny zones were accepted.');
} catch (UnexpectedValueException) {
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
if (whmcs_dns_registrable_domain('default._domainkey.cpdemo.modd.au', true) !== 'modd.au'
    || whmcs_dns_registrable_domain('default._domainkey.cpdemo.modd.au') !== null) {
    throw new RuntimeException('cPanel DKIM registrable domain parsing failed.');
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

foreach ([
    'domain' => [true, false, true],
    'service' => [false, true, true],
] as $itemType => [$domains, $services, $both]) {
    if (whmcs_dns_manage_dns_button_enabled($itemType, 'domain') !== $domains
        || whmcs_dns_manage_dns_button_enabled($itemType, 'service') !== $services
        || whmcs_dns_manage_dns_button_enabled($itemType, 'both') !== $both) {
        throw new RuntimeException('Manage DNS button location policy failed.');
    }
}

$generatedKey = whmcs_dns_generate_api_key();
if (preg_match('/^(WDNS_[a-f0-9]{16})_([a-f0-9]{64})$/D', $generatedKey['key'], $keyParts) !== 1
    || $keyParts[1] !== $generatedKey['key_id']
    || !password_verify($keyParts[2], $generatedKey['key_hash'])
    || whmcs_dns_presented_api_key('Bearer ' . $generatedKey['key'], '') !== $generatedKey['key']
    || whmcs_dns_presented_api_key('', $generatedKey['key']) !== $generatedKey['key']
    || whmcs_dns_presented_api_key('Bearer ' . $generatedKey['key'], $generatedKey['key']) !== $generatedKey['key']
    || whmcs_dns_presented_api_key('Bearer wrong', $generatedKey['key']) !== null
    || whmcs_dns_presented_api_key('Basic ' . $generatedKey['key'], '') !== null) {
    throw new RuntimeException('Automation API authentication failed.');
}
if (whmcs_dns_api_scopes(['dns_write', 'dns_read', 'dns_write']) !== ['dns_read', 'dns_write']
    || whmcs_dns_api_domains(" Example.COM.\nexample.net") !== ['example.com', 'example.net']
    || whmcs_dns_api_domains('*') !== ['*']) {
    throw new RuntimeException('Automation API policy normalization failed.');
}
foreach ([[], ['unknown']] as $scopes) {
    try {
        whmcs_dns_api_scopes($scopes);
        throw new RuntimeException('Invalid API scopes accepted.');
    } catch (InvalidArgumentException) {
    }
}
foreach (['', "*\nexample.com", 'not a domain'] as $domains) {
    try {
        whmcs_dns_api_domains($domains);
        throw new RuntimeException('Invalid API domains accepted.');
    } catch (InvalidArgumentException) {
    }
}
$expiry = whmcs_dns_api_expiry(date('Y-m-d\TH:i', time() + 3600));
if ($expiry <= time() || whmcs_dns_api_expiry('') !== 0) {
    throw new RuntimeException('Automation API expiry parsing failed.');
}
$policy = ['scopes' => ['dns_read'], 'domains' => ['example.com']];
if (!whmcs_dns_api_key_allows($policy, 'dns_read', 'EXAMPLE.COM.')
    || whmcs_dns_api_key_allows($policy, 'dns_write', 'example.com')
    || whmcs_dns_api_key_allows($policy, 'dns_read', 'child.example.com')
    || !whmcs_dns_api_key_allows(['scopes' => ['dns_read'], 'domains' => ['*']], 'dns_read', 'any.example')) {
    throw new RuntimeException('Automation API scope or domain policy failed.');
}

$mx = whmcs_dns_api_record('mail.example.com', 'example.com', 'MX', 300, '10 mx.example.net.');
$srv = whmcs_dns_api_record('_sip._tcp.example.com', 'example.com', 'SRV', 300, '1 2 443 target.example.net.');
if (whmcs_dns_api_record_value($mx) !== '10 mx.example.net'
    || whmcs_dns_api_record_value($srv) !== '1 2 443 target.example.net') {
    throw new RuntimeException('DNS API record value conversion failed.');
}
foreach (['MX' => 'mail.example.net', 'SRV' => '1 2 target.example.net'] as $type => $value) {
    try {
        whmcs_dns_api_record('record.example.com', 'example.com', $type, 300, $value);
        throw new RuntimeException("Invalid {$type} API value accepted.");
    } catch (InvalidArgumentException) {
    }
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

$cpanelRequest = whmcs_dns_cpanel_request(
    '{"server_id":3,"cpanel_user":"cpuser","domain":"WWW.Example.COM.","type":"a","value":"1.2.3.4"}'
);
if ($cpanelRequest !== [
    'server_id' => 3,
    'cpanel_user' => 'cpuser',
    'domain' => 'www.example.com',
    'type' => 'A',
    'value' => '1.2.3.4',
]) {
    throw new RuntimeException('cPanel request normalization failed.');
}
$relaxedCpanelRequest = whmcs_dns_cpanel_request(
    '{"server_id":3,"domain":"MAIL.Example.COM.","type":"a","value":"1.2.3.4"}'
);
if ($relaxedCpanelRequest['cpanel_user'] !== '' || $relaxedCpanelRequest['domain'] !== 'mail.example.com') {
    throw new RuntimeException('Relaxed cPanel request normalization failed.');
}
$dkimRequest = whmcs_dns_cpanel_request(
    '{"server_id":3,"cpanel_user":"cpuser","domain":"default._domainkey.example.com","type":"TXT","value":"v=DKIM1; p=abc"}'
);
if ($dkimRequest['domain'] !== 'default._domainkey.example.com') {
    throw new RuntimeException('cPanel DKIM request validation failed.');
}
foreach ([
    '{}',
    '{"server_id":0,"cpanel_user":"cpuser","domain":"example.com","type":"A","value":"1.2.3.4"}',
    '{"server_id":3,"cpanel_user":"bad-user","domain":"example.com","type":"A","value":"1.2.3.4"}',
    '{"server_id":3,"cpanel_user":"cpuser","domain":"example.com","type":"A","value":"invalid"}',
    '{"server_id":3,"cpanel_user":"cpuser","domain":"example.com","type":"MX","value":"mail.example.com"}',
] as $json) {
    try {
        whmcs_dns_cpanel_request($json);
        throw new RuntimeException("Invalid cPanel request accepted: {$json}");
    } catch (JsonException | InvalidArgumentException) {
    }
}
if (!whmcs_dns_hostname_in_zone('www.example.com', 'example.com')
    || whmcs_dns_hostname_in_zone('notexample.com', 'example.com')) {
    throw new RuntimeException('cPanel zone boundary check failed.');
}
if (whmcs_dns_provider_record_value('Bunny', 'TXT', 'v=spf1 -all') !== 'v=spf1 -all'
    || whmcs_dns_provider_record_value('PowerDNS', 'TXT', 'v=spf1 -all') !== '"v=spf1 -all"') {
    throw new RuntimeException('Provider TXT value formatting failed.');
}

$relaxedContext = whmcs_dns_cpanel_relaxed_context([
    ['client_id' => 10, 'domain' => 'example.com', 'status' => 'Active'],
    ['client_id' => 11, 'domain' => 'shop.example.com', 'status' => 'Pending'],
    ['client_id' => 11, 'domain' => 'shop.example.com', 'status' => 'Active'],
    ['client_id' => 12, 'domain' => 'inactive.example.com', 'status' => 'Suspended'],
], [
    ['client_id' => 11, 'domain' => 'shop.example.com'],
    ['client_id' => 11, 'domain' => 'mail.shop.example.com'],
], 'mx.mail.shop.example.com');
if ($relaxedContext !== ['client_id' => 11, 'zone' => 'mail.shop.example.com']) {
    throw new RuntimeException('Relaxed cPanel longest-domain matching failed.');
}
foreach ([
    [
        [
            ['client_id' => 10, 'domain' => 'example.com', 'status' => 'Active'],
            ['client_id' => 11, 'domain' => 'example.com', 'status' => 'Pending'],
        ],
        [],
        'mail.example.com',
    ],
    [
        [['client_id' => 10, 'domain' => 'example.com', 'status' => 'Active']],
        [['client_id' => 11, 'domain' => 'example.com']],
        'mail.example.com',
    ],
    [
        [['client_id' => 10, 'domain' => 'example.com', 'status' => 'Suspended']],
        [],
        'mail.example.com',
    ],
] as [$sources, $zones, $domain]) {
    try {
        whmcs_dns_cpanel_relaxed_context($sources, $zones, $domain);
        throw new RuntimeException('Unsafe relaxed cPanel ownership accepted.');
    } catch (UnexpectedValueException $e) {
        if ($e->getCode() !== 409) {
            throw $e;
        }
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
    || !whmcs_dns_bunny_empty_export_is_expected([['Type' => 5]])
    || whmcs_dns_bunny_empty_export_is_expected([['Type' => 0]])) {
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

if (WHMCSDNS_INTEGRATION_API_VERSION !== 1) {
    throw new RuntimeException('Unexpected local integration API version.');
}

$mx = whmcs_dns_integration_record([
    'name' => '@',
    'type' => 'mx',
    'value' => 'MX1.ForwardEmail.net.',
    'ttl' => 3600,
    'priority' => 0,
], 'Example.COM.');
if ($mx !== [
    'name' => '',
    'type' => 'MX',
    'value' => 'mx1.forwardemail.net',
    'ttl' => 3600,
    'priority' => 0,
    'weight' => null,
    'port' => null,
]) {
    throw new RuntimeException('Integration record canonicalization failed.');
}

$compactSrv = whmcs_dns_integration_record([
    'name' => '_sip._tcp',
    'type' => 'SRV',
    'value' => '20 5060 SIP.Example.com.',
    'ttl' => 300,
    'priority' => 10,
], 'example.com');
$legacySrv = whmcs_dns_integration_record([
    'name' => '_sip._tcp',
    'type' => 'SRV',
    'value' => 'SIP.Example.com.',
    'ttl' => 300,
    'priority' => 10,
    'weight' => 20,
    'port' => 5060,
], 'example.com');
if ($compactSrv !== $legacySrv || $compactSrv['value'] !== 'sip.example.com'
    || $compactSrv['weight'] !== 20 || $compactSrv['port'] !== 5060) {
    throw new RuntimeException('Compact PlexDNS SRV storage was not split correctly.');
}

$integrationPlan = whmcs_dns_integration_plan([
    $mx,
    $mx,
    ['name' => '', 'type' => 'TXT', 'value' => 'keep', 'ttl' => 300],
], [$mx], [
    ['name' => '@', 'type' => 'MX', 'value' => 'mx1.forwardemail.net', 'ttl' => 3600, 'priority' => 0],
    ['name' => '_dmarc', 'type' => 'TXT', 'value' => 'v=DMARC1; p=none', 'ttl' => 300],
], 'example.com');
if ($integrationPlan['delete_indexes'] !== [0, 1]
    || count($integrationPlan['upsert']) !== 2
    || $integrationPlan['upsert'][1]['name'] !== '_dmarc') {
    throw new RuntimeException('Integration exact-tuple retry plan failed.');
}

try {
    whmcs_dns_integration_plan([
        ['name' => 'mail', 'type' => 'A', 'value' => '8.8.8.8', 'ttl' => 300],
    ], [], [
        ['name' => 'mail', 'type' => 'CNAME', 'value' => 'forwardemail.net', 'ttl' => 300],
    ], 'example.com');
    throw new RuntimeException('Integration CNAME conflict was accepted.');
} catch (UnexpectedValueException $e) {
    if ($e->getCode() !== 409) {
        throw $e;
    }
}

foreach ([
    ['name' => 'bad name', 'type' => 'TXT', 'value' => 'x', 'ttl' => 300],
    ['name' => '@', 'type' => 'MX', 'value' => 'invalid', 'ttl' => 300, 'priority' => 0],
    ['name' => '@', 'type' => 'TXT', 'value' => '', 'ttl' => 300],
    ['name' => '@', 'type' => 'TXT', 'value' => 'x', 'ttl' => 0],
] as $record) {
    try {
        whmcs_dns_integration_record($record, 'example.com');
        throw new RuntimeException('Invalid integration record was accepted.');
    } catch (InvalidArgumentException) {
    }
}

$integrationNote = whmcs_dns_integration_replacement_note('enable', 'example.com', [$mx]);
if (!str_contains($integrationNote, 'DNS integration enable for example.com')
    || !str_contains($integrationNote, 'MX @ mx1.forwardemail.net TTL 3600 priority 0')) {
    throw new RuntimeException('Integration replacement client note failed.');
}
$GLOBALS['localApiResult'] = 'error';
try {
    whmcs_dns_integration_save_replacement_note(1, 'enable', 'example.com', [$mx]);
    throw new RuntimeException('Integration continued after a failed customer note.');
} catch (RuntimeException $e) {
    if (!str_contains($e->getMessage(), 'Could not save replaced DNS records')) {
        throw $e;
    }
}
$GLOBALS['localApiResult'] = 'success';

foreach ([
    ['', [], []],
    ['enable', [], [1]],
    ['enable', [], [['name' => '@', 'type' => 'A', 'value' => '8.8.8.8', 'ttl' => 300]]],
] as [$operation, $delete, $upsert]) {
    try {
        whmcs_dns_integration_apply_records(1, 'example.com', $delete, $upsert, $operation);
        throw new RuntimeException('Invalid integration apply request was accepted.');
    } catch (InvalidArgumentException) {
    }
}

$template = file_get_contents(dirname(__DIR__) . '/templates/clientarea.tpl');
if ($template === false || substr_count($template, '<form') !== substr_count($template, 'name="token"')) {
    throw new RuntimeException('Every POST form must submit a WHMCS token.');
}

if (!str_contains($template, 'name="action" value="sync_records"')
    || !str_contains($template, 'Sync Records')) {
    throw new RuntimeException('Provider record sync control is missing.');
}

foreach (['record_priority', 'record_weight', 'record_port'] as $field) {
    if (!str_contains($template, 'name="' . $field . '"')) {
        throw new RuntimeException("Missing SRV {$field} field.");
    }
}

$module = file_get_contents(dirname(__DIR__) . '/whmcs_dns.php');
$apiKeys = file_get_contents(dirname(__DIR__) . '/api-keys.php');
if ($module === false
    || !str_contains($module, "check_token('WHMCS.admin.default')")
    || !str_contains($module, 'Permanently delete the Bunny DNS zone')
    || str_contains($module, 'name="zones[]"')) {
    throw new RuntimeException('Admin reconciliation mutation controls failed.');
}

$hooks = file_get_contents(dirname(__DIR__) . '/hooks.php');
if ($hooks === false
    || !str_contains($hooks, "add_hook('AdminClientDomainsTabFields'")
    || !str_contains($hooks, "add_hook('AdminClientServicesTabFields'")
    || !str_contains($hooks, "add_hook('DailyCronJob'")
    || !str_contains($hooks, "whmcs_dns_zone_enabled(")
    || !str_contains($hooks, "'Active' : 'Disabled'")
    || !str_contains($hooks, 'target="_blank" rel="noopener"')
    || str_contains($hooks, 'dns_token')
    || str_contains($hooks, "'token' => generate_token('plain')")
    || !str_contains($module, "localAPI('CreateSsoToken'")
    || !str_contains($module, "'destination' => 'sso:custom_redirect'")
    || str_contains($module, 'dns_token')
    || !str_contains($module, "check_token('WHMCS.admin.default')")
    || $apiKeys === false
    || !str_contains($apiKeys, "'create_api_key'")
    || !str_contains($apiKeys, "'revoke_api_key'")
    || !str_contains($apiKeys, '14 * 86400')) {
    throw new RuntimeException('Admin DNS manager or API key controls failed.');
}

$connectEndpoint = file_get_contents(dirname(__DIR__) . '/connect-website.php');
$connectHandler = file_get_contents(dirname(__DIR__) . '/connect-website-handler.php');
if ($connectEndpoint === false
    || !str_contains($connectEndpoint, 'ServerRequest::fromGlobals()')
    || $connectHandler === false
    || str_contains($connectHandler, 'whmcs_dns_enable_domain(')
    || !str_contains($connectHandler, "UnexpectedValueException('DNS is not enabled for this domain.', 404)")) {
    throw new RuntimeException('Connect Website endpoint may enable a missing DNS zone.');
}

$cpanelEndpoint = file_get_contents(dirname(__DIR__) . '/cpanel-sync.php');
$cpanelHandler = file_get_contents(dirname(__DIR__) . '/cpanel-sync-handler.php');
if ($cpanelEndpoint === false
    || !str_contains($cpanelEndpoint, 'ServerRequest::fromGlobals()')
    || $cpanelHandler === false
    || !str_contains($cpanelHandler, "'dns_write'")
    || !str_contains($cpanelHandler, "'dns_admin'")
    || !str_contains($cpanelHandler, 'whmcs_dns_authenticate_api_key')) {
    throw new RuntimeException('cPanel synchronization endpoint or scoped authentication is missing.');
}

$dnsEndpoint = file_get_contents(dirname(__DIR__) . '/dns.php');
$dnsHandler = file_get_contents(dirname(__DIR__) . '/dns-handler.php');
if ($dnsEndpoint === false
    || !str_contains($dnsEndpoint, 'ServerRequest::fromGlobals()')
    || $dnsHandler === false
    || !str_contains($dnsHandler, "'dns_read'")
    || !str_contains($dnsHandler, "'dns_write'")
    || !str_contains($dnsHandler, "'dns_admin'")
    || file_exists(dirname(__DIR__) . '/refresh.php')) {
    throw new RuntimeException('Scoped DNS API endpoint replacement is incomplete.');
}

echo "Security checks passed.\n";
