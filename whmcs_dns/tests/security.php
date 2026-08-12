<?php

define('WHMCS', true);
require dirname(__DIR__) . '/whmcs_dns.php';

if (!whmcs_dns_domain_status_allowed('Active') || whmcs_dns_domain_status_allowed('Expired')) {
    throw new RuntimeException('Domain status policy failed.');
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

$token = 'test-refresh-token';
if (!whmcs_dns_refresh_token_valid('Bearer ' . $token, hash('sha256', $token))
    || whmcs_dns_refresh_token_valid('Bearer wrong', hash('sha256', $token))) {
    throw new RuntimeException('Refresh API authentication failed.');
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

echo "Security checks passed.\n";
