<?php

declare(strict_types=1);

define('WHMCS', true);
require dirname(__DIR__) . '/whmcs_dns.php';

$apiKey = getenv('BUNNY_API_KEY');
if (!is_string($apiKey) || $apiKey === '') {
    echo "Skipped Bunny integration test (BUNNY_API_KEY is not set).\n";
    exit;
}

$domain = 'whmcs-dns-' . bin2hex(random_bytes(6)) . '.example';
$provider = new PlexDNS\Providers\Bunny(['apikey' => $apiKey]);
$provider->createDomain($domain);
try {
    $provider->createRRset($domain, ['subname' => '_verify', 'type' => 'TXT', 'records' => ['keep'], 'ttl' => 300]);
    $provider->createRRset($domain, ['subname' => '', 'type' => 'A', 'records' => ['1.1.1.1'], 'ttl' => 300]);
    $records = whmcs_dns_normalize_bunny_records($provider->retrieveAllRRsets($domain));
    $plan = whmcs_dns_website_record_plan($records, $domain, '8.8.8.8');
    foreach ($plan['delete'] as $record) {
        $provider->deleteRRset($domain, (string) $record['host'], (string) $record['type'], (string) $record['value'], $record['recordId']);
    }
    if ($plan['create_apex']) {
        $provider->createRRset($domain, ['subname' => '', 'type' => 'A', 'records' => ['8.8.8.8'], 'ttl' => 300]);
    }
    if ($plan['create_www']) {
        $provider->createRRset($domain, ['subname' => 'www', 'type' => 'CNAME', 'records' => [$domain], 'ttl' => 300]);
    }
    $final = whmcs_dns_normalize_bunny_records($provider->retrieveAllRRsets($domain));
    $retry = whmcs_dns_website_record_plan($final, $domain, '8.8.8.8');
    if ($retry['delete'] !== [] || $retry['create_apex'] || $retry['create_www']) {
        throw new RuntimeException('Bunny reconciliation was not idempotent.');
    }
    if (!array_filter($final, fn ($record): bool => $record['type'] === 'TXT' && $record['host'] === '_verify')) {
        throw new RuntimeException('Unrelated Bunny record was not preserved.');
    }
    echo "Bunny integration checks passed.\n";
} finally {
    $provider->deleteDomain($domain);
}
