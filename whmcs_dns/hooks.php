<?php
/**
 * WHMCS-DNS module
 *
 * Written in 2025 by Taras Kondratyuk (https://namingo.org)
 *
 * @license MIT
 * @see https://opensource.org/licenses/MIT
 */

if (!defined("WHMCS")) {
    die("This file cannot be accessed directly");
}

use WHMCS\Database\Capsule;

$autoload = __DIR__ . '/vendor/autoload.php';
if (file_exists($autoload)) {
    require_once $autoload;
}
require_once __DIR__ . '/permissions.php';

add_hook('ClientAreaProductDetailsOutput', 1, function ($service) {
    if (empty($_SESSION['uid']) || !is_object($service)) {
        return '';
    }

    $clientId = (int) $_SESSION['uid'];
    if (!whmcs_dns_can_manage_domains($clientId)) {
        return '';
    }

    $product = Capsule::table('tblhosting')
        ->select('domain', 'domainstatus')
        ->where('id', (int) ($service->id ?? 0))
        ->where('userid', $clientId)
        ->first();
    if (!$product || $product->domainstatus !== 'Active') {
        return '';
    }

    $domainName = whmcs_dns_registrable_domain((string) $product->domain);
    if ($domainName === null) {
        return '';
    }

    $url = 'index.php?m=whmcs_dns&domain=' . urlencode($domainName);
    return '<a class="btn btn-primary" href="'
        . htmlspecialchars($url, ENT_QUOTES, 'UTF-8')
        . '"><i class="fas fa-globe" aria-hidden="true"></i> Manage DNS</a>';
});

add_hook('ClientAreaSecondarySidebar', 1, function ($sidebar) {
    static $injected = false;
    if ($injected) {
        return;
    }
    $injected = true;

    if (empty($_SESSION['uid'])) {
        return;
    }

    $clientId = (int) $_SESSION['uid'];
    if (!whmcs_dns_can_manage_domains($clientId)) {
        return;
    }

    $action = (string)($_GET['action'] ?? '');

    // Domain-related pages where domainid/id is present
    $allowedActions = [
        'domaindetails',
        'domaincontacts',
        'domainregisterns',
        'domaingetepp',
        'domains', // optional
    ];

    if (!in_array($action, $allowedActions, true)) {
        return;
    }

    $domainId = 0;
    if (!empty($_GET['domainid'])) {
        $domainId = (int) $_GET['domainid'];
    } elseif (!empty($_GET['id'])) {
        $domainId = (int) $_GET['id'];
    }

    if ($domainId <= 0) {
        return;
    }

    $domain = Capsule::table('tbldomains')
        ->select('domain')
        ->where('id', $domainId)
        ->where('userid', $clientId)
        ->where('status', 'Active')
        ->first();

    if (!$domain || empty($domain->domain)) {
        return;
    }

    $domainName = (string) $domain->domain;
    $url = 'index.php?m=whmcs_dns&domain=' . urlencode($domainName);

    try {
        // Prefer to attach into existing Domains panel if present
        $panel = $sidebar->getChild('Domains')
            ?: $sidebar->getChild('Domain Details')
            ?: $sidebar->getChild('DomainDetailsActions')
            ?: null;

        // Create panel if needed
        if (!$panel) {
            $panel = $sidebar->addChild('Domains', [
                'label' => 'Domains',
                'icon'  => 'fas fa-globe',
                'order' => 10,
            ]);
        }

        // De-dupe (by child name)
        if ($panel->getChild('DNSManagerLink')) {
            return;
        }

        $panel->addChild('DNSManagerLink', [
            'label' => 'DNS Manager',
            'uri'   => $url,
            'order' => 55,
        ]);
    } catch (\Throwable $e) {
        // no-op
    }
});
