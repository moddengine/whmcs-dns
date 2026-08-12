<?php

if (!defined('WHMCS')) {
    die('This file cannot be accessed directly');
}

use WHMCS\Authentication\CurrentUser;
use WHMCS\Database\Capsule;

function whmcs_dns_normalize_hostname(string $hostname): string
{
    return strtolower(rtrim(trim($hostname), '.'));
}

function whmcs_dns_registrable_domain(string $hostname): ?string
{
    $hostname = whmcs_dns_normalize_hostname($hostname);
    if ($hostname === '' || strlen($hostname) > 253
        || filter_var($hostname, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false) {
        return null;
    }

    try {
        $domain = (new \Utopia\Domains\Domain($hostname))->getRegisterable();
    } catch (Throwable) {
        return null;
    }

    return $domain !== '' && $domain[0] !== '.' ? $domain : null;
}

function whmcs_dns_client_can_manage_domain_name(int $clientId, string $domainName): bool
{
    $domainName = whmcs_dns_normalize_hostname($domainName);
    if ($domainName === '') {
        return false;
    }

    $status = Capsule::table('tbldomains')
        ->where('userid', $clientId)
        ->where('domain', $domainName)
        ->value('status');
    if (is_string($status) && $status === 'Active') {
        return true;
    }

    // ponytail: linear scan; add a stored apex column only if clients have enough services for this to measure poorly.
    $productDomains = Capsule::table('tblhosting')
        ->where('userid', $clientId)
        ->where('domainstatus', 'Active')
        ->where('domain', '<>', '')
        ->pluck('domain');

    foreach ($productDomains as $productDomain) {
        if (whmcs_dns_registrable_domain((string) $productDomain) === $domainName) {
            return true;
        }
    }

    return false;
}

function whmcs_dns_permission_list_allows(?string $permissions): bool
{
    $permissions = array_map('trim', explode(',', (string) $permissions));
    return in_array('managedomains', $permissions, true);
}

function whmcs_dns_can_manage_domains(int $clientId): bool
{
    $currentUser = new CurrentUser();
    if ($currentUser->isMasqueradingAdmin()) {
        return true;
    }

    $user = $currentUser->user();
    if (!$user) {
        return false;
    }

    $relation = Capsule::table('tblusers_clients')
        ->where('auth_user_id', (int) $user->id)
        ->where('client_id', $clientId)
        ->first();

    return $relation
        && ((bool) $relation->owner || whmcs_dns_permission_list_allows((string) $relation->permissions));
}
