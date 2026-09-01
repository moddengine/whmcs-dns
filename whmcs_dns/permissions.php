<?php

if (!defined('WHMCS')) {
    die('This file cannot be accessed directly');
}

use WHMCS\Authentication\CurrentUser;
use WHMCS\Database\Capsule;
use WHMCS\Module\Addon\Setting;

function whmcs_dns_manage_dns_button_enabled(string $itemType, ?string $location = null): bool
{
    $location ??= (string) (Setting::getSettingValueForModule(
        'whmcs_dns',
        'manage_dns_button_location'
    ) ?: 'both');

    return $location === 'both' || $location === $itemType;
}

function whmcs_dns_normalize_hostname(string $hostname): string
{
    return strtolower(rtrim(trim($hostname), '.'));
}

function whmcs_dns_registrable_domain(string $hostname, bool $allowUnderscores = false): ?string
{
    $hostname = whmcs_dns_normalize_hostname($hostname);
    if ($hostname === '' || strlen($hostname) > 253
        || filter_var($allowUnderscores ? str_replace('_', 'a', $hostname) : $hostname, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false) {
        return null;
    }

    try {
        $domain = (new \Utopia\Domains\Domain($hostname))->getRegisterable();
    } catch (Throwable) {
        return null;
    }

    return $domain !== '' && $domain[0] !== '.' ? $domain : null;
}

/** @return array{client_id: int, domain_name: string}|null */
function whmcs_dns_admin_item_context(string $itemType, int $itemId): ?array
{
    if ($itemId <= 0 || !in_array($itemType, ['domain', 'service'], true)) {
        return null;
    }

    $item = Capsule::table($itemType === 'domain' ? 'tbldomains' : 'tblhosting')
        ->select('userid', 'domain', $itemType === 'domain' ? 'status' : 'domainstatus')
        ->where('id', $itemId)
        ->first();
    $status = $itemType === 'domain' ? ($item->status ?? null) : ($item->domainstatus ?? null);
    if (!$item || $status !== 'Active') {
        return null;
    }

    $domainName = $itemType === 'domain'
        ? whmcs_dns_normalize_hostname((string) $item->domain)
        : whmcs_dns_registrable_domain((string) $item->domain);
    if ($domainName === null || filter_var($domainName, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false) {
        return null;
    }

    return ['client_id' => (int) $item->userid, 'domain_name' => $domainName];
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

function whmcs_dns_zone_enabled(int $clientId, string $domainName): bool
{
    return $clientId > 0 && Capsule::table('zones')
        ->where('client_id', $clientId)
        ->where('domain_name', whmcs_dns_normalize_hostname($domainName))
        ->exists();
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
