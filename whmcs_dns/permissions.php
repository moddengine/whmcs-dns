<?php

if (!defined('WHMCS')) {
    die('This file cannot be accessed directly');
}

use WHMCS\Authentication\CurrentUser;
use WHMCS\Database\Capsule;

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
