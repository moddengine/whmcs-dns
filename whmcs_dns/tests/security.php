<?php

define('WHMCS', true);
require dirname(__DIR__) . '/whmcs_dns.php';

if (!whmcs_dns_domain_status_allowed('Active') || whmcs_dns_domain_status_allowed('Expired')) {
    throw new RuntimeException('Domain status policy failed.');
}

if (whmcs_dns_rate_limit_reached(29) || !whmcs_dns_rate_limit_reached(30)) {
    throw new RuntimeException('Mutation rate limit boundary failed.');
}

$template = file_get_contents(dirname(__DIR__) . '/templates/clientarea.tpl');
if ($template === false || substr_count($template, '<form') !== substr_count($template, 'name="token"')) {
    throw new RuntimeException('Every POST form must submit a WHMCS token.');
}

echo "Security checks passed.\n";
