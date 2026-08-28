<?php

declare(strict_types=1);

require dirname(__DIR__, 3) . '/init.php';
require_once __DIR__ . '/whmcs_dns.php';
require_once __DIR__ . '/cpanel-sync-handler.php';

use GuzzleHttp\Psr7\ServerRequest;

whmcs_dns_emit_http_response(whmcs_dns_handle_cpanel_sync_request(ServerRequest::fromGlobals()));
