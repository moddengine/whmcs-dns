<?php

declare(strict_types=1);

namespace WHMCS\Database {
    use Illuminate\Database\Capsule\Manager;

    final class Capsule
    {
        private static Manager $manager;

        public static function boot(): void
        {
            self::$manager = new Manager();
            self::$manager->addConnection(['driver' => 'sqlite', 'database' => ':memory:']);
            self::$manager->setAsGlobal();
        }

        public static function table(string $table): mixed
        {
            return self::$manager->getConnection()->table($table);
        }

        public static function schema(): mixed
        {
            return self::$manager->getConnection()->getSchemaBuilder();
        }

        public static function connection(): mixed
        {
            return self::$manager->getConnection();
        }
    }
}

namespace WHMCS\Module\Addon {
    final class Setting
    {
        /** @var array<string, string> */
        public static array $values = [];

        public static function getSettingValueForModule(string $module, string $setting): ?string
        {
            return self::$values[$setting] ?? null;
        }
    }
}

namespace {
    use GuzzleHttp\Psr7\ServerRequest;
    use Illuminate\Database\Schema\Blueprint;
    use PlexDNS\Service;
    use Psr\Http\Message\ResponseInterface;
    use WHMCS\Database\Capsule;
    use WHMCS\Module\Addon\Setting;

    define('WHMCS', true);
    require dirname(__DIR__) . '/vendor/autoload.php';

    /** @var array<int, array{command: string, values: array<string, mixed>}> */
    $GLOBALS['localApiCalls'] = [];
    /** @var array<int, array<string, mixed>> */
    $GLOBALS['moduleCalls'] = [];

    /** @param array<string, mixed> $values @return array<string, string> */
    function localAPI(string $command, array $values, ?string $adminUsername = null): array
    {
        global $localApiCalls;
        $localApiCalls[] = ['command' => $command, 'values' => $values];
        return ['result' => 'success'];
    }

    function logModuleCall(
        string $module,
        string $action,
        mixed $request,
        mixed $response,
        mixed $processedData = null
    ): void {
        global $moduleCalls;
        $moduleCalls[] = compact('module', 'action', 'request', 'response', 'processedData');
    }

    require dirname(__DIR__) . '/whmcs_dns.php';
    require dirname(__DIR__) . '/dns-handler.php';
    require dirname(__DIR__) . '/cpanel-sync-handler.php';
    require dirname(__DIR__) . '/connect-website-handler.php';

    function expect(bool $condition, string $message): void
    {
        if (!$condition) {
            throw new RuntimeException($message);
        }
    }

    /** @return array<string, mixed>|null */
    function responseBody(ResponseInterface $response): ?array
    {
        $body = (string) $response->getBody();
        return $body === '' ? null : json_decode($body, true, 16, JSON_THROW_ON_ERROR);
    }

    function serverRequest(string $method, string $path, string $key = '', string $body = ''): ServerRequest
    {
        return new ServerRequest(
            $method,
            'https://whmcs.example/modules/addons/whmcs_dns/dns.php' . $path,
            $key === '' ? [] : ['Auth-Key' => $key],
            $body
        );
    }

    function request(string $method, string $path, string $key = '', string $body = ''): ResponseInterface
    {
        return whmcs_dns_handle_http_request(serverRequest($method, $path, $key, $body));
    }

    function cpanelRequest(string $method, string $key = '', string $body = ''): ResponseInterface
    {
        return whmcs_dns_handle_cpanel_sync_request(serverRequest($method, '/cpanel-sync', $key, $body));
    }

    function websiteRequest(string $method, string $key = '', string $body = ''): ResponseInterface
    {
        return whmcs_dns_handle_connect_website_request(serverRequest($method, '/connect-website', $key, $body));
    }

    /** @param array<int, string> $scopes @param array<int, string> $domains */
    function apiKey(array $scopes, array $domains, int $expiresAt = 0): string
    {
        $generated = whmcs_dns_generate_api_key();
        Capsule::table(WHMCSDNS_TABLE_API_KEYS)->insert([
            'key_id' => $generated['key_id'],
            'key_hash' => $generated['key_hash'],
            'name' => 'Test key',
            'scopes' => json_encode($scopes, JSON_THROW_ON_ERROR),
            'domains' => json_encode($domains, JSON_THROW_ON_ERROR),
            'expires_at' => $expiresAt,
            'created_at' => date('Y-m-d H:i:s'),
        ]);
        return $generated['key'];
    }

    Capsule::boot();
    $service = new Service(Capsule::connection()->getPdo());
    $service->install();
    whmcs_dns_add_srv_columns();
    whmcs_dns_create_rate_limit_table();
    whmcs_dns_create_api_key_table();

    Capsule::schema()->create('tbldomains', function (Blueprint $table): void {
        $table->increments('id');
        $table->integer('userid');
        $table->string('domain');
        $table->string('status');
    });
    Capsule::schema()->create('tblhosting', function (Blueprint $table): void {
        $table->increments('id');
        $table->integer('userid');
        $table->string('domain');
        $table->string('domainstatus');
        $table->integer('server')->default(0);
        $table->string('username')->default('');
    });
    Capsule::table('tbldomains')->insert([
        'userid' => 1,
        'domain' => 'example.test',
        'status' => 'Active',
    ]);
    Capsule::table('tbldomains')->insert([
        'userid' => 1,
        'domain' => 'disconnected.test',
        'status' => 'Active',
    ]);
    Capsule::table('tbldomains')->insert([
        'userid' => 1,
        'domain' => 'example.com',
        'status' => 'Active',
    ]);
    Capsule::table('tblhosting')->insert([
        'userid' => 1,
        'domain' => 'example.com',
        'domainstatus' => 'Active',
        'server' => 1,
        'username' => 'cpaneluser',
    ]);

    Setting::$values = ['provider' => 'Testing', 'apikey' => 'testing'];
    $config = ['provider' => 'Testing', 'apikey' => 'testing', 'domain_name' => 'example.test'];
    expect(whmcs_dns_enable_domain(1, $config), 'Testing zone was not created.');
    expect(!whmcs_dns_enable_domain(1, $config), 'Existing Testing zone was recreated.');
    try {
        whmcs_dns_enable_domain(2, $config);
        throw new RuntimeException('Another client claimed an existing Testing zone.');
    } catch (UnexpectedValueException $e) {
        expect($e->getCode() === 409, 'Zone ownership conflict returned the wrong status.');
    }
    expect(whmcs_dns_enable_domain(1, [
        'provider' => 'Testing',
        'apikey' => 'testing',
        'domain_name' => 'example.com',
    ]), 'cPanel Testing zone was not created.');

    $readKey = apiKey(['dns_read'], ['example.test']);
    $writeKey = apiKey(['dns_read', 'dns_write', 'dns_admin'], ['example.test']);
    $otherDomainKey = apiKey(['dns_read', 'dns_write'], ['other.test']);
    $cpanelKey = apiKey(['dns_write', 'dns_admin'], ['example.com']);
    $writeOnlyKey = apiKey(['dns_write'], ['example.com']);
    $disconnectedKey = apiKey(['dns_write'], ['disconnected.test']);
    $expiredKey = apiKey(['dns_read'], ['example.test'], time() - 1);

    expect(whmcs_dns_http_path('', '/modules/addons/whmcs_dns/dns.php/record/example.test/A')
        === '/record/example.test/A', 'Request URI path extraction failed.');
    expect(request('GET', '/missing')->getStatusCode() === 404, 'Unknown route was accepted.');
    $methodResponse = request('POST', '/record/example.test/A');
    expect($methodResponse->getStatusCode() === 405
        && $methodResponse->getHeaderLine('Allow') === 'GET, PUT, DELETE', 'Method policy failed.');
    expect(request('GET', '/record/example.test/A')->getStatusCode() === 401, 'Missing API key was accepted.');
    expect(request('GET', '/record/example.test/A', $expiredKey)->getStatusCode() === 401, 'Expired API key was accepted.');
    expect(request('PUT', '/record/example.test/A', $readKey, '{"values":["192.0.2.1"]}')
        ->getStatusCode() === 403, 'Read-only API key changed DNS.');
    expect(request('PUT', '/record/example.test/A', $otherDomainKey, '{"values":["192.0.2.1"]}')
        ->getStatusCode() === 403, 'Wrong-domain API key changed DNS.');
    expect(request('PUT', '/record/example.test/A', $writeKey, '{')->getStatusCode() === 400,
        'Malformed JSON was accepted.');

    $created = request('PUT', '/record/www.example.test/A', $writeKey, '{"ttl":300,"values":["192.0.2.1"]}');
    expect($created->getStatusCode() === 201
        && responseBody($created) === [
            'fqdn' => 'www.example.test',
            'type' => 'A',
            'ttl' => 300,
            'values' => ['192.0.2.1'],
        ], 'A RRset creation failed.');
    expect(responseBody(request('GET', '/record/www.example.test/A', $readKey)) === responseBody($created),
        'Created A RRset could not be read.');

    $replaced = request(
        'PUT',
        '/record/www.example.test/A',
        $writeKey,
        '{"ttl":600,"values":["192.0.2.3","192.0.2.2"]}'
    );
    expect($replaced->getStatusCode() === 200
        && responseBody($replaced)['values'] === ['192.0.2.2', '192.0.2.3'], 'A RRset replacement failed.');
    expect(request('PUT', '/record/www.example.test/CNAME', $writeKey, '{"values":["target.example.test"]}')
        ->getStatusCode() === 400, 'CNAME coexistence was accepted.');

    $mx = request(
        'PUT',
        '/record/example.test/MX',
        $writeKey,
        '{"values":["20 mx2.example.test.","10 mx1.example.test."]}'
    );
    expect($mx->getStatusCode() === 201
        && responseBody($mx)['values'] === ['10 mx1.example.test', '20 mx2.example.test'], 'MX RRset failed.');
    $srv = request(
        'PUT',
        '/record/_sip._tcp.example.test/SRV',
        $writeKey,
        '{"values":["10 5 5060 sip.example.test."]}'
    );
    expect($srv->getStatusCode() === 201
        && responseBody($srv)['values'] === ['10 5 5060 sip.example.test'], 'SRV RRset failed.');
    expect(responseBody(request('GET', '/record/_sip._tcp.example.test/SRV', $readKey))['values']
        === ['10 5 5060 sip.example.test'], 'Compact SRV cache value was not decoded.');

    expect(request('DELETE', '/record/www.example.test/A', $writeKey)->getStatusCode() === 204,
        'RRset deletion failed.');
    expect(request('GET', '/record/www.example.test/A', $readKey)->getStatusCode() === 404,
        'Deleted RRset remains readable.');
    expect(request('GET', '/record/example.test/BOGUS', $readKey)->getStatusCode() === 400,
        'Unsupported record type was accepted.');
    $zone = Capsule::table(WHMCSDNS_TABLE_ZONES)->where('domain_name', 'example.test')->first();
    $srvBeforeSync = Capsule::table(WHMCSDNS_TABLE_RECORDS)
        ->where('domain_id', $zone->id)
        ->where('type', 'SRV')
        ->first();
    expect(request('POST', '/sync/example.test', $writeKey)->getStatusCode() === 204,
        'Testing-provider synchronization failed.');
    $srvAfterSync = Capsule::table(WHMCSDNS_TABLE_RECORDS)
        ->where('domain_id', $zone->id)
        ->where('type', 'SRV')
        ->first();
    expect((array) $srvAfterSync === (array) $srvBeforeSync,
        'Testing-provider synchronization changed cached records.');

    Setting::$values = ['provider' => 'Cloudflare', 'apikey' => 'testing'];
    Capsule::table(WHMCSDNS_TABLE_ZONES)->where('id', $zone->id)->update([
        'config' => json_encode(['provider' => 'Cloudflare'], JSON_THROW_ON_ERROR),
    ]);
    $recordsBeforeUnsupportedSync = Capsule::table(WHMCSDNS_TABLE_RECORDS)
        ->where('domain_id', $zone->id)
        ->orderBy('id')
        ->get()
        ->map(static fn (object $record): array => (array) $record)
        ->toArray();
    $unsupported = request('POST', '/sync/example.test', $writeKey);
    expect($unsupported->getStatusCode() === 501 && responseBody($unsupported) === [
        'error' => 'unsupported_provider',
        'message' => 'DNS provider synchronization is not supported.',
    ], 'Unsupported provider synchronization returned the wrong error.');
    expect(Capsule::table(WHMCSDNS_TABLE_RECORDS)
        ->where('domain_id', $zone->id)
        ->orderBy('id')
        ->get()
        ->map(static fn (object $record): array => (array) $record)
        ->toArray() === $recordsBeforeUnsupportedSync,
        'Unsupported provider synchronization changed cached records.');
    Setting::$values = ['provider' => 'Testing', 'apikey' => 'testing'];
    Capsule::table(WHMCSDNS_TABLE_ZONES)->where('id', $zone->id)->update([
        'config' => json_encode(['provider' => 'Testing'], JSON_THROW_ON_ERROR),
    ]);

    $cpanelBody = json_encode([
        'server_id' => 1,
        'cpanel_user' => 'cpaneluser',
        'domain' => 'www.example.com',
        'type' => 'A',
        'value' => '192.0.2.10',
    ], JSON_THROW_ON_ERROR);
    $cpanelMethod = cpanelRequest('GET');
    expect($cpanelMethod->getStatusCode() === 405 && $cpanelMethod->getHeaderLine('Allow') === 'POST',
        'cPanel endpoint method policy failed.');
    expect(cpanelRequest('POST')->getStatusCode() === 401, 'cPanel endpoint accepted a missing API key.');
    expect(cpanelRequest('POST', $writeKey, '{')->getStatusCode() === 400,
        'cPanel endpoint accepted malformed JSON.');
    expect(cpanelRequest('POST', $writeOnlyKey, $cpanelBody)->getStatusCode() === 403,
        'cPanel endpoint accepted a key without dns_admin.');
    $cpanelCreated = cpanelRequest('POST', $cpanelKey, $cpanelBody);
    expect($cpanelCreated->getStatusCode() === 200
        && responseBody($cpanelCreated) === ['status' => 'ok', 'action' => 'created', 'zone' => 'example.com'],
        'cPanel endpoint did not create the Testing-provider record.');
    expect(responseBody(cpanelRequest('POST', $cpanelKey, $cpanelBody))['action'] === 'unchanged',
        'cPanel endpoint did not detect the unchanged Testing-provider record.');

    $websiteBody = '{"domain":"example.test","ipv4":"8.8.8.8"}';
    $websiteMethod = websiteRequest('GET');
    expect($websiteMethod->getStatusCode() === 405 && $websiteMethod->getHeaderLine('Allow') === 'POST',
        'Connect Website endpoint method policy failed.');
    expect(websiteRequest('POST')->getStatusCode() === 401,
        'Connect Website endpoint accepted a missing API key.');
    expect(websiteRequest('POST', $writeKey, '{')->getStatusCode() === 400,
        'Connect Website endpoint accepted malformed JSON.');
    expect(websiteRequest('POST', $otherDomainKey, $websiteBody)->getStatusCode() === 403,
        'Connect Website endpoint accepted the wrong domain scope.');
    $disconnected = websiteRequest(
        'POST',
        $disconnectedKey,
        '{"domain":"disconnected.test","ipv4":"8.8.8.8"}'
    );
    expect($disconnected->getStatusCode() === 404
        && responseBody($disconnected)['error'] === 'DNS is not enabled for this domain.',
        'Connect Website endpoint did not reject a missing DNS zone.');
    expect(websiteRequest('POST', $writeKey, $websiteBody)->getStatusCode() === 502,
        'Connect Website endpoint did not fail safely for an unsupported provider.');

    $status = whmcs_dns_integration_status(1, 'example.test');
    expect($status['enabled'] && $status['provider'] === 'Testing', 'Integration zone status failed.');
    expect(count(whmcs_dns_integration_list_records(1, 'example.test')) === 3,
        'Integration record listing failed.');

    $txt = ['name' => '_verify', 'type' => 'TXT', 'value' => 'ok', 'ttl' => 300];
    expect(whmcs_dns_integration_apply_records(1, 'example.test', [], [$txt], 'test add')
        === ['deleted_count' => 0, 'created_count' => 1], 'Integration record creation failed.');
    expect(whmcs_dns_integration_apply_records(1, 'example.test', [$txt], [], 'test remove')
        === ['deleted_count' => 1, 'created_count' => 0], 'Integration record deletion failed.');
    expect(array_column($GLOBALS['localApiCalls'], 'command') === ['AddClientNote'],
        'Deleted-record audit note was not saved.');

    Capsule::table(WHMCSDNS_TABLE_API_KEYS)->insert([
        'key_id' => 'WDNS_0000000000000000',
        'key_hash' => 'unused',
        'name' => 'Old expired key',
        'scopes' => '["dns_read"]',
        'domains' => '["example.test"]',
        'expires_at' => time() - 15 * 86400,
        'created_at' => date('Y-m-d H:i:s'),
    ]);
    expect(whmcs_dns_cleanup_expired_api_keys() === 1, 'Old expired API key cleanup failed.');
    expect(array_column($GLOBALS['moduleCalls'], 'action') === ['connect_website'],
        'Provider failures were not logged.');

    echo "DNS API checks passed.\n";
}
