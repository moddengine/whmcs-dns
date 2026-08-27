# DNS hosting module for WHMCS

[![StandWithUkraine](https://raw.githubusercontent.com/vshymanskyy/StandWithUkraine/main/badges/StandWithUkraine.svg)](https://github.com/vshymanskyy/StandWithUkraine/blob/main/docs/README.md)

[![SWUbanner](https://raw.githubusercontent.com/vshymanskyy/StandWithUkraine/main/banner2-direct.svg)](https://github.com/vshymanskyy/StandWithUkraine/blob/main/docs/README.md)

DNS hosting module for WHMCS

## Enhancements in this fork

This fork extends the [original Namingo module](https://github.com/getnamingo/whmcs-dns) with:

- **Safer client access:** active-domain/service ownership checks, WHMCS subaccount permissions, CSRF protection, mutation rate limiting, stale-record detection, and provider-record ownership validation.
- **Hosting product support:** active products with a hostname can manage the registrable domain from their product details page.
- **Improved Bunny support:** provider record IDs, SRV fields, RDR and NS records, manual record sync, optional custom nameservers, and zone export to client notes before deletion.
- **Bunny admin reconciliation:** an alphabetical view of WHMCS items, Bunny zones, and local mappings with per-zone Enable, Repair/owner reassignment, and strongly confirmed Disable actions. Cross-customer conflicts are reported without automatic actions; bulk mutations are deliberately unavailable.
- **Automation APIs:** authenticated endpoints for refreshing a Bunny zone and connecting a website to an apex A record plus `www` CNAME while preserving unrelated records.
- **Local addon integration:** a versioned PHP facade lets trusted sibling addons inspect zones and reconcile records without an HTTP API; every deleted or replaced record is saved to the customer's notes first.
- **cPanel bridge:** a durable one-way bridge imports hosting A records and DKIM from cPanel without copying its generated DNS boilerplate.
- **Release safety:** PHPStan and runnable security checks, an optional live Bunny integration check, and reproducible release archives built for version tags.

## Supported Providers

Most DNS providers **require an API key**, while some need additional authentication or server settings. Configure these values in the WHMCS addon settings.

| Provider    | Credentials | Requirements  | Status | DNSSEC |
|------------|---------------------|------------|---------------------|---------------------|
| **AnycastDNS** | `API_KEY` | | ✅ | ❌ |
| **Bind9** | `API_KEY:BIND_IP` | [bind9-api-server](https://github.com/getnamingo/bind9-api-server)/[bind9-api-server-sqlite](https://github.com/getnamingo/bind9-api-server-sqlite) | ✅ | 🚧 |
| **Bunny** | `API_KEY` | | ✅ | ✅ |
| **Cloudflare** | `EMAIL:API_KEY` or `API_TOKEN` | | ✅ | ❌ |
| **ClouDNS** | `AUTH_ID:AUTH_PASSWORD` | | ✅ | ✅ |
| **Desec** | `API_KEY` | | ✅ | ✅ |
| **DNSimple** | `API_KEY` | | ✅ | ❌ |
| **Hetzner** | `API_KEY` | | 🚧 | ❌ |
| **PowerDNS** | `API_KEY:POWERDNS_IP` | gmysql-dnssec=yes in pdns.conf | ✅ | ✅ |
| **Vultr** | `API_KEY` | | ✅ | ❌ |

## WHMCS Module Installation instructions

### 1. Upload the Module

1. Download the latest release archive of the module.
2. Extract the archive on your local machine.
3. Upload the `whmcs_dns` directory to your WHMCS installation so the final structure is: `/modules/addons/whmcs_dns/`
4. Verify that the module files are readable by the web server user.

### 2. Activate the Addon in WHMCS

1. Log in to the **WHMCS Admin Area**.
2. Navigate to **System Settings → Addons**.
3. Locate **DNS Hosting** in the list.
4. Click **Activate**.

### (BIND9 Module only) 3. Installation of BIND9 API Server:

To use the BIND9 module, you must install the [bind9-api-server](https://github.com/getnamingo/bind9-api-server) on your master BIND server. This API server allows for seamless integration and management of your DNS zones via API.

Make sure to configure the API server according to your BIND installation parameters to ensure proper synchronization of your DNS zones.

### 4. Configure the Addon

After activating the addon, configure the module settings in **WHMCS → System Settings → Addons**:

- **DNS Provider**  
  Identifier of the PlexDNS-supported provider  
  *(e.g. `Desec`, `PowerDNS`, `Cloudflare`, etc.)*

- **API Key**  
  API key for the selected DNS provider.

- **Apply Custom Nameservers**
  When using Bunny, apply NS1 and NS2 to newly created zones.

- **Show Manage DNS Button On**
  Show the button for Domains, All Products/Services, or Both in the client and admin areas.

- **SOA Email**  
  Email address used in the SOA record (where applicable).

- **Nameservers (NS1–NS5)**  
  Nameservers that clients should point their domains to when using this DNS service.

Click **Save Changes** to apply the configuration.

### 5. Usage (Client Area)

- Clients access DNS management from their **Domain Details** page.
- A **“DNS Manager”** link appears in the domain sidebar.
- Active products with a valid hostname show a **“Manage DNS”** button on the product details page.
- Product hostnames are reduced to their registrable domain (for example, `staff.company.co.nz` uses `company.co.nz`).
- DNS zones are **not created automatically**.
- Clients must explicitly click **“Enable DNS”** to create a DNS zone.
- Once enabled, DNS records can be **added, edited, or deleted**.
- Clicking **“Disable DNS”** removes (deletes) the DNS zone from the provider.

### Bunny DNS reconciliation

When Bunny is the configured provider, open **Addons → DNS Hosting** in the WHMCS admin area to compare WHMCS domains and services with Bunny and the addon's local zone mapping. The page offers per-zone Enable, Repair, and strongly confirmed Disable actions; bulk changes are intentionally unavailable.

Rows distinguish zones that are in sync, missing from Bunny, in need of local repair, attached only to inactive WHMCS items, orphaned in Bunny, stale locally, or claimed by multiple customers. Repair changes only the local customer/zone mapping and refreshes the record cache; it does not alter Bunny records.

### Automation APIs

Version 3.0 replaces the old per-endpoint keys. After upgrading, create new scoped credentials under **Addons → DNS Hosting → Automation API Keys**; old refresh, connect-website, and cPanel keys no longer work. Each key is shown once and can be limited to specific managed apex domains or `*`. Expired keys stop working immediately and are deleted by the daily cron 14 days later.

Scopes are independent: `dns_read` reads RRsets, `dns_write` changes RRsets and permits the connect-website endpoint, `dns_admin` refreshes provider state, and `auth_admin` is reserved for a future credential API. The cPanel endpoint requires both `dns_write` and `dns_admin` because it can enable a missing zone.

Send credentials as either `Auth-Key: WDNS_...` or `Authorization: Bearer WDNS_...`. The DNS API is documented in `whmcs_dns/openapi-dns-api.yaml` and exposes:

```text
GET    /modules/addons/whmcs_dns/dns.php/record/{fqdn}/{type}
PUT    /modules/addons/whmcs_dns/dns.php/record/{fqdn}/{type}
DELETE /modules/addons/whmcs_dns/dns.php/record/{fqdn}/{type}
POST   /modules/addons/whmcs_dns/dns.php/sync/{fqdn}
```

`PUT` replaces the complete RRset. MX values use `priority target`; SRV values use `priority weight port target`. The sync route replaces the removed `refresh.php` endpoint. Zone enable/disable and credential grant/revoke are not exposed over HTTP.

Connect a website to an exact active WHMCS domain:

```http
POST /modules/addons/whmcs_dns/connect-website.php
Auth-Key: <connect-website-key>
Content-Type: application/json

{"domain":"example.com","ipv4":"203.0.114.10"}
```

The connect endpoint requires DNS to already be enabled for the exact active WHMCS domain; it returns `404` and never creates or enables a missing zone. It sets the apex A record and `www` CNAME, preserves unrelated records, and records replaced website entries in the client's notes. It accepts public IPv4 addresses only.

### Local addon integration

Sibling addons in the same WHMCS installation may `require_once` `whmcs_dns.php`, check `WHMCSDNS_INTEGRATION_API_VERSION === 1`, then call `whmcs_dns_integration_status`, `whmcs_dns_integration_list_records`, and `whmcs_dns_integration_apply_records`. Records use canonical `name`, `type`, `value`, `ttl`, `priority`, `weight`, and `port` fields. The apply function validates the complete change set, refreshes Bunny first, writes deleted/replaced records to a customer note, and never creates or deletes a zone. Adds require an active customer domain or service; deletion-only cleanup remains available after termination while the owned zone exists.

### cPanel DNS bridge

The optional `whmcs-dns-bridge` runs on a WHM/cPanel host and sends selected cPanel DNS updates to this addon. By default it imports only apex/configured-domain A records and `*._domainkey` TXT records. cPanel-generated service hosts, SPF, DMARC, DCV, MX, CNAME, SRV, NS, SOA, and other records are ignored.

1. In **Addons → DNS Hosting → Automation API Keys**, create a key with `dns_write` and `dns_admin` scopes for the required domains.
2. Download the bridge archive matching the cPanel host architecture and extract it.
3. In **WHM → Server Configuration → Tweak Settings → Software**, disable the `dnsadmin` checkbox under **Dormant services**. cPanel requires `dnsadmin` to remain active for custom DNS cluster plugins.
4. Run `sudo ./install.sh`. The installer enables DNS clustering and creates the **WHMCS-DNS** backend with the **Write-only** role directly because current cPanel releases restrict the WHM add-backend form to bundled modules.
5. Edit `/usr/local/sbin/whmcs-dns-bridge.json` with the endpoint, key, and the matching WHMCS server ID, then run `sudo systemctl start whmcs-dns-bridge`.

The daemon acknowledges a cPanel operation only after its record updates are durably queued. It delivers one update at a time, retries failures five times, then retains them under `/var/lib/whmcs-dns-bridge/dead`. Inspect logs with `journalctl -u whmcs-dns-bridge`; replay a corrected dead-letter job by resetting its `attempts` field to `0`, then move and rename it in the sibling `ready` directory as `<id>.json` using the `id` stored in the file.

Synchronization is one-way from cPanel to WHMCS-DNS. Changes made in WHMCS-DNS and record deletions are not sent back to cPanel; newer pending values for the same record replace older retries.

`process_synczones` is disabled by default. Enable it in the adjacent JSON configuration only when bulk/initial cPanel zone synchronization should be imported. Zones containing more than 250 total records are rejected before filtering.

For migrations or accounts created outside WHMCS, set `relaxed_sync` to `true` in the bridge JSON configuration. Relaxed sync omits the cPanel username and imports every A record inside the zone, including mail and cPanel service hosts, plus `*._domainkey` TXT records. WHMCS maps each update to the longest matching `Active` or `Pending` registered domain or hosting-service domain and rejects ambiguous ownership. The `server_id` is retained for compatibility but is not part of relaxed ownership matching. Enable this only for a trusted bridge key: the key can update any uniquely eligible WHMCS domain regardless of its current cPanel server or username.

If WHMCS-DNS is the customer-facing editor, separately hide cPanel's Zone Editor through WHM Feature Manager. You may also disable the local nameserver daemon, but retain cPanel's DNS role and `dnsadmin` integration. These are deployment choices; the bridge does not modify cPanel settings.

## WHMCS Module Update instructions

To update the DNS hosting module to the latest version, download the newest release and replace the existing module files.

### Manual update

1. Download the **latest release** archive from the repository.
2. Extract the archive to a temporary directory.
3. Locate the `whmcs_dns` directory inside the extracted release.
4. Copy the `whmcs_dns` directory into `/modules/addons`, **overwriting** the existing `whmcs_dns` directory.

### Update via console

From your server:

```bash
cd /tmp
wget https://github.com/moddengine/whmcs-dns/releases/download/v3.0.0/whmcs-dns-3.0.0.zip
unzip whmcs-dns-3.0.0.zip
cp -a whmcs_dns /path/to/whmcs/modules/addons/
```

## Support

Your feedback and inquiries are invaluable to Namingo's evolutionary journey. If you need support, have questions, or want to contribute your thoughts:

- **Email**: Feel free to reach out directly at [help@namingo.org](mailto:help@namingo.org).

- **Discord**: Or chat with us on our [Discord](https://discord.gg/97R9VCrWgc) channel.
  
- **GitHub Issues**: For bug reports or feature requests specific to this fork, use [moddengine/whmcs-dns issues](https://github.com/moddengine/whmcs-dns/issues).

We appreciate your involvement and patience as Namingo continues to grow and adapt.

## Support This Project

If you find DNS hosting module for WHMCS useful, consider donating:

- [Donate via Stripe](https://donate.stripe.com/7sI2aI4jV3Offn28ww)
- BTC: `bc1q9jhxjlnzv0x4wzxfp8xzc6w289ewggtds54uqa`
- ETH: `0x330c1b148368EE4B8756B176f1766d52132f0Ea8`

## Licensing

DNS hosting module for WHMCS is licensed under the MIT License.
