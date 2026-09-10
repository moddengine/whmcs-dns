// Package whmcsdns provides a Caddy DNS provider for WHMCS-DNS.
package whmcsdns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/certmagic"
	"github.com/libdns/libdns"
)

const (
	defaultTTL     = 300
	maxTTL         = 1<<31 - 1
	maxResponseLen = 64 << 10
)

func init() {
	caddy.RegisterModule(Provider{})
}

// Provider manages ACME TXT records through the WHMCS-DNS API.
type Provider struct {
	Endpoint string `json:"endpoint,omitempty"`
	Token    string `json:"token,omitempty"`
}

// ponytail: one global lock keeps RRset read-modify-write safe within this Caddy
// process; use per-name locks if unrelated-zone throughput becomes material.
var mutations sync.Mutex

// CaddyModule returns the Caddy module information.
func (Provider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dns.providers.whmcs_dns",
		New: func() caddy.Module { return new(Provider) },
	}
}

// Provision expands Caddy placeholders in the credentials.
func (p *Provider) Provision(_ caddy.Context) error {
	replacer := caddy.NewReplacer()
	var err error
	p.Endpoint, err = replacer.ReplaceOrErr(p.Endpoint, true, true)
	if err != nil {
		return fmt.Errorf("expanding endpoint: %w", err)
	}
	p.Token, err = replacer.ReplaceOrErr(p.Token, true, true)
	if err != nil {
		return fmt.Errorf("expanding token: %w", err)
	}
	p.Endpoint = strings.TrimRight(p.Endpoint, "/")
	return nil
}

// Validate checks the WHMCS-DNS connection settings.
func (p Provider) Validate() error {
	endpoint, err := url.Parse(p.Endpoint)
	if err != nil || endpoint.Host == "" || (endpoint.Scheme != "https" && (endpoint.Scheme != "http" || !isLoopback(endpoint.Hostname()))) {
		return errors.New("endpoint must be an HTTPS URL (HTTP is allowed only for loopback)")
	}
	if endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return errors.New("endpoint must not contain credentials, a query, or a fragment")
	}
	if !strings.HasSuffix(strings.TrimRight(endpoint.Path, "/"), "/dns.php") {
		return errors.New("endpoint must point to the WHMCS-DNS dns.php API")
	}
	if p.Token == "" {
		return errors.New("token is required")
	}
	return nil
}

func isLoopback(host string) bool {
	return host == "localhost" || (net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback())
}

// UnmarshalCaddyfile parses the provider's Caddyfile block.
func (p *Provider) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()
	if d.NextArg() {
		return d.ArgErr()
	}
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "endpoint":
			if !d.NextArg() {
				return d.ArgErr()
			}
			p.Endpoint = d.Val()
		case "token":
			if !d.NextArg() {
				return d.ArgErr()
			}
			p.Token = d.Val()
		default:
			return d.Errf("unrecognized option %q", d.Val())
		}
		if d.NextArg() {
			return d.ArgErr()
		}
	}
	return nil
}

// AppendRecords adds TXT values without replacing existing values.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	mutations.Lock()
	defer mutations.Unlock()

	appended := make([]libdns.Record, 0, len(records))
	for _, record := range records {
		rr, fqdn, err := txtRecord(record, zone)
		if err != nil {
			return appended, err
		}
		current, found, err := p.get(ctx, fqdn)
		if err != nil {
			return appended, err
		}

		ttl, err := ttlSeconds(rr.TTL)
		if err != nil {
			return appended, err
		}
		if found {
			ttl = current.TTL
			duplicate := false
			for _, value := range current.Values {
				if value == rr.Data {
					duplicate = true
					break
				}
			}
			if duplicate {
				appended = append(appended, libdns.TXT{Name: rr.Name, TTL: time.Duration(ttl) * time.Second, Text: rr.Data})
				continue
			}
		}

		current.TTL = ttl
		current.Values = append(current.Values, rr.Data)
		updated, err := p.put(ctx, fqdn, current)
		if err != nil {
			return appended, err
		}
		appended = append(appended, libdns.TXT{Name: rr.Name, TTL: time.Duration(updated.TTL) * time.Second, Text: rr.Data})
	}
	return appended, nil
}

// DeleteRecords removes only matching TXT values and preserves their siblings.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	mutations.Lock()
	defer mutations.Unlock()

	deleted := make([]libdns.Record, 0, len(records))
	for _, record := range records {
		rr, fqdn, err := txtRecord(record, zone)
		if err != nil {
			return deleted, err
		}
		current, found, err := p.get(ctx, fqdn)
		if err != nil {
			return deleted, err
		}
		if !found || (rr.TTL > 0 && int64(current.TTL) != int64(rr.TTL/time.Second)) {
			continue
		}

		remaining := current.Values[:0]
		matched := false
		for _, value := range current.Values {
			if !matched && (rr.Data == "" || value == rr.Data) {
				matched = true
				deleted = append(deleted, libdns.TXT{Name: rr.Name, TTL: time.Duration(current.TTL) * time.Second, Text: value})
				continue
			}
			remaining = append(remaining, value)
		}
		if !matched {
			continue
		}
		if len(remaining) == 0 {
			if err := p.delete(ctx, fqdn); err != nil {
				return deleted[:len(deleted)-1], err
			}
			continue
		}
		current.Values = remaining
		if _, err := p.put(ctx, fqdn, current); err != nil {
			return deleted[:len(deleted)-1], err
		}
	}
	return deleted, nil
}

type recordSet struct {
	FQDN   string   `json:"fqdn,omitempty"`
	Type   string   `json:"type,omitempty"`
	TTL    int64    `json:"ttl"`
	Values []string `json:"values"`
}

func txtRecord(record libdns.Record, zone string) (libdns.RR, string, error) {
	rr := record.RR()
	if strings.ToUpper(rr.Type) != "TXT" {
		return rr, "", fmt.Errorf("unsupported DNS record type %q: only TXT is supported", rr.Type)
	}
	if rr.Name == "" {
		return rr, "", errors.New("record name is required")
	}
	fqdn := strings.TrimSuffix(libdns.AbsoluteName(rr.Name, zone), ".")
	zone = strings.Trim(zone, ".")
	if zone == "" || (!strings.EqualFold(fqdn, zone) && !strings.HasSuffix(strings.ToLower(fqdn), "."+strings.ToLower(zone))) {
		return rr, "", fmt.Errorf("record %q is outside zone %q", fqdn, zone)
	}
	return rr, fqdn, nil
}

func ttlSeconds(ttl time.Duration) (int64, error) {
	seconds := int64(ttl / time.Second)
	if seconds == 0 {
		return defaultTTL, nil
	}
	if seconds < 0 || seconds > maxTTL {
		return 0, errors.New("TTL must be between 1 and 2147483647 seconds")
	}
	return seconds, nil
}

func (p *Provider) get(ctx context.Context, fqdn string) (recordSet, bool, error) {
	status, body, err := p.do(ctx, http.MethodGet, fqdn, nil)
	if err != nil {
		return recordSet{}, false, err
	}
	if status == http.StatusNotFound {
		return recordSet{}, false, nil
	}
	if status != http.StatusOK {
		return recordSet{}, false, responseError(status, body)
	}
	var current recordSet
	if err := json.Unmarshal(body, &current); err != nil || current.TTL < 1 || current.TTL > maxTTL || current.Type != "TXT" || current.Values == nil {
		return recordSet{}, false, errors.New("WHMCS-DNS returned an invalid TXT record set")
	}
	return current, true, nil
}

func (p *Provider) put(ctx context.Context, fqdn string, set recordSet) (recordSet, error) {
	request := struct {
		TTL    int64    `json:"ttl"`
		Values []string `json:"values"`
	}{set.TTL, set.Values}
	status, body, err := p.do(ctx, http.MethodPut, fqdn, request)
	if err != nil {
		return recordSet{}, err
	}
	if status != http.StatusOK && status != http.StatusCreated {
		return recordSet{}, responseError(status, body)
	}
	var updated recordSet
	if err := json.Unmarshal(body, &updated); err != nil || updated.TTL < 1 || updated.TTL > maxTTL || updated.Type != "TXT" || updated.Values == nil {
		return recordSet{}, errors.New("WHMCS-DNS returned an invalid TXT record set")
	}
	return updated, nil
}

func (p *Provider) delete(ctx context.Context, fqdn string) error {
	status, body, err := p.do(ctx, http.MethodDelete, fqdn, nil)
	if err != nil {
		return err
	}
	if status != http.StatusNoContent {
		return responseError(status, body)
	}
	return nil
}

func (p *Provider) do(ctx context.Context, method, fqdn string, body any) (int, []byte, error) {
	endpoint, err := url.JoinPath(p.Endpoint, "record", fqdn, "TXT")
	if err != nil {
		return 0, nil, err
	}
	var requestBody io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		requestBody = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, requestBody)
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("Auth-Key", p.Token)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxResponseLen+1))
	if err != nil {
		return 0, nil, err
	}
	if len(responseBody) > maxResponseLen {
		return 0, nil, errors.New("WHMCS-DNS response exceeds 64 KiB")
	}
	return response.StatusCode, responseBody, nil
}

func responseError(status int, body []byte) error {
	message := strings.TrimSpace(string(body))
	if message == "" {
		return fmt.Errorf("WHMCS-DNS returned HTTP %d", status)
	}
	return fmt.Errorf("WHMCS-DNS returned HTTP %d: %s", status, message)
}

var (
	_ caddy.Module          = (*Provider)(nil)
	_ caddy.Provisioner     = (*Provider)(nil)
	_ caddy.Validator       = (*Provider)(nil)
	_ caddyfile.Unmarshaler = (*Provider)(nil)
	_ certmagic.DNSProvider = (*Provider)(nil)
)
