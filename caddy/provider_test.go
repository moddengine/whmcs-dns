package whmcsdns

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/libdns/libdns"
)

func TestModuleAndCaddyfile(t *testing.T) {
	module, err := caddy.GetModule("dns.providers.whmcs_dns")
	if err != nil || module.New() == nil {
		t.Fatalf("module registration failed: %v", err)
	}

	p := new(Provider)
	err = p.UnmarshalCaddyfile(caddyfile.NewTestDispenser(`whmcs_dns {
	endpoint http://localhost/modules/addons/whmcs_dns/dns.php
	token secret
}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if p.Endpoint != "http://localhost/modules/addons/whmcs_dns/dns.php" || p.Token != "secret" {
		t.Fatalf("unexpected config: %#v", p)
	}

	for _, invalid := range []Provider{
		{Endpoint: "http://whmcs.example/modules/addons/whmcs_dns/dns.php", Token: "secret"},
		{Endpoint: "https://whmcs.example/not-dns.php", Token: "secret"},
		{Endpoint: "https://whmcs.example/modules/addons/whmcs_dns/dns.php"},
	} {
		if err := invalid.Validate(); err == nil {
			t.Fatalf("invalid config accepted: %#v", invalid)
		}
	}
}

func TestTXTRecordLifecycle(t *testing.T) {
	type state struct {
		sync.Mutex
		exists        bool
		ttl           int64
		values        []string
		authenticated bool
	}
	current := new(state)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current.Lock()
		defer current.Unlock()
		if r.Header.Get("Auth-Key") != "secret" || r.Header.Get("Authorization") != "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		current.authenticated = true
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			if !current.exists {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(recordSet{FQDN: "_acme-challenge.example.test", Type: "TXT", TTL: current.ttl, Values: current.values})
		case http.MethodPut:
			created := !current.exists
			var input recordSet
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil || input.FQDN != "" || input.Type != "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			current.exists, current.ttl, current.values = true, input.TTL, append([]string(nil), input.Values...)
			if created {
				w.WriteHeader(http.StatusCreated)
			}
			_ = json.NewEncoder(w).Encode(recordSet{FQDN: "_acme-challenge.example.test", Type: "TXT", TTL: current.ttl, Values: current.values})
		case http.MethodDelete:
			current.exists, current.values = false, nil
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	p := &Provider{Endpoint: server.URL + "/modules/addons/whmcs_dns/dns.php", Token: "secret"}
	one := libdns.RR{Name: "_acme-challenge", Type: "TXT", Data: "one"}
	two := libdns.RR{Name: "_acme-challenge", Type: "TXT", Data: "two", TTL: time.Minute}

	created, err := p.AppendRecords(context.Background(), "example.test.", []libdns.Record{one})
	if err != nil || len(created) != 1 || created[0].RR().TTL != 300*time.Second {
		t.Fatalf("create failed: records=%v err=%v", created, err)
	}
	if _, err := p.AppendRecords(context.Background(), "example.test.", []libdns.Record{one}); err != nil {
		t.Fatal(err)
	}

	var wait sync.WaitGroup
	for _, record := range []libdns.Record{two, libdns.RR{Name: "_acme-challenge", Type: "TXT", Data: "three"}} {
		wait.Add(1)
		go func(record libdns.Record) {
			defer wait.Done()
			if _, err := p.AppendRecords(context.Background(), "example.test.", []libdns.Record{record}); err != nil {
				t.Errorf("concurrent append: %v", err)
			}
		}(record)
	}
	wait.Wait()

	current.Lock()
	slices.Sort(current.values)
	if !current.authenticated || current.ttl != 300 || strings.Join(current.values, ",") != "one,three,two" {
		t.Fatalf("unexpected state after append: %#v", current)
	}
	current.Unlock()

	deleted, err := p.DeleteRecords(context.Background(), "example.test.", []libdns.Record{
		libdns.TXT{Name: "_acme-challenge", TTL: 300 * time.Second, Text: "two"},
	})
	if err != nil || len(deleted) != 1 {
		t.Fatalf("delete one failed: records=%v err=%v", deleted, err)
	}
	if _, err := p.DeleteRecords(context.Background(), "example.test.", []libdns.Record{
		libdns.TXT{Name: "_acme-challenge", TTL: 300 * time.Second, Text: "one"},
		libdns.TXT{Name: "_acme-challenge", TTL: 300 * time.Second, Text: "three"},
	}); err != nil {
		t.Fatal(err)
	}
	current.Lock()
	defer current.Unlock()
	if current.exists {
		t.Fatalf("last TXT value did not remove RRset: %#v", current)
	}
}

func TestHTTPFailures(t *testing.T) {
	record := libdns.RR{Name: "_acme-challenge", Type: "TXT", Data: "token"}
	for name, handler := range map[string]http.HandlerFunc{
		"status": func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) },
		"malformed": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("{"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(handler)
			defer server.Close()
			p := &Provider{Endpoint: server.URL + "/dns.php", Token: "secret"}
			if _, err := p.AppendRecords(context.Background(), "example.test.", []libdns.Record{record}); err == nil {
				t.Fatal("invalid response accepted")
			}
		})
	}

	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p := &Provider{Endpoint: server.URL + "/dns.php", Token: "secret"}
	_, err := p.AppendRecords(ctx, "example.test.", []libdns.Record{record})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("context cancellation not propagated: %v", err)
	}
}
