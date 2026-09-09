package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRecordsFromZoneFiltersBoilerplate(t *testing.T) {
	zone := `$ORIGIN example.com.
@ 300 IN SOA ns.example.net. hostmaster.example.net. 1 3600 600 86400 300
@ 300 IN A 1.2.3.4
www 300 IN A 1.2.3.5
shop 300 IN A 1.2.3.6
cpanel 300 IN A 1.2.3.7
mail 300 IN A 1.2.3.8
default._domainkey 300 IN TXT "v=DKIM1; " "p=abc"
@ 300 IN TXT "v=spf1 -all"
_dmarc 300 IN TXT "v=DMARC1; p=none"
_cpanel-dcv-test-record 300 IN TXT "temporary"
`
	records, total, err := recordsFromZone(zone, "example.com", map[string]bool{
		"example.com": true, "www.example.com": true, "shop.example.com": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if total != 10 {
		t.Fatalf("total records = %d", total)
	}
	want := []updateRequest{
		{Domain: "default._domainkey.example.com", Type: "TXT", Value: "v=DKIM1; p=abc", TTL: 300},
		{Domain: "example.com", Type: "A", Value: "1.2.3.4", TTL: 300},
		{Domain: "shop.example.com", Type: "A", Value: "1.2.3.6", TTL: 300},
		{Domain: "www.example.com", Type: "A", Value: "1.2.3.5", TTL: 300},
	}
	if encoded, expected := mustJSON(records), mustJSON(want); encoded != expected {
		t.Fatalf("records = %s, want %s", encoded, expected)
	}
}

func TestRecordsFromZoneRelaxedIncludesAllInZoneARecords(t *testing.T) {
	zone := `$ORIGIN example.com.
@ 300 IN A 1.2.3.4
www 300 IN A 1.2.3.5
mail 300 IN A 1.2.3.6
cpanel 300 IN A 1.2.3.7
outside.example.net. 300 IN A 1.2.3.8
default._domainkey 300 IN TXT "v=DKIM1; p=abc"
@ 300 IN TXT "v=spf1 -all"
`
	records, _, err := recordsFromZone(zone, "example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []updateRequest{
		{Domain: "cpanel.example.com", Type: "A", Value: "1.2.3.7", TTL: 300},
		{Domain: "default._domainkey.example.com", Type: "TXT", Value: "v=DKIM1; p=abc", TTL: 300},
		{Domain: "example.com", Type: "A", Value: "1.2.3.4", TTL: 300},
		{Domain: "mail.example.com", Type: "A", Value: "1.2.3.6", TTL: 300},
		{Domain: "www.example.com", Type: "A", Value: "1.2.3.5", TTL: 300},
	}
	if encoded, expected := mustJSON(records), mustJSON(want); encoded != expected {
		t.Fatalf("records = %s, want %s", encoded, expected)
	}
}

func TestRelaxedAcceptDoesNotNeedCpanelOwner(t *testing.T) {
	s := &spool{
		dir: t.TempDir(), wake: make(chan struct{}, 1),
		cfg: config{RelaxedSync: true}, logger: logForTest(t),
	}
	if err := s.init(); err != nil {
		t.Fatal(err)
	}
	response := s.accept(socketRequest{
		Action: "QUICKZONEADD", DNSUniqID: "one",
		Zones: []zoneInput{{Zone: "example.com", Data: "@ 300 IN A 1.2.3.4\nmail 300 IN A 1.2.3.5\n"}},
	})
	if !response.OK || response.Queued != 2 {
		t.Fatalf("response = %+v", response)
	}
	entries, err := os.ReadDir(filepath.Join(s.dir, "ready"))
	if err != nil || len(entries) != 2 {
		t.Fatalf("queued jobs = %d: %v", len(entries), err)
	}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(s.dir, "ready", entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var queued job
		if json.Unmarshal(data, &queued) != nil || queued.Request.TTL != 300 {
			t.Fatalf("invalid relaxed job: %s", data)
		}
	}
}

func TestAcceptLogsSingleAndZoneSync(t *testing.T) {
	var output bytes.Buffer
	s := &spool{
		dir: t.TempDir(), wake: make(chan struct{}, 1),
		cfg:    config{ProcessSynczones: true, RelaxedSync: true},
		logger: log.New(&output, "", 0),
	}
	if err := s.init(); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"SAVEZONE", "SYNCZONES"} {
		response := s.accept(socketRequest{
			Action: action, DNSUniqID: "request-1", CpanelUser: "cpuser",
			Zones: []zoneInput{{Zone: "example.com", Data: "@ 300 IN A 1.2.3.4\n"}},
		})
		if !response.OK || response.Queued != 1 {
			t.Fatalf("%s response = %+v", action, response)
		}
		for _, message := range []string{
			"received action=" + action,
			"action=" + action + " zone=example.com selected=1 total=1",
			"queued action=" + action,
		} {
			if !strings.Contains(output.String(), message) {
				t.Errorf("missing log %q in %q", message, output.String())
			}
		}
	}
	if strings.Contains(output.String(), "DEBUG:") {
		t.Fatalf("debug output emitted while disabled: %q", output.String())
	}
	s.cfg.Debug = true
	s.accept(socketRequest{
		Action: "SAVEZONE", DNSUniqID: "request-2",
		Zones: []zoneInput{{Zone: "example.com", Data: "@ 300 IN A 1.2.3.4\n"}},
	})
	if !strings.Contains(output.String(), "DEBUG: action=SAVEZONE selected record=example.com type=A ttl=300") {
		t.Fatalf("debug record output missing: %q", output.String())
	}
}

func TestRecordsFromZoneLimitAndDuplicates(t *testing.T) {
	var zone strings.Builder
	for i := 0; i < maxZoneRecords; i++ {
		zone.WriteString("ignored")
		zone.WriteString(strings.Repeat("a", i%10))
		zone.WriteString(" 300 IN MX 10 mail.example.com.\n")
	}
	if _, _, err := recordsFromZone(zone.String(), "example.com", map[string]bool{"example.com": true}); err != nil {
		t.Fatalf("250 records rejected: %v", err)
	}
	zone.WriteString("extra 300 IN MX 10 mail.example.com.\n")
	if _, _, err := recordsFromZone(zone.String(), "example.com", map[string]bool{"example.com": true}); err == nil {
		t.Fatal("251 records accepted")
	}
	if _, _, err := recordsFromZone("@ 300 IN A 1.2.3.4\n@ 300 IN A 1.2.3.5\n", "example.com", map[string]bool{"example.com": true}); err == nil {
		t.Fatal("multi-value eligible RRset accepted")
	}
}

func TestSpoolDeliversOneAtATimeAndRetries(t *testing.T) {
	var inFlight atomic.Int32
	var maximum atomic.Int32
	var calls atomic.Int32
	var values []string
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("Auth-Key") != "secret" {
			t.Errorf("Auth-Key header = %q", request.Header.Get("Auth-Key"))
		}
		if request.Method != http.MethodPut || request.URL.Path != "/modules/addons/whmcs_dns/dns.php/record/example.com/A" {
			t.Errorf("request = %s %s", request.Method, request.URL.Path)
		}
		current := inFlight.Add(1)
		defer inFlight.Add(-1)
		if current > maximum.Load() {
			maximum.Store(current)
		}
		var rrset struct {
			TTL    uint32   `json:"ttl"`
			Values []string `json:"values"`
		}
		_ = json.NewDecoder(request.Body).Decode(&rrset)
		if rrset.TTL != 300 || len(rrset.Values) != 1 {
			t.Errorf("invalid RRset: %+v", rrset)
		}
		values = append(values, rrset.Values[0])
		if calls.Add(1) == 1 {
			return &http.Response{StatusCode: http.StatusBadGateway, Body: io.NopCloser(strings.NewReader("retry"))}, nil
		}
		return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}

	state := t.TempDir()
	s := &spool{
		dir: state, wake: make(chan struct{}, 1), client: client,
		cfg:    config{Endpoint: "https://example.invalid/modules/addons/whmcs_dns/dns.php", Token: "secret"},
		logger: logForTest(t),
	}
	if err := s.init(); err != nil {
		t.Fatal(err)
	}
	queued := job{ID: "one", Request: updateRequest{Domain: "example.com", Type: "A", Value: "1.2.3.4", TTL: 300}}
	if err := s.enqueue([]job{queued, queued}); err != nil {
		t.Fatal(err)
	}
	ready, err := os.ReadDir(filepath.Join(state, "ready"))
	if err != nil || len(ready) != 1 {
		t.Fatalf("duplicate enqueue created %d jobs: %v", len(ready), err)
	}
	if !s.processOne(time.Now()) {
		t.Fatal("ready job not processed")
	}
	retryPath := filepath.Join(state, "retry", "one.json")
	newer := queued
	newer.Request.Value = "1.2.3.5"
	if err := s.enqueue([]job{newer}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(retryPath); !os.IsNotExist(err) {
		t.Fatalf("superseded retry remains: %v", err)
	}
	if !s.processOne(time.Now()) {
		t.Fatal("newer job not processed")
	}
	if _, err := os.Stat(retryPath); !os.IsNotExist(err) {
		t.Fatalf("delivered retry remains: %v", err)
	}
	if maximum.Load() != 1 {
		t.Fatalf("maximum in-flight requests = %d", maximum.Load())
	}
	if strings.Join(values, ",") != "1.2.3.4,1.2.3.5" {
		t.Fatalf("delivered values = %v", values)
	}
}

func TestSpoolDeadLettersAfterFiveAttempts(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusBadRequest, Body: io.NopCloser(strings.NewReader("bad job"))}, nil
	})}
	state := t.TempDir()
	s := &spool{
		dir: state, wake: make(chan struct{}, 1), client: client,
		cfg:    config{Endpoint: "https://example.invalid/modules/addons/whmcs_dns/dns.php", Token: "secret"},
		logger: logForTest(t),
	}
	if err := s.init(); err != nil {
		t.Fatal(err)
	}
	queued := job{ID: "dead", Request: updateRequest{Domain: "example.com", Type: "A", Value: "1.2.3.4", TTL: 300}}
	if err := s.enqueue([]job{queued}); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if !s.processOne(time.Now().Add(time.Duration(attempt+1) * 24 * time.Hour)) {
			t.Fatalf("attempt %d was not processed", attempt+1)
		}
	}
	deadEntries, err := os.ReadDir(filepath.Join(state, "dead"))
	if err != nil || len(deadEntries) != 1 {
		t.Fatalf("dead-letter files = %d: %v", len(deadEntries), err)
	}
	data, err := os.ReadFile(filepath.Join(state, "dead", deadEntries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	var dead job
	if json.Unmarshal(data, &dead) != nil || dead.Attempts != maxAttempts || !strings.Contains(dead.LastError, "HTTP 400") {
		t.Fatalf("invalid dead letter: %s", data)
	}
}

func mustJSON(value any) string {
	data, _ := json.Marshal(value)
	return string(data)
}

func logForTest(t *testing.T) *log.Logger {
	t.Helper()
	return log.New(io.Discard, "", 0)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}
