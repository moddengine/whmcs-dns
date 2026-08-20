package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

const (
	defaultSocket  = "/run/whmcs-dns-bridge/bridge.sock"
	defaultState   = "/var/lib/whmcs-dns-bridge"
	maxZoneRecords = 250
	maxAttempts    = 5
)

type config struct {
	Endpoint         string `json:"endpoint"`
	Token            string `json:"token"`
	ServerID         int    `json:"server_id"`
	ProcessSynczones bool   `json:"process_synczones"`
	RelaxedSync      bool   `json:"relaxed_sync"`
	TimeoutSeconds   int    `json:"timeout_seconds"`
}

type zoneInput struct {
	Zone string `json:"zone"`
	Data string `json:"data"`
}

type socketRequest struct {
	Action     string      `json:"action"`
	DNSUniqID  string      `json:"dnsuniqid"`
	CpanelUser string      `json:"cpanel_user,omitempty"`
	Zones      []zoneInput `json:"zones"`
}

type socketResponse struct {
	OK        bool   `json:"ok"`
	Retryable bool   `json:"retryable,omitempty"`
	Queued    int    `json:"queued,omitempty"`
	Skipped   bool   `json:"skipped,omitempty"`
	Error     string `json:"error,omitempty"`
}

type updateRequest struct {
	ServerID   int    `json:"server_id"`
	CpanelUser string `json:"cpanel_user,omitempty"`
	Domain     string `json:"domain"`
	Type       string `json:"type"`
	Value      string `json:"value"`
}

type job struct {
	ID          string        `json:"id"`
	Request     updateRequest `json:"request"`
	Attempts    int           `json:"attempts"`
	NextAttempt time.Time     `json:"next_attempt,omitempty"`
	LastError   string        `json:"last_error,omitempty"`
}

type spool struct {
	dir       string
	wake      chan struct{}
	client    *http.Client
	cfg       config
	logger    *log.Logger
	mu        sync.Mutex
	retryTurn bool
}

func main() {
	logger := log.New(os.Stderr, "whmcs-dns-bridge: ", log.LstdFlags|log.Lmsgprefix)
	cfg, err := loadConfig()
	if err != nil {
		logger.Fatal(err)
	}
	if cfg.RelaxedSync {
		logger.Printf("WARNING: relaxed sync enabled; cPanel account ownership checks are disabled")
	}
	s := &spool{
		dir:    defaultState,
		wake:   make(chan struct{}, 1),
		client: &http.Client{Timeout: time.Duration(cfg.TimeoutSeconds) * time.Second},
		cfg:    cfg,
		logger: logger,
	}
	if err := s.init(); err != nil {
		logger.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go s.work(ctx)
	if err := serve(ctx, defaultSocket, s, logger); err != nil && !errors.Is(err, context.Canceled) {
		logger.Fatal(err)
	}
}

func loadConfig() (config, error) {
	executable, err := os.Executable()
	if err != nil {
		return config{}, err
	}
	data, err := os.ReadFile(executable + ".json")
	if err != nil {
		return config{}, fmt.Errorf("read config: %w", err)
	}
	var cfg config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return config{}, fmt.Errorf("parse config: %w", err)
	}
	endpoint, err := url.Parse(cfg.Endpoint)
	if err != nil || endpoint.Host == "" || (endpoint.Scheme != "https" && !isLoopback(endpoint.Hostname())) {
		return config{}, errors.New("endpoint must be an HTTPS URL (HTTP is allowed only for loopback)")
	}
	if cfg.Token == "" || cfg.ServerID < 1 {
		return config{}, errors.New("token and positive server_id are required")
	}
	if cfg.TimeoutSeconds == 0 {
		cfg.TimeoutSeconds = 30
	}
	if cfg.TimeoutSeconds < 1 || cfg.TimeoutSeconds > 300 {
		return config{}, errors.New("timeout_seconds must be between 1 and 300")
	}
	return cfg, nil
}

func isLoopback(host string) bool {
	return host == "localhost" || (net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback())
}

func serve(ctx context.Context, socketPath string, s *spool, logger *log.Logger) error {
	if err := os.MkdirAll(filepath.Dir(socketPath), 0755); err != nil {
		return err
	}
	_ = os.Remove(socketPath)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", socketPath, err)
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(socketPath)
	}()
	if err := os.Chmod(socketPath, 0600); err != nil {
		return err
	}
	logger.Printf("listening on %s", socketPath)
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			logger.Printf("accept: %v", err)
			continue
		}
		handleConnection(conn.(*net.UnixConn), s, logger)
	}
}

func handleConnection(conn *net.UnixConn, s *spool, logger *log.Logger) {
	defer conn.Close()
	if uid, err := peerUID(conn); err != nil || uid != 0 {
		logger.Printf("rejected socket peer uid=%d: %v", uid, err)
		_ = json.NewEncoder(conn).Encode(socketResponse{Error: "permission denied"})
		return
	}

	var request socketRequest
	decoder := json.NewDecoder(conn)
	if err := decoder.Decode(&request); err != nil {
		_ = json.NewEncoder(conn).Encode(socketResponse{Error: "invalid request"})
		return
	}
	response := s.accept(request)
	if !response.OK {
		logger.Printf("action %s rejected: %s", request.Action, response.Error)
	}
	_ = json.NewEncoder(conn).Encode(response)
}

func peerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid uint32
	var controlErr error
	err = raw.Control(func(fd uintptr) {
		cred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if err != nil {
			controlErr = err
			return
		}
		uid = cred.Uid
	})
	if err != nil {
		return 0, err
	}
	return uid, controlErr
}

func (s *spool) init() error {
	for _, name := range []string{"ready", "retry", "inflight", "dead"} {
		if err := os.MkdirAll(filepath.Join(s.dir, name), 0700); err != nil {
			return err
		}
	}
	inflight, err := os.ReadDir(filepath.Join(s.dir, "inflight"))
	if err != nil {
		return err
	}
	for _, entry := range inflight {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		source := filepath.Join(s.dir, "inflight", entry.Name())
		destination := filepath.Join(s.dir, "ready", entry.Name())
		if _, err := os.Stat(destination); err == nil {
			if err := os.Remove(source); err != nil {
				return err
			}
		} else if err := os.Rename(source, destination); err != nil {
			return err
		}
	}
	retries, err := os.ReadDir(filepath.Join(s.dir, "retry"))
	if err != nil {
		return err
	}
	for _, entry := range retries {
		if _, err := os.Stat(filepath.Join(s.dir, "ready", entry.Name())); err == nil {
			if err := os.Remove(filepath.Join(s.dir, "retry", entry.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *spool) accept(request socketRequest) socketResponse {
	action := strings.ToUpper(strings.TrimSpace(request.Action))
	if action == "SYNCZONES" && !s.cfg.ProcessSynczones {
		s.logger.Printf("SYNCZONES skipped by configuration")
		return socketResponse{OK: true, Skipped: true}
	}
	if action != "SAVEZONE" && action != "QUICKZONEADD" && action != "SYNCZONES" {
		return socketResponse{Error: "unsupported action"}
	}
	if request.DNSUniqID == "" || len(request.Zones) == 0 {
		return socketResponse{Error: "dnsuniqid and zones are required"}
	}

	jobs := make([]job, 0)
	for _, input := range request.Zones {
		zone := normalizeName(input.Zone)
		if zone == "" {
			return socketResponse{Error: "invalid zone"}
		}
		user := ""
		var allowed map[string]bool
		if !s.cfg.RelaxedSync {
			user = strings.TrimSpace(request.CpanelUser)
			if user == "" {
				var err error
				user, err = ownerForZone(zone)
				if err != nil {
					return socketResponse{Retryable: true, Error: err.Error()}
				}
			}
			var err error
			allowed, err = cpanelDomains(user, zone)
			if err != nil {
				return socketResponse{Retryable: true, Error: err.Error()}
			}
		}
		updates, err := recordsFromZone(input.Data, zone, allowed)
		if err != nil {
			return socketResponse{Error: err.Error()}
		}
		for _, update := range updates {
			update.ServerID = s.cfg.ServerID
			update.CpanelUser = user
			identity := fmt.Sprintf("%d\x00%s\x00%s\x00%s", update.ServerID, update.CpanelUser, update.Domain, update.Type)
			sum := sha256.Sum256([]byte(identity))
			jobs = append(jobs, job{ID: hex.EncodeToString(sum[:]), Request: update})
		}
	}

	if err := s.enqueue(jobs); err != nil {
		return socketResponse{Retryable: true, Error: err.Error()}
	}
	return socketResponse{OK: true, Queued: len(jobs)}
}

func normalizeName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

func ownerForZone(zone string) (string, error) {
	data, err := os.ReadFile("/etc/userdomains")
	if err != nil {
		return "", fmt.Errorf("resolve owner for %s: %w", zone, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 && normalizeName(parts[0]) == zone {
			user := strings.TrimSpace(parts[1])
			if user != "" {
				return user, nil
			}
		}
	}
	return "", fmt.Errorf("no cPanel owner found for %s", zone)
}

func cpanelDomains(user, zone string) (map[string]bool, error) {
	configured, err := runUAPI(user, "DomainInfo", "list_domains", "hide_temporary_domains=1")
	if err != nil {
		return nil, err
	}
	generated, err := runUAPI(user, "DNS", "fetch_cpanel_generated_domains", "domain="+zone)
	if err != nil {
		return nil, err
	}
	allowed := map[string]bool{zone: true}
	for _, domain := range collectDomains(configured) {
		if domain == zone || strings.HasSuffix(domain, "."+zone) {
			allowed[domain] = true
		}
	}
	for _, domain := range collectDomains(generated) {
		if domain != zone {
			delete(allowed, domain)
		}
	}
	return allowed, nil
}

func runUAPI(user string, args ...string) (any, error) {
	commandArgs := append([]string{"--output=json", "--user=" + user}, args...)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "/usr/local/cpanel/bin/uapi", commandArgs...).Output()
	if err != nil {
		return nil, fmt.Errorf("uapi %s: %w", strings.Join(args[:2], "::"), err)
	}
	var response struct {
		Result struct {
			Data   any `json:"data"`
			Errors any `json:"errors"`
			Status int `json:"status"`
		} `json:"result"`
	}
	if err := json.Unmarshal(output, &response); err != nil {
		return nil, fmt.Errorf("decode uapi response: %w", err)
	}
	if response.Result.Status != 1 {
		return nil, fmt.Errorf("uapi %s failed: %v", strings.Join(args[:2], "::"), response.Result.Errors)
	}
	return response.Result.Data, nil
}

func collectDomains(value any) []string {
	var domains []string
	var walk func(any)
	walk = func(item any) {
		switch typed := item.(type) {
		case string:
			name := normalizeName(typed)
			if _, ok := dns.IsDomainName(dns.Fqdn(name)); ok {
				domains = append(domains, name)
			}
		case []any:
			for _, child := range typed {
				walk(child)
			}
		case map[string]any:
			for _, child := range typed {
				walk(child)
			}
		}
	}
	walk(value)
	return domains
}

func recordsFromZone(zoneData, zone string, allowed map[string]bool) ([]updateRequest, error) {
	parser := dns.NewZoneParser(strings.NewReader(zoneData), dns.Fqdn(zone), "")
	updates := make([]updateRequest, 0)
	seen := make(map[string]bool)
	count := 0
	for record, ok := parser.Next(); ok; record, ok = parser.Next() {
		count++
		if count > maxZoneRecords {
			return nil, fmt.Errorf("zone %s contains more than %d records", zone, maxZoneRecords)
		}
		name := normalizeName(record.Header().Name)
		var update updateRequest
		switch typed := record.(type) {
		case *dns.A:
			if name != zone && !strings.HasSuffix(name, "."+zone) {
				continue
			}
			if allowed != nil && !allowed[name] {
				continue
			}
			update = updateRequest{Domain: name, Type: "A", Value: typed.A.String()}
		case *dns.TXT:
			if !strings.HasSuffix(name, "."+zone) {
				continue
			}
			relative := strings.TrimSuffix(name, "."+zone)
			if name == zone || !strings.HasSuffix(relative, "._domainkey") {
				continue
			}
			update = updateRequest{Domain: name, Type: "TXT", Value: strings.Join(typed.Txt, "")}
		default:
			continue
		}
		key := update.Domain + "\x00" + update.Type
		if seen[key] {
			return nil, fmt.Errorf("eligible RRset %s %s has multiple values", update.Domain, update.Type)
		}
		seen[key] = true
		updates = append(updates, update)
	}
	if err := parser.Err(); err != nil {
		return nil, fmt.Errorf("parse zone %s: %w", zone, err)
	}
	sort.Slice(updates, func(i, j int) bool {
		return updates[i].Domain+"\x00"+updates[i].Type < updates[j].Domain+"\x00"+updates[j].Type
	})
	return updates, nil
}

func (s *spool) enqueue(jobs []job) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, queued := range jobs {
		if err := writeJSON(filepath.Join(s.dir, "ready", queued.ID+".json"), queued); err != nil {
			return err
		}
		retryDir := filepath.Join(s.dir, "retry")
		if err := os.Remove(filepath.Join(retryDir, queued.ID+".json")); err == nil {
			if err := syncDir(retryDir); err != nil {
				return err
			}
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	select {
	case s.wake <- struct{}{}:
	default:
	}
	return nil
}

func writeJSON(path string, value any) error {
	dir := filepath.Dir(path)
	temporary, err := os.CreateTemp(dir, ".tmp-")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	encoder := json.NewEncoder(temporary)
	if err := encoder.Encode(value); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return err
	}
	return syncDir(dir)
}

func syncDir(dir string) error {
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (s *spool) work(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		for s.processOne(time.Now()) {
		}
		select {
		case <-ctx.Done():
			return
		case <-s.wake:
		case <-ticker.C:
		}
	}
}

func (s *spool) processOne(now time.Time) bool {
	path := s.claim(now)
	if path == "" {
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		s.logger.Printf("read queued job %s: %v", path, err)
		return false
	}
	var queued job
	if err := json.Unmarshal(data, &queued); err != nil {
		s.logger.Printf("invalid queued job %s: %v", path, err)
		_ = os.Rename(path, s.deadPath(filepath.Base(path)))
		return true
	}
	if err := s.deliver(queued); err == nil {
		if err := os.Remove(path); err != nil {
			s.logger.Printf("remove delivered job %s: %v", queued.ID, err)
		}
		return true
	} else {
		s.mu.Lock()
		defer s.mu.Unlock()
		queued.Attempts++
		queued.LastError = truncate(err.Error(), 2000)
		if _, statErr := os.Stat(filepath.Join(s.dir, "ready", filepath.Base(path))); statErr == nil {
			_ = os.Remove(path)
			s.logger.Printf("job %s superseded by a newer update", queued.ID)
			return true
		}
		if queued.Attempts >= maxAttempts {
			destination := s.deadPath(filepath.Base(path))
			if moveErr := moveJob(path, destination, queued); moveErr != nil {
				s.logger.Printf("dead-letter job %s: %v", queued.ID, moveErr)
				return false
			}
			s.logger.Printf("job %s dead-lettered at %s: %v", queued.ID, destination, err)
			return true
		}
		queued.NextAttempt = now.Add(retryDelay(queued.Attempts))
		destination := filepath.Join(s.dir, "retry", filepath.Base(path))
		if err := moveJob(path, destination, queued); err != nil {
			s.logger.Printf("queue retry for job %s: %v", queued.ID, err)
			return false
		}
		s.logger.Printf("job %s attempt %d failed: %s", queued.ID, queued.Attempts, queued.LastError)
		return true
	}
}

func (s *spool) claim(now time.Time) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.retryTurn = !s.retryTurn
	queues := []string{"ready", "retry"}
	if s.retryTurn {
		queues = []string{"retry", "ready"}
	}
	for _, queue := range queues {
		entries, err := os.ReadDir(filepath.Join(s.dir, queue))
		if err != nil {
			continue
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			path := filepath.Join(s.dir, queue, entry.Name())
			if queue == "retry" {
				data, err := os.ReadFile(path)
				if err != nil {
					continue
				}
				var queued job
				if json.Unmarshal(data, &queued) != nil || queued.NextAttempt.After(now) {
					continue
				}
			}
			destination := filepath.Join(s.dir, "inflight", entry.Name())
			if err := os.Rename(path, destination); err != nil {
				continue
			}
			return destination
		}
	}
	return ""
}

func (s *spool) deadPath(base string) string {
	name := strings.TrimSuffix(base, ".json")
	return filepath.Join(s.dir, "dead", fmt.Sprintf("%s-%d.json", name, time.Now().UnixNano()))
}

func (s *spool) deliver(queued job) error {
	body, err := json.Marshal(queued.Request)
	if err != nil {
		return err
	}
	request, err := http.NewRequest(http.MethodPost, s.cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+s.cfg.Token)
	request.Header.Set("Content-Type", "application/json")
	response, err := s.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	responseBody, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(responseBody)))
	}
	return nil
}

func moveJob(source, destination string, queued job) error {
	if source != destination {
		if err := os.Rename(source, destination); err != nil {
			return err
		}
	}
	return writeJSON(destination, queued)
}

func retryDelay(attempt int) time.Duration {
	delays := []time.Duration{5 * time.Second, 30 * time.Second, 2 * time.Minute, 10 * time.Minute}
	if attempt < 1 {
		return delays[0]
	}
	if attempt > len(delays) {
		return delays[len(delays)-1]
	}
	return delays[attempt-1]
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}
