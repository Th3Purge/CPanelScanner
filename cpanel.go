package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	programName    = "cpanel"
	programVersion = "2.1.0"
	displayName    = "CPanelScanner"
	programAuthor  = "by ThePurge"
)

const bannerArt = `
 ▄████▄   ██▓███   ▄▄▄       ███▄    █ ▓█████  ██▓      ██████  ▄████▄   ▄▄▄       ███▄    █  ███▄    █ ▓█████  ██▀███     
▒██▀ ▀█  ▓██░  ██▒▒████▄     ██ ▀█   █ ▓█   ▀ ▓██▒    ▒██    ▒ ▒██▀ ▀█  ▒████▄     ██ ▀█   █  ██ ▀█   █ ▓█   ▀ ▓██ ▒ ██▒   
▒▓█    ▄ ▓██░ ██▓▒▒██  ▀█▄  ▓██  ▀█ ██▒▒███   ▒██░    ░ ▓██▄   ▒▓█    ▄ ▒██  ▀█▄  ▓██  ▀█ ██▒▓██  ▀█ ██▒▒███   ▓██ ░▄█ ▒   
▒▓▓▄ ▄██▒▒██▄█▓▒ ▒░██▄▄▄▄██ ▓██▒  ▐▌██▒▒▓█  ▄ ▒██░      ▒   ██▒▒▓▓▄ ▄██▒░██▄▄▄▄██ ▓██▒  ▐▌██▒▓██▒  ▐▌██▒▒▓█  ▄ ▒██▀▀█▄     
▒ ▓███▀ ░▒██▒ ░  ░ ▓█   ▓██▒▒██░   ▓██░░▒████▒░██████▒▒██████▒▒▒ ▓███▀ ░ ▓█   ▓██▒▒██░   ▓██░▒██░   ▓██░░▒████▒░██▓ ▒██▒   
░ ░▒ ▒  ░▒▓▒░ ░  ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒ ░░ ▒░ ░░ ▒░▓  ░▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒ ░ ▒░   ▒ ▒ ░░ ▒░ ░░ ▒▓ ░▒▓░   
  ░  ▒   ░▒ ░       ▒   ▒▒ ░░ ░░   ░ ▒░ ░ ░  ░░ ░ ▒  ░░ ░▒  ░ ░  ░  ▒     ▒   ▒▒ ░░ ░░   ░ ▒░░ ░░   ░ ▒░ ░ ░  ░  ░▒ ░ ▒░   
░        ░░         ░   ▒      ░   ░ ░    ░     ░ ░   ░  ░  ░  ░          ░   ▒      ░   ░ ░    ░   ░ ░    ░     ░░   ░    
░ ░                     ░  ░         ░    ░  ░    ░  ░      ░  ░ ░            ░  ░         ░          ░    ░  ░   ░        
░                                                              ░                                                                                                                         ░
`

const (
	maxBodyBytes    = 64 << 10
	drainBytes      = 8 << 10
	maxRedirects    = 5
	defaultMaxHosts = 65536
	maxWorkers      = 4096
	scoreCap        = 100
	detectScore     = 60
	mediumScore     = 70
	highScore       = 85
	productFloor    = 40
	portHintFloor   = 40
	portHintWeight  = 12
)

type serviceKind uint8

const (
	serviceUnknown serviceKind = iota
	serviceCPanel
	serviceWHM
)

func (s serviceKind) String() string {
	switch s {
	case serviceCPanel:
		return "cPanel"
	case serviceWHM:
		return "WHM"
	default:
		return "unknown"
	}
}

type confidenceLevel uint8

const (
	confidenceLow confidenceLevel = iota
	confidenceMedium
	confidenceHigh
)

func (c confidenceLevel) String() string {
	switch c {
	case confidenceHigh:
		return "high"
	case confidenceMedium:
		return "medium"
	default:
		return "low"
	}
}

type signalStrength uint8

const (
	weakSignal signalStrength = iota
	mediumSignal
	strongSignal
)

func (s signalStrength) weight() int {
	switch s {
	case strongSignal:
		return 50
	case mediumSignal:
		return 22
	default:
		return 8
	}
}

type endpoint struct {
	port     int
	useTLS   bool
	expected serviceKind
}

func (e endpoint) protocol() string {
	if e.useTLS {
		return "HTTPS"
	}
	return "HTTP"
}

func (e endpoint) scheme() string {
	if e.useTLS {
		return "https"
	}
	return "http"
}

func (e endpoint) address(host string) string {
	return net.JoinHostPort(host, strconv.Itoa(e.port))
}

func (e endpoint) baseURL(host string) string {
	return e.scheme() + "://" + e.address(host)
}

var standardEndpoints = []endpoint{
	{port: 2082, useTLS: false, expected: serviceCPanel},
	{port: 2083, useTLS: true, expected: serviceCPanel},
	{port: 2086, useTLS: false, expected: serviceWHM},
	{port: 2087, useTLS: true, expected: serviceWHM},
}

var knownTLSPorts = map[int]bool{
	443:  true,
	2083: true,
	2087: true,
	2096: true,
	2031: true,
	8443: true,
}

func endpointForPort(port int) (endpoint, error) {
	if port < 1 || port > 65535 {
		return endpoint{}, fmt.Errorf("port %d out of range 1-65535", port)
	}
	for _, e := range standardEndpoints {
		if e.port == port {
			return e, nil
		}
	}
	return endpoint{port: port, useTLS: knownTLSPorts[port], expected: serviceUnknown}, nil
}

type options struct {
	target    string
	file      string
	workers   int
	timeout   time.Duration
	output    string
	userAgent string
	maxHosts  int
	insecure  bool
	verbose   bool
	noColor   bool
	selfTest  bool
}

func parseOptions(args []string, out io.Writer) (*options, error) {
	fs := flag.NewFlagSet(programName, flag.ContinueOnError)
	fs.SetOutput(out)

	opts := &options{}
	seconds := 0
	fs.StringVar(&opts.target, "ip", "", "target IP, hostname, host:port or CIDR")
	fs.StringVar(&opts.file, "f", "", "file with one target per line")
	fs.IntVar(&opts.workers, "t", 20, "concurrent workers")
	fs.IntVar(&seconds, "timeout", 6, "per-request timeout in seconds")
	fs.StringVar(&opts.output, "o", "", "write results to this file")
	fs.StringVar(&opts.userAgent, "ua", programName+"/"+programVersion, "HTTP User-Agent")
	fs.IntVar(&opts.maxHosts, "max-hosts", defaultMaxHosts, "maximum number of hosts to process")
	fs.BoolVar(&opts.insecure, "insecure", false, "accept invalid TLS certificates")
	fs.BoolVar(&opts.verbose, "v", false, "verbose output")
	fs.BoolVar(&opts.noColor, "no-color", false, "disable colored output")
	fs.BoolVar(&opts.selfTest, "selftest", false, "run internal tests and exit")
	fs.Usage = func() { printUsage(fs) }

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	opts.timeout = time.Duration(seconds) * time.Second
	if opts.selfTest {
		return opts, nil
	}
	if err := validateOptions(opts, seconds); err != nil {
		return nil, err
	}
	return opts, nil
}

func validateOptions(opts *options, seconds int) error {
	if opts.workers < 1 {
		return errors.New("-t must be greater than 0")
	}
	if opts.workers > maxWorkers {
		return fmt.Errorf("-t must not exceed %d", maxWorkers)
	}
	if seconds < 1 {
		return errors.New("-timeout must be greater than 0")
	}
	if seconds > 300 {
		return errors.New("-timeout must not exceed 300 seconds")
	}
	if opts.maxHosts < 1 {
		return errors.New("-max-hosts must be greater than 0")
	}
	if strings.TrimSpace(opts.userAgent) == "" {
		return errors.New("-ua must not be empty")
	}
	if strings.TrimSpace(opts.target) == "" && strings.TrimSpace(opts.file) == "" {
		return errors.New("no target given: use -ip or -f")
	}
	if opts.file != "" {
		info, err := os.Stat(opts.file)
		if err != nil {
			return fmt.Errorf("target file: %w", err)
		}
		if info.IsDir() {
			return fmt.Errorf("target file %q is a directory", opts.file)
		}
	}
	return nil
}

func printUsage(fs *flag.FlagSet) {
	out := fs.Output()
	fmt.Fprintf(out, "%s %s - cPanel and WHM service discovery and fingerprinting\n", programName, programVersion)
	fmt.Fprintf(out, "%s\n\n", programAuthor)
	fmt.Fprintf(out, "Identifies cPanel and WHM interfaces on hosts you own or are authorized to\naudit. It performs read-only HTTP and HTTPS fingerprinting only.\n\n")
	fmt.Fprintf(out, "Usage:\n  %s -ip <ip|cidr|host[:port]> [flags]\n  %s -f <targets.txt> [flags]\n\nFlags:\n", programName, programName)
	fs.PrintDefaults()
	fmt.Fprintf(out, `
Ports:
  2082  cPanel over HTTP     2083  cPanel over HTTPS
  2086  WHM over HTTP        2087  WHM over HTTPS

  A target written as host:port is probed on that port only. Custom ports use
  HTTPS when the port is a well known TLS port, otherwise HTTP.

-insecure:
  cPanel and WHM usually present self-signed certificates, so HTTPS probes fail
  verification by default. This flag disables certificate validation for the
  whole run. Validation stays enabled unless the flag is given.

-max-hosts:
  Upper bound on hosts expanded from CIDR ranges and target files. Hosts are
  generated progressively and never materialized upfront. When the limit is
  reached the scan stops cleanly and the summary reports the truncation.

Examples:
  %s -ip 192.168.1.10
  %s -ip 192.168.1.0/24 -t 64 -insecure
  %s -f targets.txt -t 20 -timeout 5 -o results.txt -v
  %s -selftest
`, programName, programName, programName, programName)
}

type sourceKind uint8

const (
	sourceHost sourceKind = iota
	sourceNetwork
)

type targetSource struct {
	label   string
	kind    sourceKind
	host    string
	port    int
	network *net.IPNet
	hosts   uint64
}

func (s targetSource) each(fn func(host string) bool) {
	if s.kind == sourceHost {
		fn(s.host)
		return
	}
	base := s.network.IP.Mask(s.network.Mask)
	if v4 := base.To4(); v4 != nil {
		start := binary.BigEndian.Uint32(v4)
		var buf [4]byte
		for i := uint64(0); i < s.hosts; i++ {
			binary.BigEndian.PutUint32(buf[:], start+uint32(i))
			if !fn(net.IP(buf[:]).String()) {
				return
			}
		}
		return
	}
	current := make(net.IP, len(base))
	copy(current, base)
	for i := uint64(0); i < s.hosts; i++ {
		if !s.network.Contains(current) || !fn(current.String()) {
			return
		}
		if !incrementIP(current) {
			return
		}
	}
}

func incrementIP(ip net.IP) bool {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			return true
		}
	}
	return false
}

func networkHosts(n *net.IPNet) uint64 {
	ones, bits := n.Mask.Size()
	if bits == 0 || ones > bits {
		return 0
	}
	free := bits - ones
	if free >= 63 {
		return ^uint64(0)
	}
	return uint64(1) << uint(free)
}

func saturatingAdd(a, b uint64) uint64 {
	if a > ^uint64(0)-b {
		return ^uint64(0)
	}
	return a + b
}

func saturatingMul(a, b uint64) uint64 {
	if a == 0 || b == 0 {
		return 0
	}
	if a > ^uint64(0)/b {
		return ^uint64(0)
	}
	return a * b
}

var errBlankLine = errors.New("blank line")

func parseTargetSource(raw string) (targetSource, error) {
	text := strings.TrimSpace(raw)
	if i := strings.IndexAny(text, "#;"); i >= 0 {
		text = strings.TrimSpace(text[:i])
	}
	if text == "" {
		return targetSource{}, errBlankLine
	}
	if i := strings.Index(text, "://"); i >= 0 {
		text = text[i+3:]
		if j := strings.IndexAny(text, "/?#"); j >= 0 {
			text = text[:j]
		}
	}
	if text == "" {
		return targetSource{}, errors.New("empty target")
	}
	if strings.ContainsAny(text, " \t") {
		return targetSource{}, fmt.Errorf("invalid target %q", text)
	}

	if strings.Contains(text, "/") {
		_, network, err := net.ParseCIDR(text)
		if err != nil {
			return targetSource{}, fmt.Errorf("invalid CIDR %q", text)
		}
		hosts := networkHosts(network)
		if hosts == 0 {
			return targetSource{}, fmt.Errorf("invalid CIDR %q", text)
		}
		return targetSource{label: network.String(), kind: sourceNetwork, network: network, hosts: hosts}, nil
	}

	if net.ParseIP(text) == nil && strings.Contains(text, ":") {
		host, portText, err := net.SplitHostPort(text)
		if err != nil {
			return targetSource{}, fmt.Errorf("invalid target %q", text)
		}
		port, err := strconv.Atoi(portText)
		if err != nil {
			return targetSource{}, fmt.Errorf("invalid port in %q", text)
		}
		if _, err := endpointForPort(port); err != nil {
			return targetSource{}, err
		}
		host = strings.Trim(host, "[]")
		if err := validateHost(host); err != nil {
			return targetSource{}, err
		}
		return targetSource{label: host, kind: sourceHost, host: host, port: port, hosts: 1}, nil
	}

	host := strings.Trim(text, "[]")
	if err := validateHost(host); err != nil {
		return targetSource{}, err
	}
	return targetSource{label: host, kind: sourceHost, host: host, hosts: 1}, nil
}

func validateHost(host string) error {
	if host == "" {
		return errors.New("empty host")
	}
	if net.ParseIP(host) != nil {
		return nil
	}
	if len(host) > 253 {
		return fmt.Errorf("invalid host %q", host)
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if label == "" || len(label) > 63 {
			return fmt.Errorf("invalid host %q", host)
		}
		for _, r := range label {
			allowed := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
				(r >= '0' && r <= '9') || r == '-' || r == '_'
			if !allowed {
				return fmt.Errorf("invalid host %q", host)
			}
		}
	}
	return nil
}

type sourcePlan struct {
	sources   []targetSource
	hosts     uint64
	probes    uint64
	warnings  []string
	truncated bool
}

func buildPlan(opts *options) (*sourcePlan, error) {
	plan := &sourcePlan{}
	seen := make(map[string]bool)

	collect := func(origin, line string) {
		source, err := parseTargetSource(line)
		if errors.Is(err, errBlankLine) {
			return
		}
		if err != nil {
			plan.warnings = append(plan.warnings, fmt.Sprintf("%s: %v", origin, err))
			return
		}
		key := strconv.Itoa(int(source.kind)) + "|" + source.label + "|" + strconv.Itoa(source.port)
		if seen[key] {
			return
		}
		seen[key] = true
		plan.sources = append(plan.sources, source)
	}

	if opts.target != "" {
		collect("-ip", opts.target)
	}
	if opts.file != "" {
		file, err := os.Open(opts.file)
		if err != nil {
			return nil, fmt.Errorf("target file: %w", err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)
		for number := 1; scanner.Scan(); number++ {
			collect(fmt.Sprintf("%s:%d", opts.file, number), scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("reading %s: %w", opts.file, err)
		}
	}
	if len(plan.sources) == 0 {
		return nil, errors.New("no valid targets")
	}
	plan.hosts, plan.probes, plan.truncated = estimateWorkload(plan.sources, uint64(opts.maxHosts))
	return plan, nil
}

func probesPerHost(source targetSource) uint64 {
	if source.port != 0 {
		return 1
	}
	return uint64(len(standardEndpoints))
}

func estimateWorkload(sources []targetSource, limit uint64) (uint64, uint64, bool) {
	var hosts, probes uint64
	truncated := false
	for _, source := range sources {
		if hosts >= limit {
			truncated = true
			break
		}
		count := source.hosts
		if remaining := limit - hosts; count > remaining {
			count = remaining
			truncated = true
		}
		hosts = saturatingAdd(hosts, count)
		probes = saturatingAdd(probes, saturatingMul(count, probesPerHost(source)))
	}
	return hosts, probes, truncated
}

type scanTask struct {
	host string
	ep   endpoint
}

type dispatcher struct {
	sources   []targetSource
	limit     int
	hostsSeen map[string]bool
	taskSeen  map[string]bool
	hosts     atomic.Int64
	queued    atomic.Int64
	skipped   atomic.Int64
	truncated atomic.Bool
}

func newDispatcher(sources []targetSource, limit int) *dispatcher {
	return &dispatcher{
		sources:   sources,
		limit:     limit,
		hostsSeen: make(map[string]bool),
		taskSeen:  make(map[string]bool),
	}
}

func (d *dispatcher) endpointsFor(source targetSource) []endpoint {
	if source.port == 0 {
		return standardEndpoints
	}
	ep, err := endpointForPort(source.port)
	if err != nil {
		return nil
	}
	return []endpoint{ep}
}

func (d *dispatcher) admitHost(host string) bool {
	if d.hostsSeen[host] {
		return true
	}
	if int(d.hosts.Load()) >= d.limit {
		d.truncated.Store(true)
		return false
	}
	d.hostsSeen[host] = true
	d.hosts.Add(1)
	return true
}

func (d *dispatcher) hostCount() int { return int(d.hosts.Load()) }
func (d *dispatcher) skippedCount() uint64 {
	if skipped := d.skipped.Load(); skipped > 0 {
		return uint64(skipped)
	}
	return 0
}
func (d *dispatcher) wasTruncated() bool { return d.truncated.Load() }

func (d *dispatcher) run(ctx context.Context, tasks chan<- scanTask) {
	defer close(tasks)

	for _, source := range d.sources {
		endpoints := d.endpointsFor(source)
		if len(endpoints) == 0 {
			continue
		}
		stopped := false
		source.each(func(host string) bool {
			if ctx.Err() != nil || !d.admitHost(host) {
				stopped = true
				return false
			}
			for _, ep := range endpoints {
				key := host + "|" + strconv.Itoa(ep.port)
				if d.taskSeen[key] {
					d.skipped.Add(1)
					continue
				}
				d.taskSeen[key] = true
				select {
				case tasks <- scanTask{host: host, ep: ep}:
					d.queued.Add(1)
				case <-ctx.Done():
					stopped = true
					return false
				}
			}
			return true
		})
		if stopped {
			return
		}
	}
}

type responseView struct {
	status          int
	header          http.Header
	finalURL        *url.URL
	path            string
	body            []byte
	redirectBlocked string
}

type redirectTrace struct {
	blocked string
}

type redirectTraceKey struct{}

func canonicalPort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	if strings.EqualFold(u.Scheme, "https") {
		return "443"
	}
	return "80"
}

func sameEndpointURL(origin, next *url.URL) bool {
	if origin == nil || next == nil {
		return false
	}
	return strings.EqualFold(origin.Scheme, next.Scheme) &&
		strings.EqualFold(origin.Hostname(), next.Hostname()) &&
		canonicalPort(origin) == canonicalPort(next)
}

func redirectGuard(req *http.Request, via []*http.Request) error {
	if len(via) == 0 {
		return nil
	}
	if !sameEndpointURL(via[0].URL, req.URL) {
		if trace, ok := req.Context().Value(redirectTraceKey{}).(*redirectTrace); ok && trace.blocked == "" {
			trace.blocked = req.URL.Scheme + "://" + req.URL.Host
		}
		return http.ErrUseLastResponse
	}
	if len(via) >= maxRedirects {
		return http.ErrUseLastResponse
	}
	return nil
}

func newHTTPClient(opts *options) *http.Client {
	dialer := &net.Dialer{Timeout: opts.timeout, KeepAlive: 15 * time.Second}
	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   opts.timeout,
		ResponseHeaderTimeout: opts.timeout,
		ExpectContinueTimeout: time.Second,
		IdleConnTimeout:       10 * time.Second,
		MaxIdleConns:          128,
		MaxIdleConnsPerHost:   1,
		DisableCompression:    true,
		ForceAttemptHTTP2:     false,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: opts.insecure,
			MinVersion:         tls.VersionTLS12,
		},
	}
	return &http.Client{Transport: transport, CheckRedirect: redirectGuard}
}

func requestOnce(ctx context.Context, client *http.Client, opts *options, target string) (*responseView, error) {
	reqCtx, cancel := context.WithTimeout(ctx, opts.timeout)
	defer cancel()

	trace := &redirectTrace{}
	req, err := http.NewRequestWithContext(context.WithValue(reqCtx, redirectTraceKey{}, trace),
		http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", opts.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5")
	req.Header.Set("Accept-Encoding", "identity")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	io.Copy(io.Discard, io.LimitReader(resp.Body, drainBytes))
	closeErr := resp.Body.Close()
	if len(body) == 0 {
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
	}

	final := resp.Request.URL
	if final == nil {
		final, _ = url.Parse(target)
	}
	view := &responseView{status: resp.StatusCode, header: resp.Header, finalURL: final,
		body: body, redirectBlocked: trace.blocked}
	if final != nil {
		view.path = final.Path
	}
	return view, nil
}

var errnoBuckets = map[syscall.Errno]string{
	syscall.ECONNREFUSED: "refused",
	syscall.ECONNRESET:   "reset",
	syscall.EHOSTUNREACH: "unreachable",
	syscall.ENETUNREACH:  "unreachable",
	syscall.ETIMEDOUT:    "timeout",
	10060:                "timeout",
	10061:                "refused",
	10054:                "reset",
	10051:                "unreachable",
	10065:                "unreachable",
}

func classifyNetworkError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return "tls"
	}
	var recordErr tls.RecordHeaderError
	if errors.As(err, &recordErr) {
		return "tls"
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "dns"
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		if bucket, ok := errnoBuckets[errno]; ok {
			return bucket
		}
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "x509"), strings.Contains(text, "certificate"), strings.Contains(text, "tls:"):
		return "tls"
	case strings.Contains(text, "refused"):
		return "refused"
	case strings.Contains(text, "reset"), strings.Contains(text, "eof"), strings.Contains(text, "closed"):
		return "reset"
	case strings.Contains(text, "unreachable"), strings.Contains(text, "no route"):
		return "unreachable"
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		switch opErr.Op {
		case "dial":
			return "connect"
		case "read", "write":
			return "reset"
		}
	}
	return "http"
}

type evidenceBucket uint8

const (
	productEvidence evidenceBucket = iota
	cpanelEvidence
	whmEvidence
)

type evidence struct {
	product       int
	cpanel        int
	whm           int
	strongProduct int
	mediumProduct int
	strongCPanel  int
	strongWHM     int
	title         string
	signals       []string
	recorded      map[string]bool
}

func newEvidence() *evidence {
	return &evidence{recorded: make(map[string]bool, 8)}
}

func (e *evidence) add(bucket evidenceBucket, strength signalStrength, label string) {
	if e.recorded[label] {
		return
	}
	e.recorded[label] = true
	e.signals = append(e.signals, label)

	weight := strength.weight()
	switch bucket {
	case cpanelEvidence:
		e.cpanel += weight
		if strength == strongSignal {
			e.strongCPanel++
		}
	case whmEvidence:
		e.whm += weight
		if strength == strongSignal {
			e.strongWHM++
		}
	default:
		e.product += weight
		switch strength {
		case strongSignal:
			e.strongProduct++
		case mediumSignal:
			e.mediumProduct++
		}
	}
}

type fingerprint struct {
	service    serviceKind
	confidence confidenceLevel
	score      int
	detected   bool
	title      string
	signals    []string
}

var titlePattern = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

type bodyMarker struct {
	needle   string
	bucket   evidenceBucket
	strength signalStrength
	label    string
}

var bodyMarkers = []bodyMarker{
	{"cpanel_magic_revision", productEvidence, strongSignal, "asset:magic-revision"},
	{"/cpanelbranding/", productEvidence, strongSignal, "asset:branding"},
	{"cpsrvd", productEvidence, mediumSignal, "body:cpsrvd"},
	{"cpanel, l.l.c", productEvidence, mediumSignal, "footer:cpanel-llc"},
	{"cpanel, inc", productEvidence, mediumSignal, "footer:cpanel-inc"},
	{"/unprotected/js/", productEvidence, weakSignal, "asset:unprotected-js"},
	{"security_policy", productEvidence, weakSignal, "form:security-policy"},
	{"login_theme", productEvidence, weakSignal, "form:login-theme"},
	{"whostmgr", whmEvidence, mediumSignal, "body:whostmgr"},
	{"webhost manager", whmEvidence, mediumSignal, "body:webhost-manager"},
	{"cpanel login", cpanelEvidence, mediumSignal, "body:cpanel-login"},
	{"/frontend/jupiter", cpanelEvidence, mediumSignal, "theme:jupiter"},
	{"/frontend/paper_lantern", cpanelEvidence, mediumSignal, "theme:paper-lantern"},
	{"cpanel", productEvidence, weakSignal, "body:cpanel-mention"},
}

func collectEvidence(ep endpoint, view *responseView) *evidence {
	ev := newEvidence()
	if view == nil {
		return ev
	}
	readHeaderEvidence(ev, view.header)
	readURLEvidence(ev, view.finalURL)
	readBodyEvidence(ev, view.body)
	if ev.product >= portHintFloor {
		switch ep.expected {
		case serviceCPanel:
			ev.cpanel += portHintWeight
		case serviceWHM:
			ev.whm += portHintWeight
		}
	}
	return ev
}

func readHeaderEvidence(ev *evidence, header http.Header) {
	if header == nil {
		return
	}
	server := strings.ToLower(header.Get("Server"))
	switch {
	case strings.Contains(server, "cpsrvd"):
		ev.add(productEvidence, strongSignal, "server:cpsrvd")
	case strings.Contains(server, "cpanel"):
		ev.add(productEvidence, mediumSignal, "server:cpanel")
	}
	for key := range header {
		if strings.HasPrefix(strings.ToLower(key), "x-cpanel") {
			ev.add(productEvidence, strongSignal, "header:x-cpanel")
			break
		}
	}
	if strings.Contains(strings.ToLower(header.Get("X-Powered-By")), "cpanel") {
		ev.add(productEvidence, mediumSignal, "header:x-powered-by")
	}
	for _, cookie := range header.Values("Set-Cookie") {
		lower := strings.ToLower(cookie)
		if strings.Contains(lower, "cpsession") {
			ev.add(productEvidence, strongSignal, "cookie:cpsession")
		}
		if strings.Contains(lower, "cprelogin") {
			ev.add(productEvidence, mediumSignal, "cookie:cprelogin")
		}
		if strings.Contains(lower, "whostmgrsession") {
			ev.add(whmEvidence, strongSignal, "cookie:whostmgrsession")
		}
	}
}

func readURLEvidence(ev *evidence, final *url.URL) {
	if final == nil {
		return
	}
	path := strings.ToLower(final.Path)
	query := strings.ToLower(final.RawQuery)
	if strings.Contains(path, "/cpsess") {
		ev.add(productEvidence, strongSignal, "path:cpsess")
	}
	if strings.HasPrefix(path, "/login") && strings.Contains(query, "login_only") {
		ev.add(productEvidence, mediumSignal, "redirect:login-only")
	}
	if strings.Contains(path, "whostmgr") {
		ev.add(whmEvidence, strongSignal, "path:whostmgr")
	}
	if strings.Contains(path, "/frontend/") {
		ev.add(cpanelEvidence, strongSignal, "path:frontend")
	}
}

func readBodyEvidence(ev *evidence, body []byte) {
	if len(body) == 0 {
		return
	}
	text := string(body)
	if match := titlePattern.FindStringSubmatch(text); len(match) == 2 {
		ev.title = clipRunes(strings.Join(strings.Fields(match[1]), " "), 96)
		title := strings.ToLower(ev.title)
		switch {
		case strings.Contains(title, "webhost manager"), strings.Contains(title, "whm login"):
			ev.add(productEvidence, mediumSignal, "title:whm")
			ev.add(whmEvidence, strongSignal, "title:whm-role")
		case strings.Contains(title, "cpanel") && strings.Contains(title, "login"):
			ev.add(productEvidence, mediumSignal, "title:cpanel-login")
			ev.add(cpanelEvidence, strongSignal, "title:cpanel-role")
		case strings.Contains(title, "cpanel"):
			ev.add(productEvidence, weakSignal, "title:cpanel-mention")
		}
	}
	lower := strings.ToLower(text)
	for _, marker := range bodyMarkers {
		if strings.Contains(lower, marker.needle) {
			ev.add(marker.bucket, marker.strength, marker.label)
		}
	}
}

func classify(ep endpoint, ev *evidence) fingerprint {
	service, roleScore := resolveService(ep, ev)
	score := ev.product + roleScore
	if score > scoreCap {
		score = scoreCap
	}

	result := fingerprint{
		service:    serviceUnknown,
		confidence: confidenceLow,
		score:      score,
		title:      ev.title,
		signals:    ev.signals,
	}
	enough := ev.strongProduct >= 1 || ev.mediumProduct >= 2
	if service == serviceUnknown || ev.product < productFloor || !enough || score < detectScore {
		return result
	}

	result.detected = true
	result.service = service
	switch {
	case score >= highScore && ev.strongProduct >= 1:
		result.confidence = confidenceHigh
	case score >= mediumScore:
		result.confidence = confidenceMedium
	default:
		result.confidence = confidenceLow
	}
	return result
}

func resolveService(ep endpoint, ev *evidence) (serviceKind, int) {
	switch {
	case ev.strongCPanel > 0 && ev.strongWHM == 0:
		return serviceCPanel, ev.cpanel
	case ev.strongWHM > 0 && ev.strongCPanel == 0:
		return serviceWHM, ev.whm
	case ev.cpanel > ev.whm:
		return serviceCPanel, ev.cpanel
	case ev.whm > ev.cpanel:
		return serviceWHM, ev.whm
	case ep.expected != serviceUnknown:
		return ep.expected, ev.cpanel
	default:
		return serviceUnknown, 0
	}
}

type scanResult struct {
	host            string
	ep              endpoint
	requestURL      string
	finalURL        string
	finalPath       string
	status          int
	server          string
	title           string
	service         serviceKind
	confidence      confidenceLevel
	score           int
	detected        bool
	signals         []string
	redirected      bool
	redirectBlocked string
	duration        time.Duration
	err             error
	errKind         string
}

func (r scanResult) address() string { return r.ep.address(r.host) }

var probePaths = []string{"/", "/login/", "/cgi-sys/"}

func shouldProbeAgain(view *responseView, ev *evidence) bool {
	if ev.product > 0 || ev.cpanel > 0 || ev.whm > 0 {
		return true
	}
	switch view.status {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return true
	default:
		return false
	}
}

func scanEndpoint(ctx context.Context, client *http.Client, opts *options, task scanTask) scanResult {
	base := task.ep.baseURL(task.host)
	result := scanResult{host: task.host, ep: task.ep, requestURL: base + "/", finalURL: base + "/"}
	started := time.Now()

	var (
		bestView *responseView
		bestEv   *evidence
		bestFP   fingerprint
	)
	for index, path := range probePaths {
		view, err := requestOnce(ctx, client, opts, base+path)
		if err != nil {
			if bestView == nil {
				result.err = err
				result.errKind = classifyNetworkError(err)
			}
			break
		}
		ev := collectEvidence(task.ep, view)
		fp := classify(task.ep, ev)
		if bestView == nil || fp.score > bestFP.score {
			bestView, bestEv, bestFP = view, ev, fp
			result.requestURL = base + path
		}
		if fp.detected || index == len(probePaths)-1 || ctx.Err() != nil {
			break
		}
		if !shouldProbeAgain(view, ev) {
			break
		}
	}

	result.duration = time.Since(started)
	if bestView == nil {
		return result
	}
	result.status = bestView.status
	result.server = strings.TrimSpace(bestView.header.Get("Server"))
	result.finalPath = bestView.path
	if bestView.finalURL != nil {
		result.finalURL = bestView.finalURL.String()
	}
	result.redirected = result.finalURL != result.requestURL
	result.redirectBlocked = bestView.redirectBlocked
	result.title = bestEv.title
	result.service = bestFP.service
	result.confidence = bestFP.confidence
	result.score = bestFP.score
	result.detected = bestFP.detected
	result.signals = bestFP.signals
	return result
}

func runScan(ctx context.Context, opts *options, disp *dispatcher, consume func(scanResult)) {
	client := newHTTPClient(opts)
	defer client.CloseIdleConnections()

	tasks := make(chan scanTask, opts.workers*2)
	results := make(chan scanResult, opts.workers*2)

	go disp.run(ctx, tasks)

	var wg sync.WaitGroup
	for i := 0; i < opts.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range tasks {
				if ctx.Err() != nil {
					continue
				}
				select {
				case results <- scanEndpoint(ctx, client, opts, task):
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	for result := range results {
		consume(result)
	}
}

type palette struct{ enabled bool }

func (p palette) wrap(code, text string) string {
	if !p.enabled {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

func (p palette) green(text string) string  { return p.wrap("1;32", text) }
func (p palette) cyan(text string) string   { return p.wrap("1;36", text) }
func (p palette) yellow(text string) string { return p.wrap("1;33", text) }
func (p palette) dim(text string) string    { return p.wrap("2;37", text) }
func (p palette) bold(text string) string   { return p.wrap("1", text) }

func isTerminal(file *os.File) bool {
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

type statusLine struct {
	writer  io.Writer
	enabled bool
	total   uint64
	skipped func() uint64
	done    uint64
	found   uint64
	started time.Time
	updated time.Time
	width   int
}

func newStatusLine(writer io.Writer, enabled bool, total uint64, skipped func() uint64) *statusLine {
	return &statusLine{writer: writer, enabled: enabled, total: total, skipped: skipped, started: time.Now()}
}

func (s *statusLine) pending() uint64 {
	total := s.total
	if s.skipped != nil {
		if skipped := s.skipped(); skipped < total {
			total -= skipped
		}
	}
	if total < s.done {
		return s.done
	}
	return total
}

func (s *statusLine) advance(found bool) {
	s.done++
	if found {
		s.found++
	}
	s.render(false)
}

func (s *statusLine) render(force bool) {
	if !s.enabled {
		return
	}
	now := time.Now()
	if !force && now.Sub(s.updated) < 150*time.Millisecond {
		return
	}
	s.updated = now

	total := s.pending()
	percent := 0.0
	if total > 0 {
		percent = float64(s.done) / float64(total) * 100
		if percent > 100 {
			percent = 100
		}
	}
	text := fmt.Sprintf(" scanning %5.1f%%  %d/%d  detected:%d  %s",
		percent, s.done, total, s.found, now.Sub(s.started).Truncate(time.Second))
	fmt.Fprintf(s.writer, "\r%s", text)
	if length := len([]rune(text)); length < s.width {
		fmt.Fprint(s.writer, strings.Repeat(" ", s.width-length))
	} else {
		s.width = length
	}
}

func (s *statusLine) clear() {
	if s.enabled && s.width > 0 {
		fmt.Fprintf(s.writer, "\r%s\r", strings.Repeat(" ", s.width))
	}
}

func clipRunes(text string, limit int) string {
	runes := []rune(text)
	if len(runes) <= limit {
		return text
	}
	return string(runes[:limit])
}

func shortenRunes(text string, limit int) string {
	text = strings.TrimSpace(text)
	runes := []rune(text)
	if len(runes) <= limit {
		return text
	}
	return string(runes[:limit-3]) + "..."
}

func bannerText() string {
	return fmt.Sprintf("%s\n%52s%s\n%53s%s\n\n", bannerArt, "", displayName, "", programAuthor)
}

func printBanner(w io.Writer) {
	fmt.Fprint(w, bannerText())
}

func printPlan(w io.Writer, colors palette, opts *options, plan *sourcePlan) {
	field := func(name, value string) {
		fmt.Fprintf(w, "  %s %s\n", colors.dim(fmt.Sprintf("%-10s", name)), value)
	}
	sources := opts.target
	if opts.file != "" {
		if sources != "" {
			sources += " + "
		}
		sources += opts.file
	}
	ports := make([]string, 0, len(standardEndpoints))
	for _, ep := range standardEndpoints {
		ports = append(ports, fmt.Sprintf("%d/%s", ep.port, ep.protocol()))
	}
	tlsMode := colors.green("verify certificates")
	if opts.insecure {
		tlsMode = colors.yellow("skip verification (-insecure)")
	}
	field("targets", fmt.Sprintf("%s (%d source(s))", sources, len(plan.sources)))
	field("hosts", formatCount(plan.hosts))
	field("probes", formatCount(plan.probes)+" (estimated)")
	field("ports", strings.Join(ports, "  "))
	field("workers", strconv.Itoa(opts.workers))
	field("timeout", opts.timeout.String())
	field("tls", tlsMode)
	if opts.output != "" {
		field("output", opts.output)
	}
	if plan.truncated {
		field("limit", colors.yellow(fmt.Sprintf("capped at %d hosts by -max-hosts", opts.maxHosts)))
	}
	fmt.Fprintln(w)
}

func formatCount(value uint64) string {
	if value == ^uint64(0) {
		return "unbounded"
	}
	return strconv.FormatUint(value, 10)
}

func resultLine(colors palette, result scanResult) string {
	status := "-"
	if result.status > 0 {
		status = strconv.Itoa(result.status)
	}
	if result.err != nil {
		return fmt.Sprintf("%-24s | %-5s | %s | %3s | %s",
			result.address(), result.ep.protocol(), colors.dim(fmt.Sprintf("%-7s", "error")),
			status, colors.dim("error="+result.errKind))
	}
	name := fmt.Sprintf("%-7s", result.service.String())
	switch {
	case result.detected && result.service == serviceCPanel:
		name = colors.green(name)
	case result.detected && result.service == serviceWHM:
		name = colors.cyan(name)
	default:
		name = colors.dim(name)
	}
	return fmt.Sprintf("%-24s | %-5s | %s | %3s | confidence=%s",
		result.address(), result.ep.protocol(), name, status, result.confidence)
}

func verboseDetail(colors palette, result scanResult) string {
	parts := make([]string, 0, 8)
	if result.finalURL != "" {
		parts = append(parts, "url="+result.finalURL)
	}
	if result.redirected && result.finalPath != "" {
		parts = append(parts, "path="+result.finalPath)
	}
	if result.redirectBlocked != "" {
		parts = append(parts, "redirect-blocked="+shortenRunes(result.redirectBlocked, 48))
	}
	if result.server != "" {
		parts = append(parts, "server="+shortenRunes(result.server, 40))
	}
	if result.title != "" {
		parts = append(parts, fmt.Sprintf("title=%q", shortenRunes(result.title, 48)))
	}
	parts = append(parts, "score="+strconv.Itoa(result.score))
	parts = append(parts, "took="+result.duration.Truncate(time.Millisecond).String())
	if len(result.signals) > 0 {
		parts = append(parts, "signals="+strings.Join(result.signals, ","))
	}
	if result.err != nil {
		parts = append(parts, "detail="+shortenRunes(result.err.Error(), 96))
	}
	return colors.dim("    " + strings.Join(parts, " "))
}

func reportLine(result scanResult) string {
	status := "-"
	if result.status > 0 {
		status = strconv.Itoa(result.status)
	}
	if result.err != nil {
		return fmt.Sprintf("%s | %s | error | %s | error=%s | url=%s | took=%s",
			result.address(), result.ep.protocol(), status, result.errKind,
			result.requestURL, result.duration.Truncate(time.Millisecond))
	}
	line := fmt.Sprintf("%s | %s | %s | %s | confidence=%s | score=%d | server=%q | title=%q | url=%s | took=%s | signals=%s",
		result.address(), result.ep.protocol(), result.service, status, result.confidence,
		result.score, result.server, result.title, result.finalURL,
		result.duration.Truncate(time.Millisecond), strings.Join(result.signals, ","))
	if result.redirectBlocked != "" {
		line += " | redirect-blocked=" + result.redirectBlocked
	}
	return line
}

type summary struct {
	probes   int
	cpanel   int
	whm      int
	unknown  int
	blocked  int
	failures map[string]int
}

func newSummary() *summary { return &summary{failures: make(map[string]int)} }

func (s *summary) add(result scanResult) {
	s.probes++
	if result.redirectBlocked != "" {
		s.blocked++
	}
	switch {
	case result.err != nil:
		s.failures[result.errKind]++
	case result.detected && result.service == serviceWHM:
		s.whm++
	case result.detected:
		s.cpanel++
	default:
		s.unknown++
	}
}

func (s *summary) errorCount() int {
	total := 0
	for _, count := range s.failures {
		total += count
	}
	return total
}

func (s *summary) failureBreakdown() string {
	if len(s.failures) == 0 {
		return "0"
	}
	kinds := make([]string, 0, len(s.failures))
	for kind := range s.failures {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	parts := make([]string, 0, len(kinds))
	for _, kind := range kinds {
		parts = append(parts, fmt.Sprintf("%s=%d", kind, s.failures[kind]))
	}
	return fmt.Sprintf("%d (%s)", s.errorCount(), strings.Join(parts, " "))
}

func printSummary(w io.Writer, colors palette, sum *summary, detections []scanResult, elapsed time.Duration, opts *options, truncated bool) {
	fmt.Fprintf(w, "\n%s\n", colors.bold("Summary"))
	field := func(name, value string) {
		fmt.Fprintf(w, "  %s %s\n", colors.dim(fmt.Sprintf("%-10s", name)), value)
	}
	field("duration", elapsed.Truncate(time.Millisecond).String())
	field("probes", strconv.Itoa(sum.probes))
	field("cpanel", colors.green(strconv.Itoa(sum.cpanel)))
	field("whm", colors.cyan(strconv.Itoa(sum.whm)))
	field("unknown", strconv.Itoa(sum.unknown))
	field("errors", sum.failureBreakdown())
	if sum.blocked > 0 {
		field("redirects", fmt.Sprintf("%d blocked (cross-host)", sum.blocked))
	}

	if truncated {
		fmt.Fprintf(w, "\n  %s host limit of %d reached, scan stopped early\n",
			colors.yellow("note:"), opts.maxHosts)
	}
	if !opts.insecure && sum.failures["tls"] > 0 {
		fmt.Fprintf(w, "  %s %d TLS verification failure(s), use -insecure for self-signed certificates\n",
			colors.yellow("note:"), sum.failures["tls"])
	}
	if len(detections) > 0 {
		fmt.Fprintf(w, "\n%s\n", colors.bold("Detected services"))
		for _, result := range detections {
			fmt.Fprintf(w, "  %s\n", resultLine(colors, result))
		}
	}
	fmt.Fprintln(w)
}

func sortResults(results []scanResult) {
	sort.Slice(results, func(i, j int) bool {
		left, right := results[i], results[j]
		if left.host != right.host {
			leftIP, rightIP := net.ParseIP(left.host), net.ParseIP(right.host)
			if leftIP != nil && rightIP != nil {
				return compareIP(leftIP, rightIP) < 0
			}
			return left.host < right.host
		}
		return left.ep.port < right.ep.port
	})
}

func compareIP(a, b net.IP) int {
	left, right := a.To16(), b.To16()
	if len(left) != len(right) {
		return len(left) - len(right)
	}
	for i := range left {
		switch {
		case left[i] < right[i]:
			return -1
		case left[i] > right[i]:
			return 1
		}
	}
	return 0
}

func openReport(path string) (*os.File, *bufio.Writer, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, nil, fmt.Errorf("output file: %w", err)
	}
	writer := bufio.NewWriter(file)
	fmt.Fprintf(writer, "# %s %s\n# started %s\n", programName, programVersion, time.Now().Format(time.RFC3339))
	return file, writer, nil
}

func execute(args []string, stdout, stderr io.Writer) int {
	out := bufio.NewWriter(stdout)
	defer out.Flush()

	printBanner(out)
	out.Flush()

	opts, err := parseOptions(args, stdout)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	if opts.selfTest {
		return runSelfTest(stdout)
	}

	interactive := isTerminal(os.Stdout)
	colors := palette{enabled: interactive && !opts.noColor && os.Getenv("NO_COLOR") == ""}

	plan, err := buildPlan(opts)
	if err != nil {
		out.Flush()
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	for _, warning := range plan.warnings {
		fmt.Fprintf(out, "  %s %s\n", colors.yellow("warning:"), warning)
	}
	if len(plan.warnings) > 0 {
		fmt.Fprintln(out)
	}
	printPlan(out, colors, opts, plan)
	out.Flush()

	var (
		reportFile   *os.File
		reportWriter *bufio.Writer
	)
	if opts.output != "" {
		reportFile, reportWriter, err = openReport(opts.output)
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
		defer func() {
			reportWriter.Flush()
			reportFile.Close()
		}()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	disp := newDispatcher(plan.sources, opts.maxHosts)
	status := newStatusLine(out, interactive, plan.probes, disp.skippedCount)
	sum := newSummary()
	detections := make([]scanResult, 0, 16)
	started := time.Now()

	runScan(ctx, opts, disp, func(result scanResult) {
		sum.add(result)
		if result.detected {
			detections = append(detections, result)
		}
		show := result.detected || opts.verbose
		if show {
			status.clear()
			fmt.Fprintln(out, resultLine(colors, result))
			if opts.verbose {
				fmt.Fprintln(out, verboseDetail(colors, result))
			}
			out.Flush()
			if reportWriter != nil {
				fmt.Fprintln(reportWriter, reportLine(result))
			}
		}
		status.advance(result.detected)
	})

	status.render(true)
	status.clear()
	elapsed := time.Since(started)

	if ctx.Err() != nil {
		fmt.Fprintf(out, "  %s interrupted, showing partial results\n", colors.yellow("note:"))
	}
	sortResults(detections)
	printSummary(out, colors, sum, detections, elapsed, opts, disp.wasTruncated())
	out.Flush()

	if reportWriter != nil {
		fmt.Fprintf(reportWriter, "# probes=%d cpanel=%d whm=%d unknown=%d errors=%d duration=%s\n",
			sum.probes, sum.cpanel, sum.whm, sum.unknown, sum.errorCount(), elapsed.Truncate(time.Millisecond))
		if err := reportWriter.Flush(); err != nil {
			fmt.Fprintf(stderr, "error: writing %s: %v\n", opts.output, err)
			return 1
		}
		fmt.Fprintf(out, "  results written to %s\n\n", opts.output)
		out.Flush()
	}
	return 0
}

func main() {
	os.Exit(execute(os.Args[1:], os.Stdout, os.Stderr))
}

type testReporter struct {
	writer io.Writer
	failed int
}

func (t *testReporter) check(name string, passed bool, detail string) {
	if passed {
		fmt.Fprintf(t.writer, "PASS  %s\n", name)
		return
	}
	t.failed++
	fmt.Fprintf(t.writer, "FAIL  %s: %s\n", name, detail)
}

func makeView(status int, headers map[string]string, body, finalURL string) *responseView {
	header := http.Header{}
	for key, value := range headers {
		header.Add(key, value)
	}
	parsed, _ := url.Parse(finalURL)
	view := &responseView{status: status, header: header, finalURL: parsed, body: []byte(body)}
	if parsed != nil {
		view.path = parsed.Path
	}
	return view
}

func fingerprintOf(port int, view *responseView) fingerprint {
	ep, err := endpointForPort(port)
	if err != nil {
		return fingerprint{}
	}
	return classify(ep, collectEvidence(ep, view))
}

func mustSource(text string) targetSource {
	source, err := parseTargetSource(text)
	if err != nil {
		panic(err)
	}
	return source
}

func drainTasks(tasks <-chan scanTask) []scanTask {
	collected := make([]scanTask, 0, 32)
	for task := range tasks {
		collected = append(collected, task)
	}
	return collected
}

func runSelfTest(w io.Writer) int {
	report := &testReporter{writer: w}
	fmt.Fprintf(w, "  selftest\n\n")

	testPortMapping(report)
	testTargetParsing(report)
	testRangeExpansion(report)
	testDispatching(report)
	testTransportPolicy(report)
	testFingerprinting(report)
	testReporting(report)

	fmt.Fprintln(w)
	if report.failed > 0 {
		fmt.Fprintf(w, "%d check(s) failed\n", report.failed)
		return 1
	}
	fmt.Fprintln(w, "all checks passed")
	return 0
}

func testPortMapping(t *testReporter) {
	expectations := []struct {
		port     int
		protocol string
		service  serviceKind
	}{
		{2082, "HTTP", serviceCPanel},
		{2083, "HTTPS", serviceCPanel},
		{2086, "HTTP", serviceWHM},
		{2087, "HTTPS", serviceWHM},
	}
	for _, want := range expectations {
		ep, err := endpointForPort(want.port)
		name := fmt.Sprintf("port %d is %s %s", want.port, want.service, want.protocol)
		t.check(name, err == nil && ep.protocol() == want.protocol && ep.expected == want.service,
			fmt.Sprintf("%v %s %s", err, ep.protocol(), ep.expected))
	}
	secure, _ := endpointForPort(2087)
	t.check("https url built for 2087", secure.baseURL("198.51.100.10") == "https://198.51.100.10:2087",
		secure.baseURL("198.51.100.10"))
	plain, _ := endpointForPort(2082)
	t.check("http url built for 2082", plain.baseURL("198.51.100.10") == "http://198.51.100.10:2082",
		plain.baseURL("198.51.100.10"))
	custom, err := endpointForPort(8080)
	t.check("custom port defaults to http", err == nil && !custom.useTLS && custom.expected == serviceUnknown,
		fmt.Sprintf("%v %+v", err, custom))
	customTLS, _ := endpointForPort(8443)
	t.check("known tls port uses https", customTLS.useTLS, customTLS.protocol())
	t.check("ipv6 url is bracketed",
		secure.baseURL("2001:db8::1") == "https://[2001:db8::1]:2087",
		secure.baseURL("2001:db8::1"))
	t.check("ipv6 address is bracketed", secure.address("2001:db8::1") == "[2001:db8::1]:2087",
		secure.address("2001:db8::1"))
	if _, err := endpointForPort(70000); err == nil {
		t.check("invalid port rejected", false, "accepted")
	} else {
		t.check("invalid port rejected", true, "")
	}
}

func testTargetParsing(t *testReporter) {
	single, err := parseTargetSource("192.168.1.10")
	t.check("parse single ip", err == nil && single.kind == sourceHost && single.hosts == 1 && single.port == 0,
		fmt.Sprintf("%v %+v", err, single))

	withPort, err := parseTargetSource("https://panel.example.com:2087/login")
	t.check("parse host with port", err == nil && withPort.host == "panel.example.com" && withPort.port == 2087,
		fmt.Sprintf("%v %+v", err, withPort))

	network, err := parseTargetSource("10.10.0.0/29")
	t.check("parse cidr", err == nil && network.kind == sourceNetwork && network.hosts == 8,
		fmt.Sprintf("%v %+v", err, network))

	normalized, err := parseTargetSource("10.10.0.5/24")
	t.check("cidr host bits normalized", err == nil && normalized.label == "10.10.0.0/24" && normalized.hosts == 256,
		fmt.Sprintf("%v %+v", err, normalized))

	if _, err := parseTargetSource("   "); !errors.Is(err, errBlankLine) {
		t.check("blank line skipped", false, fmt.Sprint(err))
	} else {
		t.check("blank line skipped", true, "")
	}
	if _, err := parseTargetSource("# comment"); !errors.Is(err, errBlankLine) {
		t.check("comment skipped", false, fmt.Sprint(err))
	} else {
		t.check("comment skipped", true, "")
	}
	for _, bad := range []string{"999.1.1.1/24", "10.0.0.1/33", "host.example:99999", "two hosts"} {
		if _, err := parseTargetSource(bad); err == nil {
			t.check("rejects "+bad, false, "accepted")
		} else {
			t.check("rejects "+bad, true, "")
		}
	}
	huge, err := parseTargetSource("2001:db8::/32")
	t.check("huge range saturates instead of overflowing", err == nil && huge.hosts == ^uint64(0),
		fmt.Sprintf("%v %d", err, huge.hosts))
	t.check("probe math saturates",
		saturatingMul(^uint64(0), 4) == ^uint64(0) && saturatingAdd(^uint64(0), 10) == ^uint64(0),
		"overflow not contained")
}

func testRangeExpansion(t *testReporter) {
	source := mustSource("192.168.5.0/29")
	var hosts []string
	source.each(func(host string) bool {
		hosts = append(hosts, host)
		return true
	})
	inside := true
	for _, host := range hosts {
		if !source.network.Contains(net.ParseIP(host)) {
			inside = false
		}
	}
	unique := make(map[string]bool)
	for _, host := range hosts {
		unique[host] = true
	}
	t.check("cidr yields exact host count", len(hosts) == 8, strconv.Itoa(len(hosts)))
	t.check("cidr stays inside the network", inside, strings.Join(hosts, ","))
	t.check("cidr yields no duplicates", len(unique) == len(hosts), strconv.Itoa(len(unique)))
	t.check("cidr boundaries correct",
		len(hosts) == 8 && hosts[0] == "192.168.5.0" && hosts[7] == "192.168.5.7",
		strings.Join(hosts, ","))

	stopped := 0
	source.each(func(string) bool {
		stopped++
		return stopped < 3
	})
	t.check("expansion stops on demand", stopped == 3, strconv.Itoa(stopped))

	large := mustSource("10.0.0.0/8")
	visited := 0
	large.each(func(string) bool {
		visited++
		return visited < 5
	})
	t.check("large range streams lazily", visited == 5 && large.hosts == 1<<24,
		fmt.Sprintf("%d %d", visited, large.hosts))

	v6 := mustSource("2001:db8::/126")
	var v6hosts []string
	v6.each(func(host string) bool {
		v6hosts = append(v6hosts, host)
		return true
	})
	t.check("ipv6 expansion", len(v6hosts) == 4 && v6hosts[3] == "2001:db8::3", strings.Join(v6hosts, ","))
}

func testDispatching(t *testReporter) {
	disp := newDispatcher([]targetSource{
		mustSource("192.168.9.0/30"),
		mustSource("192.168.9.1"),
		mustSource("192.168.9.1:2087"),
	}, 100)
	tasks := make(chan scanTask, 64)
	disp.run(context.Background(), tasks)
	collected := drainTasks(tasks)

	unique := make(map[string]bool)
	for _, task := range collected {
		unique[task.host+"|"+strconv.Itoa(task.ep.port)] = true
	}
	t.check("dispatcher removes duplicate targets", len(collected) == 16 && len(unique) == 16,
		fmt.Sprintf("tasks=%d unique=%d", len(collected), len(unique)))

	protocolOK := true
	for _, task := range collected {
		wantTLS := task.ep.port == 2083 || task.ep.port == 2087
		if task.ep.useTLS != wantTLS {
			protocolOK = false
		}
	}
	t.check("dispatcher keeps protocol mapping", protocolOK, "tls mismatch in queued tasks")

	t.check("dispatcher counts skipped duplicates", disp.skippedCount() == 5,
		strconv.FormatUint(disp.skippedCount(), 10))

	mixed := newDispatcher([]targetSource{
		mustSource("203.0.113.0/30"),
		mustSource("203.0.113.1"),
		mustSource("203.0.113.1:2087"),
		mustSource("203.0.113.9:8443"),
		mustSource("203.0.113.9"),
	}, 100)
	mixedTasks := make(chan scanTask, 64)
	mixed.run(context.Background(), mixedTasks)
	mixedCollected := drainTasks(mixedTasks)
	explicitOnly := 0
	for _, task := range mixedCollected {
		if task.host == "203.0.113.9" && task.ep.port == 8443 {
			explicitOnly++
		}
	}
	t.check("mixed sources keep distinct endpoints",
		len(mixedCollected) == 21 && mixed.hostCount() == 5 && explicitOnly == 1,
		fmt.Sprintf("tasks=%d hosts=%d explicit=%d", len(mixedCollected), mixed.hostCount(), explicitOnly))

	limited := newDispatcher([]targetSource{mustSource("172.20.0.0/16")}, 5)
	limitedTasks := make(chan scanTask, 64)
	limited.run(context.Background(), limitedTasks)
	limitedCollected := drainTasks(limitedTasks)
	t.check("max-hosts limits expansion",
		limited.hostCount() == 5 && limited.wasTruncated() && len(limitedCollected) == 20,
		fmt.Sprintf("hosts=%d truncated=%v tasks=%d", limited.hostCount(), limited.wasTruncated(), len(limitedCollected)))

	plan, err := buildPlan(&options{target: "172.20.0.0/16", maxHosts: 10})
	t.check("plan reports truncation",
		err == nil && plan.truncated && plan.hosts == 10 && plan.probes == 40,
		fmt.Sprintf("%v %+v", err, plan))

	hosts, probes, truncated := estimateWorkload([]targetSource{
		mustSource("10.1.0.0/30"),
		mustSource("panel.example.com:2087"),
	}, 100)
	t.check("probe estimate honors explicit ports",
		hosts == 5 && probes == 17 && !truncated,
		fmt.Sprintf("hosts=%d probes=%d truncated=%v", hosts, probes, truncated))

	cappedHosts, cappedProbes, cappedTrunc := estimateWorkload([]targetSource{
		mustSource("10.1.0.0/24"),
		mustSource("panel.example.com:2087"),
	}, 3)
	t.check("probe estimate respects max-hosts",
		cappedHosts == 3 && cappedProbes == 12 && cappedTrunc,
		fmt.Sprintf("hosts=%d probes=%d truncated=%v", cappedHosts, cappedProbes, cappedTrunc))

	giantHosts, giantProbes, _ := estimateWorkload([]targetSource{mustSource("2001:db8::/32")}, ^uint64(0))
	t.check("estimate does not overflow",
		giantHosts == ^uint64(0) && giantProbes == ^uint64(0),
		fmt.Sprintf("%d %d", giantHosts, giantProbes))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	blocking := make(chan scanTask)
	finished := make(chan struct{})
	canceled := newDispatcher([]targetSource{mustSource("172.30.0.0/16")}, defaultMaxHosts)
	go func() {
		canceled.run(ctx, blocking)
		close(finished)
	}()
	select {
	case <-finished:
		t.check("dispatcher honors cancellation", true, "")
	case <-time.After(2 * time.Second):
		t.check("dispatcher honors cancellation", false, "dispatcher kept running")
	}
	for range blocking {
	}
}

func redirectDecision(from, to string) (bool, string) {
	trace := &redirectTrace{}
	origin, _ := http.NewRequest(http.MethodGet, from, nil)
	origin = origin.WithContext(context.WithValue(context.Background(), redirectTraceKey{}, trace))
	next, _ := http.NewRequest(http.MethodGet, to, nil)
	next = next.WithContext(origin.Context())
	err := redirectGuard(next, []*http.Request{origin})
	return err == nil, trace.blocked
}

func testTransportPolicy(t *testReporter) {
	allowed, _ := redirectDecision("https://198.51.100.10:2083/", "https://198.51.100.10:2083/login/?login_only=1")
	t.check("same endpoint redirect allowed", allowed, "blocked")

	crossHost, blockedHost := redirectDecision("https://198.51.100.10:2083/", "https://evil.example.com/collect")
	t.check("cross-host redirect blocked",
		!crossHost && blockedHost == "https://evil.example.com", fmt.Sprintf("%v %q", crossHost, blockedHost))

	crossPort, blockedPort := redirectDecision("https://198.51.100.10:2083/", "https://198.51.100.10:8443/")
	t.check("cross-port redirect blocked",
		!crossPort && blockedPort == "https://198.51.100.10:8443", fmt.Sprintf("%v %q", crossPort, blockedPort))

	downgrade, _ := redirectDecision("https://198.51.100.10:2083/", "http://198.51.100.10:2083/")
	t.check("tls downgrade redirect blocked", !downgrade, "allowed")

	upgrade, _ := redirectDecision("http://198.51.100.10:2082/", "https://198.51.100.10:2083/")
	t.check("scheme upgrade to another port blocked", !upgrade, "allowed")

	relative, _ := redirectDecision("http://198.51.100.10:2082/", "http://198.51.100.10:2082/cgi-sys/defaultwebpage.cgi")
	t.check("relative redirect on same endpoint allowed", relative, "blocked")

	caseHost, _ := redirectDecision("https://Panel.Example.com:2087/", "https://panel.example.com:2087/login/")
	t.check("host comparison is case insensitive", caseHost, "blocked")

	implicit, _ := redirectDecision("https://panel.example.com/", "https://panel.example.com:443/login/")
	t.check("implicit port matches default", implicit, "blocked")

	chain := make([]*http.Request, maxRedirects)
	origin, _ := http.NewRequest(http.MethodGet, "http://198.51.100.10:2082/", nil)
	for i := range chain {
		chain[i] = origin
	}
	next, _ := http.NewRequest(http.MethodGet, "http://198.51.100.10:2082/loop", nil)
	t.check("redirect chain is bounded", redirectGuard(next, chain) == http.ErrUseLastResponse, "unbounded")

	secure := newHTTPClient(&options{timeout: time.Second})
	config := secure.Transport.(*http.Transport).TLSClientConfig
	t.check("tls minimum version is 1.2", config.MinVersion == tls.VersionTLS12,
		strconv.Itoa(int(config.MinVersion)))
	t.check("certificates verified by default", !config.InsecureSkipVerify, "verification disabled")

	relaxed := newHTTPClient(&options{timeout: time.Second, insecure: true})
	relaxedConfig := relaxed.Transport.(*http.Transport).TLSClientConfig
	t.check("insecure only relaxes verification",
		relaxedConfig.InsecureSkipVerify && relaxedConfig.MinVersion == tls.VersionTLS12,
		fmt.Sprintf("skip=%v min=%d", relaxedConfig.InsecureSkipVerify, relaxedConfig.MinVersion))
}

func testFingerprinting(t *testReporter) {
	cpanelView := makeView(200, map[string]string{
		"Server":     "cpsrvd/11.126.0.6",
		"Set-Cookie": "cpsession=abc; path=/",
	}, `<html><head><title>cPanel Login</title></head><body>
	<img src="/cpanelbranding/logo.png">
	<script src="/unprotected/js/cpanel_magic_revision_1/login.js"></script>
	<footer>Copyright 2026 cPanel, L.L.C.</footer></body></html>`,
		"https://198.51.100.10:2083/login/?login_only=1")
	cpanel := fingerprintOf(2083, cpanelView)
	t.check("cpanel login detected with high confidence",
		cpanel.detected && cpanel.service == serviceCPanel && cpanel.confidence == confidenceHigh,
		fmt.Sprintf("%v %s %s score=%d", cpanel.detected, cpanel.service, cpanel.confidence, cpanel.score))

	whm := fingerprintOf(2087, makeView(200, map[string]string{"Server": "cpsrvd/11.126.0.6"},
		`<html><head><title>WHM Login</title></head><body>
		<form action="/whostmgr/login"></form><div>cPanel, L.L.C.</div></body></html>`,
		"https://198.51.100.10:2087/login/"))
	t.check("whm login detected",
		whm.detected && whm.service == serviceWHM && whm.confidence != confidenceLow,
		fmt.Sprintf("%v %s %s", whm.detected, whm.service, whm.confidence))

	whmOnCPanelPort := fingerprintOf(2083, makeView(200,
		map[string]string{"Server": "cpsrvd/11.126.0.6"},
		`<title>WebHost Manager</title><a href="/whostmgr/">panel</a>`,
		"https://198.51.100.10:2083/"))
	t.check("evidence outweighs port for whm", whmOnCPanelPort.service == serviceWHM,
		whmOnCPanelPort.service.String())

	cpanelOnWHMPort := fingerprintOf(2087, makeView(200,
		map[string]string{"Server": "cpsrvd/11.126.0.6", "Set-Cookie": "cpsession=x"},
		`<title>cPanel Login</title><img src="/cpanelbranding/x.png">`,
		"https://198.51.100.10:2087/"))
	t.check("evidence outweighs port for cpanel", cpanelOnWHMPort.service == serviceCPanel,
		cpanelOnWHMPort.service.String())

	mention := fingerprintOf(2083, makeView(200, map[string]string{"Server": "Apache/2.4.58"},
		`<html><head><title>How to use cPanel</title></head><body>
		<p>Our hosting guide explains the cPanel login screen and cPanel features.</p>
		</body></html>`, "https://198.51.100.10:2083/"))
	t.check("generic cpanel mention stays unknown",
		!mention.detected && mention.service == serviceUnknown,
		fmt.Sprintf("%v %s score=%d signals=%v", mention.detected, mention.service, mention.score, mention.signals))

	weakOnly := fingerprintOf(2083, makeView(200, map[string]string{"Server": "nginx"},
		`<html><body><script src="/unprotected/js/app.js"></script>
		<input name="login_theme"><input name="security_policy"></body></html>`,
		"https://198.51.100.10:2083/"))
	t.check("weak signals alone stay unknown", !weakOnly.detected,
		fmt.Sprintf("score=%d signals=%v", weakOnly.score, weakOnly.signals))

	unrelated := fingerprintOf(2087, makeView(200, map[string]string{"Server": "nginx/1.24"},
		"<html><head><title>Welcome to nginx</title></head></html>", "https://198.51.100.10:2087/"))
	t.check("unrelated service stays unknown", !unrelated.detected && unrelated.score == 0,
		fmt.Sprintf("score=%d", unrelated.score))

	empty := fingerprintOf(2086, makeView(404, map[string]string{}, "", "http://198.51.100.10:2086/"))
	t.check("empty response stays unknown",
		!empty.detected && empty.service == serviceUnknown && empty.confidence == confidenceLow,
		fmt.Sprintf("%+v", empty))

	headerOnly := fingerprintOf(2086, makeView(200,
		map[string]string{"Server": "Apache", "X-Cpanel-Server": "srv1"},
		"<html><body>redirecting</body></html>", "http://198.51.100.10:2086/"))
	t.check("single strong header gives low confidence whm",
		headerOnly.detected && headerOnly.service == serviceWHM && headerOnly.confidence == confidenceLow,
		fmt.Sprintf("%v %s %s score=%d", headerOnly.detected, headerOnly.service, headerOnly.confidence, headerOnly.score))

	t.check("confidence tracks score",
		cpanel.score >= highScore && headerOnly.score < mediumScore && headerOnly.score >= detectScore,
		fmt.Sprintf("%d %d", cpanel.score, headerOnly.score))

	t.check("follow-up probing is conditional",
		shouldProbeAgain(makeView(403, nil, "", "http://x/"), newEvidence()) &&
			!shouldProbeAgain(makeView(200, nil, "", "http://x/"), newEvidence()),
		"unexpected follow-up decision")

	t.check("signal weights ordered",
		strongSignal.weight() > mediumSignal.weight() && mediumSignal.weight() > weakSignal.weight(),
		"weights out of order")

	strongVsWeak := fingerprintOf(2083, makeView(200,
		map[string]string{"Server": "cpsrvd/11.126.0.6", "Set-Cookie": "cpsession=x"},
		`<html><head><title>cPanel Login</title></head><body>
		<img src="/cpanelbranding/logo.png">
		<p>Contact your provider through the WebHost Manager interface.</p></body></html>`,
		"https://198.51.100.10:2083/login/"))
	t.check("weak signal cannot override strong classification",
		strongVsWeak.detected && strongVsWeak.service == serviceCPanel,
		fmt.Sprintf("%s score=%d signals=%v", strongVsWeak.service, strongVsWeak.score, strongVsWeak.signals))

	docs := fingerprintOf(2083, makeView(200, map[string]string{"Server": "Apache/2.4.58"},
		`<html><head><title>Server daemons explained</title></head><body>
		<p>The cpsrvd daemon powers cPanel. Learn about cPanel here.</p></body></html>`,
		"https://198.51.100.10:2083/"))
	t.check("documentation about cpsrvd stays unknown",
		!docs.detected && docs.service == serviceUnknown,
		fmt.Sprintf("score=%d signals=%v", docs.score, docs.signals))

	whmGeneric := fingerprintOf(2087, makeView(200, map[string]string{"Server": "Apache"},
		"<html><head><title>WHM hosting plans</title></head><body>WHM resellers welcome</body></html>",
		"https://198.51.100.10:2087/"))
	t.check("generic whm mention stays unknown", !whmGeneric.detected,
		fmt.Sprintf("score=%d signals=%v", whmGeneric.score, whmGeneric.signals))
}

func testReporting(t *testReporter) {
	t.check("timeout classified", classifyNetworkError(context.DeadlineExceeded) == "timeout",
		classifyNetworkError(context.DeadlineExceeded))
	t.check("tls failure classified",
		classifyNetworkError(errors.New("x509: certificate signed by unknown authority")) == "tls", "")
	localized := &net.OpError{Op: "dial", Net: "tcp",
		Err: os.NewSyscallError("connectex", syscall.Errno(10061))}
	t.check("refused classified from errno", classifyNetworkError(localized) == "refused",
		classifyNetworkError(localized))
	unmapped := &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("unmapped failure")}
	t.check("dial failure has a fallback bucket", classifyNetworkError(unmapped) == "connect",
		classifyNetworkError(unmapped))

	detected := scanResult{
		host: "198.51.100.10", ep: standardEndpoints[1], status: 200,
		service: serviceCPanel, confidence: confidenceHigh, detected: true,
	}
	plain := resultLine(palette{enabled: false}, detected)
	collapsed := strings.Join(strings.Fields(plain), " ")
	t.check("plain output has no escape codes", !strings.Contains(plain, "\x1b"), plain)
	t.check("result line format",
		collapsed == "198.51.100.10:2083 | HTTPS | cPanel | 200 | confidence=high",
		plain)
	t.check("report line format",
		strings.Contains(reportLine(detected), "198.51.100.10:2083 | HTTPS | cPanel | 200 | confidence=high"),
		reportLine(detected))

	failure := scanResult{host: "198.51.100.10", ep: standardEndpoints[3], err: errors.New("boom"), errKind: "refused"}
	t.check("errors reported per target",
		strings.Contains(resultLine(palette{}, failure), "198.51.100.10:2087") &&
			strings.Contains(resultLine(palette{}, failure), "error=refused"),
		resultLine(palette{}, failure))

	sum := newSummary()
	sum.add(detected)
	sum.add(failure)
	sum.add(scanResult{host: "198.51.100.10", ep: standardEndpoints[0]})
	t.check("summary counts by outcome",
		sum.probes == 3 && sum.cpanel == 1 && sum.unknown == 1 && sum.errorCount() == 1,
		fmt.Sprintf("%+v", sum))

	blockedResult := scanResult{
		host: "198.51.100.10", ep: standardEndpoints[1], status: 302,
		redirectBlocked: "https://evil.example.com",
	}
	t.check("blocked redirect is reported",
		strings.Contains(reportLine(blockedResult), "redirect-blocked=https://evil.example.com") &&
			strings.Contains(verboseDetail(palette{}, blockedResult), "redirect-blocked="),
		reportLine(blockedResult))

	blockedSummary := newSummary()
	blockedSummary.add(blockedResult)
	t.check("summary counts blocked redirects", blockedSummary.blocked == 1,
		strconv.Itoa(blockedSummary.blocked))

	quiet := newStatusLine(io.Discard, false, 10, nil)
	quiet.advance(false)
	quiet.render(true)
	quiet.clear()
	t.check("status line silent when not interactive", quiet.done == 1 && quiet.width == 0,
		fmt.Sprintf("done=%d width=%d", quiet.done, quiet.width))

	adjusted := newStatusLine(io.Discard, false, 16, func() uint64 { return 8 })
	adjusted.done = 8
	t.check("status total drops deduplicated probes", adjusted.pending() == 8,
		strconv.FormatUint(adjusted.pending(), 10))

	banner := bannerText()
	t.check("banner needs no escape codes", !strings.Contains(banner, ""),
		"banner contains escape codes")
	t.check("banner keeps the provided art", strings.Contains(banner, bannerArt),
		"banner art altered")
	t.check("banner carries the project identity",
		strings.Contains(banner, displayName) && strings.Contains(banner, programAuthor),
		banner)

	t.check("ip comparison tolerates invalid input",
		compareIP(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")) < 0 &&
			compareIP(net.IP{1, 2}, net.ParseIP("10.0.0.1")) != 0,
		"comparison misbehaves")

	shortened := shortenRunes("configuración de páginas", 10)
	t.check("text shortening is rune safe",
		shortened == "configu..." && len([]rune(shortened)) == 10 && clipRunes("áéíóú", 3) == "áéí",
		shortened+"|"+clipRunes("áéíóú", 3))
}
